#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.3 - Telemetry Queue Test
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'path';
import url from 'url';
import vm from 'vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const queueSrc = fs.readFileSync(path.join(repoRoot, 'src/util/telemetry-queue.js'), 'utf8');

let passed = 0;
let failed = 0;
function test(name, fn) {
  return Promise.resolve().then(fn).then(() => {
    passed++;
    console.log(`  PASS  ${name}`);
  }).catch(err => {
    failed++;
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err.message}`);
  });
}

console.log('AegisGate Lens v0.3 - Telemetry Queue Test');
console.log('');

function createChromeMock(initialData = {}, optInEnabled = false) {
  const data = { ...initialData };
  return {
    runtime: {
      getManifest: () => ({ version: '0.3.0-test' }),
      lastError: null,
    },
    storage: {
      sync: {
        get: (key, cb) => {
          const result = {};
          if (typeof key === 'string') result[key] = data[key];
          cb(result);
        },
        set: (obj, cb) => {
          Object.assign(data, obj);
          cb();
        },
      },
      local: {
        get: (key, cb) => {
          const result = {};
          if (typeof key === 'string') result[key] = data[key];
          cb(result);
        },
        set: (obj, cb) => {
          Object.assign(data, obj);
          cb();
        },
        remove: (key, cb) => {
          if (typeof key === 'string') delete data[key];
          cb();
        },
      },
    },
    _data: data,
    _optInEnabled: optInEnabled,
  };
}

async function loadQueue(chromeMock) {
  const sandbox = {
    console, Math, JSON, Date, Promise,
    setTimeout, clearTimeout, setInterval, clearInterval,
    Object, Array, Number, String, Boolean,
    chrome: chromeMock,
    self: {},
  };
  sandbox.self.AegisGateLens = {
    logger: console,
    util: {
      optIn: {
        isTelemetryEnabled: async () => chromeMock._optInEnabled,
      },
    },
  };
  sandbox.AegisGateLens = sandbox.self.AegisGateLens;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(queueSrc, ctx, { filename: 'telemetry-queue.js' });
  return sandbox.AegisGateLens.util.telemetryQueue;
}

function buildDetection() {
  return {
    category: 'pii_ssn',
    severity: 'critical',
    confidence: 0.98,
  };
}

function buildMockApi() {
  const sent = [];
  return {
    sent,
    sendEvent: async (ev) => {
      sent.push(ev);
      return { status: 200 };
    },
  };
}

// ============================================================================
// Tests
// ============================================================================

await test('buildEvent creates v0.1 schema (9 fields)', async () => {
  const q = await loadQueue(createChromeMock());
  const ev = q.buildEvent(buildDetection(), 'send_anyway', { domainHash: 'abc', lensVersion: '0.3.0' });
  assert.equal(ev.lens_event_version, 1);
  assert.equal(ev.domain_hash, 'abc');
  assert.equal(ev.category, 'pii_ssn');
  assert.equal(ev.severity, 'critical');
  assert.equal(ev.user_action, 'send_anyway');
  assert.ok(ev.timestamp > 0);
  assert.equal(ev.lens_version, '0.3.0');
  // No Tier 2 fields (no opt-in)
  assert.equal(ev.attack_keywords_hash, undefined);
});

await test('enqueue drops event when opt-in disabled', async () => {
  const q = await loadQueue(createChromeMock({}, false));
  const ev = q.buildEvent(buildDetection(), 'detect');
  const result = await q.enqueue(ev);
  assert.equal(result, false);
});

await test('enqueue accepts event when opt-in enabled', async () => {
  const chromeMock = createChromeMock({}, true);
  const q = await loadQueue(chromeMock);
  const ev = q.buildEvent(buildDetection(), 'detect');
  const result = await q.enqueue(ev);
  assert.equal(result, true);
  assert.equal(chromeMock._data['lens.telemetry.buffer'].length, 1);
});

await test('buffer caps at 200 events (oldest evicted)', async () => {
  const chromeMock = createChromeMock({}, true);
  const q = await loadQueue(chromeMock);
  // Enqueue 250 events
  for (let i = 0; i < 250; i++) {
    await q.enqueue(q.buildEvent(buildDetection(), 'detect'));
  }
  // Buffer should have only 200 (oldest 50 evicted)
  assert.equal(chromeMock._data['lens.telemetry.buffer'].length, 200);
});

await test('flush sends events to apiClient', async () => {
  const chromeMock = createChromeMock({}, true);
  const q = await loadQueue(chromeMock);
  const api = buildMockApi();
  // Enqueue 5 events
  for (let i = 0; i < 5; i++) {
    await q.enqueue(q.buildEvent(buildDetection(), 'detect'));
  }
  const result = await q.flush(api);
  assert.equal(result.sent, 5);
  assert.equal(api.sent.length, 5);
});

await test('flush respects rate limit (100/min)', async () => {
  const chromeMock = createChromeMock({}, true);
  const q = await loadQueue(chromeMock);
  const api = buildMockApi();
  // Enqueue 110 events (should send only 100 due to rate limit)
  for (let i = 0; i < 110; i++) {
    await q.enqueue(q.buildEvent(buildDetection(), 'detect'));
  }
  const result = await q.flush(api);
  assert.equal(result.sent, 100);
  // 10 should remain in buffer (could not send due to rate limit)
  assert.equal(chromeMock._data['lens.telemetry.buffer'].length, 10);
});

await test('reset clears buffer and rate state', async () => {
  const chromeMock = createChromeMock({}, true);
  const q = await loadQueue(chromeMock);
  for (let i = 0; i < 5; i++) {
    await q.enqueue(q.buildEvent(buildDetection(), 'detect'));
  }
  assert.equal(chromeMock._data['lens.telemetry.buffer'].length, 5);
  await q.reset();
  assert.equal(chromeMock._data['lens.telemetry.buffer'], undefined);
});

await test('canSend returns false after rate limit hit', async () => {
  const q = await loadQueue(createChromeMock());
  // Initially can send
  assert.equal(q.canSend(), true);
  // Simulate 100 sends by adding timestamps directly
  // (We do this by flushing 100 events)
  const api = buildMockApi();
  const chromeMock = createChromeMock({}, true);
  const q2 = await loadQueue(chromeMock);
  for (let i = 0; i < 100; i++) {
    await q2.enqueue(q2.buildEvent(buildDetection(), 'detect'));
  }
  await q2.flush(api);
  // Now rate state has 100 timestamps within last minute → canSend false
  assert.equal(q2.canSend(), false);
});

await test('buildEvent v0.3 Tier 2 includes TI extensions', async () => {
  const q = await loadQueue(createChromeMock());
  const ev = q.buildEvent(buildDetection(), 'detect', {
    domainHash: 'abc',
    attackKeywordsHash: 'xyz',
    attackPatternId: 'DAN-jailbreak-v1',
    modelConsensus: 0.95,
    similarAttackCount30d: 3,
    bundleSignature: 'aKzukcm1ElgBZDMlG7IROw12CyjPHfkuKv+Bj8I70+c=',
  });
  assert.equal(ev.attack_keywords_hash, 'xyz');
  assert.equal(ev.attack_pattern_id, 'DAN-jailbreak-v1');
  assert.equal(ev.model_consensus, 0.95);
  assert.equal(ev.similar_attack_count_30d, 3);
  assert.ok(ev.bundle_signature);
});

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);
if (failed > 0) process.exit(1);