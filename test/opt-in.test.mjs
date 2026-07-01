#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.3 - Telemetry Opt-In State Manager Test
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'path';
import url from 'url';
import vm from 'vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const optInSrc = fs.readFileSync(path.join(repoRoot, 'src/util/opt-in.js'), 'utf8');

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

console.log('AegisGate Lens v0.3 - Opt-In State Manager Test');
console.log('');

// Mock chrome.storage
function createChromeMock(initialData = {}) {
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
          if (typeof key === 'string') {
            result[key] = data[key];
          }
          cb(result);
        },
        set: (obj, cb) => {
          Object.assign(data, obj);
          cb();
        },
      },
    },
    _data: data,
  };
}

async function loadOptIn(initialData) {
  const chromeMock = createChromeMock(initialData);
  const sandbox = {
    console, Math, JSON, Date, Promise,
    setTimeout, clearTimeout,
    Object, Array, Number, String, Boolean,
    chrome: chromeMock,
    self: {},
  };
  sandbox.self.AegisGateLens = { logger: console };
  sandbox.AegisGateLens = sandbox.self.AegisGateLens;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(optInSrc, ctx, { filename: 'opt-in.js' });
  return { optIn: sandbox.AegisGateLens.util.optIn, chrome: chromeMock };
}

// ============================================================================
// Tests
// ============================================================================

await test('default opt-in state is OFF (v0.1 compat)', async () => {
  const { optIn } = await loadOptIn();
  const state = await optIn.getOptInState();
  assert.equal(state.enabled, false);
  assert.equal(state.lens_version, '0.3.0-test');
});

await test('setOptInState persists enabled=true', async () => {
  const { optIn, chrome } = await loadOptIn();
  await optIn.setOptInState({ enabled: true });
  assert.equal(chrome._data['lens.optIn.enabled'].enabled, true);
  assert.ok(chrome._data['lens.optIn.enabled'].opted_in_at > 0);
  assert.equal(chrome._data['lens.optIn.enabled'].lens_version, '0.3.0-test');
});

await test('setOptInState persists enabled=false', async () => {
  const { optIn, chrome } = await loadOptIn({ 'lens.optIn.enabled': { enabled: true, opted_in_at: 1234 } });
  await optIn.setOptInState({ enabled: false });
  assert.equal(chrome._data['lens.optIn.enabled'].enabled, false);
  assert.equal(chrome._data['lens.optIn.enabled'].opted_in_at, 1234);  // Preserved
});

await test('default v0.3 opt-in state is OFF (both tiers)', async () => {
  const { optIn } = await loadOptIn();
  const state = await optIn.getOptInStateV03();
  assert.equal(state.tier1_enabled, false);
  assert.equal(state.tier2_enabled, false);
});

await test('v0.3 setOptInStateV03 enables tier1', async () => {
  const { optIn, chrome } = await loadOptIn();
  await optIn.setOptInStateV03({ tier1_enabled: true });
  assert.equal(chrome._data['lens.optIn.v03'].tier1_enabled, true);
  assert.equal(chrome._data['lens.optIn.v03'].tier2_enabled, false);
  assert.ok(chrome._data['lens.optIn.v03'].opted_in_at_tier1 > 0);
});

await test('v0.3 setOptInStateV03 enables tier2 (requires tier1)', async () => {
  const { optIn, chrome } = await loadOptIn();
  await optIn.setOptInStateV03({ tier1_enabled: true });
  await optIn.setOptInStateV03({ tier2_enabled: true });
  const stored = chrome._data['lens.optIn.v03'];
  assert.equal(stored.tier1_enabled, true);
  assert.equal(stored.tier2_enabled, true);
});

await test('isTelemetryEnabled returns false by default', async () => {
  const { optIn } = await loadOptIn();
  assert.equal(await optIn.isTelemetryEnabled(), false);
});

await test('isTelemetryEnabled returns true after v0.1 opt-in', async () => {
  const { optIn } = await loadOptIn();
  await optIn.setOptInState({ enabled: true });
  assert.equal(await optIn.isTelemetryEnabled(), true);
});

await test('isTelemetryEnabled returns true after v0.3 tier1 opt-in', async () => {
  const { optIn } = await loadOptIn();
  await optIn.setOptInStateV03({ tier1_enabled: true });
  assert.equal(await optIn.isTelemetryEnabled(), true);
});

await test('isTelemetryEnabled returns true after v0.3 tier2 opt-in (without tier1)', async () => {
  const { optIn } = await loadOptIn();
  await optIn.setOptInStateV03({ tier2_enabled: true });
  assert.equal(await optIn.isTelemetryEnabled(), true);
});

await test('KEY_OPT_IN and KEY_OPT_IN_V03 constants exported', async () => {
  const { optIn } = await loadOptIn();
  assert.equal(optIn.KEY_OPT_IN, 'lens.optIn.enabled');
  assert.equal(optIn.KEY_OPT_IN_V03, 'lens.optIn.v03');
});

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);
if (failed > 0) process.exit(1);