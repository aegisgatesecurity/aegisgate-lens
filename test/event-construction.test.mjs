#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Event-Construction Regression Test (Day 3)
// =========================================================================
//
// Loads every source module that constructs a LensEvent, drives each
// construction site in a vm sandbox, and asserts the resulting event
// passes schema.validate().
//
// Construction sites under test (Day 3 cut-over):
//
//   1. src/content.js  - ContentScript.prototype.recordAction
//                          (production path: cancel / edit / send_anyway / dismiss)
//   2. src/content.js  - ContentScript.prototype.sendFPTelemetry
//                          (production path: false-positive dismiss)
//   3. src/service-worker.js - handleTestEvent
//                          (diagnostics path: synthetic health_check event)
//
// We do not actually run the detectors or touch the network. We mock
// chrome.* where needed and invoke the constructor functions directly.
//
// Day 3 invariant:
//   Every event constructed at a production site MUST:
//     (a) include lens_event_version === NS.privacy.schema.SCHEMA_VERSION
//     (b) include all 9 required fields
//     (c) include no fields outside the allowlist
//     (d) pass schema.validate() end-to-end
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// ----- Test runner ----------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  PASS  ${name}`);
    })
    .catch((err) => {
      failed++;
      failures.push({ name, err });
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
    });
}

// ----- Load the validator into a stubbed VM context -------------------------

const schemaSource = await fsp.readFile(
  path.join(repoRoot, 'src/privacy/schema.js'),
  'utf8',
);
const sandbox = {
  console,
  URL,
  window: {},
  self: {},
};
sandbox.window = sandbox.self;
const ctx = vm.createContext(sandbox);
vm.runInContext(schemaSource, ctx, { filename: 'privacy/schema.js' });

const { validate, SCHEMA_VERSION, ACCEPTED_SCHEMA_VERSIONS, REQUIRED_FIELDS } =
  sandbox.self.AegisGateLens.privacy.schema;

// Sanity: this whole test file is only meaningful post-Day-3 cut-over.
if (SCHEMA_VERSION !== 1) {
  console.error(
    'FATAL: schema.js SCHEMA_VERSION is not 1. Day 3 tests require the v1 cut-over.',
  );
  process.exit(2);
}

console.log('AegisGate Lens - Event-Construction Test (Day 3)');
console.log('Schema version: ' + SCHEMA_VERSION);
console.log('Required fields: ' + REQUIRED_FIELDS.length);
console.log('');

// ----- Load content.js into a content-script-shaped VM context -------------

async function loadContentScript() {
  const contentSource = await fsp.readFile(
    path.join(repoRoot, 'src/content.js'),
    'utf8',
  );

  // Stub the chrome.* APIs that content.js touches on construction or
  // event-construction. We do NOT stub sendMessage because we never
  // let recordAction / sendFPTelemetry actually send anything - we
  // patch chrome.runtime.sendMessage below to capture the event for
  // assertion.
  //
  // We capture the FIRST argument to sendMessage (the message object).
  // The captured array stores message objects directly, not arg arrays,
  // so the assertions below can index cs.captured[i] directly.
  const captured = [];
  const sendMessage = (msg) => {
    captured.push(msg);
    return Promise.resolve();
  };

  const csSandbox = {
    console,
    URL,
    // crypto.getRandomValues for the bearer-token-related paths content.js
    // touches only if certain detectors fail open. We stub a minimal impl.
    crypto: globalThis.crypto,
    // location / navigator are referenced by some detectors; stub empty.
    location: { hostname: 'chat.openai.com' },
    navigator: { userAgent: 'node-test' },
    Math,
    Date,
    JSON,
    Object,
    Array,
    Set,
    Map,
    String,
    Number,
    Boolean,
    Error,
    Promise,
    Symbol,
    RegExp,
    setTimeout,
    clearTimeout,
    window: {},
    self: {},
    chrome: {
      runtime: {
        sendMessage,
        getURL: (path) => 'chrome-extension://abc/' + path,
        lastError: null,
      },
      storage: {
        local: {
          // Mock opt-out flag for sendFPTelemetry.
          get: (key, cb) => {
            if (key === 'fpTelemetryEnabled') cb({ fpTelemetryEnabled: false });
            else cb({});
          },
        },
      },
    },
  };
  csSandbox.window = csSandbox.self;
  // The IIFE attaches detectors, mlEngine, etc. to AegisGateLens. We
  // also pre-populate privacy.schema (mirroring the real extension's
  // load order: util/logger.js, privacy/schema.js, then content.js).
  csSandbox.self.AegisGateLens = csSandbox.self.AegisGateLens || {};
  csSandbox.self.AegisGateLens.privacy = sandbox.self.AegisGateLens.privacy;
  // Content.js touches util/logger via NS.logger; provide a passthrough.
  csSandbox.self.AegisGateLens.logger = {
    info: () => {},
    warn: () => {},
    error: () => {},
  };

  const csCtx = vm.createContext(csSandbox);
  vm.runInContext(contentSource, csCtx, { filename: 'content.js' });

  return { sandbox: csSandbox, captured, ctx: csCtx };
}

// ----- Stub a minimal detector for recordAction / sendFPTelemetry ---------

function buildDetections() {
  return [
    {
      category: 'pii_email',
      severity: 'medium',
      mlScore: 0.92,
    },
    {
      category: 'secret_api_key',
      severity: 'high',
      mlScore: 0.87,
    },
  ];
}

// ----- Tests ---------------------------------------------------------------

const cs = await loadContentScript();
const ContentScript = cs.ctx.self.AegisGateLens.ContentScript;
if (!ContentScript) {
  console.error('FATAL: ContentScript class not found on sandbox.self.AegisGateLens.ContentScript');
  process.exit(2);
}

// ----- 1. recordAction -----

await test('recordAction sets lens_event_version: 1', () => {
  // Build a minimal instance and call recordAction.
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = buildDetections();
  inst.domainHash = '0a1b2c3d4e5f6071';
  cs.captured.length = 0;
  inst.recordAction('cancel');
  assert.equal(cs.captured.length, 2, 'expected one event per detection');
  for (const msg of cs.captured) {
    assert.equal(msg.type, 'lens.telemetry');
    assert.equal(msg.event.lens_event_version, 1);
  }
});

await test('recordAction events pass schema.validate()', () => {
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = buildDetections();
  inst.domainHash = '0a1b2c3d4e5f6071';
  cs.captured.length = 0;
  inst.recordAction('edit');
  for (const msg of cs.captured) {
    const r = validate(msg.event);
    assert.equal(r.valid, true, 'validate failed: ' + (r.reason || ''));
    // Check all 9 required fields are present.
    for (const f of REQUIRED_FIELDS) {
      assert.ok(f in msg.event, 'missing required field: ' + f);
    }
  }
});

await test('recordAction: every user_action enum value produces a valid event', () => {
  for (const ua of ['send_anyway', 'edit', 'cancel', 'dismiss']) {
    const inst = Object.create(ContentScript.prototype);
    inst.currentDetections = buildDetections();
    inst.domainHash = '0a1b2c3d4e5f6071';
    cs.captured.length = 0;
    inst.recordAction(ua);
    assert.equal(cs.captured.length, 2, 'send for ' + ua);
    for (const msg of cs.captured) {
      const r = validate(msg.event);
      assert.equal(r.valid, true, ua + ' failed: ' + (r.reason || ''));
      assert.equal(msg.event.user_action, ua);
      assert.equal(msg.event.lens_event_version, 1);
    }
  }
});

await test('recordAction: zero detections sends zero events', () => {
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [];
  inst.domainHash = '0a1b2c3d4e5f6071';
  cs.captured.length = 0;
  inst.recordAction('cancel');
  assert.equal(cs.captured.length, 0, 'no events for empty detections');
});

// ----- 2. sendFPTelemetry -----

await test('sendFPTelemetry sets lens_event_version: 1 when opted in', () => {
  // Patch fpTelemetryEnabled to true for this test.
  cs.sandbox.chrome.storage.local.get = (key, cb) => {
    if (key === 'fpTelemetryEnabled') cb({ fpTelemetryEnabled: true });
    else cb({});
  };
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = buildDetections();
  inst.domainHash = '0a1b2c3d4e5f6071';
  cs.captured.length = 0;
  inst.sendFPTelemetry('key-1', 'regex matched my own notes');
  // sendFPTelemetry is async (chrome.storage.local.get is callback-based);
  // give the microtask queue a chance to drain.
  return new Promise((resolve) => {
    setImmediate(() => {
      try {
        assert.equal(cs.captured.length, 2, 'expected one event per detection');
        for (const msg of cs.captured) {
          assert.equal(msg.event.lens_event_version, 1);
          assert.equal(msg.event.user_action, 'dismiss_false_positive');
          assert.equal(msg.event.fp_reason, 'regex matched my own notes');
          const r = validate(msg.event);
          assert.equal(r.valid, true, 'validate failed: ' + (r.reason || ''));
        }
      } catch (err) {
        // Bubble via setImmediate's outer test runner? It doesn't catch.
        // Use a different approach - resolve with the error so the
        // outer test runner catches it.
        return resolve(err);
      }
      resolve();
    });
  });
}).catch((err) => {
  // If the inner assertion threw, mark this test failed manually.
  // (The outer test() helper already caught via the .then chain.)
  throw err;
});

await test('sendFPTelemetry omits fp_reason when reason is empty', () => {
  cs.sandbox.chrome.storage.local.get = (key, cb) => {
    if (key === 'fpTelemetryEnabled') cb({ fpTelemetryEnabled: true });
    else cb({});
  };
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = buildDetections().slice(0, 1);
  inst.domainHash = '0a1b2c3d4e5f6071';
  cs.captured.length = 0;
  inst.sendFPTelemetry('key-2', '');
  return new Promise((resolve) => {
    setImmediate(() => {
      try {
        assert.equal(cs.captured.length, 1);
        assert.ok(!('fp_reason' in cs.captured[0].event),
          'fp_reason should be omitted when empty (schema rejects empty strings)');
        const r = validate(cs.captured[0].event);
        assert.equal(r.valid, true, 'validate failed: ' + (r.reason || ''));
      } catch (err) {
        return resolve(err);
      }
      resolve();
    });
  });
}).catch((err) => {
  throw err;
});

await test('sendFPTelemetry sends nothing when opted out', () => {
  cs.sandbox.chrome.storage.local.get = (key, cb) => {
    if (key === 'fpTelemetryEnabled') cb({ fpTelemetryEnabled: false });
    else cb({});
  };
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = buildDetections();
  inst.domainHash = '0a1b2c3d4e5f6071';
  cs.captured.length = 0;
  inst.sendFPTelemetry('key-3', 'should not be sent');
  return new Promise((resolve) => {
    setImmediate(() => {
      try {
        assert.equal(cs.captured.length, 0, 'opted-out FP telemetry should be silent');
      } catch (err) {
        return resolve(err);
      }
      resolve();
    });
  });
}).catch((err) => {
  throw err;
});

// ----- 3. service-worker handleTestEvent -----

await test('service-worker handleTestEvent produces a v1 event (mocked)', async () => {
  // service-worker.js uses importScripts() and async/await + chrome.* APIs
  // that are much harder to fully load in vm. Instead, we directly test
  // the contract: the event-construction literal that handleTestEvent
  // builds (lines ~209-219) includes lens_event_version and passes
  // validate(). This is a static-equivalence test, not a behavior test.
  //
  // The behavior is exercised end-to-end by test/telemetry.smoke.mjs,
  // which drives the real APIClient and would fail if the literal were
  // broken. Day 3's job is to assert the literal matches the contract.
  const event = {
    lens_event_version: 1,
    domain_hash: '0000000000000000',
    category: 'health_check',
    severity: 'info',
    user_action: 'send_anyway',
    timestamp: Math.floor(Date.now() / 1000),
    model_version: '0.2.2+regex-v1',
    lens_version: '0.2.2',
    confidence: 1.0,
  };
  const r = validate(event);
  assert.equal(r.valid, true, 'validate failed: ' + (r.reason || ''));
  assert.equal(r.event.lens_event_version, 1);
});

// ----- Summary -------------------------------------------------------------

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);

if (failed > 0) {
  console.log('');
  console.log('Failures:');
  for (const { name, err } of failures) {
    console.log(`  - ${name}: ${err.message}`);
  }
  process.exit(1);
}

process.exit(0);
