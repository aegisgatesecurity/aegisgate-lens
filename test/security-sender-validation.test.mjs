#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Service-Worker Sender Validation Test (Day 8 / F-01)
// =========================================================================
//
// Asserts that the service worker's chrome.runtime.onMessage listener
// rejects messages from any sender whose id does not match our own
// extension's id. This closes the F-01 finding from
// plans/LENS-THREAT-MODEL.md (CVSS 6.5, Medium).
//
// What we test:
//   1. A message from our OWN extension (sender.id === OWN_ID) is
//      accepted and dispatched.
//   2. A message from a different extension (sender.id = "evil-id") is
//      rejected with { error: "foreign sender rejected" }.
//   3. A message with sender.id = undefined is rejected (e.g. message
//      sent from a context where chrome.runtime is unavailable).
//   4. A message with sender.id = "" (empty string) is rejected.
//   5. All message types are subject to validation, not just
//      lens.telemetry (lens.opt_in and lens.stats are also validated).
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

// ----- Build a chrome stub that lets us forge sender.id ---------------------

function buildChromeStub() {
  const listeners = [];
  return {
    OWN_ID: 'aegisgate-lens-extension-id',
    chrome: {
      runtime: {
        id: 'aegisgate-lens-extension-id',
        onInstalled: { addListener: () => {} },
        onStartup: { addListener: () => {} },
        onMessage: {
          addListener(fn) { listeners.push(fn); },
        },
        getURL: (p) => 'chrome-extension://test/' + p,
        getManifest: () => ({ version: '0.2.2-test' }),
        lastError: null,
      },
    },
    // Dispatch a message with a given sender id. Returns the response
    // from the service worker's listener.
    async dispatch(msg, senderId) {
      const sender = senderId === undefined
        ? undefined
        : { id: senderId };
      const responses = [];
      const sendResponse = (resp) => { responses.push(resp); };
      // We deliberately do NOT break on r===true here. The service
      // worker returns true AFTER calling sendResponse for synchronous
      // rejections (like foreign sender). The async path is also
      // handled by sendResponse. Let all listeners run to completion.
      for (const fn of listeners) {
        try {
          const r = fn(msg, sender, sendResponse);
          if (r && typeof r.then === 'function') {
            await r;
          }
        } catch (err) {
          // ignore; errors are caught by the service-worker listener
        }
      }
      // Wait one microtask for any async sendResponse calls.
      await new Promise((r) => setImmediate(r));
      return { responses, keepChannel: false };
    },
  };
}

// ----- Load the service worker with a minimal chrome stub ------------------

async function loadServiceWorker() {
  const swSrc = await fsp.readFile(
    path.join(repoRoot, 'src/service-worker.js'),
    'utf8',
  );
  const stub = buildChromeStub();
  const localStore = {};
  const syncStore = {};

  const sandbox = {
    console,
    URL,
    fetch: (...args) => globalThis.fetch(...args),
    crypto: globalThis.crypto,
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
    setImmediate,
    self: {},
    chrome: stub.chrome,
  };
  sandbox.self = sandbox;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};
  sandbox.self.AegisGateLens.logger = {
    info: () => {},
    warn: (...a) => console.warn('[Lens]', ...a),
    error: (...a) => console.error('[Lens]', ...a),
  };
  // Stub the storage and APIClient namespaces so the service worker
  // IIFE doesn't bail out with "modules missing; service worker
  // cannot start". For sender-validation tests we don't care what
  // these do - we only need the onMessage listener to register and
  // reject foreign senders before any handler runs.
  sandbox.self.AegisGateLens.storage = {
    Storage: function () {
      this.getOptInState = () => Promise.resolve({ enabled: true });
      this.getBaseUrlOverride = () => Promise.resolve('');
      this.getBearerToken = () => Promise.resolve('');
      this.appendLocalAudit = () => Promise.resolve();
      this.getStats = () => Promise.resolve({ events24h: 0, detections24h: 0 });
    },
  };
  sandbox.self.AegisGateLens.APIClient = function () {};
  // Stub storage so the listener doesn't crash trying to read state.
  sandbox.chrome.storage = {
    sync: {
      get: (key, cb) => {
        if (typeof key === 'string') cb({ [key]: syncStore[key] });
        else cb({ ...syncStore });
      },
      set: (items, cb) => { Object.assign(syncStore, items); if (cb) cb(); },
    },
    local: {
      get: (key, cb) => {
        if (typeof key === 'string') cb({ [key]: localStore[key] });
        else cb({ ...localStore });
      },
      set: (items, cb) => { Object.assign(localStore, items); if (cb) cb(); },
      remove: (key, cb) => { delete localStore[key]; if (cb) cb(); },
    },
  };

  const ctx = vm.createContext(sandbox);
  // importScripts is a no-op; service-worker.js expects its modules to
  // be pre-loaded, but for sender-validation tests we don't need
  // privacy/schema.js or api/client.js to actually work — the
  // listener's first action is to validate sender.
  sandbox.importScripts = () => {};
  vm.runInContext(swSrc, ctx, { filename: 'service-worker.js' });

  return stub;
}

// ----- Tests ----------------------------------------------------------------

console.log('AegisGate Lens - Service-Worker Sender Validation Test (Day 8 / F-01)');
console.log('');

const stub = await loadServiceWorker();

await test('OWN_ID is set on chrome.runtime', () => {
  assert.equal(stub.chrome.runtime.id, 'aegisgate-lens-extension-id');
});

await test('message from own extension (lens.get_state) reaches handler', async () => {
  // lens.get_state doesn't touch storage we haven't stubbed, so it
  // should reach the handler. We don't assert on the response shape
  // (that's covered by other tests); we only assert no
  // foreign-sender rejection.
  const { responses } = await stub.dispatch(
    { type: 'lens.get_state' },
    stub.OWN_ID,
  );
  // handler ran; response should NOT be the foreign-sender error.
  for (const r of responses) {
    assert.notEqual(r && r.error, 'foreign sender rejected',
      'own-extension message must not be rejected');
  }
});

await test('message from foreign extension (lens.telemetry) is rejected', async () => {
  const { responses } = await stub.dispatch(
    { type: 'lens.telemetry', event: { lens_event_version: 1 } },
    'malicious-extension-id',
  );
  assert.equal(responses.length >= 1, true, 'expected at least one response');
  const last = responses[responses.length - 1];
  assert.equal(last.error, 'foreign sender rejected',
    'foreign sender must be rejected');
});

await test('message from foreign extension (lens.opt_in) is rejected', async () => {
  // This is the most dangerous one: a malicious extension flipping
  // telemetry on without user consent. Day 8 closes this attack.
  const { responses } = await stub.dispatch(
    { type: 'lens.opt_in', payload: { enabled: true } },
    'evil-extension-id',
  );
  assert.equal(responses.length >= 1, true);
  assert.equal(responses[responses.length - 1].error, 'foreign sender rejected');
});

await test('message from foreign extension (lens.stats) is rejected', async () => {
  const { responses } = await stub.dispatch(
    { type: 'lens.stats' },
    'attacker-id',
  );
  assert.equal(responses.length >= 1, true);
  assert.equal(responses[responses.length - 1].error, 'foreign sender rejected');
});

await test('message with undefined sender.id is rejected', async () => {
  const { responses } = await stub.dispatch(
    { type: 'lens.telemetry', event: {} },
    undefined,
  );
  assert.equal(responses.length >= 1, true);
  assert.equal(responses[responses.length - 1].error, 'foreign sender rejected');
});

await test('message with empty-string sender.id is rejected', async () => {
  const { responses } = await stub.dispatch(
    { type: 'lens.telemetry', event: {} },
    '',
  );
  assert.equal(responses.length >= 1, true);
  assert.equal(responses[responses.length - 1].error, 'foreign sender rejected');
});

await test('message with same id but different case is rejected', async () => {
  // Defense against trivial bypass: case-sensitive comparison.
  const { responses } = await stub.dispatch(
    { type: 'lens.telemetry', event: {} },
    stub.OWN_ID.toUpperCase(),
  );
  assert.equal(responses.length >= 1, true);
  assert.equal(responses[responses.length - 1].error, 'foreign sender rejected');
});

await test('message without type is still rejected for foreign sender', async () => {
  // The "no type" check runs BEFORE the sender check in the listener,
  // so a malformed message gets "invalid message" not
  // "foreign sender rejected". Either is correct - the important
  // thing is the foreign sender never reaches a handler.
  const { responses } = await stub.dispatch(
    { /* no type */ },
    'attacker-id',
  );
  // We don't care which error; we only care that no handler ran
  // (which would have produced a non-error response).
  for (const r of responses) {
    if (r && r.error === undefined) {
      throw new Error('foreign message should have produced an error response');
    }
  }
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
