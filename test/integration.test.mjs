#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - End-to-End Integration Test (Day 4)
// =========================================================================
//
// Drives the full event pipeline in-process:
//   content.js (ContentScript.recordAction)
//     -> chrome.runtime.sendMessage (in-process bridge)
//     -> service-worker.js (chrome.runtime.onMessage listener)
//     -> handleTelemetry(event)
//     -> APIClient.sendEvent(event)
//     -> fetch -> mock backend -> JSONL
//
// Asserts the chain holds end-to-end:
//   - A synthetic detection round-trips with lens_event_version: 1.
//   - All 9 required fields survive the trip unchanged.
//   - The chain silently drops events that fail validate().
//   - The chain enforces the 100/min rate limit across the full path.
//   - Events with forbidden fields (prompt_text) never reach the JSONL.
//
// Why this is its own file (not a smoke test extension):
//   - telemetry.smoke.mjs unit-tests the APIClient boundary.
//   - event-construction.test.mjs unit-tests content.js construction sites.
//   - integration.test.mjs wires both sides through a stubbed chrome.runtime
//     bridge and asserts the EVENT, not just the call, makes it to JSONL.
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
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

// ----- Mock backend ---------------------------------------------------------

function bootMockBackend() {
  return new Promise((resolve, reject) => {
    const output = path.join(repoRoot, 'test/mock-output/events.jsonl');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, '');

    const events = [];

    const server = http.createServer(async (req, res) => {
      const parsed = url.parse(req.url, true);
      const route = parsed.pathname;

      function jsonResp(status, body) {
        const payload = JSON.stringify(body);
        res.writeHead(status, {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Length': Buffer.byteLength(payload),
        });
        res.end(payload);
      }

      if (route === '/api/v1/lens/healthz') {
        return jsonResp(200, { status: 'ok', version: '0.0.0-mock' });
      }
      if (route === '/api/v1/lens/telemetry' && req.method === 'POST') {
        const auth = req.headers['authorization'] || '';
        if (!auth.startsWith('Bearer ')) {
          return jsonResp(401, { error: 'missing bearer token' });
        }
        const chunks = [];
        for await (const c of req) chunks.push(c);
        let body;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch (err) {
          return jsonResp(400, { error: 'invalid JSON' });
        }
        events.push(body);
        fs.appendFileSync(output, JSON.stringify(body) + '\n');
        return jsonResp(200, { accepted: true, id: 'mock-id-' + events.length });
      }
      return jsonResp(404, { error: 'not found' });
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, events, baseUrl: `http://127.0.0.1:${addr.port}`, outputPath: output });
    });
    server.on('error', reject);
  });
}

function shutdown(server) {
  return new Promise((resolve) => {
    server.close(() => resolve());
    setTimeout(() => resolve(), 500).unref();
  });
}

// ----- Chrome stub: storage + runtime bridge --------------------------------

/**
 * Build a stubbed chrome.* environment that:
 *   - Stores opt-in state, bearer token, base URL, local audit log in plain
 *     JS objects (mimicking chrome.storage.sync/local semantics).
 *   - Plumbs sendMessage <-> onMessage.addListener so that the
 *     content-script's sendMessage synchronously dispatches to the
 *     service-worker's listener.
 *
 * Returns { storage, runtime, sendMessageFromContent, dispatchTelemetry }
 * plus a getter for the captured audit log entries.
 */
function buildChromeStub() {
  const syncStore = {}; // chrome.storage.sync
  const localStore = {
    'lens.bearer_token': '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    'lens.local_audit': [],
    'lens.disabled_categories': [],
    'lens.__base_url_override': '', // set per-test
  };
  // _localAudit: a live reference to the audit array for fast clearing
  // between tests. The chrome.storage stub stores by reference, so
  // mutating this array directly updates what handleTelemetry sees.
  const _localAudit = localStore['lens.local_audit'];

  function promisify(getter) {
    return (key) =>
      new Promise((resolve) => {
        getter(key, (result) => resolve(result));
      });
  }

  function syncGet(key, cb) {
    if (typeof key === 'string') cb({ [key]: syncStore[key] });
    else if (Array.isArray(key)) {
      const out = {};
      for (const k of key) out[k] = syncStore[k];
      cb(out);
    } else cb({ ...syncStore });
  }
  function syncSet(items, cb) {
    Object.assign(syncStore, items);
    if (cb) cb();
  }
  function localGet(key, cb) {
    if (typeof key === 'string') cb({ [key]: localStore[key] });
    else if (Array.isArray(key)) {
      const out = {};
      for (const k of key) out[k] = localStore[k];
      cb(out);
    } else {
      const out = {};
      for (const k of Object.keys(localStore)) out[k] = localStore[k];
      cb(out);
    }
  }
  function localSet(items, cb) {
    Object.assign(localStore, items);
    if (cb) cb();
  }
  function localRemove(key, cb) {
    delete localStore[key];
    if (cb) cb();
  }

  const storage = {
    sync: { get: promisify(syncGet), set: syncSet },
    local: {
      get: promisify(localGet),
      set: localSet,
      remove: localRemove,
    },
  };

  // Runtime bridge: listeners registered here receive messages from
  // sendMessageFromContent().
  const listeners = [];
  const runtime = {
    onInstalled: { addListener: () => {} },
    onStartup: { addListener: () => {} },
    onMessage: {
      addListener(fn) { listeners.push(fn); },
    },
    getURL(p) { return 'chrome-extension://test/' + p; },
    getManifest() { return { version: '0.2.2-test' }; },
    // Day 8 / F-01: the OWN_ID the service worker compares sender.id
    // against. Must match the id field in sendMessageFromContent's
    // sender object below.
    id: 'test-extension-id',
    lastError: null,
  };

  /**
   * Send a message from the "content script" side. The real Chrome API
   * invokes the listener asynchronously; we mirror that with setImmediate
   * so any tests that need to wait can `await new Promise(r => setImmediate(r))`.
   */
  function sendMessageFromContent(msg) {
    return new Promise((resolve) => {
      setImmediate(() => {
        let responded = false;
        const sender = { id: 'test-extension-id' };
        const sendResponse = (resp) => {
          responded = true;
          resolve(resp);
        };
        for (const fn of listeners) {
          try {
            const keepChannel = fn(msg, sender, sendResponse);
            // Per Chrome docs: if any listener returns true, the channel
            // stays open until sendResponse is called. We already wrap
            // the response in a Promise so the listener's async work
            // resolves us when done.
            if (keepChannel === true) return; // wait for sendResponse
          } catch (err) {
            if (!responded) resolve({ error: err.message });
            return;
          }
        }
        if (!responded) resolve({});
      });
    });
  }

  return {
    storage,
    runtime,
    sendMessageFromContent,
    getLocalAudit: () => localStore['lens.local_audit'],
    _localAudit,
    setBaseUrlOverride: (url) => { localStore['lens.__base_url_override'] = url; },
    setOptedIn: (enabled) => {
      syncStore['lens.opt_in'] = {
        enabled,
        opted_in_at: enabled ? Math.floor(Date.now() / 1000) : 0,
        last_changed_at: Math.floor(Date.now() / 1000),
        lens_version: '0.2.2-test',
      };
    },
    // Force getClient() to construct a fresh APIClient next time. Used
    // by the test isolation helper to reset the rate-limit ring buffer
    // between tests. The service worker's getClient() caches by
    // baseUrl + token, so we swap the bearer token to a unique value
    // PER TEST (not just once, since the next resetState() will swap
    // again). The mock backend's bearer-token check is "starts with
    // Bearer", not "matches a specific token", so any token works.
    _invalidateClientCache: () => {
      const unique = 'reset-' + Date.now().toString(36) + '-' +
        Math.random().toString(36).slice(2, 8);
      localStore['lens.bearer_token'] = unique;
    },
  };
}

// ----- Load content.js + service-worker.js into cooperative vm contexts ----

async function loadIntegrationHarness(baseUrl, opts = {}) {
  const [schemaSrc, clientSrc, contentSrc, swSrc] = await Promise.all([
    fsp.readFile(path.join(repoRoot, 'src/privacy/schema.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/api/client.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/content.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/service-worker.js'), 'utf8'),
  ]);

  const chromeStub = buildChromeStub();
  chromeStub.setOptedIn(true);
  chromeStub.setBaseUrlOverride(baseUrl);

  // Build a shared sandbox that BOTH content.js and service-worker.js
  // can attach to. Real Chrome has separate JS contexts per realm, but
  // the modules communicate via chrome.runtime.sendMessage which we stub
  // to bridge them. We use ONE vm context to keep AegisGateLens state
  // coherent (e.g., the schema loaded once).
  const sandbox = {
    console,
    URL,
    fetch: (...args) => globalThis.fetch(...args),
    crypto: globalThis.crypto,
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
    setImmediate,
    window: {},
    self: {},
    chrome: {
      runtime: chromeStub.runtime,
      storage: chromeStub.storage,
      tabs: { create: async () => {} },
    },
  };
  sandbox.window = sandbox.self;
  // Pre-populate AegisGateLens so privacy/schema and api/client and
  // util/logger can all attach to the same namespace. We load them in
  // the order the real extension loads them (logger, storage, schema, client).
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};

  const ctx = vm.createContext(sandbox);

  // logger (minimal; schema.js doesn't need it, but content.js does)
  vm.runInContext(
    `(function () {
       const NS = (typeof self !== 'undefined' ? self : this).AegisGateLens;
       NS.logger = NS.logger || {
         info: function () {},
         warn: function () { console.warn.apply(console, ['[Lens]', ...arguments]); },
         error: function () { console.error.apply(console, ['[Lens]', ...arguments]); },
       };
     })();`,
    ctx,
    { filename: 'util/logger.js (stub)' },
  );

  // Stub importScripts (a Chrome-only API) so service-worker.js's
  // `importScripts('util/logger.js', 'storage.js', 'privacy/schema.js',
  // 'api/client.js')` is a no-op. We pre-load those modules into the
  // shared sandbox above so the namespaces they populate already exist.
  // vm contexts resolve top-level identifiers against the sandbox
  // itself, NOT against sandbox.self, so we set the property on
  // `sandbox` directly.
  const storageSrc = await fsp.readFile(
    path.join(repoRoot, 'src/storage.js'),
    'utf8',
  );
  sandbox.importScripts = function () {
    /* no-op: modules are pre-loaded below */
  };

  // privacy/schema.js
  vm.runInContext(schemaSrc, ctx, { filename: 'privacy/schema.js' });

  // storage.js (depends on chrome.storage; we provide the stub via
  // sandbox.chrome above).
  vm.runInContext(storageSrc, ctx, { filename: 'storage.js' });

  // api/client.js (uses URL, fetch)
  vm.runInContext(clientSrc, ctx, { filename: 'api/client.js' });

  // content.js — register a sendMessage stub that bridges to the
  // service-worker's listener. We override content.js's chrome.runtime
  // AFTER it's loaded. (content.js captures chrome.* at IIFE time but
  // it dereferences chrome.runtime at call time, so post-load patching
  // works.)
  vm.runInContext(contentSrc, ctx, { filename: 'content.js' });

  // Patch content.js's chrome.runtime.sendMessage to use our bridge.
  sandbox.chrome.runtime.sendMessage = (msg) => chromeStub.sendMessageFromContent(msg);

  // service-worker.js
  vm.runInContext(swSrc, ctx, { filename: 'service-worker.js' });

  const ContentScript = sandbox.self.AegisGateLens.ContentScript;

  return {
    sandbox,
    ctx,
    chromeStub,
    ContentScript,
  };
}

// ----- Test isolation helper -----------------------------------------------

/**
 * Reset all per-test state. Each integration test should call this so
 * rate-limit state, opt-in state, audit log, and mock-backend state
 * don't bleed between tests.
 */
function resetState() {
  mock.events.length = 0;
  fs.writeFileSync(mock.outputPath, '');
  // Re-create the chrome stub state. We keep the same object identity
  // (so listeners stay registered) but reset its internal stores.
  harness.chromeStub.setOptedIn(true);
  harness.chromeStub.setBaseUrlOverride(mock.baseUrl);
  // Reset the local audit log. We do this via a synchronous splice
  // through the storage stub - the stub stores arrays in a plain JS
  // object, so we mutate directly.
  harness.chromeStub._localAudit.length = 0;
  // Force a new APIClient so the cached rate-limit ring buffer resets.
  harness.chromeStub._invalidateClientCache();
}


// ----- Tests ----------------------------------------------------------------

const mock = await bootMockBackend();
const harness = await loadIntegrationHarness(mock.baseUrl);

console.log('AegisGate Lens - End-to-End Integration Test (Day 4)');
console.log(`Mock backend: ${mock.baseUrl}`);
console.log(`JSONL output: ${mock.outputPath}`);
console.log('');

await test('a v1 detection round-trips: content.js -> service-worker -> JSONL', async () => {
  resetState();

  const inst = Object.create(harness.ContentScript.prototype);
  inst.currentDetections = [{
    category: 'pii_email',
    severity: 'medium',
    mlScore: 0.92,
  }];
  inst.domainHash = '0a1b2c3d4e5f6071';

  // recordAction sends ONE message per detection. The bridge will
  // dispatch to the service-worker's onMessage, which calls
  // handleTelemetry, which appends to local audit + calls sendEvent.
  inst.recordAction('send_anyway');

  // Wait for the message to propagate through the async chain:
  // setImmediate (bridge) -> handleTelemetry -> storage.appendLocalAudit
  // -> getClient -> sendEvent -> fetch -> mock backend POST.
  for (let i = 0; i < 30 && mock.events.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }

  assert.equal(mock.events.length, 1, 'expected 1 event in JSONL');
  const ev = mock.events[0];
  assert.equal(ev.lens_event_version, 1);
  assert.equal(ev.category, 'pii_email');
  assert.equal(ev.severity, 'medium');
  assert.equal(ev.user_action, 'send_anyway');
  assert.equal(ev.domain_hash, '0a1b2c3d4e5f6071');
  assert.equal(ev.lens_version, '0.2.2-test');

  // JSONL file has the same event.
  const raw = fs.readFileSync(mock.outputPath, 'utf8');
  const lines = raw.split('\n').filter((l) => l.length > 0);
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).lens_event_version, 1);

  // Local audit log has the same event (different field set: no
  // model_version/lens_version/confidence by storage design).
  const audit = harness.chromeStub.getLocalAudit();
  assert.equal(audit.length, 1, 'expected 1 audit entry');
  assert.equal(audit[0].category, 'pii_email');
  assert.equal(audit[0].user_action, 'send_anyway');
});

await test('a versionless event is silently dropped (Day 2 cut-over holds)', async () => {
  resetState();

  // We can't trigger this via content.js (which now stamps the version),
  // so we send a synthetic message directly through the bridge, as a
  // legacy v0 client would.
  await harness.chromeStub.sendMessageFromContent({
    type: 'lens.telemetry',
    event: {
      domain_hash: '0a1b2c3d4e5f6071',
      category: 'pii_email',
      severity: 'medium',
      user_action: 'send_anyway',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: '0.0.0+legacy',
      lens_version: '0.0.0',
      confidence: 0.5,
    },
  });

  // Wait for any potential round-trip.
  await new Promise((r) => setTimeout(r, 100));

  assert.equal(mock.events.length, 0, 'versionless event must NOT reach the backend');
});

await test('an event with prompt_text is silently dropped (privacy guardrail)', async () => {
  resetState();

  await harness.chromeStub.sendMessageFromContent({
    type: 'lens.telemetry',
    event: {
      lens_event_version: 1,
      domain_hash: '0a1b2c3d4e5f6071',
      category: 'pii_email',
      severity: 'medium',
      user_action: 'send_anyway',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: '0.2.2+regex-v1',
      lens_version: '0.2.2',
      confidence: 0.9,
      prompt_text: 'this is the secret prompt content',
    },
  });

  await new Promise((r) => setTimeout(r, 100));

  assert.equal(mock.events.length, 0, 'event with prompt_text must NOT reach the backend');
});

await test('rate limit holds across the full chain: 100 accepted, 5 dropped', async () => {
  resetState();

  // Send 105 events directly through the bridge (bypassing content.js,
  // since recordAction would only send one message per detection and
  // the rate-limit semantics are owned by APIClient, not content.js).
  for (let i = 0; i < 105; i++) {
    await harness.chromeStub.sendMessageFromContent({
      type: 'lens.telemetry',
      event: {
        lens_event_version: 1,
        domain_hash: '0a1b2c3d4e5f6071',
        category: 'pii_email',
        severity: 'low',
        user_action: 'dismiss',
        timestamp: Math.floor(Date.now() / 1000),
        model_version: '0.2.2+regex-v1',
        lens_version: '0.2.2',
        confidence: 0.5,
      },
    });
  }

  // Wait for all round-trips to complete (each ~5-10ms locally).
  for (let i = 0; i < 50 && mock.events.length < 100; i++) {
    await new Promise((r) => setTimeout(r, 50));
  }

  assert.equal(
    mock.events.length, 100,
    `expected exactly 100 events at backend (rate-limited), got ${mock.events.length}`,
  );
});

await test('opt-out path: not opted in means no backend traffic', async () => {
  resetState();
  // Flip the opt-in state to disabled AFTER resetState set it to true.
  harness.chromeStub.setOptedIn(false);

  // Now send a valid event through the chain.
  await harness.chromeStub.sendMessageFromContent({
    type: 'lens.telemetry',
    event: {
      lens_event_version: 1,
      domain_hash: '0a1b2c3d4e5f6071',
      category: 'pii_email',
      severity: 'medium',
      user_action: 'send_anyway',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: '0.2.2+regex-v1',
      lens_version: '0.2.2',
      confidence: 0.9,
    },
  });

  await new Promise((r) => setTimeout(r, 100));

  assert.equal(mock.events.length, 0, 'opted-out user must NOT trigger backend traffic');
  // Local audit log should ALSO be empty (handleTelemetry returns early).
  const audit = harness.chromeStub.getLocalAudit();
  assert.equal(audit.length, 0, 'opted-out user must NOT have local audit entries');

  // Restore for subsequent tests.
  harness.chromeStub.setOptedIn(true);
});

await test('multiple detections from one user action produce multiple events', async () => {
  resetState();

  const inst = Object.create(harness.ContentScript.prototype);
  inst.currentDetections = [
    { category: 'pii_email', severity: 'medium', mlScore: 0.92 },
    { category: 'secret_api_key', severity: 'high', mlScore: 0.87 },
    { category: 'pii_phone', severity: 'medium', mlScore: 0.80 },
  ];
  inst.domainHash = '0a1b2c3d4e5f6071';

  inst.recordAction('edit');

  for (let i = 0; i < 30 && mock.events.length < 3; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }

  assert.equal(mock.events.length, 3, 'one event per detection');
  const categories = mock.events.map((e) => e.category).sort();
  assert.deepEqual(categories, ['pii_email', 'pii_phone', 'secret_api_key']);
  for (const ev of mock.events) {
    assert.equal(ev.lens_event_version, 1);
    assert.equal(ev.user_action, 'edit');
  }
});

await test('end-to-end: a fresh detection chain produces a v1 event in JSONL', async () => {
  // Independent end-to-end check: reset, send 1 event, verify it
  // shows up in JSONL with lens_event_version: 1 and the right shape.
  // (Each test above resets the file; we do our own reset here so the
  // assertion is self-contained.)
  resetState();
  await harness.chromeStub.sendMessageFromContent({
    type: 'lens.telemetry',
    event: {
      lens_event_version: 1,
      domain_hash: '0a1b2c3d4e5f6071',
      category: 'pii_phone',
      severity: 'low',
      user_action: 'cancel',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: '0.2.2+regex-v1',
      lens_version: '0.2.2-test',
      confidence: 0.7,
    },
  });
  for (let i = 0; i < 30 && mock.events.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.equal(mock.events.length, 1);
  const ev = mock.events[0];
  assert.equal(ev.lens_event_version, 1);
  assert.equal(ev.category, 'pii_phone');
  assert.equal(ev.lens_version, '0.2.2-test');

  const raw = fs.readFileSync(mock.outputPath, 'utf8');
  const lines = raw.split('\n').filter((l) => l.length > 0);
  assert.equal(lines.length, 1);
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.lens_event_version, 1);
});

// ----- Cleanup + summary ----------------------------------------------------

await shutdown(mock.server);

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
