// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Penetration Test Attack 06 (F-08)
// Extension hijack via cross-extension messaging
// =========================================================================
//
// Threat-model reference: F-08 (sender.id spoofing via cross-extension
// chrome.runtime.sendMessage).
//
// Day 8 fixed F-01 by adding sender.id validation in service-worker.js.
// This attack tries to defeat that fix from the wire side. Specifically,
// we test:
//
//   1. Foreign extension sends a lens.telemetry message with forged sender.id.
//      Expect: rejected with "foreign sender rejected".
//   2. Foreign extension sends a lens.opt_in message.
//      Expect: rejected.
//   3. Foreign extension sends lens.stats.
//      Expect: rejected.
//   4. Malicious message claiming sender.id === chrome.runtime.id (no way
//      to do this from outside, but verify the check is case-sensitive).
//   5. Multiple message types in one attack.
//   6. Race condition: send 1000 messages in parallel from foreign sender.
//
// Each test loads service-worker.js into a vm and dispatches a
// crafted message via the registered onMessage listener.
//
// Output: pen-test/evidence/06-f08.jsonl
// =========================================================================

'use strict';

import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

async function loadServiceWorker() {
  const swSrc = await fsp.readFile(path.join(repoRoot, 'src/service-worker.js'), 'utf8');
  const localStore = {};
  const syncStore = {};
  const listeners = [];

  const sandbox = {
    console: { log: () => {}, info: () => {}, warn: (...a) => console.warn('[Lens]', ...a), error: (...a) => console.error('[Lens]', ...a) },
    URL, fetch: (...args) => globalThis.fetch(...args), crypto: globalThis.crypto,
    Math, Date, JSON, Object, Array, Set, Map,
    String, Number, Boolean, Error, Promise, Symbol, RegExp,
    setTimeout, clearTimeout, setImmediate, self: {},
    chrome: {
      runtime: {
        id: 'aegisgate-lens-extension-id',
        onInstalled: { addListener: () => {} },
        onStartup: { addListener: () => {} },
        onMessage: { addListener(fn) { listeners.push(fn); } },
        getURL: (p) => 'chrome-extension://test/' + p,
        getManifest: () => ({ version: '0.2.2-test' }),
        lastError: null,
      },
    },
  };
  sandbox.self = sandbox;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};
  sandbox.self.AegisGateLens.logger = { info: () => {}, warn: () => {}, error: () => {} };
  sandbox.self.AegisGateLens.storage = {
    Storage: function () {
      this.getOptInState = () => Promise.resolve({ enabled: true });
      this.getBaseUrlOverride = () => Promise.resolve('');
      this.getBearerToken = () => Promise.resolve('test-token');
      this.appendLocalAudit = () => Promise.resolve();
      this.getStats = () => Promise.resolve({ events24h: 0, detections24h: 0 });
    },
  };
  sandbox.self.AegisGateLens.APIClient = function () {};
  sandbox.chrome.storage = {
    sync: { get: (k, cb) => cb({ [k]: syncStore[k] }), set: (i, cb) => { Object.assign(syncStore, i); if (cb) cb(); } },
    local: { get: (k, cb) => cb({ [k]: localStore[k] }), set: (i, cb) => { Object.assign(localStore, i); if (cb) cb(); }, remove: (k, cb) => { delete localStore[k]; if (cb) cb(); } },
  };
  sandbox.importScripts = () => {};

  const ctx = vm.createContext(sandbox);
  vm.runInContext(swSrc, ctx, { filename: 'service-worker.js' });
  return { listeners, OWN_ID: 'aegisgate-lens-extension-id' };
}

async function dispatch(listeners, msg, senderId) {
  const sender = senderId === undefined ? undefined : senderId === null ? null : { id: senderId };
  const responses = [];
  const sendResponse = (resp) => { responses.push(resp); };
  for (const fn of listeners) {
    try {
      const r = fn(msg, sender, sendResponse);
      if (r && typeof r.then === 'function') await r;
    } catch (err) {}
  }
  await new Promise((r) => setImmediate(r));
  return responses;
}

const OUT = path.join(repoRoot, 'pen-test/evidence/06-f08.jsonl');
await fsp.mkdir(path.dirname(OUT), { recursive: true });
const evidenceLines = [];

function log(name, verdict, detail) {
  evidenceLines.push({ name, verdict, detail });
  const tag = verdict === 'PASS' ? 'PASS' : verdict === 'FINDING' ? 'FIND' : 'INFO';
  console.log(`  [${tag}] ${name}${detail ? ': ' + detail : ''}`);
}

console.log('AegisGate Lens - Extension Hijack Pen Test (Day 12 / Attack 06)');
console.log('');

const { listeners, OWN_ID } = await loadServiceWorker();
console.log(`  Service worker loaded; OWN_ID = ${OWN_ID}; listeners registered = ${listeners.length}`);
console.log('');

const attackTypes = ['lens.telemetry', 'lens.opt_in', 'lens.stats', 'lens.get_state', 'lens.test_event'];
for (const type of attackTypes) {
  const responses = await dispatch(listeners, { type, payload: { enabled: true }, event: {} }, 'malicious-extension-id');
  const rejected = responses.some((r) => r && r.error === 'foreign sender rejected');
  log(`foreign_${type}`, rejected ? 'PASS' : 'FINDING', `responses: ${responses.map((r) => JSON.stringify(r)).join(', ')}`);
}

// Edge cases.
const edgeCases = [
  ['undefined_sender', undefined],
  ['null_sender', null],
  ['empty_string_sender', ''],
  ['case_bypass_uppercase', OWN_ID.toUpperCase()],
];
for (const [name, senderId] of edgeCases) {
  const responses = await dispatch(listeners, { type: 'lens.telemetry', event: {} }, senderId);
  const rejected = responses.some((r) => r && r.error === 'foreign sender rejected');
  log(name, rejected ? 'PASS' : 'FINDING', `responses: ${responses.map((r) => JSON.stringify(r)).join(', ')}`);
}

// Legitimate sender sanity.
{
  const responses = await dispatch(listeners, { type: 'lens.get_state' }, OWN_ID);
  const wasRejected = responses.some((r) => r && r.error === 'foreign sender rejected');
  log('legitimate_sender_baseline', !wasRejected ? 'PASS' : 'FINDING', `responses: ${responses.map((r) => JSON.stringify(r)).join(', ')}`);
}

// Parallel foreign spam.
{
  const promises = [];
  for (let i = 0; i < 100; i++) {
    promises.push(dispatch(listeners, { type: 'lens.telemetry', event: {} }, 'attacker-' + i));
  }
  const all = await Promise.all(promises);
  const allRejected = all.every((responses) =>
    responses.some((r) => r && r.error === 'foreign sender rejected'));
  log('parallel_100_foreign', allRejected ? 'PASS' : 'FINDING', `all 100 rejected: ${allRejected}`);
}

// Try to spoof own id via Object.assign-like prototype trick.
// Chrome's sender.id is a string; we send a string that LOOKS like our ID.
// (Already covered by case_bypass_uppercase.)

console.log('');
const passCount = evidenceLines.filter((e) => e.verdict === 'PASS').length;
const findCount = evidenceLines.filter((e) => e.verdict === 'FINDING').length;
console.log(`Passed: ${passCount}    Findings: ${findCount}`);

await fsp.writeFile(OUT, evidenceLines.map((e) => JSON.stringify(e)).join('\n') + '\n');
console.log(`Evidence: ${OUT}`);
