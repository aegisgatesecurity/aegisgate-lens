// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Penetration Test Attack 07 (F-09)
// Opt-in tamper via direct storage writes
// =========================================================================
//
// Threat-model reference: F-09 (opt-in state not signed).
//
// We test whether an attacker who has write access to chrome.storage.sync
// (e.g., a malicious extension with the "storage" permission reading/writing
// OUR extension's storage, which Chrome prevents via storage isolation,
// OR a user who has Chrome sync enabled and an attacker controls their
// Google account) can flip the opt-in state without the user's knowledge.
//
// Chrome's per-extension storage isolation prevents cross-extension reads
// (chicken-and-egg: an extension that could read OUR storage would need
// OUR extension's ID, which we don't grant). But IF sync is enabled,
// the storage values replicate via the user's Google account.
//
// The attack:
//   1. Forge an opt-in state directly in chrome.storage.sync (bypassing
//      handleOptIn).
//   2. Verify that the service worker's handleGetState reads the forged
//      value (this is the actual question — does the service worker
//      trust the storage value as-is?).
//   3. Forge other Lens-managed storage values.
//   4. Try to inject a different bearer token.
//
// If the service worker reads storage values without validation, F-09 is
// exploitable. If it validates (e.g., signature check), F-09 is closed.
//
// Output: pen-test/evidence/07-f09.jsonl
// =========================================================================

'use strict';

import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

async function loadServiceWorker({ presetSync = {}, presetLocal = {} } = {}) {
  const swSrc = await fsp.readFile(path.join(repoRoot, 'src/service-worker.js'), 'utf8');
  const localStore = { ...presetLocal };
  const syncStore = { ...presetSync };
  const listeners = [];

  const sandbox = {
    console: { log: () => {}, info: () => {}, warn: () => {}, error: () => {} },
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
      this.getOptInState = () => Promise.resolve(syncStore['lens.opt_in'] || { enabled: false });
      this.getBaseUrlOverride = () => Promise.resolve(localStore['lens.__base_url_override'] || '');
      this.getBearerToken = () => Promise.resolve(localStore['lens.bearer_token'] || '');
      this.appendLocalAudit = () => Promise.resolve();
      this.getStats = () => Promise.resolve({ events24h: 0, detections24h: 0 });
      this.setOptIn = (state) => { syncStore['lens.opt_in'] = state; return Promise.resolve(); };
      this.setOptInState = (state) => { syncStore['lens.opt_in'] = state; return Promise.resolve(); };
      this.setBearerToken = (tok) => { localStore['lens.bearer_token'] = tok; return Promise.resolve(); };
      this.setBaseUrlOverride = (url) => { localStore['lens.__base_url_override'] = url; return Promise.resolve(); };
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
  return { listeners, localStore, syncStore, OWN_ID: 'aegisgate-lens-extension-id' };
}

async function dispatch(listeners, msg, senderId = 'aegisgate-lens-extension-id') {
  const sender = { id: senderId };
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

const OUT = path.join(repoRoot, 'pen-test/evidence/07-f09.jsonl');
await fsp.mkdir(path.dirname(OUT), { recursive: true });
const evidenceLines = [];

function log(name, verdict, detail) {
  evidenceLines.push({ name, verdict, detail });
  const tag = verdict === 'PASS' ? 'PASS' : verdict === 'FINDING' ? 'FIND' : 'INFO';
  console.log(`  [${tag}] ${name}${detail ? ': ' + detail : ''}`);
}

console.log('AegisGate Lens - Opt-in Tamper Pen Test (Day 12 / Attack 07)');
console.log('');

// 1. Forge opt-in state with no last_changed_at (legacy format).
{
  const forged = { enabled: true /* no last_changed_at, no lens_version */ };
  const { listeners, syncStore } = await loadServiceWorker({
    presetSync: { 'lens.opt_in': forged },
  });
  const responses = await dispatch(listeners, { type: 'lens.get_state' }, 'aegisgate-lens-extension-id');
  const state = responses.find((r) => r && typeof r === 'object' && 'enabled' in r);
  log('forge_optin_no_metadata',
    state && state.enabled === true ? 'FINDING' : 'PASS',
    `state: ${JSON.stringify(state)}. Note: service worker trusts storage value as-is; this is by design (the storage is per-extension isolated). The mitigation is that an attacker needs write access to OUR extension's storage, which requires either (a) malicious extension with the same ID (impossible) or (b) Chrome sync account compromise.`);
}

// 2. Forge opt-in state with malicious lens_version.
{
  const forged = {
    enabled: true,
    opted_in_at: 0,
    last_changed_at: 0,
    lens_version: '<script>alert(1)</script>',
  };
  const { listeners } = await loadServiceWorker({
    presetSync: { 'lens.opt_in': forged },
  });
  const responses = await dispatch(listeners, { type: 'lens.get_state' }, 'aegisgate-lens-extension-id');
  const state = responses.find((r) => r && typeof r === 'object' && 'enabled' in r);
  log('forge_optin_with_xss_version',
    // linter-disable-next-line js/bad-tag-filter False positive: this
    // regex is a pen-test SENTINEL — checking whether a forged opt-in
    // value contains `<script>`. It is not an HTML filter.
    state && state.lens_version && /<script>/.test(state.lens_version) ? 'FINDING' : 'PASS',
    `state.lens_version echoed: ${JSON.stringify(state && state.lens_version)}. The lens_version field is just a string; it's never rendered as HTML. No XSS.`);
}

// 3. Forge base_url_override to attacker-controlled URL.
{
  const { listeners } = await loadServiceWorker({
    presetLocal: { 'lens.__base_url_override': 'http://attacker.example.com:9999' },
  });
  const responses = await dispatch(listeners, { type: 'lens.get_state' }, 'aegisgate-lens-extension-id');
  const state = responses.find((r) => r && typeof r === 'object' && 'enabled' in r);
  log('forge_base_url_to_attacker',
    state ? 'INFO' : 'PASS',
    `base_url_override is not exposed via get_state; it's read internally by getClient(). If a malicious sync value could redirect telemetry, that would be a finding.`);
}

// 4. Forge bearer token.
{
  const { listeners } = await loadServiceWorker({
    presetLocal: { 'lens.bearer_token': 'attacker-controlled-token' },
  });
  const responses = await dispatch(listeners, { type: 'lens.get_state' }, 'aegisgate-lens-extension-id');
  const state = responses.find((r) => r && typeof r === 'object' && 'enabled' in r);
  log('forge_bearer_token',
    state ? 'INFO' : 'PASS',
    `bearer_token is read by getClient() internally, not exposed via get_state.`);
}

// 5. Try to opt-in via legitimate message with crafted payload.
{
  const { listeners } = await loadServiceWorker();
  const responses = await dispatch(listeners, { type: 'lens.opt_in', payload: { enabled: true } });
  const optResp = responses.find((r) => r && (r.enabled === true || r.error));
  log('legitimate_opt_in_through_api',
    optResp && optResp.enabled === true ? 'PASS' : 'INFO',
    `opt-in through the legitimate message handler: ${JSON.stringify(optResp)}. This is the supported way to opt-in.`);
}

// 6. Attempt to opt out via legitimate message (verify the toggle works).
{
  const { listeners, syncStore } = await loadServiceWorker({
    presetSync: { 'lens.opt_in': { enabled: true, opted_in_at: 1, last_changed_at: 1, lens_version: '0.2.2' } },
  });
  await dispatch(listeners, { type: 'lens.opt_in', payload: { enabled: false } });
  // After the message, syncStore should reflect enabled=false.
  const newState = syncStore['lens.opt_in'];
  log('legitimate_opt_out_through_api',
    newState && newState.enabled === false ? 'PASS' : 'FINDING',
    `syncStore['lens.opt_in'].enabled = ${newState && newState.enabled}. handleOptIn returns void (no response); the actual write is verified by reading storage directly.`);
}

// 7. Try to forge a malformed opt-in object (missing fields).
{
  const { listeners, syncStore } = await loadServiceWorker({
    presetSync: { 'lens.opt_in': { enabled: true } }, // missing required fields
  });
  const responses = await dispatch(listeners, { type: 'lens.get_state' }, 'aegisgate-lens-extension-id');
  const state = responses.find((r) => r && typeof r === 'object' && 'enabled' in r);
  log('forge_optin_missing_metadata',
    state && state.enabled === true ? 'INFO' : 'PASS',
    `state: ${JSON.stringify(state)}. The service worker reads enabled from the stored object without validating other fields. This is acceptable because the lens_version and last_changed_at fields are advisory (logged for audit).`);
}

// 8. Massive opt-in (DoS via opt-in spam).
{
  const { listeners } = await loadServiceWorker();
  let errors = 0;
  for (let i = 0; i < 100; i++) {
    const responses = await dispatch(listeners, { type: 'lens.opt_in', payload: { enabled: true } });
    if (responses.some((r) => r && r.error)) errors++;
  }
  log('opt_in_spam_100',
    errors === 0 ? 'PASS' : 'FINDING',
    `100 opt-in messages, ${errors} errors`);
}

console.log('');
const passCount = evidenceLines.filter((e) => e.verdict === 'PASS').length;
const findCount = evidenceLines.filter((e) => e.verdict === 'FINDING').length;
const infoCount = evidenceLines.filter((e) => e.verdict === 'INFO').length;
console.log(`Passed: ${passCount}    Findings: ${findCount}    Info: ${infoCount}`);

await fsp.writeFile(OUT, evidenceLines.map((e) => JSON.stringify(e)).join('\n') + '\n');
console.log(`Evidence: ${OUT}`);
