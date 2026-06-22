#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Dismissals Pruning Test (Day 9 / F-04)
// =========================================================================
//
// Asserts that ContentScript.prototype.storeDismissal prunes the
// `dismissals` object in chrome.storage.local so it cannot grow
// unbounded and fill the 10 MB quota. See plans/LENS-THREAT-MODEL.md
// finding F-04 (CVSS 3.5 Low).
//
// What we test:
//   1. Pruning expired entries: 100 expired + 1 new -> 1 entry remains.
//   2. Pruning expired mixed with live: 50 expired + 50 live + 1 new
//      -> 51 entries remain (50 live + 1 new).
//   3. Cap enforcement: DISMISSAL_MAX_ENTRIES already present + 1 new
//      -> DISMISSAL_MAX_ENTRIES entries remain, the oldest was dropped.
//   4. The newly added entry is always present and has the correct
//      shape (dismissed_at, expires_at, reason).
//   5. Each stored entry retains its domain_hash prefix in the key
//      (regression: the key format must not change).
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

// ----- Minimal DOM stub -----------------------------------------------------

function makeElement() {
  return {
    style: {},
    children: [],
    parentNode: null,
    attributes: {},
    listeners: {},
    textContent: '',
    setAttribute(k, v) { this.attributes[k] = v; },
    getAttribute(k) { return this.attributes[k]; },
    appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
    removeChild(c) {
      const i = this.children.indexOf(c);
      if (i >= 0) { this.children.splice(i, 1); c.parentNode = null; }
      return c;
    },
    addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); },
    dispatchEvent(e) { for (const fn of this.listeners[e && e.type] || []) fn(e); },
  };
}
function makeDocument() { return { createElement: makeElement, body: makeElement() }; }

// ----- Chrome storage stub (callback API, mirroring real chrome.storage) ----

function makeStorageStub() {
  const data = {};
  return {
    data,
    get(key, cb) {
      if (typeof key === 'string') cb({ [key]: data[key] });
      else if (Array.isArray(key)) {
        const out = {};
        for (const k of key) out[k] = data[k];
        cb(out);
      } else cb({ ...data });
    },
    set(items, cb) { Object.assign(data, items); if (cb) cb(); },
    remove(key, cb) { delete data[key]; if (cb) cb(); },
    preset(key, value) { data[key] = value; },
    reset() { for (const k of Object.keys(data)) delete data[k]; },
  };
}

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

// ----- Load content.js into a vm sandbox ------------------------------------

async function loadContentScript() {
  const [schemaSrc, contentSrc] = await Promise.all([
    fsp.readFile(path.join(repoRoot, 'src/privacy/schema.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/content.js'), 'utf8'),
  ]);

  const storage = makeStorageStub();
  const document = makeDocument();
  const locObj = { hostname: 'chat.openai.com', protocol: 'https:' };

  const sandbox = {
    console,
    URL,
    document,
    location: locObj,
    navigator: { userAgent: 'node-test' },
    Math, Date, JSON, Object, Array, Set, Map,
    String, Number, Boolean, Error, Promise, Symbol, RegExp,
    setTimeout, clearTimeout,
    window: {},
    self: {},
    chrome: {
      runtime: {
        sendMessage: () => Promise.resolve(),
        getURL: (p) => 'chrome-extension://test/' + p,
        getManifest: () => ({ version: '0.2.2-test' }),
        lastError: null,
      },
      storage: { local: storage },
    },
  };
  sandbox.window.location = locObj;
  sandbox.window = sandbox.self;
  sandbox.self.location = locObj;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};
  sandbox.self.AegisGateLens.logger = {
    info: () => {},
    warn: (...a) => console.warn('[Lens]', ...a),
    error: (...a) => console.error('[Lens]', ...a),
  };

  const ctx = vm.createContext(sandbox);
  vm.runInContext(schemaSrc, ctx, { filename: 'privacy/schema.js' });
  vm.runInContext(contentSrc, ctx, { filename: 'content.js' });

  const ContentScript = sandbox.self.AegisGateLens.ContentScript;
  if (!ContentScript) throw new Error('ContentScript not exported');
  return { storage, ContentScript };
}

// ----- Helper: build a synthetic dismissals object -------------------------

function makeDismissals(count, opts = {}) {
  const now = Math.floor(Date.now() / 1000);
  const ttl = 24 * 60 * 60;
  const dismissals = {};
  for (let i = 0; i < count; i++) {
    const dismissedAt = opts.dismissedAt !== undefined
      ? opts.dismissedAt + i
      : now - count + i;
    const expiresAt = opts.allExpired
      ? now - 100  // 100s ago, already expired
      : (opts.expiresAt !== undefined
          ? opts.expiresAt
          : dismissedAt + ttl);
    const key = (opts.domainHash || '0a1b2c3d4e5f6071') + '::pii_email|match-' + i;
    dismissals[key] = {
      dismissed_at: dismissedAt,
      expires_at: expiresAt,
      reason: opts.reason || null,
    };
  }
  return dismissals;
}

// ----- Helper: drive storeDismissal and wait for chrome.storage.local.get
//         callback to complete.

async function storeDismissal(inst, key, reason) {
  inst.storeDismissal(key, reason);
  // chrome.storage.local.get is callback-based; let microtasks drain.
  await new Promise((r) => setTimeout(r, 20));
}

// ----- Tests ---------------------------------------------------------------

console.log('AegisGate Lens - Dismissals Pruning Test (Day 9 / F-04)');
console.log('');

const loaded = await loadContentScript();
const storage = loaded.storage;
const ContentScript = loaded.ContentScript;
const MAX = ContentScript.DISMISSAL_MAX_ENTRIES;

await test('DISMISSAL_MAX_ENTRIES is 1000 (sanity)', () => {
  assert.equal(MAX, 1000);
});

await test('pruning: 100 expired entries are removed by a new storeDismissal', async () => {
  storage.reset();
  storage.preset('dismissals', makeDismissals(100, { allExpired: true }));

  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'newdomain00';
  await storeDismissal(inst, 'pii_email|new-key', 'test_data');

  const dismissals = storage.data.dismissals || {};
  assert.equal(Object.keys(dismissals).length, 1,
    'only the new entry should remain after pruning 100 expired');
  assert.ok('newdomain00::pii_email|new-key' in dismissals,
    'the new entry should be present');
});

await test('pruning: 50 expired + 50 live + 1 new -> 51 entries', async () => {
  storage.reset();
  // 50 entries expired 1 hour ago, 50 live entries with future expiry.
  const expired = makeDismissals(50, { allExpired: true, domainHash: 'expired' });
  const live = makeDismissals(50, { domainHash: 'live' });
  storage.preset('dismissals', Object.assign({}, expired, live));

  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'newdomain01';
  await storeDismissal(inst, 'pii_email|new-key', 'test_data');

  const dismissals = storage.data.dismissals || {};
  assert.equal(Object.keys(dismissals).length, 51,
    '50 live + 1 new = 51 expected');
  assert.ok(!('expired::pii_email|match-0' in dismissals),
    'expired entry should be gone');
  assert.ok('live::pii_email|match-49' in dismissals,
    'live entry should remain');
  assert.ok('newdomain01::pii_email|new-key' in dismissals,
    'new entry should be present');
});

await test('cap enforcement: MAX already present + 1 new -> MAX entries, oldest dropped', async () => {
  storage.reset();
  storage.preset('dismissals', makeDismissals(MAX, { domainHash: 'oldest' }));

  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'newdomain02';
  await storeDismissal(inst, 'pii_email|new-key', 'test_data');

  const dismissals = storage.data.dismissals || {};
  assert.equal(Object.keys(dismissals).length, MAX,
    `expected exactly ${MAX} entries, got ${Object.keys(dismissals).length}`);
  assert.ok('newdomain02::pii_email|new-key' in dismissals,
    'new entry should be present');
  assert.ok(!('oldest::pii_email|match-0' in dismissals),
    'oldest entry (match-0) should have been dropped');
  assert.ok('oldest::pii_email|match-999' in dismissals,
    'newest of the old entries (match-999) should remain');
});

await test('cap + expiry pruning: MAX mixed expired + 1 new -> 501 entries (pruned to fit)', async () => {
  storage.reset();
  // MAX/2 expired + MAX/2 live = MAX total entries, half expired.
  const expiredHalf = makeDismissals(MAX / 2, { allExpired: true, domainHash: 'expired2' });
  const liveHalf = makeDismissals(MAX / 2, { domainHash: 'live2' });
  storage.preset('dismissals', Object.assign({}, expiredHalf, liveHalf));

  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'newdomain03';
  await storeDismissal(inst, 'pii_email|new-key', 'test_data');

  const dismissals = storage.data.dismissals || {};
  // After pruning expired (500), we have 500 live. After cap enforcement
  // (500 already at MAX-1=999), no further drops needed. Total: 501.
  assert.equal(Object.keys(dismissals).length, 501,
    'expired should be pruned first; live entries kept (500 live + 1 new = 501)');
  assert.ok('newdomain03::pii_email|new-key' in dismissals);
  assert.ok(!('expired2::pii_email|match-0' in dismissals));
  assert.ok('live2::pii_email|match-499' in dismissals);
});

await test('new entry has the correct shape (dismissed_at, expires_at, reason)', async () => {
  storage.reset();
  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'shape00';
  const before = Math.floor(Date.now() / 1000);
  await storeDismissal(inst, 'pii_email|k', 'own_data');
  const after = Math.floor(Date.now() / 1000);

  const entry = storage.data.dismissals['shape00::pii_email|k'];
  assert.ok(entry, 'entry should exist');
  assert.ok(entry.dismissed_at >= before && entry.dismissed_at <= after,
    'dismissed_at should be a current unix-second timestamp');
  // 24h TTL.
  const expectedExpires = entry.dismissed_at + 24 * 60 * 60;
  assert.equal(entry.expires_at, expectedExpires,
    'expires_at should be dismissed_at + 24h');
  assert.equal(entry.reason, 'own_data');
});

await test('domain hash prefix is preserved in the key (regression)', async () => {
  storage.reset();
  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'abcdef0123456789';
  await storeDismissal(inst, 'pii_phone|k1', null);
  const keys = Object.keys(storage.data.dismissals);
  assert.equal(keys.length, 1);
  assert.ok(keys[0].startsWith('abcdef0123456789::'),
    'key must start with the domain hash');
  assert.ok(keys[0].endsWith('::pii_phone|k1'),
    'key must end with the detection key');
});

await test('no quota overflow: 100000 entries pre-existing are bounded to MAX', async () => {
  // This is the worst-case scenario from F-04: a page pastes a large
  // corpus that triggers many distinct detections. The pruning must
  // bring the count down even if the input is much larger than MAX.
  storage.reset();
  storage.preset('dismissals', makeDismissals(100000, { domainHash: 'flood' }));

  const inst = Object.create(ContentScript.prototype);
  inst.domainHash = 'newdomain99';
  await storeDismissal(inst, 'pii_email|new-key', null);

  const dismissals = storage.data.dismissals || {};
  assert.ok(Object.keys(dismissals).length <= MAX,
    `count must be <= ${MAX}, got ${Object.keys(dismissals).length}`);
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
