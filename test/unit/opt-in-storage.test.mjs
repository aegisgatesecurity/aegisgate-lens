// AegisGate Lens — test/unit/opt-in-storage.test.mjs
// Asserts that the opt-in state is read/written consistently across
// the 3 modules that touch it:
//
//   - src/welcome/welcome.js          (writes on first-install)
//   - src/popup/popup.js              (reads to display opt-in status)
//   - src/background.js               (reads/writes for FP-report opt-in)
//
// v0.1.2 F-2: the three modules previously used two different keys
// ('opt_in' and 'aegisgate_lens_opt_in') and two different value shapes
// (nested object and bare boolean). The fix unifies on a single
// canonical key (STORAGE_KEYS.OPT_IN = 'aegisgate_lens_opt_in') and
// a single value shape: { enabled: bool, last_changed_at: number, lens_version: string }.
//
// This test asserts the unified contract. If a future change
// re-introduces a different key or shape, this test fails.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadModule } from '../helpers/load-module.js';
import { installMockChrome, resetMockChrome } from '../helpers/mock-chrome.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// --- Constants reference (single source of truth) ---
// This MUST match src/util/constants.js STORAGE_KEYS.OPT_IN.
// If a future change updates constants.js but not this test,
// the test will fail. The constants.js file is read directly
// to extract the canonical key, so the test always reflects
// the current source of truth.
function getCanonicalOptInKey() {
  const src = readFileSync(join(LENS_ROOT, 'src/util/constants.js'), 'utf8');
  // Match: OPT_IN: '...'
  const m = src.match(/OPT_IN:\s*'([^']+)'/);
  if (!m) throw new Error('constants.js: STORAGE_KEYS.OPT_IN not found');
  return m[1];
}

// --- Module source greps (no module loading; just regex) ---
function readSource(path) {
  return readFileSync(join(LENS_ROOT, path), 'utf8');
}

// --- Tests ---

test('opt-in-storage: constants.js STORAGE_KEYS.OPT_IN is the canonical key', () => {
  const key = getCanonicalOptInKey();
  assert.equal(key, 'aegisgate_lens_opt_in',
    'constants.js STORAGE_KEYS.OPT_IN must be "aegisgate_lens_opt_in" (the unified key)');
});

test('opt-in-storage: welcome.js writes to the canonical key', () => {
  const welcome = readSource('src/welcome/welcome.js');
  const key = getCanonicalOptInKey();
  // Welcome.js should reference the canonical key string somewhere
  // (either via constants or as a literal fallback)
  const referencesCanonical = welcome.includes(key) ||
                              welcome.includes("STORAGE_KEYS.OPT_IN");
  assert.ok(referencesCanonical,
    'welcome.js must reference the canonical opt-in key (' + key + ')');
  // Welcome.js must NOT write to the legacy bare 'opt_in' key
  const writesLegacyOptIn = /opt_in:\s*\{/.test(welcome);
  assert.ok(!writesLegacyOptIn,
    'welcome.js must NOT write to a bare "opt_in" key (F-2 fix)');
});

test('opt-in-storage: popup.js reads from the canonical key', () => {
  const popup = readSource('src/popup/popup.js');
  const key = getCanonicalOptInKey();
  // Popup should reference the canonical key
  const referencesCanonical = popup.includes(key) ||
                              popup.includes("STORAGE_KEYS.OPT_IN");
  assert.ok(referencesCanonical,
    'popup.js must reference the canonical opt-in key (' + key + ')');
  // Popup must NOT read the legacy bare 'opt_in' literal
  const readsLegacyOptIn = /get\(\[\s*['"]opt_in['"]\s*\]\)/.test(popup);
  assert.ok(!readsLegacyOptIn,
    'popup.js must NOT read a bare "opt_in" key (F-2 fix)');
});

test('opt-in-storage: background.js uses the canonical key', () => {
  const bg = readSource('src/background.js');
  const key = getCanonicalOptInKey();
  // Background.js should reference the canonical key
  const referencesCanonical = bg.includes(key) ||
                              bg.includes("STORAGE_KEYS.OPT_IN");
  assert.ok(referencesCanonical,
    'background.js must reference the canonical opt-in key (' + key + ')');
  // Background.js getOptIn should return the new nested-object shape
  const returnsNested = /getOptIn[\s\S]{0,200}lastChangedAt/.test(bg) ||
                        /getOptIn[\s\S]{0,200}last_changed_at/.test(bg);
  assert.ok(returnsNested,
    'background.js getOptIn() should return the nested-object shape (enabled/lastChangedAt/lensVersion)');
  // Background.js setOptIn should write the nested-object shape
  const writesNested = /setOptIn[\s\S]{0,400}last_changed_at/.test(bg);
  assert.ok(writesNested,
    'background.js setOptIn() should write the nested-object shape');
});

test('opt-in-storage: no module writes a bare boolean to the canonical key', () => {
  // The v0.1.0-beta SW wrote `aegisgate_lens_opt_in: <bool>`. The new
  // shape is a nested object. The setOptIn() function in background.js
  // should write the nested shape; the bare boolean path is only
  // for backwards-compat reads (not writes).
  const bg = readSource('src/background.js');
  // Extract the setOptIn function body (greedy, between 'function setOptIn' and the next top-level blank line at column 0)
  const setOptInMatch = bg.match(/function setOptIn[\s\S]+?\n  \}/);
  assert.ok(setOptInMatch, 'setOptIn function not found in background.js');
  const setOptInBody = setOptInMatch[0];
  // The new setOptIn must include both 'enabled:' and 'last_changed_at:' keys
  // in the payload (the new nested-object shape).
  const hasEnabledKey = /enabled:\s*!!optedIn/.test(setOptInBody) ||
                        /enabled:\s*true/.test(setOptInBody) ||
                        /enabled:\s*false/.test(setOptInBody);
  const hasLastChangedKey = /last_changed_at:/.test(setOptInBody);
  assert.ok(hasEnabledKey, 'setOptIn must write an `enabled` key (new shape)');
  assert.ok(hasLastChangedKey, 'setOptIn must write a `last_changed_at` key (new shape)');
  // The old buggy form was: `return storageSet(OPT_IN_KEY, !!optedIn);` (bare boolean)
  const hasBareBooleanWrite = /storageSet\(OPT_IN_KEY,\s*!!optedIn\)/.test(setOptInBody);
  assert.ok(!hasBareBooleanWrite,
    'setOptIn must NOT write a bare boolean (F-2 fix)');
});

test('opt-in-storage: backwards-compat read of legacy bare boolean', () => {
  // The dispatch code (drainQueue + getOptIn) must accept a legacy
  // bare boolean value. A user upgrading from v0.1.0-beta has the
  // boolean shape in storage; we must not break their install.
  const bg = readSource('src/background.js');
  const hasBackwardsCompat = /typeof v === 'boolean'/.test(bg) ||
                             /backwards-compat/i.test(bg);
  assert.ok(hasBackwardsCompat,
    'background.js getOptIn() must accept a legacy bare boolean (v0.1.0-beta backwards-compat)');
});

test('opt-in-storage: cross-module key consistency (3 writers, 1 key)', () => {
  // Final check: welcome.js, popup.js, background.js all reference
  // the same canonical key. If any module uses a different key,
  // the opt-in state will desync (the original F-2 bug).
  const key = getCanonicalOptInKey();
  const welcome = readSource('src/welcome/welcome.js');
  const popup = readSource('src/popup/popup.js');
  const bg = readSource('src/background.js');

  const uses = {
    'welcome.js': welcome.includes(key) || welcome.includes('STORAGE_KEYS.OPT_IN'),
    'popup.js':   popup.includes(key)   || popup.includes('STORAGE_KEYS.OPT_IN'),
    'background.js': bg.includes(key)    || bg.includes('STORAGE_KEYS.OPT_IN')
  };
  for (const [mod, uses_it] of Object.entries(uses)) {
    assert.ok(uses_it, mod + ' does not reference the canonical opt-in key');
  }
});

// =================================================================
// Round-trip tests: actually load the SW and verify the runtime
// behavior of getOptIn() / setOptIn() against a mock storage layer.
// =================================================================

function loadSWWithMockChrome() {
  installMockChrome();
  // Polyfill crypto.getRandomValues (mock-chrome may or may not provide it)
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.getRandomValues) {
    Object.defineProperty(globalThis, 'crypto', {
      value: { getRandomValues: function (b) {
        for (var i = 0; i < b.length; i++) b[i] = Math.floor(Math.random() * 256);
      }},
      writable: true,
      configurable: true
    });
  }
  return loadModule('src/background.js', '__lensSW');
}

test('opt-in-storage: SW getOptIn returns nested shape on fresh install (no prior state)', async () => {
  resetMockChrome();
  const sw = loadSWWithMockChrome();
  const optIn = await sw.getOptIn();
  assert.equal(optIn.enabled, false, 'fresh install: enabled must be false');
  assert.equal(optIn.lastChangedAt, null, 'fresh install: lastChangedAt must be null');
  assert.equal(optIn.lensVersion, null, 'fresh install: lensVersion must be null');
});

test('opt-in-storage: SW setOptIn(true) writes the new nested shape', async () => {
  resetMockChrome();
  const sw = loadSWWithMockChrome();
  await sw.setOptIn(true);
  const optIn = await sw.getOptIn();
  assert.equal(optIn.enabled, true, 'after setOptIn(true): enabled must be true');
  assert.equal(typeof optIn.lastChangedAt, 'number', 'lastChangedAt must be a Unix timestamp');
  assert.equal(optIn.lensVersion, '0.1.1', 'lensVersion should be the constants.js version');
  // lastChangedAt should be within the last 5 seconds
  const now = Math.floor(Date.now() / 1000);
  assert.ok(now - optIn.lastChangedAt < 5, 'lastChangedAt should be recent');
});

test('opt-in-storage: SW setOptIn(false) writes the new nested shape', async () => {
  resetMockChrome();
  const sw = loadSWWithMockChrome();
  await sw.setOptIn(true);   // first opt in
  await sw.setOptIn(false);  // then opt out
  const optIn = await sw.getOptIn();
  assert.equal(optIn.enabled, false, 'after setOptIn(false): enabled must be false');
  assert.equal(typeof optIn.lastChangedAt, 'number', 'lastChangedAt must be a Unix timestamp');
});

test('opt-in-storage: SW accepts legacy bare boolean (v0.1.0-beta backwards-compat)', async () => {
  resetMockChrome();
  const sw = loadSWWithMockChrome();
  // Simulate a v0.1.0-beta install: write a bare boolean AFTER the
  // mock chrome is installed (so resetMockChrome doesn't wipe it).
  const key = getCanonicalOptInKey();
  await new Promise(function (resolve) {
    globalThis.chrome.storage.local.set({ [key]: true }, function () { resolve(); });
  });
  const optIn = await sw.getOptIn();
  assert.equal(optIn.enabled, true, 'legacy bare boolean true must be read as enabled');
  assert.equal(optIn.lastChangedAt, null, 'legacy boolean has no lastChangedAt');
  assert.equal(optIn.lensVersion, null, 'legacy boolean has no lensVersion');
});

test('opt-in-storage: SW accepts welcome.js nested-object shape', async () => {
  resetMockChrome();
  const sw = loadSWWithMockChrome();
  // Simulate a welcome.js write AFTER the mock chrome is installed
  const key = getCanonicalOptInKey();
  const welcomeShape = {
    enabled: true,
    last_changed_at: 1234567890,
    lens_version: '0.1.0-beta'
  };
  await new Promise(function (resolve) {
    globalThis.chrome.storage.local.set({ [key]: welcomeShape }, function () { resolve(); });
  });
  const optIn = await sw.getOptIn();
  assert.equal(optIn.enabled, true);
  assert.equal(optIn.lastChangedAt, 1234567890);
  assert.equal(optIn.lensVersion, '0.1.0-beta');
});

test('opt-in-storage: handleGetOptInState returns unified payload', async () => {
  resetMockChrome();
  const sw = loadSWWithMockChrome();
  await sw.setOptIn(true);
  // Call the SW message handler
  const msg = { type: 'GET_OPT_IN_STATE', version: '0.1.0-beta', payload: {} };
  const response = await new Promise(function (resolve) {
    sw.handleGetOptInState(msg, {}, function (resp) { resolve(resp); });
  });
  assert.equal(response.type, 'OPT_IN_STATE');
  assert.equal(response.payload.enabled, true);
  assert.equal(response.payload.opted_in, true, 'backwards-compat: opted_in is the boolean alias');
  assert.equal(typeof response.payload.last_changed_at, 'number');
  assert.equal(typeof response.payload.lens_version, 'string');
});
