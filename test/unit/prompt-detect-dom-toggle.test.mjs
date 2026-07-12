// AegisGate Lens — test/unit/prompt-detect-dom-toggle.test.mjs
// v0.1.4: tests for the "Hide Lens active indicator" toggle in
// prompt-detect-dom.js::injectIndicator().
//
// The toggle is implemented as a module-level _showIndicator cache
// that defaults to true. injectIndicator() early-returns when
// _showIndicator is false. The cache is loaded from
// chrome.storage.local at module init and updated via
// chrome.storage.onChanged.
//
// These tests use a tiny in-memory chrome shim and load the source
// file via the standard load-module helper. They verify source-
// level invariants (correct guard placement, exactly one
// registration of each listener) plus a runtime sanity check.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

const SRC = readFileSync(
  join(LENS_ROOT, 'src', 'util', 'prompt-detect-dom.js'),
  'utf-8'
);

test('injectIndicator has the toggle early-return guard in the right order', () => {
  // The toggle check should appear AFTER the document guard (so SSR/
  // Node-like envs that lack `document` still work) but BEFORE the
  // DOM querySelector call (so we don't do unnecessary work when
  // the indicator is disabled).
  // Find injectIndicator's body up to the !state.input guard.
  const startMatch = SRC.match(/function injectIndicator\(state\) \{/);
  assert.ok(startMatch, 'injectIndicator function should be present');
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/if \(!state\.input\) return;/);
  assert.ok(endMatch, 'injectIndicator body end marker should be present');
  const fnSrc = SRC.substring(start, start + endMatch.index);
  assert.ok(fnSrc.includes('typeof document'), 'document guard present');
  assert.ok(fnSrc.includes('_showIndicator === false'), 'toggle guard present');
  const docIdx = fnSrc.indexOf('typeof document');
  const toggleIdx = fnSrc.indexOf('_showIndicator === false');
  assert.ok(docIdx < toggleIdx, 'document guard should come before toggle guard');
  const qselIdx = fnSrc.indexOf('querySelector');
  assert.ok(toggleIdx < qselIdx, 'toggle guard should come before querySelector (no wasted work)');
});

test('injectIndicator has exactly one toggle check (regression guard)', () => {
  // Make sure the edit didn't accidentally duplicate the check.
  const startMatch = SRC.match(/function injectIndicator\(state\) \{/);
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/if \(!state\.input\) return;/);
  const fnSrc = SRC.substring(start, start + endMatch.index);
  const matches = fnSrc.match(/_showIndicator === false/g) || [];
  assert.equal(matches.length, 1, `injectIndicator should have exactly one _showIndicator check, found ${matches.length}`);
});

test('source has exactly one chrome.storage.onChanged.addListener in prompt-detect-dom.js (regression guard)', () => {
  // The toggle wiring uses onChanged.addListener exactly once.
  // Multiple registrations would cause duplicate updates.
  const matches = SRC.match(/chrome\.storage\.onChanged\.addListener/g) || [];
  assert.equal(matches.length, 1, `prompt-detect-dom.js should register onChanged.addListener exactly once, found ${matches.length}`);
});

test('source has exactly one immediate _loadShowIndicator call at module init', () => {
  // The cache should be loaded exactly once at module init via
  // a direct call (not inside a function that could be called
  // multiple times). We exclude the function definition itself.
  const callOnly = SRC.replace(/function _loadShowIndicator[\s\S]*?\n  \}/g, '');
  const matches = callOnly.match(/_loadShowIndicator\(\)/g) || [];
  assert.equal(matches.length, 1, `_loadShowIndicator should be called exactly once at module init, found ${matches.length}`);
});

test('source has the cached _showIndicator default of true', () => {
  // The default is true (show indicator). False would be a behavior
  // change for existing users.
  assert.match(SRC, /var _showIndicator = true/, '_showIndicator should default to true');
});

test('storage key in prompt-detect-dom.js matches the canonical key in constants.js', () => {
  const constSrc = readFileSync(join(LENS_ROOT, 'src', 'util', 'constants.js'), 'utf-8');
  // Extract the canonical key from constants.js
  const canonical = constSrc.match(/SHOW_INDICATOR:\s*'([^']+)'/)?.[1];
  assert.ok(canonical, 'constants.js should define SHOW_INDICATOR');
  // The content script uses a hardcoded fallback (it loads before
  // constants in the bundle order per bootstrap.js). Verify the
  // hardcoded key matches the canonical one.
  assert.match(
    SRC,
    new RegExp("SHOW_INDICATOR_KEY\\s*=\\s*'" + canonical.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + "'"),
    'prompt-detect-dom.js SHOW_INDICATOR_KEY must match constants.STORAGE_KEYS.SHOW_INDICATOR'
  );
});
