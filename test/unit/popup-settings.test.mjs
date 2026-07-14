// AegisGate Lens — test/unit/popup-settings.test.mjs
// v0.1.4: tests for the popup "Hide Lens active indicator" toggle
// (readShowIndicator / setShowIndicator / bindShowIndicator).
//
// The popup uses chrome.storage.local directly (not via the SW
// message round-trip) for the indicator toggle because the toggle
// is high-frequency (every popup open + every checkbox change).
// The chrome.storage.onChanged event in the content script picks
// up the change in real-time.
//
// These tests verify source-level invariants (storage key match,
// default-ON behavior, defensive guards, wiring into onLoad) since
// the existing popup-message test suite already covers the runtime
// readOptIn flow.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

function read(rel) { return readFileSync(join(LENS_ROOT, rel), 'utf8'); }

const SRC = read('src/popup/popup.js');
const HTML = read('src/popup/popup.html');
const CONST = read('src/util/constants.js');

test('storage key matches constants.STORAGE_KEYS.SHOW_INDICATOR', () => {
  // The popup uses a fallback literal when constants is unavailable.
  // Verify the canonical key in constants.js matches what the popup uses.
  const canonical = CONST.match(/SHOW_INDICATOR:\s*'([^']+)'/)?.[1];
  assert.ok(canonical, 'constants.STORAGE_KEYS.SHOW_INDICATOR must be defined');
  assert.match(
    SRC,
    new RegExp("'" + canonical.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + "'"),
    'popup.js must reference the canonical storage key'
  );
});

// Helper: find the source of function F within popup.js (up to the
// next function definition, or the end of the IIFE). Functions are
// defined in order: getShowIndicatorStorageKey, readShowIndicator,
// setShowIndicator, applyShowIndicatorToUI, bindShowIndicator.
// Note: setShowIndicator takes a (value) argument; the others are ().
const FN_SIGS = [
  /function getShowIndicatorStorageKey\(\) \{/,
  /function readShowIndicator\(\) \{/,
  /function setShowIndicator\(value\) \{/,
  /function applyShowIndicatorToUI\(value\) \{/,
  /function bindShowIndicator\(\) \{/,
];
function fnSrc(name) {
  // Fix: use indexOf on the name list, not findIndex with .test()
  // (the regex expects a literal '()' or '(value)' which .test()
  // never matches against 'function name' alone).
  const FN_NAMES = [
    'getShowIndicatorStorageKey',
    'readShowIndicator',
    'setShowIndicator',
    'applyShowIndicatorToUI',
    'bindShowIndicator',
  ];
  const idx = FN_NAMES.indexOf(name);
  if (idx < 0) return '';
  const startMatch = SRC.match(FN_SIGS[idx]);
  if (!startMatch || startMatch.index === undefined) return '';
  const start = startMatch.index + startMatch[0].length;
  // End at the next function definition, or the IIFE close.
  const endRe = idx + 1 < FN_SIGS.length ? FN_SIGS[idx + 1] : /if \(document\.readyState === 'loading'\)/;
  const tail = SRC.substring(start);
  const endMatch = tail.match(endRe);
  const end = endMatch && endMatch.index !== undefined ? endMatch.index : tail.length;
  return tail.substring(0, end);
}

test('readShowIndicator defaults to true on missing key (no behavior change)', () => {
  // The function should return { showIndicator: true } when:
  //   - chrome is undefined
  //   - chrome.storage is undefined
  //   - chrome.storage.local is undefined
  //   - the result doesn't have the key
  // The pattern: `result[k] !== false` is the check, with fallback
  // to true on any error.
  const src = fnSrc('readShowIndicator');
  assert.ok(src.includes('showIndicator: true'), 'readShowIndicator must have a true fallback');
  assert.ok(src.includes("result[k] !== false"), 'readShowIndicator must default to true when value is not strictly false');
});

test('setShowIndicator persists via chrome.storage.local.set', () => {
  const src = fnSrc('setShowIndicator');
  // The code uses a local `cr` variable (getChrome()). Match the
  // local-variable form, not the fully-qualified form.
  assert.ok(src.includes('.storage.local.set'), 'setShowIndicator must use chrome.storage.local.set');
  // The function should use the canonical key (via getShowIndicatorStorageKey)
  // or the literal fallback. Either form is acceptable.
  const usesCanonicalKey = src.includes("getShowIndicatorStorageKey()") ||
                            src.includes("aegisgate_lens_show_indicator");
  assert.ok(usesCanonicalKey, 'setShowIndicator must reference the canonical key (via getShowIndicatorStorageKey or the literal fallback)');
});

test('bindShowIndicator rolls back UI on persistence failure', () => {
  // The bindShowIndicator callback handler should call
  // applyShowIndicatorToUI(!desired) on persist failure so the
  // displayed state matches the persisted state.
  const src = fnSrc('bindShowIndicator');
  assert.ok(
    src.includes('applyShowIndicatorToUI(!desired)'),
    'bindShowIndicator should rollback UI on persist failure'
  );
});

test('bindShowIndicator has a defensive addEventListener guard (test-shim compatible)', () => {
  // The test shim returns a mock element WITHOUT addEventListener.
  // bindShowIndicator must guard against that. We verify the guard
  // exists so the existing popup-message.test.mjs test shim still works.
  const src = fnSrc('bindShowIndicator');
  assert.ok(
    src.includes("typeof cb.addEventListener === 'function'"),
    'bindShowIndicator should check typeof cb.addEventListener before calling'
  );
});

test('bindShowIndicator has exactly one cb.addEventListener( call (regression guard)', () => {
  // Prevent duplicate listeners. We count only the actual call
  // (with the opening paren), not the typeof guard that mentions
  // the same name.
  const src = fnSrc('bindShowIndicator');
  const calls = src.match(/cb\.addEventListener\(/g) || [];
  assert.equal(calls.length, 1, `bindShowIndicator should call cb.addEventListener( exactly once, found ${calls.length}`);
});

test('bindShowIndicator is wired into the popup onLoad', () => {
  // onLoad must call bindShowIndicator() so the checkbox is hydrated
  // and the change listener is attached.
  const onLoadMatch = SRC.match(/function onLoad\(\) \{[\s\S]*?\n  \}/)?.[0] || '';
  assert.ok(
    onLoadMatch.includes('bindShowIndicator()'),
    'onLoad must call bindShowIndicator() to wire the toggle'
  );
});

test('popup.html default is show indicator (no behavior change for existing users)', () => {
  // The popup's HTML has the checkbox with `checked` attribute.
  // Default ON = no behavior change for existing users.
  assert.match(
    HTML,
    /id="show-indicator-toggle"[^>]*checked/,
    'checkbox should default to checked (show indicator)'
  );
});

test('popup.html has a clear, accessible label', () => {
  // The label text is what the user sees. Verify it explains the
  // toggle in plain language.
  assert.match(
    HTML,
    /Show "Lens active" indicator on chat pages/,
    'label should be clear and descriptive'
  );
  assert.match(
    HTML,
    /<label for="show-indicator-toggle"/,
    'checkbox should be inside a <label for="..."> for accessibility'
  );
});

test('popup.html has help text explaining what the toggle does', () => {
  // The setting-help text should clarify that detection still works
  // even when the indicator is hidden (otherwise users will think
  // turning it off disables the whole extension).
  assert.match(
    HTML,
    /Detection still works/i,
    'help text should clarify that detection still works'
  );
});
