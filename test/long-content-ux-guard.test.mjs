#!/usr/bin/node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Long-Content UX Guard Test (Phase 1.2 / Day 30)
//
// Verifies the long-content UX guard implemented in src/content.js:
//
//   - Prompt text >= LONG_CONTENT_THRESHOLD_CHARS (2000) and ML fires:
//       * Detection category is prompt_injection_ml_long or _transformer_long
//       * Detection severity is 'medium' (not 'high')
//
//   - Prompt text < LONG_CONTENT_THRESHOLD_CHARS and ML fires:
//       * Detection category is prompt_injection_ml or _transformer
//       * Detection severity is 'high'
//
//   - Boundary: text length exactly 2000 chars is treated as
//     short-content (text.length >= 2000 is the threshold, but
//     2000 itself is NOT >= 2000; only 2001+).
//
// This test runs src/content.js in a node:vm sandbox with a minimal
// DOM stub (no real Chrome APIs needed for the handleMLDetection path).
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
    textContent: '',
    value: '',
    setAttribute() {},
    getAttribute() { return null; },
    addEventListener() {},
    removeEventListener() {},
    appendChild() {},
    removeChild() {},
    firstChild: null,
    parentNode: null,
    contains() { return false; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    insertBefore() {},
    set className(v) {},
  };
}

const noopFn = () => {};
const noopDoc = {
  createElement: makeElement,
  body: makeElement(),
  documentElement: makeElement(),
  addEventListener: noopFn,
  removeEventListener: noopFn,
};

// ----- Sandbox setup --------------------------------------------------------

// Read the source FIRST so we can define HTMLTextAreaElement before eval.
const scriptText = await fsp.readFile(
  path.join(repoRoot, 'src/content.js'), 'utf8');

// The script does `el instanceof HTMLTextAreaElement` and `instanceof
// HTMLElement` (via `el instanceof HTMLElement`). Both must be defined in
// the sandbox BEFORE the script runs.
class StubHTMLElement {}
class StubHTMLTextAreaElement extends StubHTMLElement {}

const sandbox = {
  window: {},
  self: {},
  document: noopDoc,
  console,
  setTimeout,
  clearTimeout,
  Date,
  Object,
  Array,
  Math,
  JSON,
  String,
  Number,
  Boolean,
  Promise,
  Error,
  Map,
  Set,
  HTMLElement: StubHTMLElement,
  HTMLTextAreaElement: StubHTMLTextAreaElement,
  // Stub for chrome.* APIs used by ContentScript internals
  chrome: {
    runtime: {
      getURL: (p) => 'chrome-extension://abc/' + p,
      getManifest: () => ({ version: '0.2.2' }),
      onMessage: { addListener: noopFn },
      sendMessage: () => {},
    },
    storage: {
      local: { get: noopFn, set: noopFn },
      sync: { get: noopFn, set: noopFn },
    },
  },
};
sandbox.window.AegisGateLens = sandbox.window.AegisGateLens || {};
sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};
sandbox.window.HTMLElement = StubHTMLElement;
sandbox.window.HTMLTextAreaElement = StubHTMLTextAreaElement;
sandbox.self.HTMLElement = StubHTMLElement;
sandbox.self.HTMLTextAreaElement = StubHTMLTextAreaElement;
sandbox.window = sandbox.window;
sandbox.self = sandbox.self;
vm.createContext(sandbox);
vm.runInContext(scriptText, sandbox);

const CS = sandbox.window.AegisGateLens.ContentScript;
assert(CS, 'ContentScript should be exposed on AegisGateLens namespace');

// ----- Helpers --------------------------------------------------------------

function makeScript(textLen) {
  const cs = Object.create(CS.prototype);
  cs.currentDetections = [];
  cs.banner = null;
  cs.provider = { promptSelector: '#x', name: 'test' };
  cs.isDismissed = () => false;
  cs.recordAction = () => {};
  cs.hideBanner = () => {};
  cs.showBanner = function (detections) {
    this.shownBannerDetections = detections;
  };
  return cs;
}

const LONG_THRESHOLD = 2000;
const SHORT_TEXT = 'Short prompt that is well under the long-content threshold.';
const LONG_TEXT = 'a'.repeat(LONG_THRESHOLD + 100);

function callHandleMLDetection(cs, text, pattern) {
  const captured = [];
  const origShow = cs.showBanner;
  cs.showBanner = function (dets) { captured.push(dets); };

  // Patch document.querySelector to return a stub element that passes
  // the `el instanceof HTMLTextAreaElement` check in readPromptText.
  const stubEl = makeElement();
  stubEl.value = text;
  stubEl.textContent = text;
  stubEl.isContentEditable = false;
  Object.setPrototypeOf(stubEl, StubHTMLTextAreaElement.prototype);
  noopDoc.querySelector = () => stubEl;

  cs.handleMLDetection(text, { score: 0.91, threshold: 0.5 }, pattern,
                        [0.92, 0.88, 0.91, 0.93, 0.90]);
  cs.showBanner = origShow;
  return captured[0] ? captured[0][0] : null;
}

// ----- Test runner ---------------------------------------------------------

let _pass = 0;
let _fail = 0;
async function test(name, fn) {
  try {
    await fn();
    _pass++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    _fail++;
    console.error(`  FAIL  ${name}`);
    console.error('   ', err.message);
  }
}

// ----- Tests ---------------------------------------------------------------

await test('short prompt + Tier 2 -> prompt_injection_ml with high severity', () => {
  const cs = makeScript(SHORT_TEXT.length);
  const det = callHandleMLDetection(cs, SHORT_TEXT, 'ml_5way_ensemble');
  assert(det, 'detection should be created');
  assert.equal(det.category, 'prompt_injection_ml');
  assert.equal(det.severity, 'high');
});

await test('long prompt + Tier 2 -> prompt_injection_ml_long with medium severity', () => {
  const cs = makeScript(LONG_TEXT.length);
  const det = callHandleMLDetection(cs, LONG_TEXT, 'ml_5way_ensemble');
  assert(det, 'detection should be created');
  assert.equal(det.category, 'prompt_injection_ml_long');
  assert.equal(det.severity, 'medium');
});

await test('short prompt + Tier 3 -> prompt_injection_transformer high', () => {
  const cs = makeScript(SHORT_TEXT.length);
  const det = callHandleMLDetection(cs, SHORT_TEXT, 'transformer_minilm');
  assert(det);
  assert.equal(det.category, 'prompt_injection_transformer');
  assert.equal(det.severity, 'high');
});

await test('long prompt + Tier 3 -> prompt_injection_transformer_long medium', () => {
  const cs = makeScript(LONG_TEXT.length);
  const det = callHandleMLDetection(cs, LONG_TEXT, 'transformer_minilm');
  assert(det);
  assert.equal(det.category, 'prompt_injection_transformer_long');
  assert.equal(det.severity, 'medium');
});

await test('boundary: text length exactly 2000 -> long-content (inclusive boundary)', () => {
  const cs = makeScript(LONG_THRESHOLD);
  const text2000 = 'x'.repeat(LONG_THRESHOLD);
  const det = callHandleMLDetection(cs, text2000, 'ml_5way_ensemble');
  // text.length >= 2000 is TRUE when length == 2000 (inclusive).
  assert.equal(det.category, 'prompt_injection_ml_long',
    'at exactly 2000 chars, inclusive boundary: text.length >= 2000 is TRUE');
});

await test('boundary: text length 1999 -> short-content', () => {
  const cs = makeScript(LONG_THRESHOLD - 1);
  const text1999 = 'x'.repeat(LONG_THRESHOLD - 1);
  const det = callHandleMLDetection(cs, text1999, 'ml_5way_ensemble');
  assert.equal(det.category, 'prompt_injection_ml',
    'at 1999 chars, one below threshold, should be short-content');
});

if (_fail > 0) {
  console.error(`\nFAILED: ${_fail}/${_pass + _fail}`);
  process.exit(1);
}
console.log(`\nPASSED: ${_pass}/${_pass + _fail} long-content-ux-guard tests`);
