// AegisGate Lens — test/unit/selectors-prompt-detect.test.mjs
// Unit tests for the selectors and prompt-detect modules.
//
// These tests run in Node with a minimal DOM mock (we mock
// document, window, MutationObserver) so we can exercise the
// selector matching and the attach/detach logic without
// needing a real browser.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// Minimal DOM mock. We implement just enough to exercise the
// selector logic. This is NOT a full jsdom — it's a test harness.
class MockElement {
  constructor(tag, attrs = {}, text = '') {
    this.tagName = tag.toUpperCase();
    this.attrs = attrs;
    this.children = [];
    this.parent = null;
    this._text = text;
    this._innerText = text;
    this._value = attrs.value || '';
    this._contentEditable = attrs.contenteditable || null;
    this.style = {};
    this.classList = {
      add: () => {},
      remove: () => {},
      contains: () => false
    };
    this.eventListeners = {};
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k] || null; }
  isContentEditable = false;
  addEventListener(type, fn, capture) {
    this.eventListeners[type] = (this.eventListeners[type] || []).concat([fn]);
  }
  removeEventListener(type, fn, capture) {
    if (!this.eventListeners[type]) return;
    this.eventListeners[type] = this.eventListeners[type].filter(f => f !== fn);
  }
  dispatchEvent(e) { /* noop */ }
  querySelectorAll(sel) { return globalThis.__mockQuerySelectorAll(sel, this); }
  querySelector(sel) {
    var r = this.querySelectorAll(sel);
    return r.length > 0 ? r[0] : null;
  }
  getBoundingClientRect() { return { width: 200, height: 50, top: 0, left: 0 }; }
  get innerText() { return this._innerText; }
  set innerText(v) { this._innerText = v; }
  get textContent() { return this._text; }
  get value() { return this._value; }
  set value(v) { this._value = v; }
  get contenteditable() { return this._contentEditable; }
  set contenteditable(v) { this._contentEditable = v; }
}

// The mock global document/window
class MockDocument {
  constructor() {
    this._elements = new Map();  // id -> element
    this.body = new MockElement('body');
  }
  getElementById(id) { return this._elements.get(id) || null; }
  querySelectorAll(sel) { return globalThis.__mockQuerySelectorAll(sel, this.body); }
  querySelector(sel) {
    var r = this.querySelectorAll(sel);
    return r.length > 0 ? r[0] : null;
  }
  get readyState() { return 'complete'; }
  addEventListener(type, fn) { /* noop */ }
  createElement(tag) { return new MockElement(tag); }
}

// Simple CSS selector matcher: supports tag, #id, .class, [attr=val]
function matchSelector(element, sel) {
  // Strip leading/trailing whitespace
  sel = sel.trim();
  // Comma-separated selectors
  if (sel.includes(',')) {
    return sel.split(',').some(s => matchSelector(element, s.trim()));
  }
  // Simple cases
  if (sel.startsWith('#')) {
    return element.attrs.id === sel.substring(1);
  }
  if (sel.startsWith('.')) {
    return (element.attrs.class || '').split(/\s+/).includes(sel.substring(1));
  }
  // attribute selector [attr=val] or [attr*="val"]
  if (sel.startsWith('[')) {
    var m = sel.match(/^\[([\w-]+)(?:([\*\^\$~\|]?=)"?([^"\]]+)"?)?\]$/);
    if (!m) return false;
    var attr = m[1];
    var op = m[2];
    var val = m[3];
    var actual = element.attrs[attr];
    if (!actual) return false;
    if (!op) return true;
    if (op === '=') return actual === val;
    if (op === '*=') return actual.toLowerCase().includes(val.toLowerCase().replace(/^"|"$/g, ''));
    return false;
  }
  // Tag selector
  return element.tagName === sel.toUpperCase();
}

// Mock querySelectorAll: walk the tree, return matching elements
globalThis.__mockQuerySelectorAll = function(sel, root) {
  var results = [];
  function walk(el) {
    // Split selector into parts (tag + attributes)
    var parts = sel.split(/\s+/);
    // For simple selectors, check each part
    // We only support flat (no descendant combinator) for now
    // since the test only uses simple selectors
    if (matchSelector(el, sel)) results.push(el);
    if (el.children) {
      for (var c of el.children) walk(c);
    }
  }
  walk(root);
  return results;
};

globalThis.window = {
  location: { hostname: 'chat.openai.com' },
  HTMLTextAreaElement: { prototype: { value: { set: function(v) { this._value = v; } } } }
};
globalThis.document = new MockDocument();
globalThis.MutationObserver = class {
  constructor(cb) { this.cb = cb; this.observing = false; }
  observe(target, opts) { this.observing = true; this.target = target; this.opts = opts; }
  disconnect() { this.observing = false; }
};
globalThis.setTimeout = setTimeout;
globalThis.clearTimeout = clearTimeout;
globalThis.Event = class { constructor(type, init) { this.type = type; Object.assign(this, init); } };

function loadModule(relPath, globalKey) {
  const src = readFileSync(join(LENS_ROOT, relPath), 'utf8');
  // Wrap so 'this' is globalThis
  var wrapped = '(function() { ' + src + ' })()';
  (0, eval)(wrapped);
  return globalThis[globalKey];
}

// --- Tests for selectors.js ---

test('selectors: 8 providers configured', () => {
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  assert.equal(sels.PROVIDERS.length, 8, 'expected 8 providers, got ' + sels.PROVIDERS.length);
});

test('selectors: each provider has required fields', () => {
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  for (const p of sels.PROVIDERS) {
    assert.ok(p.id, 'provider missing id: ' + JSON.stringify(p));
    assert.ok(p.name, 'provider missing name: ' + p.id);
    assert.ok(Array.isArray(p.hosts) && p.hosts.length > 0, 'provider missing hosts: ' + p.id);
    assert.ok(p.inputSelector, 'provider missing inputSelector: ' + p.id);
    assert.ok(p.sendSelector, 'provider missing sendSelector: ' + p.id);
    assert.ok(p.containerSelector, 'provider missing containerSelector: ' + p.id);
    assert.ok(['enter', 'click'].includes(p.submitMethod), 'invalid submitMethod: ' + p.id);
    assert.equal(typeof p.isContentEditable, 'boolean');
  }
});

test('selectors: identifyProvider matches chat.openai.com to chatgpt', () => {
  // Reset window.location
  globalThis.window = { location: { hostname: 'chat.openai.com' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should identify provider for chat.openai.com');
  assert.equal(p.id, 'chatgpt');
});

test('selectors: identifyProvider matches claude.ai to claude', () => {
  globalThis.window = { location: { hostname: 'claude.ai' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should identify provider for claude.ai');
  assert.equal(p.id, 'claude');
});

test('selectors: identifyProvider matches gemini.google.com to gemini', () => {
  globalThis.window = { location: { hostname: 'gemini.google.com' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should identify provider for gemini.google.com');
  assert.equal(p.id, 'gemini');
});

test('selectors: identifyProvider matches duck.ai to duck_ai', () => {
  globalThis.window = { location: { hostname: 'duck.ai' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should identify provider for duck.ai');
  assert.equal(p.id, 'duck_ai');
});

test('selectors: identifyProvider matches x.com to grok', () => {
  globalThis.window = { location: { hostname: 'x.com' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should identify provider for x.com');
  assert.equal(p.id, 'grok');
});

test('selectors: identifyProvider returns null for unknown', () => {
  globalThis.window = { location: { hostname: 'example.com' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.equal(p, null);
});

test('selectors: identifyProvider matches subdomain', () => {
  globalThis.window = { location: { hostname: 'www.perplexity.ai' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should match subdomain');
  assert.equal(p.id, 'perplexity');
});

test('selectors: identifyProvider matches case-insensitively', () => {
  globalThis.window = { location: { hostname: 'CHAT.OPENAI.COM' } };
  const sels = loadModule('src/util/selectors.js', '__lensSelectors');
  const p = sels.identifyProvider();
  assert.ok(p, 'should match case-insensitively');
  assert.equal(p.id, 'chatgpt');
});

// --- Tests for prompt-detect.js ---

// Mock the dispatcher dependencies before loading prompt-detect.
// We load EVERY detector so the dispatcher has all 4 facets.
function loadWithDeps() {
  // Reset globals
  globalThis.window = { location: { hostname: 'chat.openai.com' } };
  globalThis.document = new MockDocument();

  // Load deps (order matters: facets first, then schema, then dispatcher)
  loadModule('src/util/logger.js', '__lensLogger');
  loadModule('src/detectors/luhn.js', '__lensLuhn');
  // Load the 4 PII sub-files FIRST, then pii.js (the aggregator).
  loadModule('src/detectors/regex/pii-us-core.js',          '__lensPII_us_core');
  loadModule('src/detectors/regex/pii-us-extended.js',      '__lensPII_us_extended');
  loadModule('src/detectors/regex/pii-international-id.js', '__lensPII_international_id');
  loadModule('src/detectors/regex/pii-financial.js',        '__lensPII_financial');
  loadModule('src/detectors/regex/pii.js', '__lensPII');
  loadModule('src/detectors/regex/secrets.js', '__lensSecrets');
  loadModule('src/detectors/regex/source_xss.js', '__lensXSS');
  loadModule('src/detectors/regex/compliance.js', '__lensCompliance');
  loadModule('src/privacy/schema.js', '__lensSchema');
  loadModule('src/detectors/index.js', '__lensDispatcher');
  loadModule('src/util/selectors.js', '__lensSelectors');

  // Load the 2 prompt-detect sub-files FIRST, then the aggregator.
  // This mirrors the production content_scripts.js load order in manifest.json.
  loadModule('src/util/prompt-detect-dom.js',       '__lensPromptDetect_dom');
  loadModule('src/util/prompt-detect-lifecycle.js', '__lensPromptDetect_lifecycle');

  // Now load prompt-detect
  return loadModule('src/util/prompt-detect.js', '__lensPromptDetect');
}

test('prompt-detect: init identifies provider and attaches', () => {
  const pd = loadWithDeps();
  // Create a mock input element and add it to body
  var input = new MockElement('textarea', { placeholder: 'Ask anything...' });
  globalThis.document.body.children.push(input);
  // Find the chatgpt provider
  var sels = globalThis.__lensSelectors;
  var provider = sels.identifyProvider();
  assert.ok(provider);
  assert.equal(provider.id, 'chatgpt');

  var initOk = pd.init({ onDetect: () => {}, onSendIntercept: () => ({action:'cancel'}) });
  // init returns true even if input not found (it will retry on mutation)
  assert.equal(initOk, true);
  pd.shutdown();
});

test('prompt-detect: getState returns expected fields', () => {
  const pd = loadWithDeps();
  pd.init({});
  var st = pd.getState();
  assert.equal(st.provider, 'chatgpt');
  assert.equal(st.hasInput, false);  // no input in body
  assert.equal(st.inputAttached, false);
  pd.shutdown();
});

test('prompt-detect: shutdown is idempotent', () => {
  const pd = loadWithDeps();
  pd.init({});
  pd.shutdown();
  // Second shutdown should not throw
  pd.shutdown();
  var st = pd.getState();
  assert.equal(st.provider, null);
});

test('prompt-detect: detectPrompt delegates to dispatcher', () => {
  const pd = loadWithDeps();
  var result = pd.detectPrompt('My SSN is 123-45-6789');
  assert.ok(Array.isArray(result), 'detectPrompt should return an array');
  assert.ok(result.length > 0, 'expected at least one event');
  // The dispatcher returns events with facet + category + severity
  var first = result[0];
  assert.equal(typeof first.facet, 'string');
  assert.equal(first.facet, 'pii');
  assert.equal(first.category, 'pii_ssn');
  assert.equal(first.severity, 'critical');
});

test('prompt-detect: detectPrompt returns empty for benign', () => {
  const pd = loadWithDeps();
  var result = pd.detectPrompt('What is the capital of France?');
  assert.equal(result.length, 0);
});

test('prompt-detect: identifyProvider on wrong hostname', () => {
  // loadWithDeps() forces chat.openai.com; to test a wrong hostname
  // we load with chat.openai.com, then change window.location, then
  // call init() which reads window.location at call time.
  const pd = loadWithDeps();
  globalThis.window = { location: { hostname: 'example.com' } };
  var initOk = pd.init({});
  assert.equal(initOk, false, 'init should fail when no provider matches');
});
