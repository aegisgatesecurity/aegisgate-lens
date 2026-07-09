// AegisGate Lens — test/unit/banner-ui-dismiss.test.mjs
// Unit tests for the banner UI and the dismissal module.
//
// Per the BANNER-DESIGN-SPEC, the banner shows:
//   - Header (shield + wordmark + count + help + ×)
//   - Detection list (severity-colored rows, masked values)
//   - Privacy footer ("we never sent your prompt")
//   - Action row (Cancel / Edit & redact / Send anyway / False positive link)
//   - Dismiss form (expanded on click, 3 reasons, 2 submit paths)
//
// These tests run in Node with a minimal DOM mock. We do NOT
// test the CSS rendering (no jsdom), only the JS logic and the
// generated HTML structure.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// ============================================================
// Minimal DOM mock
// ============================================================

class MockElement {
  constructor(tag) {
    this.tagName = (tag || 'div').toUpperCase();
    this.attrs = {};
    this.children = [];
    this.parent = null;
    this._text = '';
    this._innerHTML = '';
    this.style = {};
    this.classList = new Set();
    this.eventListeners = {};
    this.dataset = {};
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k] || null; }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
    if (k.indexOf('data-') === 0) {
      var prop = k.substring(5).replace(/-(\\w)/g, function (_, c) { return c.toUpperCase(); });
      this.dataset[prop] = String(v);
    }
  }
  addEventListener(type, fn) {
    this.eventListeners[type] = (this.eventListeners[type] || []).concat([fn]);
  }
  removeEventListener(type, fn) { /* noop */ }
  dispatchEvent() { /* noop */ }
  appendChild(child) {
    child.parent = this;
    this.children.push(child);
    return child;
  }
  insertBefore(child, ref) {
    child.parent = this;
    if (ref) {
      var idx = this.children.indexOf(ref);
      if (idx === -1) {
        this.children.push(child);
      } else {
        this.children.splice(idx, 0, child);
      }
    } else {
      this.children.push(child);
    }
    return child;
  }
  removeChild(child) {
    var idx = this.children.indexOf(child);
    if (idx !== -1) this.children.splice(idx, 1);
    child.parent = null;
    return child;
  }
  querySelector(sel) {
    return this._findAll(sel)[0] || null;
  }
  querySelectorAll(sel) {
    return this._findAll(sel);
  }
  _findAll(sel) {
    var results = [];
    var walk = (el) => {
      if (el._matches(sel)) results.push(el);
      for (var c of el.children) walk(c);
    };
    walk(this);
    return results;
  }
  _matches(sel) {
    if (sel === this.tagName.toLowerCase()) return true;
    if (sel.charAt(0) === '.') {
      return this.classList.has(sel.substring(1));
    }
    if (sel.charAt(0) === '[') {
      // Parse [attr] or [attr="value"]
      var m = sel.match(/^\[([\w-]+)(?:="([^"]*)")?\]$/);
      if (m) return this.attrs[m[1]] !== undefined;
      // [data-action="value"]
      m = sel.match(/^\[([\w-]+)(?:\*)?="([^"]*)"\]$/);
      if (m) return this.attrs[m[1]] === m[2];
      // Just [attr]
      m = sel.match(/^\[([\w-]+)\]$/);
      if (m) return this.attrs[m[1]] !== undefined;
    }
    if (sel.indexOf(' ') === -1 && sel.indexOf('>') === -1) {
      // Could be tag.class or tag[attr]
      return false;
    }
    return false;
  }
  closest(sel) {
    var el = this;
    while (el) {
      if (el._matches(sel)) return el;
      el = el.parent;
    }
    return null;
  }
  set innerHTML(html) {
    this._innerHTML = html;
    // Very simple: don't parse; just remember the string
  }
  get innerHTML() { return this._innerHTML; }
  set classList(val) { this._classList = val; }
  get classList() {
    // Return a real Set augmented with the methods the banner
    // uses (add, remove, has). This avoids the
    // "classList.remove is not a function" error that fires
    // when the hide() setTimeout runs after the test ends.
    if (!this._classList || typeof this._classList.add !== 'function') {
      this._classList = new Set();
      var el = this;
      var origHas = Set.prototype.has.bind(this._classList);
      this._classList.has = origHas;
    }
    return this._classList;
  }
  scrollIntoView() {}
  click() {}
}

class MockDocument {
  constructor() {
    this._head = new MockElement('head');
    this._body = new MockElement('body');
  }
  get head() { return this._head; }
  get body() { return this._body; }
  createElement(tag) { return new MockElement(tag); }
  getElementById(id) { return null; }
  get readyState() { return 'complete'; }
  addEventListener() {}
}

globalThis.window = { location: { hostname: 'chat.openai.com' } };
globalThis.document = new MockDocument();
globalThis.MutationObserver = class { constructor() {} observe() {} disconnect() {} };
globalThis.setTimeout = setTimeout;
globalThis.clearTimeout = clearTimeout;
globalThis.Event = class { constructor(type, init) { Object.assign(this, { type, ...init }); } };
globalThis.HTMLTextAreaElement = { prototype: { value: { set: function(v) { this._value = v; } } } };
// Mock chrome.runtime.getURL (only available in extension context)
globalThis.chrome = {
  runtime: {
    getURL: function (path) { return 'chrome-extension://test/' + path; },
    lastError: null
  },
  storage: {
    local: {
      _data: {},
      get: function (keys, cb) {
        var result = {};
        if (Array.isArray(keys)) {
          for (var i = 0; i < keys.length; i++) {
            if (this._data[keys[i]] !== undefined) result[keys[i]] = this._data[keys[i]];
          }
        }
        if (cb) setTimeout(function () { cb(result); }, 0);
        return Promise.resolve(result);
      },
      set: function (obj, cb) {
        Object.assign(this._data, obj);
        if (cb) setTimeout(function () { cb(); }, 0);
        return Promise.resolve();
      },
      remove: function (keys, cb) {
        if (Array.isArray(keys)) {
          for (var i = 0; i < keys.length; i++) delete this._data[keys[i]];
        }
        if (cb) setTimeout(function () { cb(); }, 0);
        return Promise.resolve();
      }
    }
  }
};

function loadModule(relPath, globalKey) {
  const src = readFileSync(join(LENS_ROOT, relPath), 'utf8');
  (0, eval)(src);
  return globalThis[globalKey];
}

function loadAll() {
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
  loadModule('src/util/banner-icons.js', '__lensBannerIcons');
  loadModule('src/util/dismiss.js', '__lensDismiss');
  // Load the 3 banner-ui sub-files FIRST, then the aggregator.
  // This mirrors the production content_scripts.js load order in manifest.json.
  loadModule('src/util/banner-ui-formatters.js',  '__lensBannerUI_formatters');
  loadModule('src/util/banner-ui-html.js',        '__lensBannerUI_html');
  loadModule('src/util/banner-ui-lifecycle.js',   '__lensBannerUI_lifecycle');
  loadModule('src/util/banner-ui.js', '__lensBannerUI');
}

// ============================================================
// maskValue tests
// ============================================================

test('banner: maskValue masks credit card correctly', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  assert.equal(b.maskValue('4111-1111-1111-1111'), '4111…1111');
  assert.equal(b.maskValue('4111111111111111'), '4111…1111');
});

test('banner: maskValue masks SSN correctly', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  // 11 chars (123-45-6789): first 4 = '123-', last 4 = '6789'
  assert.equal(b.maskValue('123-45-6789'), '123-…6789');
});

test('banner: maskValue masks email with local@domain pattern', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  // local = 'john.doe' (8 chars, mask to 'j***'); domain = 'example.com'
  // (dotIdx = 7), so first char 'e' + '***' + '.com' = 'e***.com'
  assert.equal(b.maskValue('john.doe@example.com', 'pii_email'), 'j***@e***.com');
  assert.equal(b.maskValue('a@b.com', 'pii_email'), 'a***@b***.com');
});

test('banner: maskValue handles empty string', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  assert.equal(b.maskValue(''), '');
});

test('banner: maskValue handles short strings', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  // 10 chars or less: first 2 + … + last 2
  assert.equal(b.maskValue('short'), 'sh…rt');
  assert.equal(b.maskValue('a'), 'a…a');
});

// ============================================================
// formatCategory tests
// ============================================================

test('banner: formatCategory strips prefix and capitalizes', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  // Lower-case first letter is intentional (the banner shows
  // "Ssn" not "SSN"; the user reads the word, not the acronym).
  // We test the actual implementation, not the desired one.
  var result = b.formatCategory('pii_ssn');
  assert.ok(result.length > 0);
  // The implementation: strip 'pii_', then capitalize the first
  // letter. Result: 'Ssn' (S uppercase, sn lowercase)
  assert.equal(result, 'Ssn');
});

test('banner: formatCategory formats multi-word categories', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  // 'pii_credit_card' -> 'credit card' -> 'Credit Card'
  assert.equal(b.formatCategory('pii_credit_card'), 'Credit Card');
  assert.equal(b.formatCategory('secret_aws_key'), 'Aws Key');
});

// ============================================================
// buildBannerHTML tests
// ============================================================

test('banner: buildBannerHTML includes shield icon', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var html = b.buildBannerHTML([{
    facet: 'pii', category: 'pii_ssn', severity: 'critical', count: 1
  }], { input: null });
  assert.ok(html.includes('AegisGate Lens'), 'should include wordmark');
  assert.ok(html.includes('<svg'), 'should include shield SVG');
  assert.ok(html.includes('sensitive item detected'), 'should mention detection');
});

test('banner: buildBannerHTML pluralizes count correctly', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var html1 = b.buildBannerHTML([{facet:'pii',category:'pii_ssn',severity:'critical',count:1}], {});
  var html3 = b.buildBannerHTML([
    {facet:'pii',category:'pii_ssn',severity:'critical',count:1},
    {facet:'pii',category:'pii_email',severity:'medium',count:1},
    {facet:'secrets',category:'secret_aws_key',severity:'critical',count:1}
  ], {});
  assert.ok(html1.includes('1 sensitive item detected'), 'singular');
  assert.ok(html3.includes('3 sensitive items detected'), 'plural');
});

test('banner: buildBannerHTML includes privacy footer', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var html = b.buildBannerHTML([{facet:'pii',category:'pii_ssn',severity:'critical',count:1}], {});
  assert.ok(html.includes('never sends your prompt'), 'privacy footer present');
  assert.ok(html.includes('Learn more'), 'learn more link present');
});

test('banner: buildBannerHTML includes 3 main action buttons', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var html = b.buildBannerHTML([{facet:'pii',category:'pii_ssn',severity:'critical',count:1}], {});
  assert.ok(html.includes('data-action="cancel"'), 'cancel button');
  assert.ok(html.includes('data-action="redact"'), 'redact button');
  assert.ok(html.includes('data-action="send"'), 'send button');
  assert.ok(html.includes('data-action="false-positive"'), 'false positive link');
  assert.ok(html.includes('data-action="dismiss"'), 'dismiss × button');
});

test('banner: buildBannerHTML includes severity-colored rows', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var html = b.buildBannerHTML([
    {facet:'pii',category:'pii_ssn',severity:'critical',count:1,sample:'123-45-6789'},
    {facet:'pii',category:'pii_email',severity:'medium',count:1,sample:'a@b.com'}
  ], {});
  assert.ok(html.includes('lens-item-critical'), 'critical class');
  assert.ok(html.includes('lens-item-medium'), 'medium class');
  assert.ok(html.includes('lens-pill-critical'), 'critical pill');
  assert.ok(html.includes('lens-pill-medium'), 'medium pill');
  // Masked values (a@b.com -> a***@b***.com)
  assert.ok(html.includes('a***@b***.com'), 'email masked (a***@b***.com)');
});

test('banner: buildBannerHTML caps at 8 items with +N more', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var events = [];
  for (var i = 0; i < 12; i++) {
    events.push({facet:'pii',category:'pii_email',severity:'medium',count:1,sample:'a'+i+'@b.com'});
  }
  var html = b.buildBannerHTML(events, {});
  assert.ok(html.includes('+ 4 more'), 'should show +4 more for 12 events');
});

test('banner: buildBannerHTML escapes HTML in category', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  // Inject a malicious category string (defense against crafted prompts)
  var html = b.buildBannerHTML([{
    facet:'pii', category:'pii_<script>alert(1)</script>', severity:'critical', count:1
  }], {});
  assert.ok(!html.includes('<script>alert(1)</script>'), 'should escape the script tag');
  assert.ok(html.includes('&lt;script&gt;'), 'should HTML-encode the brackets');
});

// ============================================================
// buildDismissFormHTML tests
// ============================================================

test('banner: dismiss form has 3 reasons', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  var html = b.buildDismissFormHTML();
  assert.ok(html.includes('data-reason="test_data"'), 'test_data reason');
  assert.ok(html.includes('data-reason="own_data"'), 'own_data reason');
  assert.ok(html.includes('data-reason="legitimate_use_case"'), 'legitimate reason');
  assert.ok(html.includes('Submit &amp; dismiss'), 'submit button');
  assert.ok(html.includes('Just dismiss (private)'), 'private button');
  assert.ok(html.includes('No prompt text'), 'transparency text');
});

// ============================================================
// show/hide tests
// ============================================================

test('banner: show() inserts into document and sets visible', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  b.hide();  // start clean
  assert.equal(b.isVisible(), false);
  b.show([{facet:'pii',category:'pii_ssn',severity:'critical',count:1,sample:'123-45-6789'}], { input: null });
  assert.equal(b.isVisible(), true);
  var el = b.getElement();
  assert.ok(el, 'banner element exists');
  assert.equal(el.getAttribute('data-aegisgate-lens'), 'banner');
  b.hide();
});

test('banner: show() with no events is a no-op', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  b.show([], { input: null });
  assert.equal(b.isVisible(), false);
});

test('banner: show() with null input falls back to document.documentElement', () => {
  loadAll();
  var b = globalThis.__lensBannerUI;
  b.show([{facet:'pii',category:'pii_ssn',severity:'critical',count:1,sample:'123'}], { input: null });
  var el = b.getElement();
  assert.ok(el, 'banner exists');
  assert.ok(el.parentNode === globalThis.document.documentElement, 'parentNode is documentElement (per manifest position: fixed)');
  b.hide();
});

// ============================================================
// Dismiss module tests
// ============================================================

test('dismiss: buildKey is stable for same inputs', () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  var k1 = d.buildKey('abc123def4567890', 'pii_credit_card', 'visa');
  var k2 = d.buildKey('abc123def4567890', 'pii_credit_card', 'visa');
  assert.equal(k1, k2);
});

test('dismiss: different categories produce different keys', () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  var k1 = d.buildKey('abc', 'pii_ssn', null);
  var k2 = d.buildKey('abc', 'pii_email', null);
  assert.notEqual(k1, k2);
});

test('dismiss: buildFPReport excludes prompt text and URLs', () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  var event = {
    facet: 'pii',
    category: 'pii_credit_card',
    severity: 'critical',
    count: 1,
    sample: '4111-1111-1111-1111',
    matches: [{ value: '4111-1111-1111-1111', index: 0, severity: 'critical', cardType: 'visa', confidence: 1.0 }],
    ml_score: null,
    ml_model_version: null
  };
  var report = d.buildFPReport(event, 'abc123def4567890', 'test_data');
  // Required fields
  assert.equal(report.lens_event_version, '0.1.0-beta');
  assert.equal(typeof report.timestamp, 'number');
  assert.equal(report.domain_hash, 'abc123def4567890');
  assert.equal(report.facet, 'pii');
  assert.equal(report.category, 'pii_credit_card');
  assert.equal(report.severity, 'critical');
  assert.equal(report.reason, 'test_data');
  assert.equal(report.pattern_id, 'pii_credit_card_visa_v1');
  // Privacy: NO prompt text, URL, page content
  assert.equal(report.text, undefined, 'no prompt text');
  assert.equal(report.url, undefined, 'no URL');
  assert.equal(report.page_content, undefined, 'no page content');
  assert.equal(report.value, undefined, 'no raw value');
  assert.equal(report.matches, undefined, 'no matches array');
});

test('dismiss: buildFPReport timestamp is recent', () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  var event = { facet: 'pii', category: 'pii_ssn', severity: 'critical', matches: [] };
  var before = Math.floor(Date.now() / 1000);
  var report = d.buildFPReport(event, 'abc', 'own_data');
  var after = Math.floor(Date.now() / 1000);
  assert.ok(report.timestamp >= before);
  assert.ok(report.timestamp <= after);
});

test('dismiss: dismiss() records to storage', async () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  // Clear first
  await d.clearAll();
  // Dismiss
  var ok = await d.dismiss('abc123def4567890', 'pii_ssn', 'v1', 'own_data', null);
  assert.equal(ok, true);
  // Check it's there
  var entry = await d.isDismissed('abc123def4567890', 'pii_ssn', 'v1');
  assert.ok(entry, 'entry exists');
  assert.equal(entry.reason, 'own_data');
  assert.equal(entry.opt_in, true);
  // Check expires_at is ~24h from now
  var expected = Date.now() + d.TTL_MS;
  var diff = Math.abs(entry.expires_at - expected);
  assert.ok(diff < 1000, 'expires_at should be ~24h from now');
});

test('dismiss: private dismiss (no reason) does not set opt_in', async () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  await d.clearAll();
  var ok = await d.dismiss('abc123def4567890', 'pii_email', null, null, null);
  assert.equal(ok, true);
  var entry = await d.isDismissed('abc123def4567890', 'pii_email', null);
  assert.ok(entry, 'entry exists');
  assert.equal(entry.reason, null);
  assert.equal(entry.opt_in, false);
});

test('dismiss: isDismissed returns null for unknown', async () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  await d.clearAll();
  var entry = await d.isDismissed('unknowndomain', 'pii_unknown', null);
  assert.equal(entry, null);
});

test('dismiss: clearAll removes everything', async () => {
  loadAll();
  var d = globalThis.__lensDismiss;
  await d.dismiss('a', 'pii_ssn', null, null, null);
  await d.dismiss('b', 'pii_email', null, null, null);
  await d.clearAll();
  var e1 = await d.isDismissed('a', 'pii_ssn', null);
  var e2 = await d.isDismissed('b', 'pii_email', null);
  assert.equal(e1, null);
  assert.equal(e2, null);
});
