#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - False-Positive Opt-In Prompt Test (Day 5)
// =========================================================================
//
// Tests the in-banner "Help improve detection" opt-in prompt that
// appears after the user's first false-positive dismissal.
//
// Asserts:
//   1. The card appears when the user dismisses a detection as FP
//      AND has not yet seen the prompt AND has not enabled FP
//      telemetry.
//   2. The card contains the privacy guarantee ("anonymous metadata",
//      "never prompt content" or similar text per the schema doc).
//   3. Clicking "Allow" sets fpTelemetryEnabled = true AND
//      fpOptInPromptSeen = true in chrome.storage.local.
//   4. Clicking "Not now" sets fpOptInPromptSeen = true but does NOT
//      set fpTelemetryEnabled.
//   5. After the user has decided (either button), subsequent FP
//      dismissals do NOT show the card.
//   6. If the user already has fpTelemetryEnabled = true (opted in
//      via the popup earlier), the card is suppressed on FP dismiss.
//
// We stub the DOM with just enough surface area to drive content.js:
// Element.style (an object with properties), Element.appendChild,
// Element.addEventListener, document.createElement, document.body.
// We don't render pixels; we only assert that the right methods were
// called and the right state was set.
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

function makeElement(tagName) {
  const el = {
    tagName: tagName.toUpperCase(),
    style: {}, // plain object; content.js uses Object.assign(el.style, {...})
    children: [],
    parentNode: null,
    attributes: {},
    listeners: {},
    textContent: '',
    setAttribute(k, v) { this.attributes[k] = v; },
    getAttribute(k) { return this.attributes[k]; },
    appendChild(child) {
      child.parentNode = this;
      this.children.push(child);
      return child;
    },
    removeChild(child) {
      const idx = this.children.indexOf(child);
      if (idx >= 0) {
        this.children.splice(idx, 1);
        child.parentNode = null;
      }
      return child;
    },
    addEventListener(type, fn) {
      this.listeners[type] = this.listeners[type] || [];
      this.listeners[type].push(fn);
    },
    dispatchEvent(evt) {
      const fns = this.listeners[evt && evt.type] || [];
      for (const fn of fns) fn(evt);
    },
  };
  return el;
}

function makeDocument() {
  return {
    createElement: makeElement,
    body: makeElement('body'),
  };
}

// ----- Chrome storage stub --------------------------------------------------

function makeStorageStub() {
  const data = {};
  return {
    data,
    get(key, cb) {
      if (typeof key === 'string') {
        cb({ [key]: data[key] });
      } else if (Array.isArray(key)) {
        const out = {};
        for (const k of key) out[k] = data[k];
        cb(out);
      } else {
        cb({ ...data });
      }
    },
    set(items, cb) {
      Object.assign(data, items);
      if (cb) cb();
    },
    remove(key, cb) {
      delete data[key];
      if (cb) cb();
    },
    // Test helpers.
    preset(flag, value) { data[flag] = value; },
    reset() { for (const k of Object.keys(data)) delete data[k]; },
  };
}

// ----- Sandbox load: schema + content.js ------------------------------------

async function loadContentScript() {
  const [schemaSrc, contentSrc, bannerUISrc] = await Promise.all([
    fsp.readFile(path.join(repoRoot, 'src/privacy/schema.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/content.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/util/banner-ui.js'), 'utf8'),
  ]);

  const storage = makeStorageStub();
  const document = makeDocument();

  // Note: vm contexts do NOT inherit Node globals like `location`.
  // Content.js reads `window.location.hostname` at IIFE init time, so
  // we set location AND window.location explicitly. We also expose
  // Math/Date/etc. (Node has these on globalThis but vm doesn't
  // automatically forward them.)
  const locObj = { hostname: 'chat.openai.com', protocol: 'https:' };
  const sandbox = {
    console,
    URL,
    document,
    location: locObj,
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
    window: {},
    self: {},
    chrome: {
      runtime: {
        sendMessage: () => Promise.resolve(),
        getURL: (p) => 'chrome-extension://test/' + p,
        getManifest: () => ({ version: '0.2.2-test' }),
        lastError: null,
      },
      storage: {
        local: storage,
      },
    },
  };
  sandbox.window.location = locObj;
  sandbox.window = sandbox.self;
  sandbox.self.location = locObj;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};
  // Pre-attach logger so content.js's IIFE picks it up.
  sandbox.self.AegisGateLens.logger = {
    info: () => {},
    warn: (...a) => console.warn('[Lens]', ...a),
    error: (...a) => console.error('[Lens]', ...a),
  };

  const ctx = vm.createContext(sandbox);
  vm.runInContext(schemaSrc, ctx, { filename: 'privacy/schema.js' });
  vm.runInContext(bannerUISrc, ctx, { filename: 'util/banner-ui.js' });
  vm.runInContext(contentSrc, ctx, { filename: 'content.js' });

  const ContentScript = sandbox.self.AegisGateLens.ContentScript;
  if (!ContentScript) {
    throw new Error('ContentScript class not exported by content.js');
  }
  return { ctx, sandbox, storage, document, ContentScript };
}

// ----- Helper: find an element by data attribute in a tree ------------------

function findByAttr(el, attr, value) {
  if (!el || !el.children) return null;
  if (el.attributes && el.attributes[attr] === value) return el;
  for (const c of el.children) {
    const hit = findByAttr(c, attr, value);
    if (hit) return hit;
  }
  return null;
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

console.log('AegisGate Lens - False-Positive Opt-In Prompt Test (Day 5)');
console.log('');

// ----- Tests ---------------------------------------------------------------

await test('opt-in card appears on first FP dismissal', async () => {
  const { sandbox, storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  // Build a minimal banner the content script can append to.
  inst.banner = document.createElement('div');
  storage.reset();
  // Pre-populate the content script's knowledge of the banner; we
  // attach it to the document body so it's findable.
  document.body.appendChild(inst.banner);
  // also stub hideBanner to set a flag we can assert against
  inst.hideBanner = function () { inst._hidden = true; };

  inst.dismissAsFalsePositive(null);

  // Wait for the async chrome.storage.local.get callback.
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.ok(card, 'opt-in card should be appended to the banner');
  // _hidden starts undefined; if hideBanner() ran it would be true.
  // We assert hideBanner was NOT called while the card is visible.
  assert.notEqual(inst._hidden, true,
    'banner should NOT be hidden while card is visible');
});

await test('opt-in card contains the privacy guarantee text', async () => {
  const { storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.ok(card, 'card should exist');
  // Find the body paragraph (the second child: title, body, actions).
  const bodyEl = card.children[1];
  assert.ok(bodyEl, 'card should have a body child');
  const text = bodyEl.textContent;
  // Per the Day 5 spec: "Help improve detection - anonymous metadata, never prompt content"
  // We assert key phrases from the privacy guarantee. The exact text
  // may evolve but the contract holds.
  assert.match(text, /anonymous metadata/i, 'should mention anonymous metadata');
  assert.match(text, /no prompt text/i, 'should explicitly disavow prompt content');
  assert.match(text, /no URLs/i, 'should explicitly disavow URLs');
  assert.match(text, /off by default/i, 'should state the off-by-default invariant');
});

await test('clicking Allow sets fpTelemetryEnabled = true', async () => {
  const { storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.ok(card, 'card should exist');
  const allowBtn = card.children[2].children[0]; // title, body, actions -> [0]=Allow
  assert.ok(allowBtn, 'Allow button should exist');
  assert.equal(allowBtn.textContent, 'Allow');
  allowBtn.dispatchEvent({ type: 'click' });

  await new Promise((r) => setTimeout(r, 10));
  assert.equal(storage.data.fpTelemetryEnabled, true, 'fpTelemetryEnabled should be true');
  assert.equal(storage.data.fpOptInPromptSeen, true, 'fpOptInPromptSeen should also be true');
  assert.equal(inst._hidden, true, 'banner should be hidden after Allow click');
});

await test('clicking Not now sets fpOptInPromptSeen = true but NOT fpTelemetryEnabled', async () => {
  const { storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.ok(card, 'card should exist');
  const notNowBtn = card.children[2].children[1]; // [1]=Not now
  assert.equal(notNowBtn.textContent, 'Not now');
  notNowBtn.dispatchEvent({ type: 'click' });

  await new Promise((r) => setTimeout(r, 10));
  assert.equal(storage.data.fpOptInPromptSeen, true, 'fpOptInPromptSeen should be true');
  assert.notEqual(storage.data.fpTelemetryEnabled, true, 'fpTelemetryEnabled should NOT be true');
  assert.equal(inst._hidden, true, 'banner should be hidden after Not now click');
});

await test('opt-in card does NOT appear on second FP dismiss after Allow', async () => {
  const { storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();
  storage.preset('fpTelemetryEnabled', true); // already enabled
  storage.preset('fpOptInPromptSeen', true);

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.equal(card, null, 'card should NOT appear after Allow was clicked previously');
  assert.equal(inst._hidden, true, 'banner should hide normally');
});

await test('opt-in card does NOT appear on second FP dismiss after Not now', async () => {
  const { storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();
  storage.preset('fpOptInPromptSeen', true); // previously dismissed

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.equal(card, null, 'card should NOT appear after Not now was clicked previously');
  assert.equal(inst._hidden, true, 'banner should hide normally');
});

await test('opt-in card does NOT appear when fpTelemetryEnabled is set (opted in via popup)', async () => {
  const { storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();
  storage.preset('fpTelemetryEnabled', true);
  // No fpOptInPromptSeen flag — but fpTelemetryEnabled alone suppresses the card.

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  const card = findByAttr(inst.banner, 'data-aegis-fp-opt-in', '1');
  assert.equal(card, null, 'card should NOT appear when fpTelemetryEnabled is already true');
});

await test('dismissAsFalsePositive still records the user_action telemetry when card shows', async () => {
  // Regression: the existing recordAction('dismiss_false_positive')
  // telemetry must still fire BEFORE the opt-in card. This is what
  // the user-action event in the integration test relies on.
  const { sandbox, storage, document, ContentScript } = await loadContentScript();
  const inst = Object.create(ContentScript.prototype);
  inst.currentDetections = [{ category: 'pii_email', severity: 'medium' }];
  inst.domainHash = '0a1b2c3d4e5f6071';
  inst.banner = document.createElement('div');
  document.body.appendChild(inst.banner);
  inst.hideBanner = function () { inst._hidden = true; };
  storage.reset();

  // Capture sendMessage calls.
  const sentMessages = [];
  sandbox.chrome.runtime.sendMessage = (msg) => {
    sentMessages.push(msg);
    return Promise.resolve();
  };

  inst.dismissAsFalsePositive(null);
  await new Promise((r) => setTimeout(r, 30));

  // One dismiss_false_positive event per detection.
  assert.equal(sentMessages.length, 1, 'expected one telemetry message');
  assert.equal(sentMessages[0].type, 'lens.telemetry');
  assert.equal(
    sentMessages[0].event.user_action, 'dismiss_false_positive',
    'telemetry must use dismiss_false_positive action',
  );
  assert.equal(
    sentMessages[0].event.lens_event_version, 1,
    'telemetry must carry lens_event_version: 1 (Day 3 invariant)',
  );
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
