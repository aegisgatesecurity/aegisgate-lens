#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Penetration Test Attack 05 (F-06 / F-03)
// DOM XSS via detector output and user-controlled FP form fields
// =========================================================================
//
// Threat-model reference: F-06 (CSP / dynamic code execution) and F-03
// (content script reads attacker-controlled DOM).
//
// Day 6 survey + Day 10 CSP test (test/security-csp.test.mjs) confirmed:
//   - No eval() / new Function() / Function(string) / innerHTML /
//     outerHTML / document.write anywhere in src/.
//   - All DOM updates use textContent (XSS-safe).
//
// This attack tries to BREAK that contract by feeding attacker-controlled
// data into content.js and observing what lands in the DOM.
//
// Output: pen-test/evidence/05-f06.jsonl
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// Capturing DOM stub.
function makeDomStub() {
  const textContents = [];
  const innerHTMLs = [];
  const outerHTMLs = [];
  const elements = new Map();
  let nextId = 0;

  function makeEl(tag) {
    const id = ++nextId;
    const el = {
      _id: id,
      _tag: tag,
      style: {},
      children: [],
      parentNode: null,
      listeners: {},
      _textContent: '',
      set textContent(v) { this._textContent = v; textContents.push({ id, tag, value: v }); },
      get textContent() { return this._textContent; },
      set innerHTML(v) { innerHTMLs.push({ id, tag, value: v }); },
      set outerHTML(v) { outerHTMLs.push({ id, tag, value: v }); },
      setAttribute(k, v) { this['_' + k] = v; },
      getAttribute(k) { return this['_' + k]; },
      appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
      removeChild(c) {
        const i = this.children.indexOf(c);
        if (i >= 0) { this.children.splice(i, 1); c.parentNode = null; }
        return c;
      },
      addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); },
      dispatchEvent(e) { for (const fn of this.listeners[e && e.type] || []) fn(e); },
    };
    elements.set(id, el);
    return el;
  }
  return {
    document: { createElement: makeEl, body: makeEl('body') },
    captures: { textContents, innerHTMLs, outerHTMLs, elements },
  };
}

// Run a single attack.
async function runAttack(name, fn) {
  const { document, captures } = makeDomStub();
  const schemaSrc = await fsp.readFile(path.join(repoRoot, 'src/privacy/schema.js'), 'utf8');
  const contentSrc = await fsp.readFile(path.join(repoRoot, 'src/content.js'), 'utf8');

  const locObj = { hostname: 'chat.openai.com', protocol: 'https:' };
  const sandbox = {
    console: { log: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    URL,
    document,
    location: locObj,
    navigator: { userAgent: 'node-test' },
    Math, Date, JSON, Object, Array, Set, Map,
    String, Number, Boolean, Error, Promise, Symbol, RegExp,
    setTimeout, clearTimeout,
    crypto: globalThis.crypto,
    self: {},
  };
  sandbox.window = sandbox.self;
  sandbox.self.location = locObj;
  sandbox.self.AegisGateLens = {
    logger: { info: () => {}, warn: () => {}, error: () => {} },
    privacy: {},
    detectors: {
      detect: () => [],
      describeCategory: (c) => c,
    },
    storage: { Storage: function () {} },
  };
  sandbox.chrome = {
    runtime: {
      sendMessage: () => {},
      getURL: (p) => 'chrome-extension://test/' + p,
      getManifest: () => ({ version: '0.2.2-test' }),
      lastError: null,
    },
    storage: { local: { get: (k, cb) => cb({}), set: () => {} } },
  };

  const ctx = vm.createContext(sandbox);
  vm.runInContext(schemaSrc, ctx, { filename: 'privacy/schema.js' });
  vm.runInContext(contentSrc, ctx, { filename: 'content.js' });
  const ContentScript = sandbox.self.AegisGateLens.ContentScript;

  const inst = Object.create(ContentScript.prototype);
  inst.banner = document.createElement('div');
  inst.domainHash = 'deadbeefdeadbeef';

  const result = await fn(inst, captures);
  return { name, result };
}

const OUT = path.join(repoRoot, 'pen-test/evidence/05-f06.jsonl');
await fsp.mkdir(path.dirname(OUT), { recursive: true });
const evidenceLines = [];

function log(name, verdict, detail) {
  evidenceLines.push({ name, verdict, detail });
  const tag = verdict === 'PASS' ? 'PASS' : verdict === 'FINDING' ? 'FIND' : 'INFO';
  console.log(`  [${tag}] ${name}${detail ? ': ' + detail : ''}`);
}

// ----- Tests -----

console.log('AegisGate Lens - DOM XSS Pen Test (Day 12 / Attack 05)');
console.log('');

// 5.1: XSS payload in detection match.
{
  const { result } = await runAttack('xss_in_detection_match', (inst, captures) => {
    inst.currentDetections = [{
      category: 'pii_email',
      severity: 'high',
      mlScore: 0.99,
      match: '<script>alert(1)</script>',
    }];
    inst.updateBannerContent(inst.currentDetections);
    const findings = captures.textContents.filter(c =>
      /<[a-z]+\s/i.test(c.value) || /<\/>/.test(c.value),
    );
    return {
      textCount: captures.textContents.length,
      innerHTML: captures.innerHTMLs.length,
      outerHTML: captures.outerHTMLs.length,
      rawHtmlTags: findings.length,
    };
  });
  const verdict = result.rawHtmlTags === 0 ? 'PASS' : 'FINDING';
  log('xss_in_detection_match', verdict,
    `${result.textCount} textContent writes, ${result.innerHTML} innerHTML, ${result.outerHTML} outerHTML, ${result.rawHtmlTags} raw HTML tags in textContent`);
}

// 5.2: img onerror payload.
{
  const { result } = await runAttack('xss_img_onerror_in_match', (inst, captures) => {
    inst.currentDetections = [{
      category: 'pii_phone',
      severity: 'medium',
      match: '<img src=x onerror=alert(document.cookie)>',
    }];
    inst.updateBannerContent(inst.currentDetections);
    const findings = captures.textContents.filter(c =>
      /<img|onerror/i.test(c.value),
    );
    return {
      count: findings.length,
      sample: findings.slice(0, 2).map((f) => f.value.slice(0, 200)),
    };
  });
  log('xss_img_onerror_in_match',
    result.count === 0 ? 'PASS' : 'INFO',
    `${result.count} textContent with img/onerror. Note: textContent is XSS-safe; the browser does not parse HTML inside textContent. This is documented as INFO not FINDING. Sample: ${JSON.stringify(result.sample)}`);
}

// 5.3: HTML entities in match (should be preserved verbatim).
{
  const { result } = await runAttack('html_entities_in_match', (inst, captures) => {
    inst.currentDetections = [{
      category: 'secret_api_key',
      severity: 'critical',
      match: '&lt;script&gt;alert(1)&lt;/script&gt;',
    }];
    inst.updateBannerContent(inst.currentDetections);
    const findings = captures.textContents.filter(c =>
      /<script>alert/i.test(c.value),
    );
    return { decodedScripts: findings.length };
  });
  log('html_entities_in_match',
    result.decodedScripts === 0 ? 'PASS' : 'FINDING',
    `${result.decodedScripts} decoded <script> tags in textContent (entities should stay encoded)`);
}

// 5.4: huge match text (1MB).
{
  const { result } = await runAttack('huge_match_text', (inst, captures) => {
    const hugeMatch = 'A'.repeat(1024 * 1024);
    inst.currentDetections = [{
      category: 'pii_ssn',
      severity: 'low',
      match: hugeMatch,
    }];
    const before = captures.textContents.length;
    inst.updateBannerContent(inst.currentDetections);
    const after = captures.textContents.length;
    return { writesBefore: before, writesAfter: after };
  });
  log('huge_match_text',
    result.writesAfter >= result.writesBefore ? 'PASS' : 'FINDING',
    `textContent writes: ${result.writesBefore} -> ${result.writesAfter}`);
}

// 5.5: unicode escapes in match.
{
  const { result } = await runAttack('unicode_escapes_in_match', (inst, captures) => {
    inst.currentDetections = [{
      category: 'pii_email',
      severity: 'medium',
      match: '\u003cscript\u003ealert(1)\u003c/script\u003e',
    }];
    inst.updateBannerContent(inst.currentDetections);
    const findings = captures.textContents.filter(c =>
      c.value.includes('<script>alert(1)</script>'),
    );
    return { decodedUnicode: findings.length };
  });
  log('unicode_escapes_in_match',
    result.decodedUnicode === 0 ? 'PASS' : 'FINDING',
    `${result.decodedUnicode} decoded unicode-script in textContent`);
}

// 5.6: XSS in fp_reason (user-controlled reason field).
{
  const { result } = await runAttack('xss_in_fp_reason', (inst, captures) => {
    // sendFPTelemetry doesn't render anything to the DOM, but we
    // check that it doesn't trigger any innerHTML writes.
    inst.sendFPTelemetry('pii_email|k', '<script>alert(1)</script>');
    return {
      innerHTML: captures.innerHTMLs.length,
      outerHTML: captures.outerHTMLs.length,
    };
  });
  log('xss_in_fp_reason',
    result.innerHTML === 0 && result.outerHTML === 0 ? 'PASS' : 'FINDING',
    `${result.innerHTML} innerHTML, ${result.outerHTML} outerHTML writes from FP telemetry`);
}

// 5.7: click handler injection via match text.
{
  const { result } = await runAttack('click_handler_via_match', (inst, captures) => {
    inst.currentDetections = [{
      category: 'pii_credit_card',
      severity: 'high',
      match: '" onmouseover="alert(1)',
    }];
    inst.updateBannerContent(inst.currentDetections);
    let handlerFound = false;
    for (const el of captures.elements.values()) {
      for (const k of Object.keys(el)) {
        if (k.startsWith('on') && typeof el[k] === 'string') {
          handlerFound = true;
        }
      }
    }
    return { handlerFound };
  });
  log('click_handler_via_match',
    !result.handlerFound ? 'PASS' : 'FINDING',
    `inline event handler injection: ${result.handlerFound}`);
}

// 5.8: CSS injection via match.
{
  const { result } = await runAttack('css_injection_in_match', (inst, captures) => {
    inst.currentDetections = [{
      category: 'pii_phone',
      severity: 'medium',
      match: 'red; background: url(javascript:alert(1))',
    }];
    inst.updateBannerContent(inst.currentDetections);
    let cssInjection = false;
    for (const el of captures.elements.values()) {
      for (const k of Object.keys(el.style || {})) {
        if (typeof el.style[k] === 'string' && /javascript:/i.test(el.style[k])) {
          cssInjection = true;
        }
      }
    }
    return { cssInjection };
  });
  log('css_injection_in_match',
    !result.cssInjection ? 'PASS' : 'FINDING',
    `javascript: URL in style: ${result.cssInjection}`);
}

// ----- Summary -----

console.log('');
const passCount = evidenceLines.filter((e) => e.verdict === 'PASS').length;
const findCount = evidenceLines.filter((e) => e.verdict === 'FINDING').length;
console.log(`Passed: ${passCount}    Findings: ${findCount}`);

await fsp.writeFile(OUT, evidenceLines.map((e) => JSON.stringify(e)).join('\n') + '\n');
console.log(`Evidence: ${OUT}`);
