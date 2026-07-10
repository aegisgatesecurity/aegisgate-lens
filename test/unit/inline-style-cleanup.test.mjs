// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - Regression test for the B4 inline style cleanup
//
// Verifies that the inline style="display: none;" and the inline
// style="position:absolute;..." sr-only hack have been removed
// from the codebase, replaced with .hidden and .sr-only CSS classes
// + classList.add/remove calls.
//
// This is a static check (no DOM). It catches regressions where a
// future change re-introduces inline styles where classes should
// be used instead.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

function read(relPath) {
  return readFileSync(join(LENS_ROOT, relPath), 'utf8');
}

const popupHtml = read('src/popup/popup.html');
const popupJs = read('src/popup/popup.js');
const bannerUiHtml = read('src/util/banner-ui-html.js');
const bannerUiLifecycle = read('src/util/banner-ui-lifecycle.js');
const bannerCss = read('src/util/banner.css');

// ============================================================================
// popup.html - inline style="display: none;" removed
// ============================================================================
test('B4 popup.html: upgrade-banner uses .hidden class instead of inline style', () => {
  assert.match(popupHtml, /<div id="upgrade-banner" class="status upgrade hidden"/);
  assert.ok(!/id="upgrade-banner"[^>]*style=["']display:\s*none/i.test(popupHtml),
    'upgrade-banner still has inline style="display: none;"');
});

test('B4 popup.html: upgrade-heading uses .sr-only class (no inline position hack)', () => {
  assert.match(popupHtml, /<h2 id="upgrade-heading" class="sr-only">/);
  assert.ok(!/<h2 id="upgrade-heading"[^>]*style=["']position:absolute/i.test(popupHtml),
    'upgrade-heading still has inline position:absolute hack');
});

test('B4 popup.html: .hidden and .sr-only classes are defined in inline style', () => {
  assert.match(popupHtml, /\.hidden\s*\{\s*display:\s*none\s*!important/,
    '.hidden class should be defined as .hidden { display: none !important; }');
  assert.match(popupHtml, /\.sr-only\s*\{[^}]*position:\s*absolute/,
    '.sr-only class should be defined with position: absolute');
});

// ============================================================================
// popup.js - no el.style.display assignments
// ============================================================================
test('B4 popup.js: uses classList instead of el.style.display', () => {
  assert.match(popupJs, /banner\.classList\.remove\(['"]hidden['"]\)/,
    'popup.js should use banner.classList.remove("hidden") to show the upgrade banner');
  assert.ok(!/style\.display\s*=\s*['"]block['"]/.test(popupJs),
    'popup.js still has style.display = "block" (should use classList)');
});

// ============================================================================
// banner-ui-html.js - createBannerElement uses .hidden class
// ============================================================================
test('B4 banner-ui-html.js: createBannerElement adds .hidden class (not inline display)', () => {
  assert.match(bannerUiHtml, /el\.classList\.add\(['"]hidden['"]\)/,
    'createBannerElement should add .hidden class to the banner');
  assert.ok(!/el\.style\.display\s*=\s*['"]none['"]/.test(bannerUiHtml),
    'createBannerElement still uses el.style.display = "none"');
});

// ============================================================================
// banner-ui-lifecycle.js - show() and hide() use classList
// ============================================================================
test('B4 banner-ui-lifecycle.js: show() uses classList.remove("hidden")', () => {
  assert.match(bannerUiLifecycle, /state\.el\.classList\.remove\(['"]hidden['"]\)/,
    'show() should use classList.remove("hidden") to show the banner');
  assert.ok(!/state\.el\.style\.display\s*=\s*['"]['"]/.test(bannerUiLifecycle),
    'show() still uses state.el.style.display = "" (should use classList)');
});

test('B4 banner-ui-lifecycle.js: hide() (dismiss) uses classList.add("hidden")', () => {
  assert.match(bannerUiLifecycle, /el\.classList\.add\(['"]hidden['"]\)/,
    'hide() (dismiss) should use classList.add("hidden")');
  const styleDisplayCount = (bannerUiLifecycle.match(/style\.display/g) || []).length;
  assert.equal(styleDisplayCount, 0,
    'banner-ui-lifecycle.js should have 0 style.display references (was 1)');
});

// ============================================================================
// banner.css - the .hidden rule scoped to the banner
// ============================================================================
test('B4 banner.css: has [data-aegisgate-lens="banner"].hidden rule', () => {
  // The CSS is: [data-aegisgate-lens="banner"].hidden { display: none !important; }
  // In JS regex: /[data-aegisgate-lens=["']banner["']].hiddens*{s*display:s*nones*!important/
  // (note: in a string, \ becomes , so /[/ becomes /[/ in the regex)
  const re = /\[data-aegisgate-lens=["']banner["']\]\.hidden\s*\{\s*display:\s*none\s*!important/;
  assert.match(bannerCss, re,
    'banner.css should have [data-aegisgate-lens="banner"].hidden rule');
});

// ============================================================================
// Cross-cutting - no .style.display anywhere in popup/ or banner-ui
// ============================================================================
test('B4: total .style.display references in popup + banner-ui files is 0', () => {
  const allFiles = [popupHtml, popupJs, bannerUiHtml, bannerUiLifecycle];
  let total = 0;
  for (const f of allFiles) {
    const matches = f.match(/style\.display/g) || [];
    total += matches.length;
  }
  assert.equal(total, 0,
    'Total .style.display references should be 0 (was 3 before B4)');
});
