#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.2 — Banner UI Test (Node.js vm)
//
// Tests the banner UI module in isolation. Validates that the
// exported functions are all present and have the right shape.

import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const bannerUISrc = fs.readFileSync(
  path.join(repoRoot, 'src/util/banner-ui.js'),
  'utf8'
);

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err.message}`);
  }
}

console.log('AegisGate Lens v0.2 - Banner UI Test');
console.log('');

// Load banner-ui.js into a vm context (it attaches to AegisGateLens)
const NS = { util: {} };
const sandbox = {
  console,
  document: {
    createElement: (tag) => ({
      tagName: tag.toUpperCase(),
      style: {},
      setAttribute: () => {},
      appendChild: () => {},
      addEventListener: () => {},
      firstChild: null,
      removeChild: () => {},
    }),
    body: { appendChild: () => {}, contains: () => true },
    getElementById: () => null,
  },
  window: { AegisGateLens: NS },
  setTimeout: () => 1,
  clearTimeout: () => {},
};
sandbox.window = { ...sandbox.window, AegisGateLens: NS };
NS.util = NS.util;

const ctx = Object.assign(sandbox, { AegisGateLens: NS });
const fn = new Function(
  'console', 'document', 'window', 'setTimeout', 'AegisGateLens',
  bannerUISrc
);
fn(console, sandbox.document, sandbox.window, sandbox.setTimeout, NS);

const bannerUI = NS.util.bannerUI;
assert.ok(bannerUI, 'bannerUI should be exposed on NS.util');

test('bannerUI.severityTint is a function', () => {
  assert.equal(typeof bannerUI.severityTint, 'function');
});

test('severityTint returns expected shape', () => {
  const r = bannerUI.severityTint('critical');
  assert.equal(r.accent, '#f43f5e');
  assert.equal(r.fg, '#ffffff');
  assert.equal(r.label, 'CRITICAL');
});

test('severityTint handles all severity levels', () => {
  for (const s of ['critical', 'high', 'medium', 'low', 'info']) {
    const r = bannerUI.severityTint(s);
    assert.ok(r.accent, `severityTint(${s}) has accent`);
    assert.ok(r.label, `severityTint(${s}) has label`);
  }
});

test('severityTint returns default for unknown', () => {
  const r = bannerUI.severityTint('banana');
  assert.equal(r.accent, '#94a3b8');
  assert.equal(r.label, 'INFO');
});

test('buttonStyle is a function', () => {
  assert.equal(typeof bannerUI.buttonStyle, 'function');
});

test('buttonStyle returns expected keys', () => {
  const s = bannerUI.buttonStyle('#38bdf8');
  assert.equal(s.background, 'transparent');
  assert.equal(s.color, '#38bdf8');
  assert.equal(s.border, '1px solid #38bdf8');
  assert.ok(s.cursor);
  assert.ok(s.transition);
});

test('describeCategory is a function', () => {
  assert.equal(typeof bannerUI.describeCategory, 'function');
});

test('describeCategory handles known categories', () => {
  assert.equal(bannerUI.describeCategory('pii_ssn'), 'Social Security Number');
  assert.equal(bannerUI.describeCategory('jwt_none'), 'JWT with "none" algorithm (security vulnerability)');
});

test('describeCategory falls back to category name', () => {
  assert.equal(bannerUI.describeCategory('unknown_thing'), 'unknown_thing');
});

test('showBanner is a function', () => {
  assert.equal(typeof bannerUI.showBanner, 'function');
});

test('hideBanner is a function', () => {
  assert.equal(typeof bannerUI.hideBanner, 'function');
});

test('updateBannerContent is a function', () => {
  assert.equal(typeof bannerUI.updateBannerContent, 'function');
});

test('BANNER_BG constant', () => {
  assert.equal(bannerUI.BANNER_BG, 'rgba(10, 12, 16, 0.92)');
});

test('BANNER_FONT_FAMILY constant', () => {
  assert.match(bannerUI.BANNER_FONT_FAMILY, /Inter/);
});

test('showBanner does not throw on empty array', () => {
  // Empty array should not throw (defensive)
  bannerUI.showBanner([]);
});

test('showBanner does not throw with null detection', () => {
  bannerUI.showBanner(null);
});

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);
if (failed > 0) process.exit(1);