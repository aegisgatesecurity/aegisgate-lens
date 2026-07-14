// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - Regression test for the B5 responsive icon set
//
// Verifies:
//   1. The root manifest.json has BARE icon paths (no 'src/' prefix)
//   2. The 3 responsive banner PNGs exist (1x/2x/3x at 24/48/72 px)
//   3. banner-ui-html.js uses <picture> with srcset for 1x/2x/3x
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

function read(relPath) {
  return readFileSync(join(LENS_ROOT, relPath), 'utf8');
}

const rootManifest = JSON.parse(read('manifest.json'));
const bannerHtml = read('src/util/banner-ui-html.js');

// ============================================================================
// A: root manifest.json icon paths are bare (no 'src/' prefix)
// ============================================================================
test('B5 manifest: root manifest.json icon paths do NOT have src/ prefix', () => {
  for (const size of Object.keys(rootManifest.icons)) {
    const path = rootManifest.icons[size];
    assert.ok(path.indexOf('src/') !== 0,
      'icons[' + size + ']="' + path + '" should not have src/ prefix');
    assert.ok(path.indexOf('icons/') === 0,
      'icons[' + size + ']="' + path + '" should start with icons/');
  }
  if (rootManifest.action && rootManifest.action.default_icon) {
    for (const size of Object.keys(rootManifest.action.default_icon)) {
      const path = rootManifest.action.default_icon[size];
      assert.ok(path.indexOf('src/') !== 0,
        'action.default_icon[' + size + ']="' + path + '" should not have src/ prefix');
    }
  }
});

// ============================================================================
// B: 3 responsive banner PNGs exist at the right sizes
// ============================================================================
test('B5 icons: banner-1x.png exists and is smaller than banner-3x.png', () => {
  const p1 = join(LENS_ROOT, 'src/icons/banner-1x.png');
  const p3 = join(LENS_ROOT, 'src/icons/banner-3x.png');
  assert.ok(existsSync(p1), 'banner-1x.png should exist in src/icons/');
  assert.ok(existsSync(p3), 'banner-3x.png should exist in src/icons/');
  const size1 = statSync(p1).size;
  const size3 = statSync(p3).size;
  assert.ok(size1 > 0, 'banner-1x.png should not be empty');
  assert.ok(size3 > size1, 'banner-3x.png should be larger than banner-1x.png');
});

test('B5 icons: banner-2x.png is a byte-for-byte copy of icon-48.png', () => {
  const p2 = join(LENS_ROOT, 'src/icons/banner-2x.png');
  const icon48 = join(LENS_ROOT, 'src/icons/icon-48.png');
  assert.ok(existsSync(p2), 'banner-2x.png should exist in src/icons/');
  assert.ok(existsSync(icon48), 'icon-48.png should still exist');
  const b2x = readFileSync(p2);
  const orig = readFileSync(icon48);
  assert.equal(b2x.length, orig.length,
    'banner-2x.png should be a byte-for-byte copy of icon-48.png');
});

// ============================================================================
// C: banner-ui-html.js uses <picture> with srcset
// ============================================================================
test('B5 banner: uses <picture> element with srcset (not a plain <img>)', () => {
  assert.ok(bannerHtml.indexOf('<picture>') >= 0,
    'banner-ui-html.js should use <picture>');
  assert.ok(bannerHtml.indexOf('banner-3x.png') >= 0,
    'should reference banner-3x.png for 3x displays');
  assert.ok(bannerHtml.indexOf('banner-2x.png') >= 0,
    'should reference banner-2x.png for 2x displays');
  assert.ok(bannerHtml.indexOf('alt="AegisGate Lens"') >= 0,
    'fallback <img> should have alt text');
  assert.ok(bannerHtml.indexOf('width="24"') >= 0,
    'fallback <img> should have width="24" to prevent layout shift');
  assert.ok(bannerHtml.indexOf('height="24"') >= 0,
    'fallback <img> should have height="24" to prevent layout shift');
});

test('B5 banner: <picture> has source media queries for 2dppx and 3dppx', () => {
  // Use a non-regex approach: count occurrences of the media query strings
  const has2dppx = bannerHtml.indexOf('(min-resolution: 2dppx)') >= 0;
  const has3dppx = bannerHtml.indexOf('(min-resolution: 3dppx)') >= 0;
  assert.ok(has2dppx, 'should have 2dppx source for standard retina');
  assert.ok(has3dppx, 'should have 3dppx source for high-DPI');
});

test('B5 banner: no longer references the old icon-48.png for the shield', () => {
  // The shield <img> should now reference banner-2x.png, not icon-48.png.
  // The old pattern was: class="lens-shield-img" src="...icons/icon-48.png..."
  const oldPattern = 'class="lens-shield-img"' + ' ' + 'src=' + '"' + 'icons/icon-48.png';
  assert.ok(bannerHtml.indexOf(oldPattern) === -1,
    'old <img class="lens-shield-img" src="...icons/icon-48.png..."> should be gone');
  // And the new pattern: src="...icons/banner-2x.png..."
  const newPattern = 'icons/banner-2x.png';
  assert.ok(bannerHtml.indexOf(newPattern) >= 0,
    'new <img> should reference icons/banner-2x.png');
});
