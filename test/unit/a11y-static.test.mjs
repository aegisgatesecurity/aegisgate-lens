// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - Static a11y regression test (B3)
//
// This test catches a11y regressions in popup.html, welcome.html,
// and banner-ui-html.js by checking for the attributes and patterns
// that the v0.1.3 a11y audit (docs/A11Y-AUDIT-v0.1.3.md) flagged
// as REQUIRED. It does NOT replace a real Lighthouse or
// screen-reader test (those are deferred to v0.2.0 per Bucket E);
// this is a static check that runs in <100ms and catches the
// common regressions.
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

// ============================================================================
// popup.html
// ============================================================================
const popup = read('src/popup/popup.html');

test('a11y popup: <html lang="en"> is present (WCAG 3.1.1)', () => {
  assert.match(popup, /<html\s+lang=["']en["']/);
});

test('a11y popup: <title> is present and descriptive (WCAG 2.4.2)', () => {
  const m = popup.match(/<title>([^<]+)<\/title>/);
  assert.ok(m, '<title> tag must be present');
  assert.ok(m[1].trim().length > 0, '<title> must not be empty');
  assert.match(m[1], /Lens/i, '<title> should mention the product name');
});

test('a11y popup: status div has role="status" and aria-live="polite" (WCAG 4.1.3)', () => {
  assert.match(popup, /role=["']status["']\s+aria-live=["']polite["']/, 'status div must have role="status" aria-live="polite"');
});

test('a11y popup: upgrade banner has role="complementary" and aria-labelledby (WCAG 1.3.1)', () => {
  assert.match(popup, /role=["']complementary["']/, 'upgrade banner must have role="complementary"');
  assert.match(popup, /aria-labelledby=["']upgrade-heading["']/, 'upgrade banner must be labelled by the upgrade-heading');
  assert.match(popup, /id=["']upgrade-heading["']/, 'upgrade-heading id must exist');
});

test('a11y popup: all <a> links have rel="noopener noreferrer" (security)', () => {
  const links = popup.match(/<a [^>]*>/g) || [];
  assert.ok(links.length > 0, 'popup should have at least one link');
  for (const link of links) {
    assert.match(link, /rel=["'][^"']*noopener[^"']*noreferrer[^"']*["']/,
      `link missing rel="noopener noreferrer": ${link}`);
  }
});

test('a11y popup: h1 is present (WCAG 1.3.1)', () => {
  assert.match(popup, /<h1[^>]*>/, 'popup must have an h1');
});

test('a11y popup: no h2 missing a heading role (heading hierarchy)', () => {
  const h1s = (popup.match(/<h1[^>]*>/g) || []).length;
  const h2s = (popup.match(/<h2[^>]*>/g) || []).length;
  assert.equal(h1s, 1, 'popup must have exactly one h1 (found ' + h1s + ')');
  // h2s allowed (upgrade-heading is a screen-reader-only h2)
  assert.ok(h2s >= 1, 'popup should have at least one h2 for the upgrade section');
});

// ============================================================================
// welcome.html
// ============================================================================
const welcome = read('src/welcome/welcome.html');

test('a11y welcome: <html lang="en"> is present (WCAG 3.1.1)', () => {
  assert.match(welcome, /<html\s+lang=["']en["']/);
});

test('a11y welcome: <title> is present and descriptive (WCAG 2.4.2)', () => {
  const m = welcome.match(/<title>([^<]+)<\/title>/);
  assert.ok(m, '<title> tag must be present');
  assert.ok(m[1].trim().length > 0, '<title> must not be empty');
});

test('a11y welcome: <meta name="viewport"> is present (responsive)', () => {
  assert.match(welcome, /<meta\s+name=["']viewport["']\s+content=/, 'welcome page should have a viewport meta tag');
});

test('a11y welcome: opt-in and dismiss buttons have aria-describedby (WCAG 1.3.1)', () => {
  const optIn = welcome.match(/<button[^>]*id=["']opt-in["'][^>]*>/);
  const dismiss = welcome.match(/<button[^>]*id=["']dismiss["'][^>]*>/);
  assert.ok(optIn, 'opt-in button must exist');
  assert.ok(dismiss, 'dismiss button must exist');
  assert.match(optIn[0], /aria-describedby=["']optin-explainer["']/, 'opt-in button must have aria-describedby="optin-explainer"');
  assert.match(dismiss[0], /aria-describedby=["']optin-explainer["']/, 'dismiss button must have aria-describedby="optin-explainer"');
  // And the optin-explainer paragraph must exist
  assert.match(welcome, /id=["']optin-explainer["']/, 'optin-explainer id must exist');
});

test('a11y welcome: heading hierarchy is correct (one h1, then h2)', () => {
  const h1s = (welcome.match(/<h1[^>]*>/g) || []).length;
  const h2s = (welcome.match(/<h2[^>]*>/g) || []).length;
  assert.equal(h1s, 1, 'welcome must have exactly one h1 (found ' + h1s + ')');
  assert.ok(h2s >= 2, 'welcome should have at least 2 h2s for sections');
});

test('a11y welcome: all <a> links have rel="noopener noreferrer" (security)', () => {
  const links = welcome.match(/<a [^>]*>/g) || [];
  for (const link of links) {
    assert.match(link, /rel=["'][^"']*noopener[^"']*noreferrer[^"']*["']/,
      `welcome link missing rel="noopener noreferrer": ${link}`);
  }
});

// ============================================================================
// banner-ui-html.js
// ============================================================================
const banner = read('src/util/banner-ui-html.js');

test('a11y banner: has data-aegisgate-lens="banner" container (test hook)', () => {
  assert.match(banner, /data-aegisgate-lens=["']banner["']/);
});

test('a11y banner: container has aria-live="polite" (WCAG 4.1.3)', () => {
  assert.match(banner, /aria-live=["']polite["']/, 'banner must announce detection via aria-live');
});

test('a11y banner: all icon-only buttons have aria-label (WCAG 4.1.2)', () => {
  // Find all <button> elements that look like icon-only (no visible text)
  // We approximate "icon-only" as: has class containing "icon" OR has
  // data-action matching one of: primer-dismiss, help, dismiss, false-positive
  const iconButtons = banner.match(/<button[^>]*data-action=["'](primer-dismiss|help|dismiss|false-positive)["'][^>]*>/g) || [];
  assert.ok(iconButtons.length >= 4, 'expected at least 4 icon-only buttons, found ' + iconButtons.length);
  for (const btn of iconButtons) {
    assert.match(btn, /aria-label=/, `icon-only button missing aria-label: ${btn}`);
  }
});

test('a11y banner: all <a> links have rel="noopener noreferrer" (security)', () => {
  const links = banner.match(/<a [^>]*>/g) || [];
  assert.ok(links.length > 0, 'banner should have at least one link');
  for (const link of links) {
    assert.match(link, /rel=["'][^"']*noopener[^"']*noreferrer[^"']*["']/,
      `banner link missing rel="noopener noreferrer": ${link}`);
  }
});

test('a11y banner: image has alt text (WCAG 1.1.1)', () => {
  const images = banner.match(/<img[^>]*>/g) || [];
  assert.ok(images.length > 0, 'banner should have at least one image');
  for (const img of images) {
    assert.match(img, /alt=/, `image missing alt attribute: ${img}`);
  }
});

test('a11y banner: has role="note" or role="region" for landmark structure (WCAG 1.3.1)', () => {
  // The banner has both: role="note" for the primer, role="region" for the detection
  const hasNote = /role=["']note["']/.test(banner);
  const hasRegion = /role=["']region["']/.test(banner);
  assert.ok(hasNote || hasRegion, 'banner should use role="note" or role="region" for landmark structure');
});

// ============================================================================
// banner.css
// ============================================================================
const bannerCss = read('src/util/banner.css');

test('a11y banner.css: has prefers-reduced-motion media query (WCAG 2.3.3, B3 fix)', () => {
  assert.match(bannerCss, /@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)/,
    'banner.css should have a prefers-reduced-motion media query to honor OS-level motion preferences');
});
