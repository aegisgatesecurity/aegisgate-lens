// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - F-1 isolation test (v0.1.2 fix verification)
//
// F-1 (commit 7b78135): pii_phone_intl_loose digit bound 15 -> 13.
// This was a defensive fix to reject 14+ digit unseparated digit
// runs (IBAN body matches). Without this fix, the v0.1.2 release
// would have a regression on the F-1 measurement (the 6,500-prompt
// WildChat FPR would re-introduce 14-15 digit matches).
//
// Per pt3.md's Tier 1 list: "Add a unit test that asserts the F-1
// fix is in place" -- this is that test.
//
// This test is source-based (no module loading) so it runs fast
// and doesn't depend on the bundle being built.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

function readSource(path) {
  return readFileSync(join(LENS_ROOT, path), 'utf8');
}

// === F-1 isolation: the digit bound is 13 (not 15) ===
test('F-1 isolation: pii_phone_intl_loose digit bound is 13 (not 15)', () => {
  const pii = readSource('src/detectors/regex/pii.js');
  // The F-1 fix is on the line in the pii_phone_intl_loose postProcess
  // block: `if (digits < 7 || digits > 13) return null;`
  // The original v0.1.0-beta was: `if (digits < 7 || digits > 15)`
  //
  // The fix should be in the pii_phone_intl_loose block specifically,
  // not anywhere else (e.g., the pii_bip39_seed or pii_credit_card
  // blocks have different bounds).
  //
  // We extract the pii_phone_intl_loose block by finding the
  // `if (category === 'pii_phone_intl_loose')` open and the
  // matching `}` close.
  const blockMatch = pii.match(/if \(category === 'pii_phone_intl_loose'\) \{([\s\S]+?)\n  \}/);
  assert.ok(blockMatch, 'pii_phone_intl_loose postProcess block not found in pii.js');
  const block = blockMatch[1];
  // The F-1 line should be in this block
  assert.ok(/digits < 7 \|\| digits > 13\) return null;/.test(block),
    'F-1 fix not in pii_phone_intl_loose block. The digit bound must be > 13 (not > 15). ' +
    'Block content: ' + block);
  // The F-1 regression: the bound is 15 (pre-fix)
  assert.ok(!/digits < 7 \|\| digits > 15\) return null;/.test(block),
    'F-1 has been REVERTED. The digit bound is back to > 15 (pre-fix). ' +
    'Block content: ' + block);
});

// === F-2 isolation: the opt-in storage key is the canonical STORAGE_KEYS.OPT_IN ===
// (This was supposed to be covered by opt-in-storage.test.mjs, but
// we add a minimal F-2 assertion here too for defense in depth.)
test('F-2 isolation: opt-in storage key is the canonical STORAGE_KEYS.OPT_IN', () => {
  const welcome = readSource('src/welcome/welcome.js');
  const popup = readSource('src/popup/popup.js');
  const background = readSource('src/background.js');

  // The F-2 fix: all 3 modules use STORAGE_KEYS.OPT_IN (or a literal
  // fallback to 'aegisgate_lens_opt_in'), not a bare 'opt_in' key.
  const canonical = 'aegisgate_lens_opt_in';

  // welcome.js writes the canonical key (or via constants)
  const welcomeUsesCanonical = welcome.includes(canonical) || welcome.includes('STORAGE_KEYS.OPT_IN');
  assert.ok(welcomeUsesCanonical,
    'welcome.js must reference the canonical opt-in key. ' +
    'The F-2 fix: all 3 modules must use aegisgate_lens_opt_in (not opt_in).');

  // popup.js reads the canonical key (or via constants)
  const popupUsesCanonical = popup.includes(canonical) || popup.includes('STORAGE_KEYS.OPT_IN');
  assert.ok(popupUsesCanonical,
    'popup.js must reference the canonical opt-in key. ' +
    'The F-2 fix: all 3 modules must use aegisgate_lens_opt_in (not opt_in).');

  // background.js uses the canonical key (or via constants)
  const backgroundUsesCanonical = background.includes(canonical) || background.includes('STORAGE_KEYS.OPT_IN');
  assert.ok(backgroundUsesCanonical,
    'background.js must reference the canonical opt-in key. ' +
    'The F-2 fix: all 3 modules must use aegisgate_lens_opt_in (not opt_in).');

  // No module writes the legacy bare 'opt_in' key
  const welcomeWritesBare = /opt_in:\s*\{/.test(welcome);
  const popupReadsBare = /get\(\[\s*['"]opt_in['"]\s*\]\)/.test(popup);
  assert.ok(!welcomeWritesBare,
    'welcome.js must NOT write to a bare "opt_in" key (F-2 regression).');
  assert.ok(!popupReadsBare,
    'popup.js must NOT read a bare "opt_in" key (F-2 regression).');
});

// === F-10 isolation: popup uses chrome.runtime.sendMessage, not direct storage ===
test('F-10 isolation: popup uses chrome.runtime.sendMessage (GET_OPT_IN_STATE)', () => {
  const popup = readSource('src/popup/popup.js');
  // F-10: popup.js uses chrome.runtime.sendMessage (GET_OPT_IN_STATE)
  // as the primary path, NOT direct chrome.storage.local.get.
  assert.ok(popup.includes('chrome.runtime.sendMessage'),
    'popup.js must use chrome.runtime.sendMessage (F-10 primary path). ' +
    'The F-10 fix: popup must ask the SW for opt-in state via sendMessage.');
  assert.ok(popup.includes('GET_OPT_IN_STATE'),
    'popup.js must send GET_OPT_IN_STATE message (F-10 contract).');
});

// === Schema fix (v0.1.3 commit f5ad946): missing categories are present ===
// The v0.1.2 bundle emitted 11+ categories that weren't in the
// schema's VALID_CATEGORIES map. The schema fix added them.
// This test asserts the schema fix is in place.
test('Schema fix (f5ad946): pii_letter_only_id is in the schema', () => {
  const schema = readSource('src/privacy/schema.js');
  assert.ok(schema.includes('pii_letter_only_id'),
    'pii_letter_only_id must be in src/privacy/schema.js. ' +
    'The schema fix (f5ad946) added this category. Without it, the dispatcher ' +
    'drops the event entirely.');
});
test('Schema fix (f5ad946): pii_credit_card_loose is in the schema', () => {
  const schema = readSource('src/privacy/schema.js');
  assert.ok(schema.includes('pii_credit_card_loose'),
    'pii_credit_card_loose must be in src/privacy/schema.js. ' +
    'The schema fix (f5ad946) added this category.');
});
test('Schema fix (f5ad946): pii_id_generic_alphanumeric is in the schema', () => {
  const schema = readSource('src/privacy/schema.js');
  assert.ok(schema.includes('pii_id_generic_alphanumeric'),
    'pii_id_generic_alphanumeric must be in src/privacy/schema.js. ' +
    'The schema fix (f5ad946) added this category.');
});

// === Manifest fix (F-1 / B5): the root manifest.json has the right host paths ===
test('Manifest fix: root manifest.json icons use bare paths (no src/ prefix)', () => {
  // Read the root manifest.json (B5 found a stale src/ prefix in
  // icons entries). The fix is that the icons use bare paths like
  // icons/icon-16.png, not src/icons/icon-16.png.
  const manifest = readSource('manifest.json');
  // The manifest has both an "icons" key (for the extension icon)
  // and an "action.default_icon" key (for the toolbar icon).
  // Both should have bare paths.
  const iconsBlock = manifest.match(/"icons":\s*\{([\s\S]+?)\}/);
  assert.ok(iconsBlock, '"icons" block not found in manifest.json');
  const iconsContent = iconsBlock[1];
  assert.ok(!/src\//.test(iconsContent),
    'root manifest.json icons block has a "src/" prefix. ' +
    'The B5 fix: icons should use bare paths (e.g., icons/icon-16.png).');
});
