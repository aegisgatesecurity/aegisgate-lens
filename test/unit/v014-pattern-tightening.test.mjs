// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - v0.1.4 patch: regression test for the 3 tightened patterns.
//
// Per the user's v0.1.4 patch request (2026-07-10):
//   "Tighten the 3 new patterns (pii_letter_only_id,
//    pii_id_generic_alphanumeric, pii_passport_generic) to reduce
//    the FPR back to ~2.4%."
//
// The fix: all 3 patterns now require an ID-label context
// (id/code/number/ref/license/certificate/document/serial/account/
// passport) in the postProcess check. This eliminates the FPs from
// random alphanumerics in prompts (DNA sequences, engine numbers,
// alternators, KPI tables, etc.) while preserving the TPs (real ID
// codes are always preceded by a label).
//
// This test was rewritten in v0.1.4 to test the BEHAVIOR (does
// d.detect() return the right result) instead of the regex
// structure (the previous version tested for a lookbehind that
// JavaScript doesn't support well).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadModule } from '../helpers/load-module.js';

// Browser-like globals
globalThis.window = { location: { hostname: 'test.example' } };
globalThis.document = {
  readyState: 'complete',
  addEventListener: () => {},
  querySelectorAll: () => [],
  body: { addEventListener: () => {} }
};
globalThis.MutationObserver = class { constructor() {} observe() {} disconnect() {} };
globalThis.setTimeout = setTimeout;
globalThis.clearTimeout = clearTimeout;
globalThis.Event = class { constructor(type, init) { Object.assign(this, { type, ...init }); } };
globalThis.HTMLTextAreaElement = { prototype: { value: { set: function(v) { this._value = v; } } } };

function loadAll() {
  loadModule('src/util/logger.js', '__lensLogger');
  loadModule('src/detectors/luhn.js', '__lensLuhn');
  loadModule('src/detectors/regex/pii-us-core.js', '__lensPII_us_core');
  loadModule('src/detectors/regex/pii-us-extended.js', '__lensPII_us_extended');
  loadModule('src/detectors/regex/pii-international-id.js', '__lensPII_international_id');
  loadModule('src/detectors/regex/pii-financial.js', '__lensPII_financial');
  loadModule('src/detectors/regex/pii.js', '__lensPII');
  loadModule('src/privacy/schema.js', '__lensSchema');
  loadModule('src/detectors/index.js', '__lensDispatcher');
}

function detectHas(text, category) {
  const r = globalThis.__lensDispatcher.detect(text);
  return r.events.some((e) => e.category === category);
}

// === pii_letter_only_id: FP cases (no ID label) should NOT fire ===
test('v0.1.4: pii_letter_only_id rejects DNA sequences without ID label', () => {
  loadAll();
  assert.equal(detectHas("5'-CCGCACGGAUAU-3' to dna", 'pii_letter_only_id'), false,
    'pii_letter_only_id should NOT match DNA sequences (CCGCACGGAUAU) without an ID label');
});

test('v0.1.4: pii_letter_only_id rejects bare uppercase without ID label', () => {
  loadAll();
  assert.equal(detectHas('SCZOTYNCUC alone', 'pii_letter_only_id'), false,
    'pii_letter_only_id should NOT match bare uppercase strings without an ID label');
});

// === pii_letter_only_id: TP cases (with ID label) should fire ===
test('v0.1.4: pii_letter_only_id matches "ID SCZOTYNCUC"', () => {
  loadAll();
  assert.equal(detectHas('ID SCZOTYNCUC', 'pii_letter_only_id'), true,
    'pii_letter_only_id SHOULD match uppercase strings with "ID" label');
});

test('v0.1.4: pii_letter_only_id matches "passport ABXUHKNRJL"', () => {
  loadAll();
  assert.equal(detectHas('passport ABXUHKNRJL', 'pii_letter_only_id'), true,
    'pii_letter_only_id SHOULD match uppercase strings with "passport" label');
});

// === pii_id_generic_alphanumeric: FP cases should NOT fire ===
test('v0.1.4: pii_id_generic_alphanumeric rejects bare alphanumerics without ID label', () => {
  loadAll();
  assert.equal(detectHas('AUM082114 alone', 'pii_id_generic_alphanumeric'), false,
    'pii_id_generic_alphanumeric should NOT match bare alphanumerics without an ID label');
});

test('v0.1.4: pii_id_generic_alphanumeric rejects short alphanumerics without ID label', () => {
  loadAll();
  assert.equal(detectHas('5DR', 'pii_id_generic_alphanumeric'), false,
    'pii_id_generic_alphanumeric should NOT match very short bare alphanumerics');
});

// === pii_id_generic_alphanumeric: TP cases should fire ===
test('v0.1.4: pii_id_generic_alphanumeric matches "Order ID AUM082114"', () => {
  loadAll();
  assert.equal(detectHas('Order ID AUM082114', 'pii_id_generic_alphanumeric'), true,
    'pii_id_generic_alphanumeric SHOULD match alphanumerics with "Order ID" label');
});

test('v0.1.4: pii_id_generic_alphanumeric matches "Case A3B2C1"', () => {
  loadAll();
  assert.equal(detectHas('Case A3B2C1', 'pii_id_generic_alphanumeric'), true,
    'pii_id_generic_alphanumeric SHOULD match alphanumerics with "Case" label');
});

// === pii_passport_generic: FP cases should NOT fire ===
test('v0.1.4: pii_passport_generic rejects bare alphanumerics without ID label', () => {
  loadAll();
  assert.equal(detectHas('AUM082114 alone', 'pii_passport_generic'), false,
    'pii_passport_generic should NOT match bare alphanumerics without an ID label');
});

// === pii_passport_generic: TP cases should fire ===
test('v0.1.4: pii_passport_generic matches "passport number LJL573183"', () => {
  loadAll();
  assert.equal(detectHas('passport number LJL573183', 'pii_passport_generic'), true,
    'pii_passport_generic SHOULD match alphanumerics with "passport number" label');
});

test('v0.1.4: pii_passport_generic matches "ID 24WP95966"', () => {
  loadAll();
  assert.equal(detectHas('ID 24WP95966', 'pii_passport_generic'), true,
    'pii_passport_generic SHOULD match alphanumerics with "ID" label');
});
