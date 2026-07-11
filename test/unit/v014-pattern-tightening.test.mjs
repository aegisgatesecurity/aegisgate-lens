// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - v0.1.4 patch: regression test for the 3 tightened patterns.
//
// Per the user's v0.1.4 patch request (2026-07-10):
//   "Tighten the 3 new patterns (pii_letter_only_id,
//    pii_id_generic_alphanumeric, pii_passport_generic) to reduce
//    the FPR back to ~2.4%."
//
// The fix: all 3 patterns now require an ID-label context
// (id/code/number/ref/license/certificate/document/serial/account).
// This eliminates the FPs from random alphanumerics in prompts
// (DNA sequences, engine numbers, alternators, KPI tables, etc.)
// while preserving the TP rate (real ID codes are always preceded
// by a label).
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

const piiJs = readSource('src/detectors/regex/pii.js');
const piiUsExt = readSource('src/detectors/regex/pii-us-extended.js');

function getPattern(source, name) {
  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === name + ': {') {
      for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
        const m = lines[j].match(/re:\s*(\/[^\/]+\/[gimsuy]*)/);
        if (m) return m[1];
      }
    }
  }
  return null;
}

test('v0.1.4: pii_letter_only_id regex has a context-word lookbehind', () => {
  const re = getPattern(piiUsExt, 'pii_letter_only_id');
  assert.ok(re, 'pii_letter_only_id not found');
  // The tightening: regex must contain a lookbehind with
  // one of the ID label keywords
  assert.ok(/\(\?<=\(\?:id\|code\|number/i.test(re) || /\(\?<=\(\?:passport\|id/i.test(re),
    'pii_letter_only_id regex must have a context-word lookbehind. ' +
    'The v0.1.4 fix: regex should require an ID label (id/code/number/etc.) ' +
    'before the match. Current regex: ' + re);
});

test('v0.1.4: pii_id_generic_alphanumeric regex has a context-word lookbehind', () => {
  const re = getPattern(piiUsExt, 'pii_id_generic_alphanumeric');
  assert.ok(re, 'pii_id_generic_alphanumeric not found');
  assert.ok(/\(\?<=\(\?:id\|code\|number/i.test(re) || /\(\?<=\(\?:passport\|id/i.test(re),
    'pii_id_generic_alphanumeric regex must have a context-word lookbehind. ' +
    'Current regex: ' + re);
});

test('v0.1.4: pii_passport_generic regex has a context-word lookbehind', () => {
  const re = getPattern(piiUsExt, 'pii_passport_generic');
  assert.ok(re, 'pii_passport_generic not found');
  assert.ok(/\(\?<=\(\?:id\|code\|number/i.test(re) || /\(\?<=\(\?:passport\|id/i.test(re),
    'pii_passport_generic regex must have a context-word lookbehind. ' +
    'Current regex: ' + re);
});

test('v0.1.4: pii_letter_only_id is not matched WITHOUT context (regression test)', () => {
  // Sample the actual FPs that were in the v0.1.3 test output:
  //   "5'–CCGCACGGAUAU–3' to dna" -> "CCGCACGGAUAU" should NOT match
  //   "SCZOTYNCUC" alone (no label) should NOT match
  const re = getPattern(piiUsExt, 'pii_letter_only_id');
  // Reconstruct a RegExp from the source string
  const reSrc = re.slice(1, re.lastIndexOf('/'));  // strip /.../g
  const re1 = re.match(/^\/(.*)\/([gimsuy]*)$/);
  const body = re1 ? re1[1] : re;
  const flags = re1 ? re1[2] : 'g';
  const regex = new RegExp(body, flags);

  // FP cases: bare uppercase strings without an ID label
  assert.equal(regex.test('SCZOTYNCUC alone'), false,
    'pii_letter_only_id should NOT match bare uppercase strings without an ID label. ' +
    'The v0.1.4 fix: regex must require an ID label context.');
  assert.equal(regex.test('CCGCACGGAUAU'), false,
    'pii_letter_only_id should NOT match DNA sequences (CCGCACGGAUAU). ' +
    'FP fix test.');

  // TP cases: uppercase strings WITH an ID label
  assert.equal(regex.test('ID SCZOTYNCUC'), true,
    'pii_letter_only_id SHOULD match "ID: SCZOTYNCUC" (TP case).');
  assert.equal(regex.test('passport ABXUHKNRJL'), true,
    'pii_letter_only_id SHOULD match "passport ABXUHKNRJL" (TP case).');
});

test('v0.1.4: pii_id_generic_alphanumeric is not matched WITHOUT context (regression test)', () => {
  const re = getPattern(piiUsExt, 'pii_id_generic_alphanumeric');
  const re1 = re.match(/^\/(.*)\/([gimsuy]*)$/);
  const regex = new RegExp(re1[1], re1[2]);

  // FP cases: bare alphanumerics without an ID label
  //   "Engine number AUM082114" -- "AUM082114" is mid-sentence, not labeled
  //   "A3 1.8T" -- "1.8T" might match if we don't have context
  //   "alternators 2003 A3 1.8T 5DR" -- "5DR" might match
  assert.equal(regex.test('AUM082114 alone'), false,
    'pii_id_generic_alphanumeric should NOT match bare alphanumerics without an ID label. ' +
    'FP fix test.');
  assert.equal(regex.test('5DR'), false,
    'pii_id_generic_alphanumeric should NOT match very short bare alphanumerics. ' +
    '5DR is too short and not labeled.');

  // TP cases: alphanumerics WITH an ID label
  assert.equal(regex.test('Order ID AUM082114'), true,
    'pii_id_generic_alphanumeric SHOULD match "Order ID: AUM082114" (TP case).');
  assert.equal(regex.test('Case A3B2C1'), true,
    'pii_id_generic_alphanumeric SHOULD match "Case A3B2C1" (TP case).');
});

test('v0.1.4: pii_passport_generic is not matched WITHOUT context (regression test)', () => {
  const re = getPattern(piiUsExt, 'pii_passport_generic');
  const re1 = re.match(/^\/(.*)\/([gimsuy]*)$/);
  const regex = new RegExp(re1[1], re1[2]);

  // FP cases: bare 6-9 char alphanumerics without an ID label
  //   "Engine number AUM082114" -- "AUM082114" is mid-sentence
  //   "A3 1.8T 5DR" -- "5DR" is too short
  //   "I0623513" (the original TP example) - this SHOULD match
  //     because it's a passport number
  assert.equal(regex.test('AUM082114 alone'), false,
    'pii_passport_generic should NOT match bare alphanumerics without an ID label. ' +
    'FP fix test.');

  // TP cases
  assert.equal(regex.test('passport number LJL573183'), true,
    'pii_passport_generic SHOULD match "passport number LJL573183" (TP case).');
  assert.equal(regex.test('ID 24WP95966'), true,
    'pii_passport_generic SHOULD match "ID: 24WP95966" (TP case).');
});
