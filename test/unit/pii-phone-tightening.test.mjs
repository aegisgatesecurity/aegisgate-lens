// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - Unit test for pii_phone_intl_loose + _strict regex
// changes (v0.1.3 follow-up to the H2 metrics re-verification).
//
// Per docs/METRICS-v0.1.2.md: pii_phone_intl_loose was 54.4% of all
// WildChat FPs. The fix: tighten the loose regex to exclude "." from
// the inner char class (the worst backtracker) + add a strict pattern
// that requires a phone-format separator (dash/space/parens).
//
// This test extracts the regex strings from the source and uses
// STRING OPERATIONS (not regex matching) to avoid escaping hell.
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

const src = read('src/detectors/regex/pii-us-extended.js');

// Extract the regex literals (they're the value of the re: field
// in the patterns object). Each pattern looks like:
//   name: {
//     ...
//     re: /.../g
//     ...
//   }
function getPattern(name) {
  // Find the pattern block. The regex is on a re: line within ~15
  // lines of the name: line.
  const lines = src.split('\n');
  let i = 0;
  while (i < lines.length) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith(name + ':') && !trimmed.startsWith('//')) {
      // Search the next 15 lines for `re:`
      for (let j = i; j < Math.min(i + 15, lines.length); j++) {
        const m = lines[j].match(/re:\s*(\/[^\/]+\/g[a-z]*)/);
        if (m) return m[1];
      }
    }
    i++;
  }
  return null;
}

const looseRe = getPattern('pii_phone_intl_loose');
const strictRe = getPattern('pii_phone_intl_strict');

test('regex extraction: both loose and strict patterns are in the source', () => {
  assert.ok(looseRe, 'pii_phone_intl_loose must be in the source');
  assert.ok(strictRe, 'pii_phone_intl_strict must be in the source');
});

test('pii_phone_intl_loose: inner char class is tightened (no "." inside, bound 6-12)', () => {
  // The OLD regex had `[\d\s.\-()]{6,18}` (dot inside, bound 6-18).
  // The NEW regex has `[\d\s\-()]{6,12}` (no dot, bound 6-12).
  // The dot in the lookbehind `(?<![\d@+\.])` is allowed.
  // Check: the new char class is present
  assert.ok(looseRe.includes('[\\d\\s\\-()]{6,12}'),
    'pii_phone_intl_loose should have `[\\d\\s\\-()]{6,12}` (no dot, tighter bound). Got: ' + looseRe);
  // Check: the old `[\d\s.\-()]{6,18}` is NOT present
  assert.ok(!looseRe.includes('[\\d\\s.\\-()]{6,18}'),
    'pii_phone_intl_loose should NOT have the old `[\\d\\s.\\-()]{6,18}` class. Got: ' + looseRe);
});

test('pii_phone_intl_strict: has the country-code + separator structure', () => {
  // The strict pattern should have a country code pattern + followed by
  // digits, then separator, then area, etc.
  assert.ok(strictRe.includes('+') && strictRe.includes('\\+'),
    'pii_phone_intl_strict should have a + in the regex. Got: ' + strictRe);
  assert.ok(strictRe.includes('{1,3}'),
    'pii_phone_intl_strict should have {1,3} (country code 1-3 digits). Got: ' + strictRe);
  // Should reject 0x/0X (hex markers) - the lookbehind (?<![xX])
  assert.ok(strictRe.includes('(?<![xX])'),
    'pii_phone_intl_strict should have (?<![xX]) to reject hex markers. Got: ' + strictRe);
});

test('pii_phone_intl_loose: rejects "." in inner char class (the backtracker fix)', () => {
  // Eval the regex and verify it does NOT match inputs that have
  // long runs of dots (the backtracker case).
  const re = new RegExp(looseRe.slice(1, looseRe.lastIndexOf('/')));
  // Build inputs that should not match long digit runs
  const shouldNotMatch = [
    'version 1.2.3.4567.890.123.456.789.012',  // version string with dots
    'api_key sk-1234.5678.9012.3456.7890',   // API key with dots
    'function test_000000000000000',          // unseparated 15 zeros
  ];
  for (const inp of shouldNotMatch) {
    const m = inp.match(re);
    if (m) {
      // The OLD regex would match 15+ digit runs. The NEW regex should
      // not match digit runs > 12 in length (the bound is now 6-12).
      const digitCount = (m[0].match(/\d/g) || []).length;
      assert.ok(digitCount <= 12,
        'WildChat FP sample matched too many digits: ' + inp +
        ' matched ' + JSON.stringify(m) + ' (' + digitCount + ' digits, max should be 12)');
    }
  }
});

test('pii_phone_intl_loose: real phone numbers (unseparated) still match', () => {
  // The NEW regex (bound 6-12) should still match real unseparated
  // international phones in the 7-12 digit range.
  const re = new RegExp(looseRe.slice(1, looseRe.lastIndexOf('/')));
  const realUnseparated = [
    '+447946123456',   // 12 digits + country code
    '+861380013456',   // 12 digits + 86
    '5552671234',      // 10 digits (US)
    '18005551212',     // 11 digits (US toll-free)
  ];
  for (const phone of realUnseparated) {
    const m = phone.match(re);
    assert.ok(m, 'real phone should still match loose: ' + phone + ' got: ' + JSON.stringify(m));
  }
});

test('pii_phone_intl_strict: real international phone numbers (with separators) still match', () => {
  const re = new RegExp(strictRe.slice(1, strictRe.lastIndexOf('/')));
  // International phones with + and separators
  const realPhones = [
    '+1 (415) 555-2671',
    '+44 20 7946 0958',
    '+86 138 0013 4567',
    '+49 30 12345678',
  ];
  for (const phone of realPhones) {
    const m = phone.match(re);
    assert.ok(m, 'real phone should match strict: ' + phone + ' got: ' + JSON.stringify(m));
  }
});

test('pii_phone_intl_strict: code-context FPs (hex, function names) do NOT match', () => {
  const re = new RegExp(strictRe.slice(1, strictRe.lastIndexOf('/')));
  // Note: the strict pattern allows + so a + followed by 7-12 digits
  // WILL match. The improvements over loose are: (a) the lookbehind
  // rejects [xX] (so 0x... doesn't match), (b) the inner char class
  // is more structured (requires separators), (c) the digit count
  // total is 7-12 (vs loose's 7-12 too, but loose allows . in the
  // inner class which strict does NOT).
  const codeFps = [
    'ssl_evp_cipher_fetch 0x000000010e5f5400',  // hex function ptr (0x rejected)
    'function test_000000000000000',            // 15 zeros (too long, > 12)
  ];
  for (const inp of codeFps) {
    const m = inp.match(re);
    assert.ok(!m, 'code FP should NOT match strict: ' + inp + ' got: ' + JSON.stringify(m));
  }
});
