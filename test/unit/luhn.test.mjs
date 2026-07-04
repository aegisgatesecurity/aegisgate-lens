// AegisGate Lens — test/unit/luhn.test.mjs
// Unit tests for the Luhn credit card validator.
// Uses node:test (built-in, no Jest/Mocha).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// Load the luhn module by sourcing it into the global scope.
// The luhn.js is a classic-script that exposes `__lensLuhn` on
// globalThis. In a browser, globalThis is window; in Node, it's
// the Node global. We use eval to run the script in the current
// scope (NOT inside a wrapper IIFE, which would shadow the `module`
// variable with Node's CommonJS `module`).
function loadLuhn() {
  const src = readFileSync(join(LENS_ROOT, 'src/detectors/luhn.js'), 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis.__lensLuhn;
}

const luhn = loadLuhn();
if (!luhn) {
  throw new Error('Failed to load luhn module: globalThis.__lensLuhn is undefined');
}

test('luhn: valid Visa test card', () => {
  // 4111-1111-1111-1111 is the standard test card
  assert.equal(luhn.luhnCheck('4111111111111111'), true);
});

test('luhn: valid Visa with dashes', () => {
  assert.equal(luhn.luhnCheck('4111-1111-1111-1111'), true);
});

test('luhn: valid Visa with spaces', () => {
  assert.equal(luhn.luhnCheck('4111 1111 1111 1111'), true);
});

test('luhn: valid Mastercard test card', () => {
  // 5500-0000-0000-0004
  assert.equal(luhn.luhnCheck('5500000000000004'), true);
});

test('luhn: valid Amex test card', () => {
  // 3782-822463-10005
  assert.equal(luhn.luhnCheck('378282246310005'), true);
});

test('luhn: rejects random 16-digit number', () => {
  // 1234-5678-9012-3456 fails Luhn
  assert.equal(luhn.luhnCheck('1234567890123456'), false);
});

test('luhn: rejects too-short input', () => {
  assert.equal(luhn.luhnCheck('4111'), false);
  assert.equal(luhn.luhnCheck('411111111111'), false);
});

test('luhn: rejects too-long input', () => {
  assert.equal(luhn.luhnCheck('41111111111111111111'), false);
});

test('luhn: rejects non-digit input', () => {
  assert.equal(luhn.luhnCheck('4111-1111-1111-111X'), false);
  assert.equal(luhn.luhnCheck('abcd-efgh-ijkl-mnop'), false);
});

test('luhn: rejects null/undefined', () => {
  assert.equal(luhn.luhnCheck(null), false);
  assert.equal(luhn.luhnCheck(undefined), false);
});

test('luhn: identifyCard detects Visa', () => {
  assert.equal(luhn.identifyCard('4111111111111111'), 'visa');
});

test('luhn: identifyCard detects Mastercard', () => {
  assert.equal(luhn.identifyCard('5500000000000004'), 'mastercard');
});

test('luhn: identifyCard detects Amex', () => {
  assert.equal(luhn.identifyCard('378282246310005'), 'amex');
});

test('luhn: identifyCard returns null for unknown', () => {
  assert.equal(luhn.identifyCard('6011000000000000'), 'discover');
  // A weird prefix
  assert.equal(luhn.identifyCard('0000000000000000'), null);
});

test('luhn: validateCard returns both', () => {
  var v = luhn.validateCard('4111111111111111');
  assert.equal(v.valid, true);
  assert.equal(v.type, 'visa');
});

test('luhn: validateCard with dashes', () => {
  var v = luhn.validateCard('5500-0000-0000-0004');
  assert.equal(v.valid, true);
  assert.equal(v.type, 'mastercard');
});

test('luhn: rejects non-Luhn even with valid IIN', () => {
  // Valid Visa IIN, but invalid Luhn
  var v = luhn.validateCard('4111111111111112');
  assert.equal(v.valid, false);
});
