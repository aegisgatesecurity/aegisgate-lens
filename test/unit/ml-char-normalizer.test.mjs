// AegisGate Lens — test/unit/ml-char-normalizer.test.mjs
// Unit tests for the ML character normalizer (src/detectors/ml/char-normalizer.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadModule } from '../helpers/load-module.js';
const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

test('char-normalizer: encode returns Int32Array of length 256', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const result = cn.encode('Hello, world!');
  assert.ok(result instanceof Int32Array, 'encode should return Int32Array');
  assert.equal(result.length, cn.MAX_SEQ_LEN, 'length should be MAX_SEQ_LEN (256)');
});

test('char-normalizer: encode maps printable ASCII to their code points', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const result = cn.encode('AB');
  assert.equal(result[0], 97, 'A (lowercased to "a") should map to code point 97');
  assert.equal(result[1], 98, 'B (lowercased to "b") should map to code point 98');
  assert.equal(result[2], cn.PAD_ID, 'rest should be PAD_ID (0)');
});

test('char-normalizer: encode pads short input with PAD_ID', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const result = cn.encode('Hi');
  // First 2 chars are mapped, rest should be PAD_ID
  assert.equal(result[0], 104, 'h (lowercased) = 104');
  assert.equal(result[1], 105, 'i = 105');
  for (let i = 2; i < cn.MAX_SEQ_LEN; i++) {
    assert.equal(result[i], cn.PAD_ID, `position ${i} should be PAD_ID`);
  }
});

test('char-normalizer: encode truncates long input to 256 chars', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const longText = 'A'.repeat(300);
  const result = cn.encode(longText);
  assert.equal(result.length, 256, 'length should be 256');
  for (let i = 0; i < 256; i++) {
    assert.equal(result[i], 97, 'all chars should be "a" (lowercased) = 97');
  }
});

test('char-normalizer: encode maps Latin-1 chars to their code points', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const result = cn.encode('Héllo');
  // H → 104 (lowercase h), é → 233 (Latin-1 code point), l → 108, l → 108, o → 111
  assert.equal(result[0], 104, 'h = 104');
  assert.equal(result[1], 233, 'é should be Latin-1 code point 233');
  assert.equal(result[2], 108, 'l = 108');
  assert.equal(result[3], 108, 'l = 108');
  assert.equal(result[4], 111, 'o = 111');
});

test('char-normalizer: encode maps non-printable ASCII to UNK_ID', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const result = cn.encode('\x01\x02\x03');
  // Control characters → UNK_ID
  assert.equal(result[0], cn.UNK_ID, 'control char 0x01 → UNK_ID');
  assert.equal(result[1], cn.UNK_ID, 'control char 0x02 → UNK_ID');
  assert.equal(result[2], cn.UNK_ID, 'control char 0x03 → UNK_ID');
});

test('char-normalizer: normalize lowercases input', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  assert.equal(cn.normalize('HELLO WORLD'), 'hello world');
});

test('char-normalizer: normalize strips leading/trailing whitespace', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  assert.equal(cn.normalize('  hello  '), 'hello');
});

test('char-normalizer: normalize collapses multiple whitespace', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  assert.equal(cn.normalize('hello   world'), 'hello world');
});

test('char-normalizer: normalize truncates to 256 chars', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const longText = 'a'.repeat(300);
  const result = cn.normalize(longText);
  assert.equal(result.length, 256, 'normalized text should be truncated to 256 chars');
});

test('char-normalizer: encodeBatch returns correct shape', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const batch = cn.encodeBatch(['hello', 'world']);
  assert.ok(batch.data instanceof Int32Array, 'batch data should be Int32Array');
  assert.equal(batch.dims[0], 2, 'batch size should be 2');
  assert.equal(batch.dims[1], 256, 'sequence length should be 256');
  assert.equal(batch.data.length, 512, 'total elements should be 2 * 256 = 512');
});

test('char-normalizer: decode reverses encode for printable ASCII', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const encoded = cn.encode('hello');
  const decoded = cn.decode(encoded);
  assert.equal(decoded, 'hello', 'decode should reverse encode for printable ASCII');
});

test('char-normalizer: decode skips PAD_ID', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const encoded = cn.encode('hi');
  // After encoding, positions 2-255 are PAD_ID
  // decode should skip them
  const decoded = cn.decode(encoded);
  assert.equal(decoded, 'hi', 'decode should skip PAD_ID positions');
});

test('char-normalizer: decode reverses encode for Latin-1 chars', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  const encoded = cn.encode('héllo');
  const decoded = cn.decode(encoded);
  // With Latin-1 vocab, é (233) should decode back to é
  assert.equal(decoded, 'héllo', 'decode should reverse encode for Latin-1 chars');
});

test('char-normalizer: constants are correct', () => {
  const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  assert.equal(cn.MAX_SEQ_LEN, 256, 'MAX_SEQ_LEN should be 256');
  assert.equal(cn.PAD_ID, 0, 'PAD_ID should be 0');
  assert.equal(cn.UNK_ID, 1, 'UNK_ID should be 1');
  assert.equal(cn.VOCAB_SIZE, 256, 'VOCAB_SIZE should be 256 (Latin-1)');
});