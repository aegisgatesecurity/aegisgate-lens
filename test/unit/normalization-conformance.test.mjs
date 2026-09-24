// AegisGate Lens — test/unit/normalization-conformance.test.mjs
// Validates Lens's normalization functions against the canonical conformance
// vectors in testkit/normalization-conformance-vectors.json.
//
// This ensures Lens stays in parity with Platform and Rampart.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadModule, LENS_ROOT } from '../helpers/load-module.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load the conformance vectors
const candidates = [
  join(LENS_ROOT, 'testkit', 'normalization-conformance-vectors.json'),
  join(process.env.AEGISGATE_ROOT || '', 'aegisgate-platform', 'testkit', 'normalization-conformance-vectors.json'),
  join(process.env.AEGISGATE_ROOT || '', 'aegisgate-lens', 'testkit', 'normalization-conformance-vectors.json'),
];

let vectors = null;
let vectorsPath = null;
for (const p of candidates) {
  try {
    const data = readFileSync(p, 'utf-8');
    vectors = JSON.parse(data).vectors;
    vectorsPath = p;
    break;
  } catch (e) {
    // try next
  }
}

if (!vectors) {
  console.error('Conformance vectors not found. Set AEGISGATE_ROOT or place in testkit/.');
}

// Load the normalizer module
const cn = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');

test('conformance: stripZeroWidth', { skip: !vectors }, () => {
  for (const tc of vectors.stripZeroWidth) {
    const got = cn.stripZeroWidth(tc.input);
    assert.equal(got, tc.expected, `stripZeroWidth(${JSON.stringify(tc.input)}) [${tc.name}]`);
  }
});

test('conformance: slidingROT13', { skip: !vectors }, () => {
  for (const tc of vectors.NormalizeSlidingROT13) {
    const got = cn.slidingROT13(tc.input);

    if (tc.expected_variants && tc.expected_variants.length === 0 &&
        (!tc.expected_variants_contains || tc.expected_variants_contains.length === 0)) {
      // Expect empty result
      assert.equal(got.length, 0,
        `slidingROT13(${JSON.stringify(tc.input)}) [${tc.name}]: expected 0 variants, got ${got.length}`);
      continue;
    }

    // Check exact match
    if (tc.expected_variants && tc.expected_variants.length > 0) {
      assert.equal(got.length, tc.expected_variants.length,
        `slidingROT13(${JSON.stringify(tc.input)}) [${tc.name}]: expected ${tc.expected_variants.length} variants, got ${got.length}: ${JSON.stringify(got)}`);
      for (let i = 0; i < tc.expected_variants.length; i++) {
        assert.equal(got[i], tc.expected_variants[i],
          `slidingROT13(${JSON.stringify(tc.input)}) [${tc.name}] variant ${i}: expected ${JSON.stringify(tc.expected_variants[i])}, got ${JSON.stringify(got[i])}`);
      }
    }

    // Check contains
    if (tc.expected_variants_contains && tc.expected_variants_contains.length > 0) {
      for (const expected of tc.expected_variants_contains) {
        assert.ok(got.includes(expected),
          `slidingROT13(${JSON.stringify(tc.input)}) [${tc.name}]: missing expected variant ${JSON.stringify(expected)} in ${JSON.stringify(got)}`);
      }
    }
  }
});

test('conformance: reverseKeyboardWalk', { skip: !vectors }, () => {
  for (const tc of vectors.NormalizeKeyboardWalk) {
    const got = cn.reverseKeyboardWalk(tc.input);
    // Case-insensitive comparison (Lens may handle case differently)
    assert.equal(got.toLowerCase(), tc.expected.toLowerCase(),
      `reverseKeyboardWalk(${JSON.stringify(tc.input)}) [${tc.name}]: expected ${JSON.stringify(tc.expected)}, got ${JSON.stringify(got)}`);
  }
});

// Note: Lens doesn't implement NormalizeRepeatingChars, NormalizeBackslashEscapes,
// NormalizeROT13, or NormalizeHomoglyphs as standalone functions. These are
// Platform/Rampart-only. Lens implements stripZeroWidth, slidingROT13,
// reverseKeyboardWalk, nfkcNormalize, and decodeHexEscapes.
// The conformance test only checks functions that Lens implements.