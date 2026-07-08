// AegisGate Lens — test/unit/regex-secrets.test.mjs
// Unit tests for the Secrets regex detector.
// Uses node:test (built-in, no Jest/Mocha).
//
// Each pattern is tested with positive cases (should detect) and
// negative cases (should NOT detect, no false positives on benign
// text). Severity and category are also asserted.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

function loadModule(srcPath, globalKey) {
  const src = readFileSync(join(LENS_ROOT, srcPath), 'utf8');
  // Each module does (function(global) { ...; globalThis.__lensFoo = module; })(globalThis)
  // We eval it in a scope where globalThis is the Node global, then
  // read back the exposed module.
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis[globalKey];
}

const secretsModule = loadModule('src/detectors/regex/secrets.js', '__lensSecrets');
const patternRegexes = secretsModule.patterns;
