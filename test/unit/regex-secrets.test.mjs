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

import { loadModule } from '../helpers/load-module.js';
const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

const secretsModule = loadModule('src/detectors/regex/secrets.js', '__lensSecrets');
const patternRegexes = secretsModule.patterns;
