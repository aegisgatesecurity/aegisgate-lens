// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - Unit tests for test/helpers/load-module.js (B2)
//
// Tests the v0.1.3 B2 additions:
//   - KNOWN_LENS_GLOBALS is the canonical list of __lens* keys
//   - resetGlobals() clears all __lens* keys from globalThis
//   - loadModuleDetailed() returns { value, keys } with the list
//     of __lens* keys that were touched during the load
//   - loadChainDetailed() returns the combined key list for a chain
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  KNOWN_LENS_GLOBALS,
  LENS_ROOT,
  resetGlobals,
  loadModule,
  loadModuleDetailed,
  loadChain,
  loadChainDetailed,
  loadSideEffectModule,
} from '../helpers/load-module.js';

test('load-module: KNOWN_LENS_GLOBALS is a non-empty array of __lens* keys', () => {
  assert.ok(Array.isArray(KNOWN_LENS_GLOBALS));
  assert.ok(KNOWN_LENS_GLOBALS.length >= 20, 'expected >= 20 __lens* keys, got ' + KNOWN_LENS_GLOBALS.length);
  for (const k of KNOWN_LENS_GLOBALS) {
    assert.equal(typeof k, 'string');
    assert.ok(k.startsWith('__lens'), 'key must start with __lens: ' + k);
    assert.ok(k.length > 7, 'key must have a module name after __lens: ' + k);
  }
  // No duplicates
  assert.equal(new Set(KNOWN_LENS_GLOBALS).size, KNOWN_LENS_GLOBALS.length, 'no duplicates');
});

test('load-module: LENS_ROOT points at the aegisgate-lens repo root', () => {
  assert.ok(typeof LENS_ROOT === 'string');
  // The repo root should contain both src/ and test/
  assert.ok(existsSync(join(LENS_ROOT, 'src', 'util', 'logger.js')),
    'LENS_ROOT should contain src/util/logger.js');
  assert.ok(existsSync(join(LENS_ROOT, 'test', 'unit')),
    'LENS_ROOT should contain test/unit/');
});

test('load-module: resetGlobals returns the list of cleared keys (may be empty)', () => {
  // Clean slate first
  const initial = resetGlobals();
  assert.ok(Array.isArray(initial));

  // Load a module that sets __lensConstants
  loadModule('src/util/constants.js', '__lensConstants');
  assert.ok(typeof globalThis.__lensConstants !== 'undefined');

  // Now reset - should clear at least __lensConstants
  const cleared = resetGlobals();
  assert.ok(cleared.includes('__lensConstants'),
    'resetGlobals should include __lensConstants in the cleared list, got: ' + cleared.join(','));
  assert.equal(typeof globalThis.__lensConstants, 'undefined',
    'globalThis.__lensConstants should be undefined after resetGlobals');
});

test('load-module: resetGlobals is idempotent (resetting twice is safe)', () => {
  resetGlobals();
  loadModule('src/util/constants.js', '__lensConstants');
  resetGlobals();
  const second = resetGlobals();
  // Second reset should be a no-op (or near no-op)
  assert.ok(Array.isArray(second));
  assert.equal(typeof globalThis.__lensConstants, 'undefined');
});

test('load-module: loadModule returns the value at the requested globalKey', () => {
  resetGlobals();
  const v = loadModule('src/util/constants.js', '__lensConstants');
  assert.ok(v);
  // The constants module should have a STORAGE_KEYS export
  assert.ok(v.STORAGE_KEYS);
  assert.equal(typeof v.STORAGE_KEYS.OPT_IN, 'string');
});

test('load-module: loadModuleDetailed returns { value, keys }', () => {
  resetGlobals();
  const r = loadModuleDetailed('src/util/constants.js', '__lensConstants');
  assert.ok(r);
  assert.ok(typeof r === 'object');
  assert.ok('value' in r, 'should have .value');
  assert.ok('keys' in r, 'should have .keys');
  assert.ok(Array.isArray(r.keys));
  assert.ok(r.keys.includes('__lensConstants'),
    'keys should include __lensConstants, got: ' + r.keys.join(','));
  assert.equal(r.value, globalThis.__lensConstants);
});

test('load-module: loadModuleDetailed detects only the keys actually set by the load', () => {
  resetGlobals();
  // Load constants - should set only __lensConstants
  const r1 = loadModuleDetailed('src/util/constants.js', '__lensConstants');
  assert.deepEqual(r1.keys, ['__lensConstants']);

  // Now load logger - should set only __lensLogger (not __lensConstants)
  const r2 = loadModuleDetailed('src/util/logger.js', '__lensLogger');
  assert.deepEqual(r2.keys, ['__lensLogger']);

  // Now load pii-us-core - should set only __lensPII_us_core
  const r3 = loadModuleDetailed('src/detectors/regex/pii-us-core.js', '__lensPII_us_core');
  assert.deepEqual(r3.keys, ['__lensPII_us_core']);
});

test('load-module: loadModuleDetailed detects re-loading a module (new object reference)', () => {
  resetGlobals();
  loadModule('src/util/constants.js', '__lensConstants');
  const oldRef = globalThis.__lensConstants;
  // Re-load - the IIFE runs again and creates a NEW module object.
  // The new object has the same KEY-VALUES (e.g., STORAGE_KEYS.OPT_IN
  // is still 'aegisgate_lens_opt_in') but a different REFERENCE.
  // Our detection uses reference equality, so it flags the key as
  // "changed". This is the correct behavior for the B2 design
  // (callers who want to assert "this module was just loaded" can
  // do so without first calling resetGlobals).
  const r = loadModuleDetailed('src/util/constants.js', '__lensConstants');
  assert.deepEqual(r.keys, ['__lensConstants']);
  assert.notEqual(r.value, oldRef, 're-loading should create a new object reference');
  // But the values inside should be equal
  assert.equal(r.value.STORAGE_KEYS.OPT_IN, oldRef.STORAGE_KEYS.OPT_IN);
});

test('load-module: loadModuleDetailed for pii.js aggregator returns all sub-file keys', () => {
  resetGlobals();
  // pii.js requires the 4 sub-files + constants + typedefs to be loaded
  // first (it does loadSubFile() at the top of its IIFE). But we
  // haven't loaded them. The IIFE will run but the loadSubFile calls
  // will throw "no __lensPII_us_core" - which is caught and logged.
  // The aggregator itself still sets __lensPII, so let's just check
  // that.
  //
  // Actually, looking at the dispatcher: the IIFE does:
  //   var us_core = loadSubFile('__lensPII_us_core');
  //   if (!us_core) { log.error(...); return; }
  // So if the sub-file isn't loaded, pii.js returns WITHOUT setting
  // __lensPII. We need to load the chain.
  //
  // Use loadChainDetailed instead for this case.
  const chain = [
    'src/util/constants.js',
    'src/util/typedefs.js',
    'src/util/logger.js',
    'src/detectors/luhn.js',
    'src/detectors/regex/pii-us-core.js',
    'src/detectors/regex/pii-us-extended.js',
    'src/detectors/regex/pii-international-id.js',
    'src/detectors/regex/pii-financial.js',
    'src/detectors/regex/pii.js',
  ];
  const r = loadChainDetailed(chain, '__lensPII');
  assert.ok(r.value, 'chain should produce a __lensPII value');
  // The keys should include the 4 sub-file keys + the aggregator
  const expectedSubKeys = [
    '__lensPII_us_core',
    '__lensPII_us_extended',
    '__lensPII_international_id',
    '__lensPII_financial',
    '__lensPII',
  ];
  for (const k of expectedSubKeys) {
    assert.ok(r.keys.includes(k), 'keys should include ' + k + ', got: ' + r.keys.join(','));
  }
  // And the dependency chain
  assert.ok(r.keys.includes('__lensConstants'));
  assert.ok(r.keys.includes('__lensLogger'));
  assert.ok(r.keys.includes('__lensLuhn'));
});

test('load-module: loadChain returns the last module value (backward-compat)', () => {
  resetGlobals();
  const v = loadChain(['src/util/constants.js'], '__lensConstants');
  assert.ok(v);
  assert.ok(v.STORAGE_KEYS);
});

test('load-module: loadSideEffectModule works without a return value', () => {
  resetGlobals();
  // No return; just verify the side effect happened
  loadSideEffectModule('src/util/constants.js');
  assert.ok(globalThis.__lensConstants);
});
