// AegisGate Lens — test/helpers/load-module.js
//
// A clean, no-magic test helper for loading the IIFE-style
// modules from src/ into the Node.js test environment.
//
// Each src/ module follows this pattern:
//
//   (function (global) {
//     'use strict';
//     // ...module body...
//     if (typeof self !== 'undefined') self.__lensFoo = module;
//     if (typeof window !== 'undefined') window.__lensFoo = module;
//     if (typeof globalThis !== 'undefined') globalThis.__lensFoo = module;
//   })(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
//
// This helper reads the source, evals it in the current Node
// context (so globalThis/self/window are all available), and
// returns the exposed module handle.
//
// Why this helper exists (v0.1.1 item 9):
// - Replaces the (0, eval)(src) pattern scattered across 8 test
//   files with a single, documented entry point
// - Centralizes the lint suppression (`$(0, eval)`$ triggers
//   no-eval warnings in stricter configs)
// - Makes the test setup DRY: callers just pass the relative
//   path + the global name
//
// v0.1.3 B2 additions:
// - resetGlobals() clears all known __lens* keys from globalThis,
//   giving tests a clean slate. Previously, tests using loadModule
//   to load the same module twice would see stale state from the
//   first load. With resetGlobals(), each test starts fresh.
// - loadModuleDetailed() returns { value, keys } where keys is
//   the list of __lens* identifiers that were set (or changed)
//   during the load. Tests can assert "loading pii.js set
//   __lensPII and NOT __lensPII_us_core (that's from a sub-file)".
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Resolve LENS_ROOT (the aegisgate-lens project root) relative
 * to this helper file. The helper lives at test/helpers/load-module.js,
 * so LENS_ROOT is two levels up.
 */
export const LENS_ROOT = join(__dirname, '..', '..');

/**
 * The canonical list of __lens* global keys that the Lens
 * modules expose. Used by resetGlobals() and by loadModuleDetailed()
 * to know which keys to track.
 *
 * If you add a new __lens* key to a module, add it here too.
 * The alternative is to scan src/ on every load, but that adds
 * I/O and risks picking up comment fragments. Hardcoding the
 * 30 known keys is more robust.
 */
export const KNOWN_LENS_GLOBALS = ["__lensBannerIcons","__lensBannerUI","__lensBannerUI_formatters","__lensBannerUI_html","__lensBannerUI_lifecycle","__lensBannerUI_getRuntimeUrl","__lensBannerUI_injectStyles","__lensBootstrap","__lensCompliance","__lensConstants","__lensContent","__lensDismiss","__lensDispatcher","__lensDomainHash","__lensLogger","__lensLuhn","__lensMessages","__lensPII","__lensPII_us_core","__lensPII_us_extended","__lensPII_international_id","__lensPII_financial","__lensPromptDetect","__lensPromptDetect_dom","__lensPromptDetect_lifecycle","__lensSW","__lensSchema","__lensSecrets","__lensSelectors","__lensTypedefs","__lensXSS"];

/**
 * Take a snapshot of which __lens* keys are currently set on
 * globalThis. Returns a Set of key names.
 *
 * @returns {Set<string>}
 */
function snapshotLensGlobals() {
  const set = new Set();
  for (const k of KNOWN_LENS_GLOBALS) {
    if (typeof globalThis[k] !== 'undefined') set.add(k);
  }
  return set;
}

/**
 * Reset all known __lens* keys to undefined. Tests should call
 * this in their setup() (or before each subtest) to ensure they
 * start from a clean slate. Without this, a module loaded by
 * one test can leak its state into the next test (e.g., a
 * mocked logger set by test A persists into test B).
 *
 * @returns {string[]} The list of keys that were reset (useful
 *   for assertion in tests: "resetGlobals() cleared 5 keys")
 */
export function resetGlobals() {
  const cleared = [];
  for (const k of KNOWN_LENS_GLOBALS) {
    if (typeof globalThis[k] !== 'undefined') {
      try { delete globalThis[k]; } catch (_) { globalThis[k] = undefined; }
      cleared.push(k);
    }
  }
  return cleared;
}

/**
 * Load a src/ module by reading it and evaluating the IIFE in
 * the current Node.js context. Returns whatever the module
 * exposed on `globalThis[globalKey]`.
 *
 * @param {string} relPath - Path relative to LENS_ROOT
 *   (e.g. 'src/util/selectors.js', 'src/detectors/regex/pii.js')
 * @param {string} globalKey - The name the module assigns to
 *   globalThis (e.g. '__lensSelectors', '__lensPII')
 * @returns {*} The exposed module (or undefined if the module
 *   didn't expose anything by that name)
 */
export function loadModule(relPath, globalKey) {
  const fullPath = join(LENS_ROOT, relPath);
  const src = readFileSync(fullPath, 'utf8');
  // Each module does (function(global) { ...; globalThis.__lensFoo = module; })(globalThis)
  // We eval it in a scope where globalThis is the Node global, then
  // read back the exposed module. The indirect eval (0, eval) is
  // intentional - direct eval() would inherit the local scope,
  // which would not match the production behavior of running in
  // a Chrome content script's global scope.
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis[globalKey];
}

/**
 * Load a module AND report which __lens* keys were set (or
 * changed) during the load. This is the v0.1.3 B2 addition.
 *
 * Use this when you want to assert that loading module X sets
 * exactly the keys you expect. For example:
 *
 *   const r = loadModuleDetailed('src/detectors/regex/pii.js', '__lensPII');
 *   assert.ok(r.value);                          // the __lensPII value
 *   assert.deepEqual(r.keys.sort(), [
 *     '__lensPII',
 *     '__lensPII_us_core',
 *     '__lensPII_us_extended',
 *     '__lensPII_international_id',
 *     '__lensPII_financial',
 *   ]);
 *
 * @param {string} relPath - Path relative to LENS_ROOT
 * @param {string} globalKey - The global key the caller wants
 *   the value of (this is what .value contains)
 * @returns {{ value: *, keys: string[] }} The exposed value
 *   and the list of __lens* keys that were touched during the
 *   load (set for the first time, or overwritten with a new value).
 *   Keys whose value was set to undefined are NOT counted (the
 *   module's IIFE checks typeof and only sets if defined).
 */
export function loadModuleDetailed(relPath, globalKey) {
  // Snapshot which keys are currently set
  const before = snapshotLensGlobals();
  // Capture the BEFORE values for the keys that are set, so we
  // can detect a "set to a NEW value" (not just "set again to
  // the same value").
  const beforeValues = new Map();
  for (const k of before) {
    beforeValues.set(k, globalThis[k]);
  }
  // Do the actual load
  const fullPath = join(LENS_ROOT, relPath);
  const src = readFileSync(fullPath, 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  // Snapshot which keys are now set, and detect new/changed
  const after = snapshotLensGlobals();
  const keys = [];
  for (const k of KNOWN_LENS_GLOBALS) {
    const inBefore = before.has(k);
    const inAfter = after.has(k);
    if (!inBefore && inAfter) {
      // Newly set
      keys.push(k);
    } else if (inBefore && inAfter && beforeValues.get(k) !== globalThis[k]) {
      // Changed
      keys.push(k);
    } else if (!inBefore && !inAfter) {
      // Not set before, not set after - skip
    } else if (inBefore && !inAfter) {
      // Was set, now undefined - not tracked (uncommon, would
      // only happen if the module explicitly deleted a global,
      // which none do)
    }
  }
  return {
    value: globalThis[globalKey],
    keys: keys.sort()
  };
}

/**
 * Load a module without checking for a specific global. Useful
 * for side-effect-only modules (constants.js, typedefs.js,
 * logger.js) where the test doesn't need the return value.
 *
 * @param {string} relPath - Path relative to LENS_ROOT
 * @returns {void}
 */
export function loadSideEffectModule(relPath) {
  const fullPath = join(LENS_ROOT, relPath);
  const src = readFileSync(fullPath, 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
}

/**
 * Load a chain of modules in order. The first call sets up the
 * dependencies; subsequent calls add more. Returns the last
 * module's exposed value (or null if globalKey is not provided
 * for the last entry).
 *
 * Example:
 *   const chain = [
 *     'src/util/constants.js',
 *     'src/util/typedefs.js',
 *     'src/detectors/regex/pii-us-core.js',
 *     'src/detectors/regex/pii-us-extended.js',
 *     'src/detectors/regex/pii-international-id.js',
 *     'src/detectors/regex/pii-financial.js',
 *     'src/detectors/regex/pii.js',
 *   ];
 *   loadChain(chain, '__lensPII');
 *
 * @param {string[]} relPaths - Paths in load order
 * @param {string} [lastGlobalKey] - The global key for the LAST
 *   module in the chain; its value is returned
 * @returns {*}
 */
export function loadChain(relPaths, lastGlobalKey) {
  for (const p of relPaths) {
    loadSideEffectModule(p);
  }
  if (!lastGlobalKey) return null;
  return globalThis[lastGlobalKey];
}

/**
 * Load a chain of modules AND return the combined set of
 * __lens* keys that were touched. Equivalent to calling
 * loadModuleDetailed on the last module after loading the full
 * chain, but uses a single before/after snapshot for accuracy.
 *
 * @param {string[]} relPaths - Paths in load order
 * @param {string} [lastGlobalKey] - The global key for the last module
 * @returns {{ value: *, keys: string[] }}
 */
export function loadChainDetailed(relPaths, lastGlobalKey) {
  const before = snapshotLensGlobals();
  const beforeValues = new Map();
  for (const k of before) beforeValues.set(k, globalThis[k]);
  for (const p of relPaths) {
    const fullPath = join(LENS_ROOT, p);
    const src = readFileSync(fullPath, 'utf8');
    // eslint-disable-next-line no-eval
    (0, eval)(src);
  }
  const after = snapshotLensGlobals();
  const keys = [];
  for (const k of KNOWN_LENS_GLOBALS) {
    const inBefore = before.has(k);
    const inAfter = after.has(k);
    if (!inBefore && inAfter) keys.push(k);
    else if (inBefore && inAfter && beforeValues.get(k) !== globalThis[k]) keys.push(k);
  }
  return {
    value: lastGlobalKey ? globalThis[lastGlobalKey] : null,
    keys: keys.sort()
  };
}
