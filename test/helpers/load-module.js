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
// - Centralizes the lint suppression (`(0, eval)` triggers
//   no-eval warnings in stricter configs)
// - Makes the test setup DRY: callers just pass the relative
//   path + the global name
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
  // intentional — direct eval() would inherit the local scope,
  // which would not match the production behavior of running in
  // a Chrome content script's global scope.
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis[globalKey];
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
