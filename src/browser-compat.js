// AegisGate Lens — browser-compat.js
//
// Firefox MV3 compatibility shim. Loaded as the FIRST content script
// (before logger.js) so every subsequent module sees a consistent
// `chrome.*` namespace.
//
// Firefox 128+ provides `chrome.*` natively with callback support
// (matching Chrome's behavior). This shim covers edge cases where
// only `browser.*` is available (e.g., older Firefox MV3 builds, or
// GeckoView-based browsers that expose `browser.*` but not `chrome.*`).
//
// Important: if `browser.*` is used as a fallback, its APIs return
// Promises instead of using callbacks. This means callback-based code
// would break in that fallback scenario. Firefox 128+ (our target)
// provides `chrome.*` natively, so the fallback is a last resort.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  // If chrome.* is already available (Chrome, Firefox 128+ MV3),
  // this shim is a no-op.
  if (typeof chrome !== 'undefined') return;

  // Firefox MV3 (pre-128) or GeckoView: only browser.* is available.
  // Alias it so the rest of the codebase can use chrome.* uniformly.
  if (typeof browser !== 'undefined') {
    globalThis.chrome = browser;
  }
})();