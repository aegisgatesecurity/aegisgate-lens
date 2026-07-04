// AegisGate Lens — content.js
// Injected into AI provider pages (10 hosts per manifest.json).
//
// This is Step 3a: the MINIMUM VIABLE content script that proves the
// extension loads cleanly in real Chrome. It does NOT yet contain:
//   - The 6-facet dispatcher (added in 3e: detectors/index.js)
//   - The SPA prompt-area MutationObserver (added in 3d: util/prompt-detect.js + selectors.js)
//   - The detection banner UI (added in 3f: util/banner-ui.js)
//   - The ML detection (added in 3h: detectors/ml/*)
//   - The message transport to the service worker (added in 3g: api/messages.js + background.js)
//
// What this file DOES do, today (Step 3a):
//   1. Logs that the content script loaded and on which page
//   2. Verifies the logger and schema are accessible
//   3. Verifies the domain_hash module works
//   4. Exposes a __lens_cs object on `window` so later steps can
//      detect that the content script is loaded
//
// All async work is wrapped in try/catch with REAL error logging.
// We never silently swallow errors.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ console.log('[AegisGate Lens] ' + m); },
              warn: function(m){ console.warn('[AegisGate Lens] ' + m); },
              error: function(m,e){ console.error('[AegisGate Lens] ' + m, e); } };

  var schema = (typeof self !== 'undefined' && self.__lensSchema) ||
               (typeof globalThis !== 'undefined' && globalThis.__lensSchema) ||
               null;

  var domainHash = (typeof self !== 'undefined' && self.__lensDomainHash) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensDomainHash) ||
                   null;

  function init() {
    try {
      log.info('content.js loaded on ' + (window.location && window.location.hostname ? window.location.hostname : '<unknown>'));

      // Verify the modules we depend on are loaded. logger.js is
      // listed first in manifest.json content_scripts so it should
      // always be present, but we check defensively in case a future
      // change reorders the script list.
      if (!schema) {
        log.error('content.js: __lensSchema not available; schema.js failed to load');
        return;
      }
      if (!domainHash) {
        log.error('content.js: __lensDomainHash not available; domain_hash.js failed to load');
        return;
      }

      // Compute the domain hash for this page. This is the value that
      // will be attached to every detection event (per the threat model
      // F-09: hashed locally, never sent in plaintext).
      var hostname = (window.location && window.location.hostname) || '';
      domainHash.computeDomainHash(hostname).then(function (hash) {
        log.info('domain_hash computed: ' + hash + ' for ' + hostname);
        // Expose on window so the dispatcher (3e) and banner (3f) can
        // grab it without re-computing.
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: hash,
          schemaVersion: schema.SCHEMA_VERSION,
          // Placeholder for the 6-facet dispatcher; set in 3e.
          detect: null,
          // Placeholder for the banner UI; set in 3f.
          showBanner: null
        };
        log.info('content.js init complete; __lens_cs is on window');
      }).catch(function (err) {
        log.error('content.js: failed to compute domain_hash', err);
        // Even if hash fails, we still mark the content script as
        // loaded so subsequent steps can detect partial init.
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: null,
          schemaVersion: schema ? schema.SCHEMA_VERSION : null,
          initError: err && err.message ? err.message : String(err)
        };
      });
    } catch (err) {
      log.error('content.js: uncaught error in init()', err);
    }
  }

  // Run init. We use DOMContentLoaded if the script ran before it,
  // otherwise we run immediately. The manifest specifies
  // run_at: document_idle so DOMContentLoaded has already fired.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
