// AegisGate Lens — content.js
// Injected into AI provider pages (10 hosts per manifest.json).
//
// Step 3d: this content script now wires up the SPA-aware prompt
// detector. The detectors (3b/3c) and selectors (3d) are loaded
// before this file in the manifest content_scripts array.
//
// What this file does:
//   1. Logs that the content script loaded and on which page
//   2. Verifies the logger, schema, and domain_hash modules are loaded
//   3. Computes the domain hash for telemetry
//   4. Initializes prompt-detect with onDetect + onSendIntercept
//      callbacks. The banner UI (3f) will replace the placeholder
//      console.log with a real banner element.
//   5. Exposes __lens_cs on window for diagnostics
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

  var promptDetect = (typeof self !== 'undefined' && self.__lensPromptDetect) ||
                     (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect) ||
                     null;

  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;

  // The onDetect callback. Called by prompt-detect when detections
  // change. The `result` is a DetectionResult from the dispatcher:
  //   {
  //     text: string,
  //     hasDetections: boolean,
  //     count: number,
  //     maxSeverity: 'critical' | 'high' | 'medium' | 'low' | null,
  //     events: [DetectionEvent]
  //   }
  //
  // For 3d, we just log a summary. The banner UI (3f) will replace
  // this with a real banner element.
  function onDetect(events, text) {
    try {
      if (events && events.length > 0) {
        // Group by severity for a quick summary
        var crit = 0, high = 0, med = 0, low = 0;
        for (var i = 0; i < events.length; i++) {
          if (events[i].severity === 'critical') crit++;
          else if (events[i].severity === 'high') high++;
          else if (events[i].severity === 'medium') med++;
          else low++;
        }
        log.info('detected ' + events.length + ' items (crit=' + crit + ' high=' + high + ' med=' + med + ' low=' + low + ')');
        // TODO(3f): show banner
      }
    } catch (err) {
      log.error('onDetect threw', err);
    }
  }

  // The onSendIntercept callback. Called when the user tries to
  // send a prompt that has detections. Returns one of:
  //   { action: 'send' }   - user wants to send anyway
  //   { action: 'redact' } - user wants to redact
  //   { action: 'cancel' } - user wants to cancel the send
  //
  // For 3d, we use confirm() as a placeholder. The banner UI
  // (3f) will replace this with proper UI buttons.
  function onSendIntercept(events, text) {
    try {
      // Summarize what was found
      var summary = events.length + ' item(s) detected:\n';
      for (var i = 0; i < Math.min(events.length, 5); i++) {
        summary += '  - [' + events[i].severity + '] ' + events[i].category + '\n';
      }
      if (events.length > 5) summary += '  ... and ' + (events.length - 5) + ' more\n';
      summary += '\nOK = send anyway, Cancel = cancel the send';
      // NOTE: confirm() is a placeholder for 3d. The banner UI
      // (3f) will replace this with proper UI.
      var ok = window.confirm(summary);
      if (ok) return { action: 'send' };
      return { action: 'cancel' };
    } catch (err) {
      log.error('onSendIntercept threw', err);
      return { action: 'cancel' };
    }
  }

  function init() {
    try {
      log.info('content.js loaded on ' + (window.location && window.location.hostname ? window.location.hostname : '<unknown>'));

      // Verify modules
      if (!schema) {
        log.error('content.js: __lensSchema not available; schema.js failed to load');
        return;
      }
      if (!domainHash) {
        log.error('content.js: __lensDomainHash not available; domain_hash.js failed to load');
        return;
      }
      if (!selectors) {
        log.error('content.js: __lensSelectors not available; selectors.js failed to load');
        return;
      }
      if (!promptDetect) {
        log.error('content.js: __lensPromptDetect not available; prompt-detect.js failed to load');
        return;
      }

      // Compute the domain hash
      var hostname = (window.location && window.location.hostname) || '';
      domainHash.computeDomainHash(hostname).then(function (hash) {
        // Expose the content script state on window
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

        // Initialize the prompt detector with our callbacks
        var ok = promptDetect.init({
          onDetect: onDetect,
          onSendIntercept: onSendIntercept
        });
        if (ok) {
          log.info('content.js init complete; prompt-detect attached');
        } else {
          log.warn('content.js init complete; prompt-detect failed (no provider)');
        }
      }).catch(function (err) {
        log.error('content.js: failed to compute domain_hash', err);
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

  // Run init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
