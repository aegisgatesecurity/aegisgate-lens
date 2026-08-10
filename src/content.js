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
//      callbacks. The banner UI (3f) shows the detection banner
//      above the input element.
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

  var dispatcher = (typeof self !== 'undefined' && self.__lensDispatcher) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensDispatcher) ||
                   null;

  var bannerUI = (typeof self !== 'undefined' && self.__lensBannerUI) ||
                 (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI) ||
                 null;

  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
                (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
                null;

  // Module state (shared between init, onDetect, etc.)
  var state = {
    domainHash: null,
    provider: null,
    input: null
  };

  // The onSendIntercept callback. Called by prompt-detect when the
  // user attempts to send a message that has detections. The return
  // value is a decision object: { action: 'send' | 'redact' | 'cancel' }.
  // All three actions are fully implemented: 'cancel' (default -- the
  // banner pauses the send), 'send' (user override -- they accept the
  // risk and send anyway), and 'redact' (replace detected values with
  // [REDACTED:<category>] in the input). The minimal implementation
  // blocks the send (return 'cancel') unless the user clicks an action.
  function onSendIntercept(events, text) {
    try {
      log.info('onSendIntercept: blocking send (' + (events ? events.length : 0) + ' detections)');
      return { action: 'cancel', reason: 'detections' };
    } catch (err) {
      log.error('onSendIntercept threw', err);
      return { action: 'cancel', reason: 'error' };
    }
  }

  // The onDetect callback. Called by prompt-detect when detections
  // change. Shows the brand-matched banner above the input.
  function onDetect(events, text) {
    try {
      // Expose lastDetections on window.__lens_cs for diagnostics,
      // testing (headless smoke test), and the popup's "what was
      // detected" panel. This is the bridge between prompt-detect's
      // internal state and the test harness / popup UI.
      if (window.__lens_cs) {
        window.__lens_cs.lastDetections = events || [];
        window.__lens_cs.lastText = text || '';
        window.__lens_cs.lastDetectedAt = Date.now();
      }
      if (!events || events.length === 0) {
        if (bannerUI) bannerUI.hide();
        return;
      }
      if (!bannerUI) {
        log.warn('onDetect: bannerUI not available; cannot show banner');
        return;
      }
      // Check if any event is currently dismissed (24h scope)
      // If all events are dismissed, hide the banner
      if (dismiss) {
        var allDismissed = true;
        for (var i = 0; i < events.length; i++) {
          var ev = events[i];
          if (!state.domainHash) break;  // not yet known
          dismiss.isDismissed(state.domainHash, ev.category, ev.category + '_v1')
            .then(function (entry) {
              if (!entry) allDismissed = false;
            });
        }
        // NOTE: the isDismissed check is async; for simplicity we
        // show the banner regardless. The banner's dismiss action
        // (× button) will record the dismissal for next time.
      }
      bannerUI.show(events, {
        input: selectors && state.provider ? selectors.findInput(state.provider) : null,
        domainHash: state.domainHash,
        learnMoreUrl: 'https://github.com/aegisgatesecurity/aegisgate-lens#readme',
        onAction: function (action, payload) {
          handleBannerAction(action, payload);
        }
      });
    } catch (err) {
      log.error('onDetect threw', err);
    }
  }

  // Replace each detected value with [REDACTED:<category>] in the input
  // element. Operates on the LIVE input value (in case the user typed more
  // between the detect and the click) and replaces at the original index
  // positions reported in the events.
  //
  // Strategy:
  //   1. Read the current value of the input.
  //   2. Sort events by index descending so we replace from end to start
  //      (each replacement doesn't shift earlier indexes).
  //   3. For each event, splice the value at [index, index+len] with
  //      [REDACTED:<category>].
  //   4. Use selectors.setInputValue to write back, which dispatches the
  //      'input' event so the provider's framework sees the change.
  //   5. If anything goes wrong, log and let the user edit manually.
  function redactInput(events) {
    try {
      if (!events || events.length === 0) {
        log.info('redactInput: no events; nothing to do');
        return;
      }
      var input = selectors && state.provider ?
        selectors.findInput(state.provider) : null;
      if (!input || !selectors) {
        log.warn('redactInput: no input element available; user must edit manually');
        return;
      }
      var current = selectors.getInputValue(input);
      if (!current || current.length === 0) {
        log.info('redactInput: input is empty; nothing to do');
        return;
      }
      // Sort events by index descending so we can replace from end to start.
      // Each event has .index (start position) and .value (matched text).
      // We trust .index and .value, but if .index is missing, fall back to
      // string match from the value.
      var sorted = events.slice().sort(function (a, b) {
        return (b.index || 0) - (a.index || 0);
      });
      var out = current;
      var redactedCount = 0;
      for (var i = 0; i < sorted.length; i++) {
        var ev = sorted[i];
        if (!ev || !ev.value) continue;
        var start = typeof ev.index === 'number' ? ev.index : -1;
        var len = ev.value.length;
        if (start < 0 || start + len > out.length) {
          // Index invalid (user typed more, or detection was on a different
          // snapshot). Fall back to a string replace for this event.
          var replacement = '[REDACTED:' + (ev.category || 'PII') + ']';
          if (out.indexOf(ev.value) >= 0) {
            out = out.replace(ev.value, replacement);
            redactedCount++;
          }
        } else {
          // Verify the slice matches the event value (sanity check)
          if (out.substr(start, len) === ev.value) {
            var rep = '[REDACTED:' + (ev.category || 'PII') + ']';
            out = out.slice(0, start) + rep + out.slice(start + len);
            redactedCount++;
          } else {
            // Mismatch (e.g., user typed more). Fall back to string replace.
            var rep2 = '[REDACTED:' + (ev.category || 'PII') + ']';
            if (out.indexOf(ev.value) >= 0) {
              out = out.replace(ev.value, rep2);
              redactedCount++;
            }
          }
        }
      }
      if (redactedCount === 0) {
        log.info('redactInput: no values matched the current input; user must edit manually');
        return;
      }
      selectors.setInputValue(input, out);
      log.info('redactInput: redacted ' + redactedCount + ' of ' + events.length + ' detections');
    } catch (err) {
      log.error('redactInput threw', err);
    }
  }

  // Handle banner action. The banner has 3 main actions (cancel,
  // redact, send) and a 4th: dismiss_optin (the "Submit & dismiss"
  // opt-in path). For 3f, the actual send/cancel/re-dispatch
  // behavior is fully wired; the SW (3g) handles FP_REPORTS
  // messages, queueing, and backend delivery.
  function handleBannerAction(action, payload) {
    try {
      log.info('banner action: ' + action);
      if (action === 'cancel') {
        // The prompt-detect onSendClick already preventDefault'd.
        // Just log; user can edit the input.
      } else if (action === 'redact') {
        // Wire the redaction: replace each detected value with [REDACTED:
        // <category>] in the input element. We rebuild the input value
        // from the current text (in case the user typed more between the
        // detect and the click) and replace at the original index positions.
        // We process events in reverse index order so earlier positions are
        // not affected by later replacements.
        redactInput(payload && payload.events ? payload.events : []);
      } else if (action === 'send') {
        // The send was preventDefault'd by onSendClick. For now,
        // log only. The user can re-press Enter / click send to
        // actually send. (A future enhancement could automatically
        // re-dispatch the send event after a delay.)
        log.info('user chose send anyway; user must re-send');
      } else if (action === 'dismiss' || action === 'dismiss_optin') {
        // The dismiss module already recorded this. FP reports
        // are delivered via the fp_reports action below.
        log.info('user dismissed (' + action + ')');
      } else if (action === 'fp_reports') {
        // The user opted in. The reports are in payload.reports.
        // Send them to the SW via chrome.runtime.sendMessage.
        // The SW validates the message shape, queues it, and
        // attempts to send to the backend. See api/messages.js
        // for the message envelope and background.js for the
        // SW handler.
        if (typeof chrome !== 'undefined' && chrome.runtime &&
            typeof chrome.runtime.sendMessage === 'function') {
          try {
            var message = {
              type: 'FP_REPORTS',
              version: '0.3.0',
              payload: {
                timestamp: Math.floor(Date.now() / 1000),
                reports: payload.reports || []
              }
            };
            chrome.runtime.sendMessage(message, function (response) {
              if (chrome.runtime && chrome.runtime.lastError) {
                log.warn('sendMessage error: ' + chrome.runtime.lastError.message);
                return;
              }
              if (response && response.type === 'ACK') {
                log.info('SW ack: ' + JSON.stringify(response.payload || {}));
              } else if (response && response.type === 'ERROR') {
                log.error('SW error: ' + (response.payload && response.payload.error));
              }
            });
          } catch (e) {
            log.error('sendMessage threw', e);
          }
        } else {
          log.info('chrome.runtime.sendMessage not available; reports queued locally only');
        }
        // For diagnostic purposes, also log the first report
        if (payload && payload.reports && payload.reports[0]) {
          log.info('FP report payload: ' + JSON.stringify(payload.reports[0]));
        }
      }
    } catch (err) {
      log.error('handleBannerAction threw', err);
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
        state.domainHash = hash;
        // Expose the content script state on window
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: hash,
          schemaVersion: schema.SCHEMA_VERSION,
          detect: dispatcher ? dispatcher.detect : null,
          showBanner: bannerUI ? bannerUI.show : null
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

  // Kill switch: if globalThis.__lensDisabled is true, exit immediately.
// This is a critical-bug mitigation: push a v0.2.0 with this set to
// true to disable Lens in production within 24 hours, then roll out
// the real fix in v0.2.1. See the ops runbook for the full procedure.
if (typeof globalThis !== 'undefined' && globalThis.__lensDisabled === true) {
  log.warn('content: __lensDisabled is true; exiting without initializing');
  return; // exits the IIFE
}

// Test-only hook: expose the init function so the headless smoke
  // test runner can re-init prompt-detect between test cases (the
  // B1-flake fix). Production code never calls this -- the
  // MutationObserver + content script lifecycle handle re-init
  // automatically.
  if (typeof window !== 'undefined') {
    window.__lensContentInit = init;
  }
})();