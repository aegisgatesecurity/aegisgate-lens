// AegisGate Lens — util/prompt-detect.js
//
// Per-keystroke detection orchestrator. Aggregates 2 sub-files
// that each own a logical group of helpers:
//
//   prompt-detect-dom.js         (findElements, onInput,
//                                onSendClick, onKeyDown)
//   prompt-detect-lifecycle.js   (attach, detach, onMutation)
//
// The aggregator owns the public API (init, shutdown, getState,
// detectPrompt), the debounce helper, the identifyProvider helper,
// the state object, and the __lensPromptDetect global.
//
// Per the architecture doc Section 9 (SPA MutationObserver pattern),
// modern AI chat UIs are React SPAs that re-mount the input element
// when state changes. document_idle does not fire reliably on these
// pages. The MutationObserver is the canonical fix.
//
// All 3 files (this + 2 sub-files) are loaded in this order in
// manifest.json content_scripts.js; see src/bootstrap.js.
//
// Per the v0.1.1 code-quality plan (item 3: split prompt-detect.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Dependencies: read from globals (set by earlier-loaded modules).
  // -------------------------------------------------------------------------
  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };
  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;
  var dom = (typeof self !== 'undefined' && self.__lensPromptDetect_dom) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect_dom) ||
            null;
  var lifecycle = (typeof self !== 'undefined' && self.__lensPromptDetect_lifecycle) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect_lifecycle) ||
                  null;

  if (!dom) {
    throw new Error('prompt-detect.js: required sub-file not loaded: __lensPromptDetect_dom');
  }
  if (!lifecycle) {
    throw new Error('prompt-detect.js: required sub-file not loaded: __lensPromptDetect_lifecycle');
  }

  // -------------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------------
  var state = {
    provider: null,
    input: null,
    sendButton: null,
    attached: false,
    lastValue: '',
    lastDetections: [],
    onDetect: null,
    onSendIntercept: null,
    observer: null,
    debounceTimer: null,
    _debouncedInput: null
  };

  // -------------------------------------------------------------------------
  // The detection pipeline. Delegates to the 4-facet dispatcher
  // (loaded in pii.js' content_scripts chain). The dispatcher
  // aggregates PII + Secrets + XSS + Compliance (regex facets)
  // and (in v0.2.0+) Toxicity + Prompt-Injection (ML facets).
  // It validates each event against the schema, deduplicates by
  // category, and sorts by severity.
  // -------------------------------------------------------------------------
  function detectPrompt(text) {
    var dispatcher = (typeof self !== 'undefined' && self.__lensDispatcher) ||
                     (typeof globalThis !== 'undefined' && globalThis.__lensDispatcher) ||
                     null;
    if (!dispatcher) {
      log.error('prompt-detect: dispatcher not available; cannot detect');
      return [];
    }
    var result = dispatcher.detect(text);
    // The banner wants the events array (with sample, matches, etc.)
    return result.events;
  }

  // -------------------------------------------------------------------------
  // Debounce helper: schedule fn to run after ms of quiet
  // -------------------------------------------------------------------------
  function debounce(fn, ms) {
    var timer = null;
    return function () {
      var args = arguments;
      var ctx = this;
      if (timer) clearTimeout(timer);
      timer = setTimeout(function () {
        timer = null;
        fn.apply(ctx, args);
      }, ms);
    };
  }

  // -------------------------------------------------------------------------
  // Identify the current provider from the hostname. Returns the
  // matching provider descriptor or null.
  // -------------------------------------------------------------------------
  function identifyProvider() {
    if (!selectors) return null;
    return selectors.identifyProvider();
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------
  function init(opts) {
    opts = opts || {};
    state.onDetect = opts.onDetect || null;
    state.onSendIntercept = opts.onSendIntercept || null;

    state.provider = identifyProvider();
    if (!state.provider) {
      log.warn('no provider identified; prompt-detect will not attach');
      return false;
    }

    dom.findElements(state);
    if (!state.input) {
      log.warn('input not found yet; will retry on mutations');
    } else {
      lifecycle.attach(state, debounce, detectPrompt, function (muts) { lifecycle.onMutation(muts, state, function (s) { lifecycle.attach(s, debounce, detectPrompt, function () {}); }, lifecycle.detach); });
    }

    // Set up the MutationObserver
    try {
      state.observer = new MutationObserver(function (mutations) {
        lifecycle.onMutation(mutations, state,
          function (s) { lifecycle.attach(s, debounce, detectPrompt, function () {}); },
          lifecycle.detach);
      });
      state.observer.observe(document.body, {
        childList: true,
        subtree: true
      });
      log.info('MutationObserver attached on body');
    } catch (err) {
      log.error('failed to create MutationObserver', err);
      return false;
    }

    return true;
  }

  // Shutdown
  function shutdown() {
    try {
      if (state.observer) {
        state.observer.disconnect();
        state.observer = null;
      }
      lifecycle.detach(state);
      state.provider = null;
      state.input = null;
      state.sendButton = null;
      log.info('prompt-detect shut down');
    } catch (err) {
      log.error('shutdown threw', err);
    }
  }

  // For testing: get current state
  function getState() {
    return {
      provider: state.provider ? state.provider.id : null,
      inputAttached: state.attached,
      hasInput: !!state.input,
      hasSendButton: !!state.sendButton,
      lastValue: state.lastValue.substring(0, 50),
      lastDetectionCount: state.lastDetections.length
    };
  }

  var module = {
    init: init,
    shutdown: shutdown,
    getState: getState,
    detectPrompt: detectPrompt
  };

  if (typeof self !== 'undefined') self.__lensPromptDetect = module;
  if (typeof window !== 'undefined') window.__lensPromptDetect = module;
  /**
   * @type {import("./typedefs").LensPromptDetect}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensPromptDetect = module;
  if (typeof globalThis !== 'undefined' && globalThis.__lensConstants) module.__lensConstants = globalThis.__lensConstants;
})(typeof globalThis !== 'undefined' ? globalThis : this);
