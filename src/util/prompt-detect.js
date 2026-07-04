// AegisGate Lens — util/prompt-detect.js
// Attaches to the AI provider prompt input and triggers detection
// as the user types. Uses MutationObserver to survive React re-mounts.
//
// Per the architecture doc Section 9 (SPA MutationObserver pattern),
// modern AI chat UIs are React SPAs that re-mount the input element
// when state changes. document_idle does not fire reliably on these
// pages. The MutationObserver is the canonical fix.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;

  // The detection pipeline. The dispatcher (3e) will replace this
  // with a real 6-facet detection. For Step 3d, we just check the
  // PII facet as a smoke test.
  function detectPrompt(text) {
    var pii = (typeof self !== 'undefined' && self.__lensPII) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensPII) ||
              null;
    if (!pii) return [];
    return pii.detect(text);
  }

  // Debounce helper: schedule fn to run after ms of quiet
  function debounce(fn, ms) {
    var timer = null;
    return function () {
      var args = arguments;
      var selfCtx = this;
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(function () {
        timer = null;
        try { fn.apply(selfCtx, args); } catch (e) { log.error('debounced fn threw', e); }
      }, ms);
    };
  }

  // State
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

  // Identify the provider for the current page
  function identifyProvider() {
    if (!selectors) {
      log.error('selectors module not available; cannot identify provider');
      return null;
    }
    var p = selectors.identifyProvider();
    if (p) {
      log.info('identified provider: ' + p.id + ' (' + p.name + ')');
    } else {
      log.warn('no provider matched hostname: ' + (window.location && window.location.hostname));
    }
    return p;
  }

  // Find the current input and send button
  function findElements() {
    if (!state.provider || !selectors) return;
    state.input = selectors.findInput(state.provider);
    state.sendButton = selectors.findSendButton(state.provider);
  }

  // The onInput handler: read the current value, run detection
  function onInput() {
    try {
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value === state.lastValue) return;
      state.lastValue = value;
      if (value.length === 0) {
        state.lastDetections = [];
        if (state.onDetect) {
          try { state.onDetect([], ''); } catch (e) { log.error('onDetect threw', e); }
        }
        return;
      }
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (state.onDetect) {
        try { state.onDetect(dets, value); } catch (e) { log.error('onDetect threw', e); }
      }
    } catch (err) {
      log.error('onInput handler threw', err);
    }
  }

  // The onSendClick handler: intercept the send button click
  function onSendClick(e) {
    try {
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value.length === 0) return;
      // Always re-detect on send (the last keyup might have been
      // before the user finished typing)
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (dets.length > 0 && state.onSendIntercept) {
        // Pause the default action; let the consumer decide
        try { e.preventDefault(); e.stopPropagation(); } catch (e2) { /* ignore */ }
        try {
          var decision = state.onSendIntercept(dets, value);
          if (decision && decision.action === 'send') {
            log.info('user chose to send anyway despite ' + dets.length + ' detections');
            // Re-dispatch on the next tick (we already prevented it)
            setTimeout(function () {
              if (state.sendButton) state.sendButton.click();
            }, 0);
          } else if (decision && decision.action === 'redact') {
            log.info('user chose to redact ' + dets.length + ' detections');
            // Remove the detected values from the input
            var redacted = value;
            for (var i = 0; i < dets.length; i++) {
              redacted = redacted.replace(dets[i].value, '[REDACTED]');
            }
            selectors.setInputValue(state.input, redacted);
          } else {
            log.info('user chose to cancel the send');
          }
        } catch (e3) { log.error('onSendIntercept threw', e3); }
      }
    } catch (err) {
      log.error('onSendClick handler threw', err);
    }
  }

  // The onKeyDown handler for Enter on contenteditable
  function onKeyDown(e) {
    try {
      if (!state.provider) return;
      if (state.provider.submitMethod !== 'enter') return;
      if (e.key !== 'Enter') return;
      if (e.shiftKey) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value.length === 0) return;
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (dets.length > 0 && state.onSendIntercept) {
        try { e.preventDefault(); e.stopPropagation(); } catch (e2) { /* ignore */ }
        try {
          var decision = state.onSendIntercept(dets, value);
          if (decision && decision.action === 'send') {
            log.info('user chose to send anyway despite detections; press Enter again to confirm');
          } else if (decision && decision.action === 'redact') {
            var redacted = value;
            for (var i = 0; i < dets.length; i++) {
              redacted = redacted.replace(dets[i].value, '[REDACTED]');
            }
            selectors.setInputValue(state.input, redacted);
          }
        } catch (e3) { log.error('onSendIntercept (keydown) threw', e3); }
      }
    } catch (err) {
      log.error('onKeyDown handler threw', err);
    }
  }

  // Attach event listeners to the current input + send button
  function attach() {
    if (state.attached) return;
    if (!state.input) return;
    try {
      var debouncedInput = debounce(onInput, 250);
      state.input.addEventListener('input', debouncedInput, true);
      state.input.addEventListener('keyup', debouncedInput, true);
      state.input.addEventListener('keydown', onKeyDown, true);
      if (state.sendButton) {
        state.sendButton.addEventListener('click', onSendClick, true);
      }
      state._debouncedInput = debouncedInput;
      state.attached = true;
      log.info('attached to input' + (state.sendButton ? ' + send button' : ''));
    } catch (err) {
      log.error('attach() threw', err);
    }
  }

  // Detach event listeners
  function detach() {
    if (!state.attached) return;
    try {
      if (state.input) {
        if (state._debouncedInput) {
          state.input.removeEventListener('input', state._debouncedInput, true);
          state.input.removeEventListener('keyup', state._debouncedInput, true);
        }
        state.input.removeEventListener('keydown', onKeyDown, true);
      }
      if (state.sendButton) {
        state.sendButton.removeEventListener('click', onSendClick, true);
      }
      state.attached = false;
      log.info('detached from input');
    } catch (err) {
      log.error('detach() threw', err);
    }
  }

  // The MutationObserver callback: re-attach if the input was replaced
  function onMutation(mutations) {
    try {
      if (!state.provider) return;
      var newInput = selectors.findInput(state.provider);
      if (newInput && newInput !== state.input) {
        log.info('input element changed; re-attaching');
        detach();
        state.input = newInput;
        state.sendButton = selectors.findSendButton(state.provider);
        attach();
      } else if (!newInput && state.input) {
        log.info('input element removed; detaching');
        detach();
        state.input = null;
        state.sendButton = null;
      }
    } catch (err) {
      log.error('onMutation threw', err);
    }
  }

  // Initialize the prompt detector
  function init(opts) {
    opts = opts || {};
    state.onDetect = opts.onDetect || null;
    state.onSendIntercept = opts.onSendIntercept || null;

    state.provider = identifyProvider();
    if (!state.provider) {
      log.warn('no provider identified; prompt-detect will not attach');
      return false;
    }

    findElements();
    if (!state.input) {
      log.warn('input not found yet; will retry on mutations');
    } else {
      attach();
    }

    // Set up the MutationObserver
    try {
      state.observer = new MutationObserver(onMutation);
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
      detach();
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
  if (typeof globalThis !== 'undefined') globalThis.__lensPromptDetect = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
