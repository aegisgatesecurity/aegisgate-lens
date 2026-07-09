// AegisGate Lens — util/prompt-detect-dom.js
//
// DOM event handlers for the prompt-detect orchestrator. Owns:
//   - findElements: locate the input/sendButton for the current provider
//   - onInput: per-keystroke detection trigger
//   - onSendClick: intercept the send button click
//   - onKeyDown: intercept Enter on contentEditable inputs
//
// Loaded by prompt-detect.js (the aggregator) BEFORE the lifecycle
// sub-file, so the aggregator's attach() can reference the DOM
// handlers.
//
// Per the v0.1.1 code-quality plan (item 3: split prompt-detect.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Pull in dependencies from the globals set by earlier-loaded modules.
  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  function findElements(state) {
    if (!state.provider || !selectors) return;
    state.input = selectors.findInput(state.provider);
    state.sendButton = selectors.findSendButton(state.provider);
  }

  // v0.1.1 item 19: on-page "Lens active" indicator.
  // Renders a small, unobtrusive chip in the input area so the
  // user knows the Lens is running. The chip is a <span> with
  // [data-aegisgate-lens="indicator"]; the CSS in banner.css
  // positions it absolutely at the bottom-right of the input
  // container. Clicking the chip shows a console.info message
  // (and can be extended to open a small "what this is" popover
  // in v0.2.0).
  function injectIndicator(state) {
    if (typeof document === 'undefined') return;
    if (document.querySelector('[data-aegisgate-lens="indicator"]')) return;
    if (!state.input) return;
    var container = state.input.parentNode;
    if (!container || container.nodeType !== 1) return;
    var indicator = document.createElement('span');
    indicator.setAttribute('data-aegisgate-lens', 'indicator');
    indicator.setAttribute('role', 'status');
    indicator.setAttribute('aria-label', 'AegisGate Lens is active on this page');
    indicator.title = 'AegisGate Lens is active — click for details';
    indicator.innerHTML = '<span class="lens-indicator-shield" aria-hidden="true">🛡️</span> Lens active';
    indicator.addEventListener('click', function (e) {
      try {
        e.preventDefault();
        if (typeof console !== 'undefined' && console.info) {
          console.info('AegisGate Lens is watching this prompt for PII, secrets, and compliance issues. ' +
                       'Click the banner for details. ' +
                       'Opt out: click the dismiss icon on the banner for 24h.');
        }
      } catch (e2) { /* ignore */ }
    }, true);
    // Make sure the container is positioned so the absolute
    // indicator positions relative to it.
    var containerStyle = (typeof window !== 'undefined' && window.getComputedStyle) ?
                         window.getComputedStyle(container) : null;
    if (containerStyle && containerStyle.position === 'static') {
      container.style.position = 'relative';
    }
    container.appendChild(indicator);
  }

  function removeIndicator() {
    if (typeof document === 'undefined') return;
    var el = document.querySelector('[data-aegisgate-lens="indicator"]');
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  // The onInput handler: read the current value, run detection
  // (caller passes in detectPrompt so we can stay decoupled from
  // the aggregator's internal API).
  function onInput(state, detectPrompt) {
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
  function onSendClick(e, state, detectPrompt) {
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
  function onKeyDown(e, state, detectPrompt) {
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

  if (typeof self !== 'undefined') self.__lensPromptDetect_dom = {
    findElements: findElements,
    onInput: onInput,
    onSendClick: onSendClick,
    onKeyDown: onKeyDown,
    injectIndicator: injectIndicator,
    removeIndicator: removeIndicator
  };
  if (typeof window !== 'undefined') window.__lensPromptDetect_dom = {
    findElements: findElements,
    onInput: onInput,
    onSendClick: onSendClick,
    onKeyDown: onKeyDown,
    injectIndicator: injectIndicator,
    removeIndicator: removeIndicator
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPromptDetect_dom = {
      findElements: findElements,
      onInput: onInput,
      onSendClick: onSendClick,
      onKeyDown: onKeyDown,
      injectIndicator: injectIndicator,
      removeIndicator: removeIndicator
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
