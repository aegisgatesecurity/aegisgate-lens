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

  // -----------------------------------------------------------------
  // v0.1.4: "Pause Lens for 1h / 1d" toggle state.
  //
  // Cached timestamp (ms since epoch) at which the pause expires.
  // When Date.now() < _pausedUntil, onInput() early-returns BEFORE
  // running the 4-facet regex scan — detection is suppressed
  // globally across all domains, categories, and patterns.
  //
  // Default 0 (not paused). When the user clicks "Pause for 1h" in
  // the popup, the popup writes Date.now() + 3600000 to
  // chrome.storage.local. The onChanged listener updates the
  // cache in real-time. The pause auto-expires — when Date.now() >=
  // _pausedUntil, detection resumes automatically. No manual
  // "unpause" action needed.
  //
  // Different semantic from the per-domain 24h dismiss (dismiss.js):
  // pause is global, dismiss is per-domain per-category. Pause is
  // for "I'm testing prompts, suppress all detection"; dismiss is
  // for "this specific detection is wrong, don't show it again
  // for 24h on this domain".
  //
  // The constants module is NOT imported here (this file loads
  // before constants in the bundle order per bootstrap.js), so we
  // hardcode the key as a fallback. The canonical key is in
  // src/util/constants.js STORAGE_KEYS.PAUSE_UNTIL.
  // -----------------------------------------------------------------
  var _pausedUntil = 0;
  var PAUSE_UNTIL_KEY = 'aegisgate_lens_pause_until';
  function _loadPausedUntil() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
      chrome.storage.local.get([PAUSE_UNTIL_KEY], function (result) {
        try {
          if (result && Object.prototype.hasOwnProperty.call(result, PAUSE_UNTIL_KEY)) {
            var v = result[PAUSE_UNTIL_KEY];
            _pausedUntil = (typeof v === 'number' && v > 0) ? v : 0;
          }
        } catch (e) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }
  _loadPausedUntil();
  // v0.1.4: react to popup pause changes in real-time.
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;
        if (changes && changes[PAUSE_UNTIL_KEY]) {
          var nv = changes[PAUSE_UNTIL_KEY].newValue;
          _pausedUntil = (typeof nv === 'number' && nv > 0) ? nv : 0;
        }
      });
    }
  } catch (e) { /* ignore */ }

  // -----------------------------------------------------------------
  // v0.1.4: "Hide Lens active indicator" toggle state.
  //
  // Cached at module init from chrome.storage.local, with a
  // chrome.storage.onChanged listener that updates the cache in
  // real-time if the user toggles the popup setting while the
  // content script is running. The cache is consulted by
  // injectIndicator() — if disabled, the on-page "🛡️ Lens active"
  // chip is never rendered.
  //
  // Default ON (show indicator). If the storage read fails (e.g.,
  // chrome.storage unavailable in a test env), we default to ON
  // for safety — a missing toggle should not silently hide the
  // indicator.
  //
  // The constants module is NOT imported here (this file loads
  // before constants in the bundle order per bootstrap.js), so we
  // hardcode the key as a fallback. The canonical key is in
  // src/util/constants.js STORAGE_KEYS.SHOW_INDICATOR.
  // -----------------------------------------------------------------
  var _showIndicator = true;
  var SHOW_INDICATOR_KEY = 'aegisgate_lens_show_indicator';
  function _loadShowIndicator() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
      chrome.storage.local.get([SHOW_INDICATOR_KEY], function (result) {
        try {
          if (result && Object.prototype.hasOwnProperty.call(result, SHOW_INDICATOR_KEY)) {
            _showIndicator = result[SHOW_INDICATOR_KEY] !== false;
          }
        } catch (e) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }
  _loadShowIndicator();
  // v0.1.4: react to popup toggle in real-time. The popup writes
  // directly to chrome.storage.local, which fires onChanged in the
  // content script's storage area.
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;
        if (changes && changes[SHOW_INDICATOR_KEY]) {
          _showIndicator = changes[SHOW_INDICATOR_KEY].newValue !== false;
        }
      });
    }
  } catch (e) { /* ignore */ }

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
    // v0.1.4: respect the "Hide Lens active indicator" popup
    // toggle. The cached _showIndicator is updated by the
    // chrome.storage.onChanged listener above.
    if (_showIndicator === false) return;
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
      // v0.1.4: global pause check. If the user paused Lens from
      // the popup (Date.now() < _pausedUntil), suppress all
      // detection globally. The 4-facet regex scan is skipped
      // entirely; the banner is not shown; the FP report queue is
      // not touched. Auto-resumes when the pause expires.
      if (_pausedUntil > 0 && Date.now() < _pausedUntil) return;
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
