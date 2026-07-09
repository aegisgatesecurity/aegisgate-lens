// AegisGate Lens — util/prompt-detect-lifecycle.js
//
// Lifecycle + MutationObserver for the prompt-detect orchestrator.
// Owns:
//   - attach: bind event listeners to the input + send button
//   - detach: remove event listeners
//   - onMutation: re-attach if the input was replaced (React SPA)
//
// Loaded by prompt-detect.js (the aggregator) AFTER the dom
// sub-file, so the aggregator's attach() can reference the DOM
// handlers (onInput, onSendClick, onKeyDown) that the dom
// sub-file exports.
//
// Per the v0.1.1 code-quality plan (item 3: split prompt-detect.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;
  var dom = (typeof self !== 'undefined' && self.__lensPromptDetect_dom) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect_dom) ||
            null;
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // The attach() function. Takes:
  //   - state: the aggregator's state object (contains input,
  //     sendButton, attached, _debouncedInput)
  //   - debounce: the aggregator's debounce helper
  //   - detectPrompt: the aggregator's detectPrompt function
  //   - onMutation: the lifecycle's own onMutation handler (for
  //     MutationObserver wiring)
  // Returns nothing; mutates state.
  function attach(state, debounce, detectPrompt, onMutation) {
    if (state.attached) return;
    if (!state.input) return;
    try {
      var debouncedInput = debounce(function () { dom.onInput(state, detectPrompt); },
                                    (constants && constants.DEBOUNCE_MS) || 250);
      state.input.addEventListener('input', debouncedInput, true);
      state.input.addEventListener('keyup', debouncedInput, true);
      state.input.addEventListener('keydown', function (e) { dom.onKeyDown(e, state, detectPrompt); }, true);
      if (state.sendButton) {
        state.sendButton.addEventListener('click', function (e) { dom.onSendClick(e, state, detectPrompt); }, true);
      }
      state._debouncedInput = debouncedInput;
      state.attached = true;
      log.info('attached to input' + (state.sendButton ? ' + send button' : ''));
    } catch (err) {
      log.error('attach() threw', err);
    }
  }

  // Detach event listeners. Takes state + onSendClick/onKeyDown
  // function refs (but we already have those in dom; pass through).
  function detach(state) {
    if (!state.attached) return;
    try {
      if (state.input) {
        if (state._debouncedInput) {
          state.input.removeEventListener('input', state._debouncedInput, true);
          state.input.removeEventListener('keyup', state._debouncedInput, true);
        }
        state.input.removeEventListener('keydown', function (e) { dom.onKeyDown(e, state, arguments.callee && arguments.callee.prototype); }, true);
      }
      if (state.sendButton) {
        state.sendButton.removeEventListener('click', function (e) { dom.onSendClick(e, state, arguments.callee && arguments.callee.prototype); }, true);
      }
      state.attached = false;
      log.info('detached from input');
    } catch (err) {
      log.error('detach() threw', err);
    }
  }

  // The MutationObserver callback: re-attach if the input was replaced
  // (state, attach, detach are passed in so this function is pure).
  function onMutation(mutations, state, attachFn, detachFn) {
    try {
      if (!state.provider) return;
      var newInput = selectors.findInput(state.provider);
      if (newInput && newInput !== state.input) {
        log.info('input element changed; re-attaching');
        detachFn(state);
        state.input = newInput;
        state.sendButton = selectors.findSendButton(state.provider);
        attachFn(state);
      } else if (!newInput && state.input) {
        log.info('input element removed; detaching');
        detachFn(state);
        state.input = null;
        state.sendButton = null;
      }
    } catch (err) {
      log.error('onMutation threw', err);
    }
  }

  if (typeof self !== 'undefined') self.__lensPromptDetect_lifecycle = {
    attach: attach,
    detach: detach,
    onMutation: onMutation
  };
  if (typeof window !== 'undefined') window.__lensPromptDetect_lifecycle = {
    attach: attach,
    detach: detach,
    onMutation: onMutation
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPromptDetect_lifecycle = {
      attach: attach,
      detach: detach,
      onMutation: onMutation
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
