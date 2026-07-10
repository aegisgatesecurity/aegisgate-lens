// AegisGate Lens — util/banner-ui-lifecycle.js
//
// Banner lifecycle + DOM event handling. Owns:
//   - state object (the shared mutable state)
//   - attachListeners: bind click handlers
//   - showDismissForm / hideDismissForm: the FP report form
//   - handleAction / handleDismissAction: route to onAction callback
//   - recordDismissalForEvents: write the dismissal to storage
//   - show / hide / isVisible / getElement / getState: the public API
//
// Loaded by banner-ui.js (the aggregator) AFTER the formatters
// and HTML sub-files. Calls into the HTML sub-file's buildBannerHTML
// and buildDismissFormHTML; calls into the formatters sub-file's
// escapeHtml.
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };
  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
               (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
               null;
  var html = (typeof self !== 'undefined' && self.__lensBannerUI_html) ||
             (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_html) ||
             null;
  // injectStyles is provided by the aggregator (banner-ui.js) via
  // globalThis.__lensBannerUI_injectStyles. Read lazily at call time
  // (not at IIFE-time) so the order of script loading doesn't matter.
  function injectStylesRef() {
    var ref = (typeof self !== 'undefined' && self.__lensBannerUI_injectStyles) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_injectStyles) ||
              null;
    if (ref) ref();
    // Fallback: do nothing (CSS won't be injected, but tests can still run)
  }

  if (!html) {
    throw new Error('banner-ui-lifecycle.js: required sub-file not loaded: __lensBannerUI_html');
  }
  // Note: __lensBannerUI_injectStyles is provided by the aggregator
  // (banner-ui.js) and read lazily at call time via injectStylesRef().

  // -------------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------------
  var state = {
    el: null,                  // the banner DOM element
    currentEvents: null,       // the events currently displayed
    currentOpts: null,         // the opts used to show the banner
    parentInput: null,         // the input element the banner is anchored to
    inserting: false,          // are we currently in the middle of attaching?
    isVisible: false,
    // v0.1.1 item C (first-run onboarding):
    // 'unknown' until the first show() reads chrome.storage.session
    // (no chrome.* in tests), then 'pending' / 'done' / 'failed'.
    // 'pending' means "show the primer line on the next banner".
    // 'done' means "skip the primer".
    // 'failed' means "storage read errored; show the primer
    // (fail-open: the user gets a helpful message even if the
    // read fails)".
    onboardStatus: 'unknown'
  };

  // Read the ONBOARDED flag from chrome.storage.session.
  // Returns 'done' if the user has been onboarded, 'pending' if not.
  // Returns 'failed' if storage is unavailable or the read errors.
  // This is sync-friendly: we cache the result in state.onboardStatus
  // and the show() function reads it synchronously.
  function readOnboardedFlag() {
    var KEY = (constants && constants.STORAGE_KEYS && constants.STORAGE_KEYS.ONBOARDED) || 'aegisgate_lens_onboarded';
    try {
      if (typeof chrome === 'undefined' || !chrome.storage) {
        return 'failed';  // tests: storage not available, skip primer
      }
      var area = null;
      if (chrome.storage.session) area = chrome.storage.session;
      else if (chrome.storage.local) area = chrome.storage.local;
      if (!area) return 'failed';
      // Chrome storage API is callback-based; we use the sync-shim
      // pattern of checking last-set value via a module-level cache.
      // The cache is populated by the first call (async) and used
      // by subsequent calls (sync). For first-call, we return
      // 'pending' and let the show() render the primer once.
      if (onboardedFlagCache !== null) return onboardedFlagCache;
      // First call: kick off an async read, return 'pending' for now.
      try {
        area.get([KEY], function (result) {
          try {
            if (chrome.runtime && chrome.runtime.lastError) {
              onboardedFlagCache = 'failed';
              return;
            }
            onboardedFlagCache = (result && result[KEY]) ? 'done' : 'pending';
          } catch (e) { onboardedFlagCache = 'failed'; }
        });
      } catch (e) { onboardedFlagCache = 'failed'; }
      return 'pending';
    } catch (e) {
      return 'failed';
    }
  }

  // Write the ONBOARDED flag = true. Called after the banner's
  // first show(), so the next time the user types the primer is
  // skipped.
  function writeOnboardedFlag() {
    var KEY = (constants && constants.STORAGE_KEYS && constants.STORAGE_KEYS.ONBOARDED) || 'aegisgate_lens_onboarded';
    try {
      if (typeof chrome === 'undefined' || !chrome.storage) return;
      var area = null;
      if (chrome.storage.session) area = chrome.storage.session;
      else if (chrome.storage.local) area = chrome.storage.local;
      if (!area) return;
      area.set({ [KEY]: true }, function () {
        if (chrome.runtime && chrome.runtime.lastError) {
          log.warn('onboarded set failed: ' + chrome.runtime.lastError.message);
        }
      });
    } catch (e) {
      log.warn('writeOnboardedFlag threw', e);
    }
  }

  // Module-level cache for the ONBOARDED flag read.
  // Populated by the first readOnboardedFlag() async call.
  var onboardedFlagCache = null;

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------
  function handleDismissAction(action, opts) {
    if (action === 'cancel') {
      hideDismissForm();
      return;
    }
    // Get the checked reason
    var form = state.el && state.el.querySelector('.lens-dismiss');
    var reason = null;
    if (form) {
      var checkboxes = form.querySelectorAll('input[type="checkbox"]');
      for (var i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
          reason = checkboxes[i].getAttribute('data-reason');
          break;
        }
      }
    }
    if (action === 'private') {
      // Just dismiss (private) — no reason required, no FP report
      recordDismissalForEvents('private', null, opts).then(function () {
        hide();
        if (typeof opts.onAction === 'function') {
          try { opts.onAction('dismiss', { events: state.currentEvents }); } catch (e) { log.error('onAction threw', e); }
        }
      });
      return;
    }
    if (action === 'submit') {
      // Submit & dismiss — opt-in path
      // If no reason was selected, default to 'own_data' (most common)
      if (!reason) reason = 'own_data';
      recordDismissalForEvents('optin', reason, opts).then(function () {
        hide();
        if (typeof opts.onAction === 'function') {
          try {
            opts.onAction('dismiss_optin', {
              events: state.currentEvents,
              reason: reason
            });
          } catch (e) { log.error('onAction threw', e); }
        }
      });
    }
  }

  function recordDismissalForEvents(mode, reason, opts) {
    if (!dismiss) {
      log.warn('dismiss module not available; cannot record dismissal');
      return Promise.resolve();
    }
    if (!state.currentEvents) return Promise.resolve();
    var domainHash = opts.domainHash || null;
    if (!domainHash) {
      log.warn('no domainHash in opts; cannot record dismissal');
      return Promise.resolve();
    }
    var promises = [];
    for (var i = 0; i < state.currentEvents.length; i++) {
      var ev = state.currentEvents[i];
      var fpReport = null;
      if (mode === 'optin') {
        fpReport = dismiss.buildFPReport(ev, domainHash, reason);
      }
      promises.push(dismiss.dismiss(domainHash, ev.category,
        ev.matches && ev.matches[0] && ev.matches[0].cardType ?
          ev.category + '_' + ev.matches[0].cardType : ev.category,
        mode === 'optin' ? reason : null,
        fpReport));
    }
    // On opt-in, surface the FP reports via the onAction callback
    // so the SW can send them. We do NOT send them here because
    // the banner-ui is the content script and the SW is the only
    // place that has the network handle.
    return Promise.all(promises).then(function () {
      if (mode === 'optin' && typeof opts.onAction === 'function') {
        try {
          var reports = [];
          for (var j = 0; j < state.currentEvents.length; j++) {
            var report = dismiss.buildFPReport(state.currentEvents[j], domainHash, reason);
            if (report) reports.push(report);
          }
          opts.onAction('fp_reports', { reports: reports });
        } catch (e) { log.error('onAction(fp_reports) threw', e); }
      }
    });
  }

  // -------------------------------------------------------------------------
  // Public API (lifecycle)
  // -------------------------------------------------------------------------
  function attachListeners(el, opts) {
    opts = opts || {};
    el.addEventListener('click', function (e) {
      try {
        var target = e.target;
        // Walk up to find the button or its data-action
        var btn = target.closest && target.closest('[data-action]');
        if (btn) {
          handleAction(btn.getAttribute('data-action'), opts);
          return;
        }
        var dismissBtn = target.closest && target.closest('[data-dismiss-action]');
        if (dismissBtn) {
          handleDismissAction(dismissBtn.getAttribute('data-dismiss-action'), opts);
        }
      } catch (err) {
        log.error('click handler threw', err);
      }
    }, true);
    // v0.1.1 item 21: keyboard navigation support.
    //   - Esc closes the banner (default: cancel action).
    //   - Tab / Shift-Tab is trapped within the banner so a
    //     keyboard user can't tab past the last button and lose
    //     focus into the page below.
    el.addEventListener('keydown', function (e) {
      try {
        if (e.key === 'Escape' || e.keyCode === 27) {
          e.preventDefault();
          e.stopPropagation();
          handleAction('cancel', opts);
          return;
        }
        if (e.key === 'Tab' || e.keyCode === 9) {
          // Trap focus within the banner. The first focusable
          // element is the auto-focus target; the last is the
          // dismiss button.
          var focusables = el.querySelectorAll(
            'button, [href], input, [tabindex]:not([tabindex="-1"])'
          );
          if (focusables.length === 0) return;
          var first = focusables[0];
          var last = focusables[focusables.length - 1];
          var active = el.ownerDocument && el.ownerDocument.activeElement;
          if (e.shiftKey && active === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
          }
        }
      } catch (err) {
        log.error('keydown handler threw', err);
      }
    }, true);
  }

  // Show the dismiss form inline (replaces the action row)
  function showDismissForm(opts) {
    if (!state.el) return;
    var actionsRow = state.el.querySelector('.lens-actions');
    if (!actionsRow) return;
    // Remove any existing dismiss form
    var existing = state.el.querySelector('.lens-dismiss');
    if (existing) existing.remove();
    // Insert the dismiss form after the actions row
    actionsRow.insertAdjacentHTML('afterend', html.buildDismissFormHTML());
    // Scroll the dismiss form into view
    var form = state.el.querySelector('.lens-dismiss');
    if (form) form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Hide the dismiss form (restore the action row)
  function hideDismissForm() {
    if (!state.el) return;
    var form = state.el.querySelector('.lens-dismiss');
    if (form) form.remove();
  }

  // Action handler. Routes to the consumer's onAction callback.
  function handleAction(action, opts) {
    if (action === 'false-positive') {
      showDismissForm(opts);
      return;
    }
    // v0.1.1 item C: primer-dismiss writes the ONBOARDED flag
    // and hides the primer line, but does NOT hide the banner
    // itself. The user is still looking at the detection.
    if (action === 'primer-dismiss') {
      writeOnboardedFlag();
      onboardedFlagCache = 'done';
      // Remove just the primer line from the DOM
      if (state.el) {
        var primerEl = state.el.querySelector('.lens-primer');
        if (primerEl && primerEl.parentNode) {
          primerEl.parentNode.removeChild(primerEl);
        }
      }
      return;
    }
    // All other actions hide the banner and call onAction
    if (action === 'dismiss') {
      // Dismiss for 24h on the same domain + category
      recordDismissalForEvents('private', null, opts);
    }
    hide();
    if (typeof opts.onAction === 'function') {
      try {
        opts.onAction(action, { events: state.currentEvents });
      } catch (err) {
        log.error('opts.onAction threw', err);
      }
    }
  }

  // Show the banner above the input element
  function show(events, opts) {
    opts = opts || {};
    if (!Array.isArray(events) || events.length === 0) {
      log.warn('show() called with no events; ignoring');
      return;
    }
    if (!state.el) {
      injectStylesRef();
      state.el = html.createBannerElement();
      attachListeners(state.el, opts);
    }
    state.currentEvents = events;
    state.currentOpts = opts;
    // v0.1.1 item C (first-run onboarding): decide whether to
    // show the primer line. The primer appears on the FIRST
    // banner render of a session for a new user. After that
    // (or if the user clicks the × dismiss), the primer is
    // skipped. Fail-open: if storage is unavailable we show
    // the primer (it's helpful, not harmful).
    var onboardStatus = readOnboardedFlag();
    state.onboardStatus = onboardStatus;
    var showPrimer = (onboardStatus === 'pending' || onboardStatus === 'failed');
    // The HTML builder reads opts.showPrimer
    var renderOpts = showPrimer ? Object.assign({}, opts, { showPrimer: true }) : opts;
    state.el.innerHTML = html.buildBannerHTML(events, renderOpts);
    // If we showed the primer, write the flag immediately so
    // the next banner doesn't show it. (We don't wait for the
    // user to click × first; the primer is more like a "splash"
    // than a modal.)
    if (showPrimer) {
      writeOnboardedFlag();
      onboardedFlagCache = 'done';
    }
    state.el.classList.remove('hidden');

    // Attach the banner above the input
    var input = opts.input || null;
    if (input && input.parentNode) {
      // If the banner is already inserted, remove it first
      if (state.el.parentNode && state.el.parentNode !== input.parentNode) {
        state.el.parentNode.removeChild(state.el);
      }
      if (state.el.parentNode !== input.parentNode) {
        input.parentNode.insertBefore(state.el, input);
      }
      state.parentInput = input;
    } else {
      // No input provided; fall back to document.documentElement
      if (state.el.parentNode !== document.documentElement) {
        if (state.el.parentNode) state.el.parentNode.removeChild(state.el);
        document.documentElement.appendChild(state.el);
      }
    }
    state.isVisible = true;
    // v0.1.1 item 21: auto-focus the banner so keyboard users can
    // navigate it immediately and screen readers announce it. We
    // focus the first focusable element (the Help button, the
    // first button in the header). We use a small setTimeout to
    // let the DOM settle after the innerHTML assignment.
    setTimeout(function () {
      try {
        if (!state.el) return;
        var firstBtn = state.el.querySelector('button, [href], [tabindex="0"]');
        if (firstBtn && typeof firstBtn.focus === 'function') firstBtn.focus();
      } catch (e) { /* ignore focus errors */ }
    }, 0);
    log.info('banner shown with ' + events.length + ' events');
  }

  // Hide the banner
  function hide() {
    if (!state.el || !state.isVisible) return;
    // Snapshot the element before the timeout (state.el may be
    // cleared by a subsequent show())
    var el = state.el;
    try { el.classList.add('lens-hiding'); } catch (e) { /* ignore */ }
    setTimeout(function () {
      try {
        el.classList.add('hidden');
        try { el.classList.remove('lens-hiding'); } catch (e2) { /* ignore */ }
        if (el.parentNode) el.parentNode.removeChild(el);
      } catch (e3) {
        log.warn('banner hide() cleanup error (test env?): ' + e3.message);
      }
    }, 200);
    state.isVisible = false;
    state.currentEvents = null;
    state.currentOpts = null;
    log.info('banner hidden');
  }

  function isVisible() { return state.isVisible; }
  function getElement() { return state.el; }

  // For testing: get the current state
  function getState() {
    return {
      isVisible: state.isVisible,
      hasElement: !!state.el,
      eventCount: state.currentEvents ? state.currentEvents.length : 0
    };
  }

  if (typeof self !== 'undefined') self.__lensBannerUI_lifecycle = {
    show: show,
    hide: hide,
    isVisible: isVisible,
    getElement: getElement,
    getState: getState,
    handleAction: handleAction,
    showDismissForm: showDismissForm,
    hideDismissForm: hideDismissForm
  };
  if (typeof window !== 'undefined') window.__lensBannerUI_lifecycle = {
    show: show,
    hide: hide,
    isVisible: isVisible,
    getElement: getElement,
    getState: getState,
    handleAction: handleAction,
    showDismissForm: showDismissForm,
    hideDismissForm: hideDismissForm
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_lifecycle = {
      show: show,
      hide: hide,
      isVisible: isVisible,
      getElement: getElement,
      getState: getState,
      handleAction: handleAction,
      showDismissForm: showDismissForm,
      hideDismissForm: hideDismissForm
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
