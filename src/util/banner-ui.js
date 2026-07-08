// AegisGate Lens — util/banner-ui.js
// The brand-matched banner UI. Per the BANNER-DESIGN-SPEC.
//
// Public API:
//   banner-ui.show(events, opts)        // show the banner above the input
//   banner-ui.hide()                     // hide the banner
//   banner-ui.isVisible()                // boolean
//   banner-ui.getElement()               // the DOM element (or null)
//
// The banner does NOT modify the input or the page. It only
// shows UI and emits user actions through the callback set
// via opts.onAction(action, payload).
//
// All styles are applied via inline data-aegisgate-lens="banner"
// attribute. The CSS file is injected at boot via injectStyles().
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var icons = (typeof self !== 'undefined' && self.__lensBannerIcons) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerIcons) ||
              null;

  // Resolve a relative extension resource path to a chrome-extension:// URL.
  function getRuntimeUrl(relativePath) {
    if (typeof chrome !== "undefined" && chrome.runtime && typeof chrome.runtime.getURL === "function") {
      try { return chrome.runtime.getURL(relativePath); } catch (e) {}
    }
    return relativePath;
  }


  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
                (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
                null;

  // CSS for the banner. We use a <link> tag to load the CSS file
  // from the extension's web_accessible_resources. If chrome.runtime
  // is not available (e.g., in tests), we skip the link injection;
  // tests don't actually render the banner so the missing CSS is fine.
  var STYLE_ID = 'aegisgate-lens-banner-styles';
  var CSS_URL = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
    ? chrome.runtime.getURL('util/banner.css')
    : null;

  function injectStyles() {
    try {
      if (document.getElementById(STYLE_ID)) return;
      if (!CSS_URL) {
        // chrome.runtime.getURL not available (e.g., in tests);
        // the banner will use default browser styles. Tests don't
        // render the banner anyway.
        return;
      }
      var link = document.createElement('link');
      link.id = STYLE_ID;
      link.rel = 'stylesheet';
      link.type = 'text/css';
      link.href = CSS_URL;
      link.setAttribute('data-aegisgate-lens', 'banner-css');
      document.head.appendChild(link);
    } catch (err) {
      log.error('injectStyles threw', err);
    }
  }

  // Mask a value for display. First 4 + ellipsis + last 4.
  // Special handling for email: local part masked differently.
  function maskValue(value, category) {
    if (typeof value !== 'string' || value.length === 0) return '';
    // Email: j***@e****.com
    if (category === 'pii_email' && value.indexOf('@') !== -1) {
      var parts = value.split('@');
      var local = parts[0];
      var domain = parts[1];
      // Local: first char + '***' (e.g. 'j***')
      // Edge: empty local (shouldn't happen, but guard)
      var maskedLocal = local.length === 0 ? '***' : local[0] + '***';
      var dotIdx = domain.lastIndexOf('.');
      var maskedDomain = dotIdx > 0
        ? domain[0] + '***' + domain.substring(dotIdx)
        : '***';
      return maskedLocal + '@' + maskedDomain;
    }
    // Default: first 4 + … + last 4
    if (value.length <= 10) {
      // Too short to meaningfully mask; show first 2 + …
      return value.substring(0, 2) + '…' + value.substring(value.length - 2);
    }
    return value.substring(0, 4) + '…' + value.substring(value.length - 4);
  }

  // Format a category for display: strip the prefix and
  // replace underscores with spaces.
  function formatCategory(category) {
    if (typeof category !== 'string') return '';
    var s = category;
    // Strip known prefixes
    var prefixes = ['pii_', 'secret_', 'xss_', 'owasp_', 'atlas_', 'eu_ai_act_', 'anp_', 'cu_', 'toxicity_', 'pi_'];
    for (var i = 0; i < prefixes.length; i++) {
      if (s.indexOf(prefixes[i]) === 0) {
        s = s.substring(prefixes[i].length);
        break;
      }
    }
    // Word-boundary regex. NOTE: in the source file this is the
    // literal string '/\b\w/g' (single backslashes after the
    // regex delimiter). When written via Python/Node string
    // concatenation it can accidentally become '/\\b\\w/g' (which
    // matches a literal backslash-b). The Lesson here: ALWAYS
    // test the output of any string-based regex manipulation.
    var s2 = s.replace(/_/g, ' ');
    var result = '';
    for (var j = 0; j < s2.length; j++) {
      var c = s2[j];
      if (j === 0 || s2[j-1] === ' ') {
        result += c.toUpperCase();
      } else {
        result += c;
      }
    }
    return result;
  }

  // Create the banner DOM element. The element is a <div> with
  // data-aegisgate-lens="banner". It is NOT attached to the
  // DOM until show() is called.
  function createBannerElement() {
    var el = document.createElement('div');
    el.setAttribute('data-aegisgate-lens', 'banner');
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-live', 'polite');
    el.style.display = 'none';
    return el;
  }

  // Build the inner HTML for the banner. Pulled out so tests
  // can construct the same structure without DOM.
  function buildBannerHTML(events, opts) {
    opts = opts || {};
    var count = events.length;
    var countText = count + ' sensitive item' + (count === 1 ? '' : 's') + ' detected';

    // Build the detection list HTML
    var listHtml = '<div class="lens-list">';
    var maxItems = 8;
    for (var i = 0; i < events.length && i < maxItems; i++) {
      var ev = events[i];
      listHtml += '<div class="lens-item lens-item-' + ev.severity + '">';
      listHtml += '<span class="lens-item-category">' + escapeHtml(formatCategory(ev.category)) + '</span>';
      listHtml += '<span class="lens-pill lens-pill-' + ev.severity + '">' + ev.severity + '</span>';
      if (ev.sample) {
        listHtml += '<span class="lens-item-match" dir="ltr">' + escapeHtml(maskValue(ev.sample, ev.category)) + '</span>';
      }
      listHtml += '</div>';
    }
    if (events.length > maxItems) {
      listHtml += '<div class="lens-item" style="color: var(--lens-text-muted); font-style: italic; border-left-color: transparent;">';
      listHtml += '+ ' + (events.length - maxItems) + ' more';
      listHtml += '</div>';
    }
    listHtml += '</div>';

    // Privacy footer
    var learnMoreUrl = opts.learnMoreUrl ||
      'https://github.com/aegisgatesecurity/aegisgate-lens#readme';
    var privacyHtml =
      '<div class="lens-privacy">' +
        '<strong>These items are visible to the AI provider when you send.</strong> ' +
        'AegisGate Lens never sends your prompt to any server. ' +
        '<a href="' + escapeHtml(learnMoreUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>.' +
      '</div>';

    // AegisGate Platform CTA (Lens is free forever; this drives TOFU traffic
    // to the paid Platform: server-side enforcement, automated redaction,
    // enterprise SSO, compliance modules. Per the pricing doctrine in
    // AEGISGATE-LENS-PIVOT-2026-06-18.md.)
    var platformUrl = opts.platformUrl ||
      'https://aegisgatesecurity.io/platform/pricing';
    var platformHtml =
      '<a class="lens-platform-cta" href="' + escapeHtml(platformUrl) + '" target="_blank" rel="noopener noreferrer">' +
        'Get automated redaction, enterprise features, and custom patterns with ' +
        '<strong>AegisGate Platform</strong> →' +
      '</a>';

    // Action row
    var actionsHtml =
      '<div class="lens-actions">' +
        '<button type="button" class="lens-btn lens-btn-secondary" data-action="cancel">Cancel send</button>' +
        '<button type="button" class="lens-btn lens-btn-primary" data-action="redact">Edit &amp; redact</button>' +
        '<button type="button" class="lens-btn lens-btn-ghost" data-action="send">Send anyway</button>' +
        '<button type="button" class="lens-false-positive-link" data-action="false-positive">' +
          (icons && icons.ICONS.chevronDown ? icons.ICONS.chevronDown : '') +
          'This is a false positive' +
        '</button>' +
      '</div>';

    // Header
    var headerHtml =
      '<div class="lens-header">' +
        '' + (function () { var s = getRuntimeUrl("icons/icon-48.png"); return '<img class="lens-shield-img" src="' + s + '" alt="AegisGate Lens"/>'; })() +
          '<span class="lens-shield-fallback">' + (icons && icons.ICONS.shield ? icons.ICONS.shield : '') + '</span>' +
        '<span class="lens-wordmark">AegisGate Lens</span>' +
        '<span class="lens-count">' + countText + '</span>' +
        '<span class="lens-header-actions">' +
          '<button type="button" class="lens-icon-btn" data-action="help" aria-label="Help">' +
            (icons && icons.ICONS.help ? icons.ICONS.help : '?') +
          '</button>' +
          '<button type="button" class="lens-icon-btn" data-action="dismiss" aria-label="Dismiss for 24 hours">' +
            (icons && icons.ICONS.close ? icons.ICONS.close : '×') +
          '</button>' +
        '</span>' +
      '</div>';

    return headerHtml + listHtml + privacyHtml + platformHtml + actionsHtml;
  }

  // The dismiss form (expanded). Shown when the user clicks
  // "This is a false positive".
  function buildDismissFormHTML() {
    return '' +
      '<div class="lens-dismiss" role="region" aria-label="Mark as false positive">' +
        '<div class="lens-dismiss-prompt">Tell us why this is a false positive (helps us improve):</div>' +
        '<div class="lens-dismiss-reasons">' +
          '<label><input type="checkbox" data-reason="test_data"> This is test/fake data</label>' +
          '<label><input type="checkbox" data-reason="own_data"> This is my own data (I know what I\'m doing)</label>' +
          '<label><input type="checkbox" data-reason="legitimate_use_case"> This is for a legitimate use case I trust</label>' +
        '</div>' +
        '<div class="lens-dismiss-actions">' +
          '<button type="button" class="lens-btn lens-btn-primary" data-dismiss-action="submit">Submit &amp; dismiss</button>' +
          '<button type="button" class="lens-btn lens-btn-secondary" data-dismiss-action="private">Just dismiss (private)</button>' +
          '<button type="button" class="lens-btn lens-btn-ghost" data-dismiss-action="cancel">Cancel</button>' +
        '</div>' +
        '<div class="lens-dismiss-transparency">' +
          'Submit sends one anonymous, sanitized report (category, pattern, reason). No prompt text, no URLs, no page content. Just dismiss is 100% local.' +
        '</div>' +
      '</div>';
  }

  // Minimal HTML escape (defense against malicious category text)
  function escapeHtml(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
  }

  // State
  var state = {
    el: null,                  // the banner DOM element
    currentEvents: null,       // the events currently displayed
    currentOpts: null,         // the opts used to show the banner
    parentInput: null,         // the input element the banner is anchored to
    inserting: false,          // are we currently in the middle of attaching?
    isVisible: false
  };

  // Attach event listeners to the banner. Called once at create time.
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
    actionsRow.insertAdjacentHTML('afterend', buildDismissFormHTML());
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

  // Dismiss-form action handler
  async function handleDismissAction(action, opts) {
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
      await recordDismissalForEvents('private', null, opts);
      hide();
      if (typeof opts.onAction === 'function') {
        try { opts.onAction('dismiss', { events: state.currentEvents }); } catch (e) { log.error('onAction threw', e); }
      }
      return;
    }
    if (action === 'submit') {
      // Submit & dismiss — opt-in path
      // If no reason was selected, default to 'own_data' (most common)
      if (!reason) reason = 'own_data';
      await recordDismissalForEvents('optin', reason, opts);
      hide();
      if (typeof opts.onAction === 'function') {
        try {
          opts.onAction('dismiss_optin', {
            events: state.currentEvents,
            reason: reason
          });
        } catch (e) { log.error('onAction threw', e); }
      }
    }
  }

  // Record a dismissal for every event currently displayed.
  // On the opt-in path, also build the FP report(s).
  async function recordDismissalForEvents(mode, reason, opts) {
    if (!dismiss) {
      log.warn('dismiss module not available; cannot record dismissal');
      return;
    }
    if (!state.currentEvents) return;
    var domainHash = opts.domainHash || null;
    if (!domainHash) {
      log.warn('no domainHash in opts; cannot record dismissal');
      return;
    }
    for (var i = 0; i < state.currentEvents.length; i++) {
      var ev = state.currentEvents[i];
      var fpReport = null;
      if (mode === 'optin') {
        fpReport = dismiss.buildFPReport(ev, domainHash, reason);
      }
      await dismiss.dismiss(domainHash, ev.category,
                            ev.matches && ev.matches[0] && ev.matches[0].cardType ?
                              ev.category + '_' + ev.matches[0].cardType : ev.category,
                            mode === 'optin' ? reason : null,
                            fpReport);
    }
    // On opt-in, surface the FP reports via the onAction callback
    // so the SW (3g) can send them. We do NOT send them here
    // because the banner-ui is the content script and the SW is
    // the only place that has the network handle.
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
  }

  // Show the banner above the input element
  function show(events, opts) {
    opts = opts || {};
    if (!Array.isArray(events) || events.length === 0) {
      log.warn('show() called with no events; ignoring');
      return;
    }
    if (!state.el) {
      injectStyles();
      state.el = createBannerElement();
      attachListeners(state.el, opts);
    }
    state.currentEvents = events;
    state.currentOpts = opts;
    state.el.innerHTML = buildBannerHTML(events, opts);
    state.el.style.display = '';

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
      // No input provided; fall back to document.body
      if (state.el.parentNode !== document.documentElement) {
        if (state.el.parentNode) state.el.parentNode.removeChild(state.el);
        document.documentElement.appendChild(state.el);
      }
    }
    state.isVisible = true;
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
        el.style.display = 'none';
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

  var module = {
    show: show,
    hide: hide,
    isVisible: isVisible,
    getElement: getElement,
    getState: getState,
    // Exposed for tests
    maskValue: maskValue,
    formatCategory: formatCategory,
    buildBannerHTML: buildBannerHTML,
    buildDismissFormHTML: buildDismissFormHTML
  };

  if (typeof self !== 'undefined') self.__lensBannerUI = module;
  if (typeof window !== 'undefined') window.__lensBannerUI = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensBannerUI = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
