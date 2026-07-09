// AegisGate Lens — util/banner-ui-html.js
//
// HTML string builders for the banner UI. No DOM manipulation, no
// event listeners. These return HTML strings that the lifecycle
// sub-file injects into a DOM element.
//
// Owns:
//   - createBannerElement: the empty <div data-aegisgate-lens="banner">
//   - buildBannerHTML: the inner HTML of the banner (header + list +
//     privacy footer + platform CTA + action buttons)
//   - buildDismissFormHTML: the "false positive" form expansion
//
// Loaded by banner-ui.js (the aggregator) AFTER the formatters
// sub-file (so we can call maskValue, formatCategory, escapeHtml)
// and BEFORE the lifecycle sub-file (so the lifecycle can inject
// the HTML into a real DOM element).
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var icons = (typeof self !== 'undefined' && self.__lensBannerIcons) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerIcons) ||
              null;
  var formatters = (typeof self !== 'undefined' && self.__lensBannerUI_formatters) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_formatters) ||
                   null;
  // getRuntimeUrl is provided by the aggregator (banner-ui.js) via
  // globalThis.__lensBannerUI_getRuntimeUrl. Read lazily at call time
  // (not at IIFE-time) so the order of script loading doesn't matter.
  function getRuntimeUrlRef(relativePath) {
    var ref = (typeof self !== 'undefined' && self.__lensBannerUI_getRuntimeUrl) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_getRuntimeUrl) ||
              null;
    if (ref) return ref(relativePath);
    // Fallback: relative path (will 404 in CWS but lets tests run)
    return relativePath;
  }

  if (!formatters) {
    throw new Error('banner-ui-html.js: required sub-file not loaded: __lensBannerUI_formatters');
  }
  // Note: __lensBannerUI_getRuntimeUrl is provided by the aggregator
  // (banner-ui.js) and read lazily at call time via getRuntimeUrlRef().

  // Create the empty <div data-aegisgate-lens="banner"> that
  // the lifecycle sub-file will populate.
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
    var maxItems = (constants && constants.BANNER_MAX_ITEMS) || 8;
    for (var i = 0; i < events.length && i < maxItems; i++) {
      var ev = events[i];
      listHtml += '<div class="lens-item lens-item-' + ev.severity + '">';
      listHtml += '<span class="lens-item-category">' + formatters.escapeHtml(formatters.formatCategory(ev.category)) + '</span>';
      listHtml += '<span class="lens-pill lens-pill-' + ev.severity + '">' + ev.severity + '</span>';
      if (ev.sample) {
        listHtml += '<span class="lens-item-match" dir="ltr">' + formatters.escapeHtml(formatters.maskValue(ev.sample, ev.category)) + '</span>';
      }
      listHtml += '</div>';
    }
    if (events.length > maxItems) {
      listHtml += '<div class="lens-item lens-item-overflow">';
      listHtml += '+ ' + (events.length - maxItems) + ' more';
      listHtml += '</div>';
    }
    listHtml += '</div>';

    // Privacy footer
    var learnMoreUrl = opts.learnMoreUrl ||
      ((constants && constants.URLS && constants.URLS.LEARN_MORE) || 'https://github.com/aegisgatesecurity/aegisgate-lens#readme');
    var privacyHtml =
      '<div class="lens-privacy">' +
        '<strong>These items are visible to the AI provider when you send.</strong> ' +
        'AegisGate Lens never sends your prompt to any server. ' +
        '<a href="' + formatters.escapeHtml(learnMoreUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>.' +
      '</div>';

    // AegisGate Platform CTA (Lens is free forever; this drives TOFU traffic
    // to the paid Platform: server-side enforcement, automated redaction,
    // enterprise SSO, compliance modules. Per the pricing doctrine in
    // AEGISGATE-LENS-PIVOT-2026-06-18.md.)
    var platformUrl = opts.platformUrl ||
      ((constants && constants.URLS && constants.URLS.PLATFORM_CTA) || 'https://aegisgatesecurity.io/platform/pricing');
    var platformHtml =
      '<a class="lens-platform-cta" href="' + formatters.escapeHtml(platformUrl) + '" target="_blank" rel="noopener noreferrer">' +
        'When your team needs server-side enforcement, custom patterns, audit logs, or SSO, upgrade to <strong>AegisGate Platform</strong> →' +
      '</a>';

    // Action row
    var actionsHtml =
      '<div class="lens-actions">' +
        '<button type="button" class="lens-btn lens-btn-secondary" data-action="cancel">Cancel send</button>' +
        '<button type="button" class="lens-btn lens-btn-primary" data-action="redact">Edit manually</button>' +
        '<button type="button" class="lens-btn lens-btn-ghost" data-action="send">Send anyway</button>' +
        '<button type="button" class="lens-false-positive-link" data-action="false-positive">' +
          (icons && icons.ICONS.chevronDown ? icons.ICONS.chevronDown : '') +
          'This is a false positive' +
        '</button>' +
      '</div>';

    // Header
    var headerHtml =
      '<div class="lens-header">' +
        '<img class="lens-shield-img" src="' + getRuntimeUrlRef('icons/icon-48.png') + '" alt="AegisGate Lens"/>' +
          '<span class="lens-shield-fallback">' + (icons && icons.ICONS.shield ? icons.ICONS.shield : '') + '</span>' +
        '<span class="lens-wordmark">AegisGate Lens</span>' +
        '<span class="lens-count">' + countText + '</span>' +
        '<span class="lens-header-actions">' +
          '<button type="button" class="lens-icon-btn" data-action="help" aria-label="Help" title="Help: what this banner does">' +
            (icons && icons.ICONS.help ? icons.ICONS.help : '?') +
          '</button>' +
          '<button type="button" class="lens-icon-btn" data-action="dismiss" aria-label="Dismiss for 24 hours" title="Dismiss for 24 hours">' +
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

  if (typeof self !== 'undefined') self.__lensBannerUI_html = {
    createBannerElement: createBannerElement,
    buildBannerHTML: buildBannerHTML,
    buildDismissFormHTML: buildDismissFormHTML
  };
  if (typeof window !== 'undefined') window.__lensBannerUI_html = {
    createBannerElement: createBannerElement,
    buildBannerHTML: buildBannerHTML,
    buildDismissFormHTML: buildDismissFormHTML
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_html = {
      createBannerElement: createBannerElement,
      buildBannerHTML: buildBannerHTML,
      buildDismissFormHTML: buildDismissFormHTML
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
