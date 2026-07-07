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

  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
                (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
                null;

  // CSS for the banner - EMBEDDED directly to ensure styles are always applied
  // This avoids CORS issues and ensures the banner appears correctly on all sites
  var CSS_STRING = '' +
    '[data-aegisgate-lens="banner"] {' +
      '--lens-bg-primary: #0a0c10;' +
      '--lens-bg-secondary: #11141d;' +
      '--lens-bg-tertiary: #1a1f2e;' +
      '--lens-primary: #38bdf8;' +
      '--lens-primary-hover: #00c4ec;' +
      '--lens-primary-glow: rgba(56, 189, 248, 0.15);' +
      '--lens-secondary: #10b981;' +
      '--lens-accent: #f43f5e;' +
      '--lens-text-primary: #f8fafc;' +
      '--lens-text-secondary: #94a3b8;' +
      '--lens-text-muted: #64748b;' +
      '--lens-border-color: rgba(51, 65, 85, 0.5);' +
      '--lens-glass-bg: rgba(17, 20, 29, 0.7);' +
      '--lens-radius-sm: 6px;' +
      '--lens-radius-md: 12px;' +
      '--lens-font: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif;' +
      'position: fixed !important;' +
      'top: 0 !important;' +
      'left: 0 !important;' +
      'right: 0 !important;' +
      'z-index: 2147483647 !important;' +
      'display: block !important;' +
      'box-sizing: border-box !important;' +
      'margin: 0 !important;' +
      'padding: 0 !important;' +
      'width: 100% !important;' +
      'max-width: 100% !important;' +
      'font-family: var(--lens-font) !important;' +
      'font-size: 13px !important;' +
      'line-height: 1.45 !important;' +
      'color: var(--lens-text-primary) !important;' +
      'background: var(--lens-glass-bg) !important;' +
      'backdrop-filter: blur(8px) !important;' +
      '-webkit-backdrop-filter: blur(8px) !important;' +
      'border: 1px solid var(--lens-border-color) !important;' +
      'border-radius: var(--lens-radius-md) !important;' +
      'box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4) !important;' +
      'animation: lens-fade-in 200ms ease-out !important;' +
      'text-align: left !important;' +
    '}' +
    '@keyframes lens-fade-in {' +
      'from { opacity: 0; transform: translateY(-4px); }' +
      'to   { opacity: 1; transform: translateY(0); }' +
    '}' +
    '@keyframes lens-fade-out {' +
      'from { opacity: 1; transform: translateY(0); }' +
      'to   { opacity: 0; transform: translateY(-4px); }' +
    '}' +
    '[data-aegisgate-lens="banner"].lens-hiding {' +
      'animation: lens-fade-out 200ms ease-in !important;' +
      'opacity: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-header {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 8px !important;' +
      'padding: 10px 14px !important;' +
      'border-bottom: 1px solid var(--lens-border-color) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-logo {' +
      'height: 24px !important;' +
      'width: auto !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-logo {' +
      'height: 24px !important;' +
      'width: auto !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-logo-container {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 4px !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-logo-text {' +
      'font-weight: 700 !important;' +
      'font-size: 12px !important;' +
      'color: var(--lens-text-primary) !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-wordmark {' +
      'font-weight: 700 !important;' +
      'font-size: 12px !important;' +
      'letter-spacing: 0.01em !important;' +
      'color: var(--lens-text-primary) !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-count {' +
      'flex: 1 !important;' +
      'font-size: 12px !important;' +
      'color: var(--lens-text-secondary) !important;' +
      'padding-left: 4px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-header-actions {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 6px !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-icon-btn {' +
      'display: inline-flex !important;' +
      'align-items: center !important;' +
      'justify-content: center !important;' +
      'width: 22px !important;' +
      'height: 22px !important;' +
      'padding: 0 !important;' +
      'margin: 0 !important;' +
      'background: transparent !important;' +
      'border: none !important;' +
      'border-radius: var(--lens-radius-sm) !important;' +
      'color: var(--lens-text-secondary) !important;' +
      'cursor: pointer !important;' +
      'font-size: 14px !important;' +
      'line-height: 1 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-icon-btn:hover {' +
      'background: rgba(56, 189, 248, 0.1) !important;' +
      'color: var(--lens-text-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-icon-btn svg {' +
      'width: 14px !important;' +
      'height: 14px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-list {' +
      'padding: 4px 0 !important;' +
      'max-height: 240px !important;' +
      'overflow-y: auto !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-item {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 8px !important;' +
      'padding: 6px 14px !important;' +
      'border-left: 3px solid transparent !important;' +
      'font-size: 12px !important;' +
      'color: var(--lens-text-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-item-critical { border-left-color: var(--lens-accent) !important; }' +
    '[data-aegisgate-lens="banner"] .lens-item-high     { border-left-color: var(--lens-primary) !important; }' +
    '[data-aegisgate-lens="banner"] .lens-item-medium   { border-left-color: var(--lens-primary) !important; }' +
    '[data-aegisgate-lens="banner"] .lens-item-low      { border-left-color: var(--lens-text-muted) !important; }' +
    '[data-aegisgate-lens="banner"] .lens-item-category {' +
      'flex: 1 !important;' +
      'font-weight: 500 !important;' +
      'text-transform: capitalize !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-pill {' +
      'display: inline-block !important;' +
      'padding: 1px 6px !important;' +
      'border-radius: 4px !important;' +
      'font-size: 9px !important;' +
      'font-weight: 700 !important;' +
      'letter-spacing: 0.04em !important;' +
      'text-transform: uppercase !important;' +
      'line-height: 1.4 !important;' +
      'flex-shrink: 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-pill-critical {' +
      'background: rgba(244, 63, 94, 0.15) !important;' +
      'color: var(--lens-accent) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-pill-high {' +
      'background: rgba(255, 189, 46, 0.15) !important;' +
      'color: #d97706 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-pill-medium {' +
      'background: rgba(56, 189, 248, 0.15) !important;' +
      'color: var(--lens-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-pill-low {' +
      'background: rgba(100, 116, 139, 0.15) !important;' +
      'color: var(--lens-text-muted) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-item-match {' +
      'font-family: \'SF Mono\', \'Fira Code\', \'Consolas\', monospace !important;' +
      'font-size: 11px !important;' +
      'color: var(--lens-text-muted) !important;' +
      'flex-shrink: 0 !important;' +
      'max-width: 140px !important;' +
      'overflow: hidden !important;' +
      'text-overflow: ellipsis !important;' +
      'white-space: nowrap !important;' +
      'direction: ltr !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-privacy {' +
      'padding: 8px 14px !important;' +
      'background: rgba(0, 0, 0, 0.2) !important;' +
      'border-top: 1px solid var(--lens-border-color) !important;' +
      'font-size: 11px !important;' +
      'line-height: 1.5 !important;' +
      'color: var(--lens-text-secondary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-privacy strong {' +
      'color: var(--lens-text-primary) !important;' +
      'font-weight: 600 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-privacy a {' +
      'color: var(--lens-primary) !important;' +
      'text-decoration: none !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-privacy a:hover {' +
      'text-decoration: underline !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-actions {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 6px !important;' +
      'padding: 10px 14px !important;' +
      'border-top: 1px solid var(--lens-border-color) !important;' +
      'background: rgba(0, 0, 0, 0.15) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn {' +
      'display: inline-block !important;' +
      'padding: 5px 12px !important;' +
      'border-radius: var(--lens-radius-sm) !important;' +
      'font-size: 12px !important;' +
      'font-weight: 600 !important;' +
      'cursor: pointer !important;' +
      'transition: all 0.15s ease !important;' +
      'border: none !important;' +
      'line-height: 1.4 !important;' +
      'text-align: center !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn-secondary {' +
      'background: var(--lens-bg-tertiary) !important;' +
      'color: var(--lens-text-primary) !important;' +
      'border: 1px solid var(--lens-border-color) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn-secondary:hover {' +
      'background: var(--lens-border-color) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn-primary {' +
      'background: var(--lens-primary) !important;' +
      'color: var(--lens-bg-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn-primary:hover {' +
      'background: var(--lens-primary-hover) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn-ghost {' +
      'background: transparent !important;' +
      'color: var(--lens-text-secondary) !important;' +
      'padding: 5px 10px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-btn-ghost:hover {' +
      'color: var(--lens-text-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-false-positive-link {' +
      'margin-left: auto !important;' +
      'font-size: 11px !important;' +
      'color: var(--lens-text-muted) !important;' +
      'background: transparent !important;' +
      'border: none !important;' +
      'cursor: pointer !important;' +
      'padding: 4px 8px !important;' +
      'border-radius: var(--lens-radius-sm) !important;' +
      'display: inline-flex !important;' +
      'align-items: center !important;' +
      'gap: 4px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-false-positive-link:hover {' +
      'color: var(--lens-text-secondary) !important;' +
      'background: rgba(56, 189, 248, 0.05) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-false-positive-link svg {' +
      'width: 10px !important;' +
      'height: 10px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss {' +
      'padding: 10px 14px !important;' +
      'background: rgba(0, 0, 0, 0.3) !important;' +
      'border-top: 1px solid var(--lens-border-color) !important;' +
      'font-size: 12px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss-prompt {' +
      'font-weight: 600 !important;' +
      'margin-bottom: 8px !important;' +
      'color: var(--lens-text-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss-reasons {' +
      'display: flex !important;' +
      'flex-direction: column !important;' +
      'gap: 4px !important;' +
      'margin-bottom: 10px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss-reasons label {' +
      'display: flex !important;' +
      'align-items: flex-start !important;' +
      'gap: 6px !important;' +
      'cursor: pointer !important;' +
      'font-size: 11px !important;' +
      'color: var(--lens-text-secondary) !important;' +
      'line-height: 1.4 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss-reasons input[type="checkbox"] {' +
      'margin: 0 !important;' +
      'flex-shrink: 0 !important;' +
      'margin-top: 2px !important;' +
      'accent-color: var(--lens-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss-actions {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 6px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-dismiss-transparency {' +
      'font-size: 10px !important;' +
      'color: var(--lens-text-muted) !important;' +
      'margin-top: 8px !important;' +
      'line-height: 1.4 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade {' +
      'display: flex !important;' +
      'align-items: center !important;' +
      'gap: 12px !important;' +
      'padding: 12px 14px !important;' +
      'background: var(--lens-primary-glow) !important;' +
      'border: 1px solid var(--lens-primary) !important;' +
      'border-radius: var(--lens-radius-md) !important;' +
      'margin: 8px 0 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-icon {' +
      'flex-shrink: 0 !important;' +
      'color: var(--lens-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-content {' +
      'flex: 1 !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-title {' +
      'font-weight: 700 !important;' +
      'font-size: 13px !important;' +
      'color: var(--lens-text-primary) !important;' +
      'margin-bottom: 2px !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-desc {' +
      'font-size: 11px !important;' +
      'color: var(--lens-text-secondary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-btn {' +
      'display: inline-block !important;' +
      'padding: 6px 12px !important;' +
      'background: var(--lens-primary) !important;' +
      'color: var(--lens-bg-primary) !important;' +
      'text-decoration: none !important;' +
      'border-radius: var(--lens-radius-sm) !important;' +
      'font-size: 12px !important;' +
      'font-weight: 600 !important;' +
      'transition: background 0.15s ease !important;' +
      'border: none !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-btn:hover {' +
      'background: var(--lens-primary-hover) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade-btn:visited {' +
      'color: var(--lens-bg-primary) !important;' +
    '}' +
    '[data-aegisgate-lens="banner"] .lens-upgrade { margin-top: 4px !important; }';

  function injectStyles() {
    try {
      if (document.getElementById('aegisgate-lens-banner-styles')) return;
      
      // Create a <style> element with the embedded CSS
      var style = document.createElement('style');
      style.id = 'aegisgate-lens-banner-styles';
      style.textContent = CSS_STRING;
      
      // Append to documentElement to ensure CSS is loaded
      (document.documentElement || document.head || document).appendChild(style);
      
      log.info('CSS embedded successfully');
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

    // Upgrade CTA for Platform
    var upgradeHtml =
      '<div class="lens-upgrade">' +
        '<div class="lens-upgrade-icon">' +
          '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
            '<path d="M12 2L15 8H21L16 12L18 18L12 15L6 18L8 12L3 8H9L12 2Z" fill="#4a90d9"/>' +
          '</svg>' +
        '</div>' +
        '<div class="lens-upgrade-content">' +
          '<div class="lens-upgrade-title">Upgrade to AegisGate Platform</div>' +
          '<div class="lens-upgrade-desc">Get automated redaction, enterprise features, and custom patterns</div>' +
        '</div>' +
        '<a href="https://aegisgatesecurity.io/lens/pricing" target="_blank" class="lens-upgrade-btn">Upgrade</a>' +
      '</div>';

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

    // Header - using AegisGate logo SVG (embedded directly, no external file needed)
    var headerHtml =
      '<div class="lens-header">' +
        '<div class="lens-logo-container">' +
          '<svg class="lens-logo" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
            '<path d="M12 2L15 8H21L16 12L18 18L12 15L6 18L8 12L3 8H9L12 2Z" fill="#38bdf8"/>' +
          '</svg>' +
          '<span class="lens-logo-text">AegisGate</span>' +
        '</div>' +
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

    return headerHtml + listHtml + privacyHtml + upgradeHtml + actionsHtml;
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
      // No input provided; append to document.documentElement
      // With position: fixed and top: 0, it will appear at the top
      // Using documentElement instead of body to avoid body margin/padding issues
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
