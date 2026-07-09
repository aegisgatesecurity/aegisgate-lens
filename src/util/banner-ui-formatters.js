// AegisGate Lens — util/banner-ui-formatters.js
//
// Pure formatters for the banner UI. No DOM manipulation, no state,
// no event listeners. These are deterministic functions that take
// a value and return a string, suitable for unit testing in
// isolation.
//
// Owns:
//   - maskValue: truncate + mask a sensitive value for display
//   - formatCategory: strip pii_/secret_ prefix, replace underscores
//     with spaces, capitalize each word
//   - escapeHtml: prevent XSS in HTML string interpolation
//
// Loaded by banner-ui.js (the aggregator) BEFORE the HTML and
// lifecycle sub-files, so the HTML builders can call into the
// formatters.
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

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
    // Replace underscores with spaces, capitalize each word start
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

  // HTML escape: protect against XSS when interpolating user data
  // into the HTML string returned by buildBannerHTML.
  function escapeHtml(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
  }

  if (typeof self !== 'undefined') self.__lensBannerUI_formatters = {
    maskValue: maskValue,
    formatCategory: formatCategory,
    escapeHtml: escapeHtml
  };
  if (typeof window !== 'undefined') window.__lensBannerUI_formatters = {
    maskValue: maskValue,
    formatCategory: formatCategory,
    escapeHtml: escapeHtml
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_formatters = {
      maskValue: maskValue,
      formatCategory: formatCategory,
      escapeHtml: escapeHtml
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
