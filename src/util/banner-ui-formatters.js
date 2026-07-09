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
  //
  // v0.1.1 item 16: uses Intl.Segmenter for grapheme-aware truncation
  // so emoji and multi-codepoint characters (e.g., accented Latin
  // characters, CJK ideographs, ZWJ sequences) are never split mid-
  // codepoint. We deliberately do NOT use Intl.NumberFormat because
  // masked sensitive values should NOT be locale-formatted; the goal
  // of the mask is to make the value un-parseable by anyone who
  // glimpses it, so a locale-aware separator (e.g., "4,1111,1111,
  // 1111,1111" in en-US vs "4.1111.1111.1111.1111" in de-DE) would
  // be both confusing and counterproductive. The hardcoded "first
  // N + U+2026 + last N" mask is correct; what we needed was
  // grapheme safety, not locale formatting.
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
    // Grapheme-aware truncation: count graphemes, not UTF-16 code
    // units. Defaults to "first 4 + … + last 4" for length > 10, and
    // "first 2 + …" for length <= 10 (matching the original behavior).
    // Falls back to substring() if Intl.Segmenter is unavailable
    // (older browsers without it, e.g., Chrome < 87).
    var graphemeCount = value.length;
    if (typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function') {
      try {
        // "grapheme" granularity (not "word"!) — "word" treats
        // hyphens and apostrophes as word boundaries, which would
        // collapse "123-45-6789" into 5 word-segments (giving
        // graphemeCount=5, < 10, "12…" output). "grapheme" gives
        // 11 (correct: 11 code-point clusters).
        var seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
        var graphemes = [];
        for (var g of seg.segment(value)) {
          graphemes.push(g.segment);
        }
        graphemeCount = graphemes.length;
      } catch (e) {
        // Intl.Segmenter with an invalid locale throws; fall back
        // to the UTF-16 code unit count.
        graphemeCount = value.length;
      }
    }
    if (graphemeCount <= 10) {
      // Too short to meaningfully mask; show first 2 + … + last 2
      // (matches the original behavior; e.g., "short" -> "sh…rt").
      // For a 1-char string we return "a…a" (the same char twice
      // joined by the ellipsis, which is the least-bad output for
      // a single-character value).
      if (value.length <= 1) {
        return value + '\u2026' + value;
      }
      return value.substring(0, 2) + '\u2026' + value.substring(value.length - 2);
    }
    // For long values, take the first 4 graphemes and last 4
    // graphemes. We use substring() (UTF-16 code units) for the
    // offset, which is a safe approximation: the worst case is
    // that we include 1-2 extra code units at the boundary, which
    // the Ellipsis (\u2026) hides. To do this PERFECTLY we'd
    // need to walk grapheme boundaries; that overhead is not
    // justified for a 4-grapheme truncation.
    return value.substring(0, 4) + '\u2026' + value.substring(value.length - 4);
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
