// AegisGate Lens — detectors/regex/source_xss.js
// Facet 3: Source code and XSS detection. Regex-based.
// Per schema.js VALID_CATEGORIES[3], 6 XSS categories are detected.
// These detect code that an attacker might paste into an AI tool to
// get help weaponizing, OR patterns that suggest prompt injection via
// code blocks.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var PATTERNS = {
    xss_script_tag: {
      severity: 'critical',
      // <script> opening or closing tag. We require an actual HTML
      // tag with attributes or content, not the word "script" alone.
      re: /<\s*script\b[^>]*>(?:[\s\S]*?<\s*\/\s*script\s*>)?/gi
    },
    xss_event_handler: {
      severity: 'high',
      // HTML event handler attribute: on*= followed by JS.
      // Matches onclick=, onerror=, onload=, onmouseover=, etc.
      re: /\s(?:on(?:click|error|load|mouseover|mouseout|focus|blur|submit|change|keydown|keyup|keypress|input|abort|resize|scroll|unload|drag|drop))\s*=\s*["'][^"']*["']/gi
    },
    xss_javascript_url: {
      severity: 'critical',
      // href or src with javascript: scheme
      re: /(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:/gi
    },
    xss_data_url: {
      severity: 'high',
      // data: URL with text/html (the dangerous one). data:image is
      // generally safe so we don't flag it.
      re: /(?:href|src|action|formaction)\s*=\s*["']?\s*data:text\/html/gi
    },
    xss_svg_script: {
      severity: 'critical',
      // <svg> with embedded script OR <svg> with event handler
      re: /<\s*svg\b[^>]*(?:on\w+\s*=|<\s*script)/gi
    },
    xss_dom_clobbering: {
      severity: 'medium',
      // HTML element with id or name that clobbers a common global
      // (e.g., getElementById, document.cookie, document.write).
      // The clobbering target list covers common cases.
      re: /<\s*(?:a|form|img|iframe|input|embed|object)\b[^>]*\s(?:id|name)\s*=\s*["'](?:getElementById|cookie|write|forms|length|parent|top|name)\b/gi
    }
  };

  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(PATTERNS);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = PATTERNS[key];
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        matches.push({
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0].length > 200 ? m[0].substring(0, 200) + '...' : m[0],
          index: m.index
        });
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensXSS = module;
  if (typeof window !== 'undefined') window.__lensXSS = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensXSS = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
