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
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta XSS expansion, 2026-07-04)
    // Each pattern: strict regex + tests covering positive cases and
    // benign strings (no FPs on common English / common code).
    // ====================================================================
    xss_svg_namespace_abuse: {
      // SVG with embedded foreignObject, animation, or use elements
      // (namespace abuse allows script execution in non-script contexts).
      // These are SVG-specific XSS vectors.
      severity: 'critical',
      re: /<\s*svg\b[^>]*\s+(?:xmlns|xmlns:[a-z]+)\s*=\s*["'][^"']*["'][^>]*<\s*(?:foreignObject|animation|set|animate|use|script)\b/gi
    },
    xss_mutation_xss: {
      // Mutation XSS (mXSS) patterns: HTML where the parser's
      // mutation produces different output than the author wrote.
      // Common mXSS vectors: nested <noembed>/<noscript>/<title>,
      // <svg>/<math> with <style>, <form> with <math>, <a> inside
      // <svg>, etc. We match the structural patterns that produce
      // mXSS, not the runtime behavior.
      //
      // The inner content (0-500 chars) must contain at least one
      // XSS indicator: a tag opener '<', an event handler 'on*=',
      // or 'javascript:'. This reduces FPs on normal title text
      // like '<title>Page Title</title>'.
      severity: 'high',
      re: /<\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\b[^>]*>(?:[^<]|<(?!\s*\/\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\s*>)){0,500}?(?:<[^>]*(?:on\w+\s*=|javascript:)[^>]*>|javascript:)[^<]{0,500}?<\s*\/\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\s*>/gi
    },
    xss_polyglot: {
      // Polyglot XSS: a single payload that is valid in multiple
      // contexts (HTML, JS, CSS, URL). Common vectors:
      //   - JavaScript comment in a CSS context: /* */
      //   - alert() inside a data: URL that's also a JS file
      //   - HTML entities that decode to JS
      // We match the most common polyglot patterns: inline event
      // handlers combined with template literals, or alert/eval
      // inside CSS or SVG.
      severity: 'high',
      re: /(?:alert|eval|prompt|confirm|document\.write)\s*\(\s*[`'"][^`'"]{0,200}?\$\{[^}]{0,100}?\}[^`'"]*[`'"]\s*\)/g
    },
    xss_svg_use_external: {
      // SVG <use> with external href (XXE/SVG XSS vector). When a
      // SVG references an external file via <use href="external">,
      // it can load attacker-controlled content. The pattern
      // requires the <use> element AND an external href.
      severity: 'critical',
      re: /<\s*use\b[^>]*\s(?:xlink:)?href\s*=\s*["']\s*(?:https?:|data:|file:|\/\/)/gi
    },
    xss_javascript_data_url: {
      // javascript: scheme in any URL context (not just href/src).
      // Includes formaction, xlink:href, action, etc. The
      // existing xss_javascript_url pattern covers href/src;
      // this extends to all URL contexts.
      severity: 'critical',
      re: /(?:href|src|action|formaction|xlink:href|background|poster|cite|usemap|data)\s*=\s*["']?\s*javascript:/gi
    },
    xss_meta_refresh: {
      // <meta http-equiv="refresh" content="0;url=javascript:...">
      // This is a less-common XSS vector but still possible in
      // older browsers and some HTML contexts.
      severity: 'medium',
      re: /<\s*meta\b[^>]*\shttp-equiv\s*=\s*["']\s*refresh\s*["'][^>]*\scontent\s*=\s*["'][^"']*javascript:/gi
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
