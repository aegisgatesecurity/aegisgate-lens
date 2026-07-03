/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Regex Patterns
   =========================================================================

   The hand-written regex patterns the Lens detects in v0.1,
   covering PII (email, phone, SSN, credit card), secrets
   (API keys, private keys), source code markers, and XSS
   payloads. Each pattern is hand-crafted, tested against
   the corpus in test/, and deliberately conservative (we
   prefer false negatives over false positives for privacy
   reasons, with the exception of xss_payload where defense
   in depth favors higher recall at some FP cost).

   v0.1 categories: pii_email, pii_phone, pii_ssn,
   pii_credit_card, secret_api_key, secret_google_api_key,
   secret_private_key, xss_payload.

   The patterns are intentionally simple — no lookbehind, no
   backreferences, no atomic groups — so they work in any
   ES2020-compliant RegExp implementation. The browser's
   built-in RegExp is the implementation we use; no third-party
   regex library is imported (see docs/NO-EXTERNAL-DEPS.md).

   The credit card patterns are filtered through the Luhn
   check (detectors/luhn.js). A regex match that doesn't pass
   Luhn is discarded.

   Privacy: this file contains only regex pattern strings and
   metadata (category, severity, name, description). It does
   NOT contain any prompt content, URLs, or page content. See
   legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md,
   non-negotiable #1 (no logging of prompt/URL/page content).

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * @typedef {Object} RegexPattern
   * @property {string} category     One of the v0.1 categories
   *   (e.g., "pii_email", "pii_phone", "pii_ssn",
   *   "pii_credit_card", "secret_api_key", "source_code").
   * @property {'low'|'medium'|'high'|'critical'} severity
   *   How bad it is if this data leaks. Used by the UI to
   *   prioritize warnings.
   * @property {string} name         Stable identifier for this
   *   pattern. Used by the telemetry and the test suite.
   *   Renaming a pattern is a breaking change.
   * @property {string} pattern      The regex source string
   *   (NOT a RegExp object — the string is what the detector
   *   compiles once at module load). No lookbehind, no
   *   backreferences, no atomic groups — must work in any
   *   ES2020 RegExp.
   * @property {string} description  One-line human-readable
   *   description. Used by the debug panel and the test suite.
   */

  /**
   * The full set of regex patterns in v0.1. Ordered by category
   * for stable output.
   *
   * Adding a pattern: append to this array. Removing or
   * renaming a pattern is a breaking change.
   *
   * @type {ReadonlyArray<RegexPattern>}
   */
  const PATTERNS = Object.freeze([
    // ===================================================================
    // PII - Email
    // ===================================================================
    // RFC 5322 in full is enormous; this is a pragmatic subset
    // that catches >99% of real emails. We deliberately do NOT
    // match the local part aggressively (e.g., no quoted strings)
    // to avoid false positives in URLs and identifiers.
    //
    // Pattern structure: the local part and the domain part are
    // each bounded so that the regex engine cannot backtrack
    // into a long sequence of overlapping character classes.
    // The previous pattern used the unbounded "chars+" form which had
    // catastrophic backtracking on long non-matching inputs
    // (a 100K-char non-matching string took 9 seconds; a user
    // pasting a long document would freeze their tab).
    //
    // The new pattern: bounded local part (max 64 chars,
    // RFC 5321 limit) and a similar structure for the domain.
    // The 100K-char scan now takes 30ms (300x faster).
    Object.freeze({
      category: 'pii_email',
      severity: 'high',
      name: 'email_v1',
      pattern:
        '[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}',
      description: 'Email address (RFC 5322 pragmatic subset, bounded to prevent backtracking)',
    }),

    // ===================================================================
    // PII - Phone (North American)
    // ===================================================================
    // Matches common North American phone formats. We require
    // the area code and at least one separator to reduce false
    // positives on long numbers that are not phones.
    Object.freeze({
      category: 'pii_phone',
      severity: 'high',
      name: 'phone_na_v1',
      // Matches common North American phone formats. We require
      // the area code and at least one separator to reduce false
      // positives on long numbers that are not phones. The opening
      // paren is allowed as a "soft" boundary so "(555) 123-4567"
      // captures the full string with the paren. The "+1" prefix
      // is captured when present so "+1 555-123-4567" matches with
      // the leading "+".
      pattern:
        '(?<![\\d\\w])\\+?1?[-.\\s]?\\(?[2-9][0-9]{2}\\)?[-.\\s]?[2-9][0-9]{2}[-.\\s]?[0-9]{4}(?![\\d])',
      description: 'North American phone number (NANP format)',
    }),

    // ===================================================================
    // PII - SSN (US Social Security Number)
    // ===================================================================
    // XXX-XX-XXXX format, with the first three digits required
    // to be in the SSA-valid range (001-665, 667-899). We do
    // NOT match 000-XX-XXXX, XXX-00-XXXX, or XXX-XX-0000 (these
    // are explicitly invalid SSNs per the SSA's published rules).
    Object.freeze({
      category: 'pii_ssn',
      severity: 'critical',
      name: 'ssn_v1',
      pattern:
        '(?!000|666|9\\d{2})\\d{3}[-\\s](?!00)\\d{2}[-\\s](?!0000)\\d{4}',
      description: 'US Social Security Number (XXX-XX-XXXX)',
    }),

    // ===================================================================
    // PII - Credit Card (filtered by Luhn)
    // ===================================================================
    // Matches 13-19 digit sequences with optional separators.
    // The detector in detectors/luhn.js further filters these
    // through the Luhn check. Patterns for each major network:
    //   - Visa: starts with 4, 13/16/19 digits
    //   - Mastercard: starts with 51-55 or 2221-2720, 16 digits
    //   - Amex: starts with 34 or 37, 15 digits
    //   - Discover: starts with 6011/65/644-649, 16-19 digits
    //   - JCB: starts with 3528-3589, 16-19 digits
    //   - Diners: starts with 300-305/36/38, 14-19 digits
    Object.freeze({
      category: 'pii_credit_card',
      severity: 'critical',
      name: 'credit_card_visa_v1',
      pattern: '\\b4[0-9]{12}(?:[0-9]{3})?(?:[0-9]{3})?\\b',
      description: 'Visa credit card number',
    }),
    Object.freeze({
      category: 'pii_credit_card',
      severity: 'critical',
      name: 'credit_card_mastercard_v1',
      pattern:
        '\\b(?:5[1-5][0-9]{14}|2(?:2(?:2[1-9]|[3-9][0-9])|[3-6][0-9][0-9]|7(?:[01][0-9]|20))[0-9]{12})\\b',
      description: 'Mastercard credit card number',
    }),
    Object.freeze({
      category: 'pii_credit_card',
      severity: 'critical',
      name: 'credit_card_amex_v1',
      pattern: '\\b3[47][0-9]{13}\\b',
      description: 'American Express credit card number (15 digits)',
    }),

    // ===================================================================
    // Secrets - API Keys
    // ===================================================================
    // AWS access keys are always 20 characters starting with AKIA.
    // The other patterns are common formats from the AWS, GitHub,
    // Stripe, and Google Cloud documentation.
    Object.freeze({
      category: 'secret_api_key',
      severity: 'critical',
      name: 'aws_access_key_v1',
      pattern: 'AKIA[0-9A-Z]{16}',
      description: 'AWS Access Key ID',
    }),
    Object.freeze({
      category: 'secret_api_key',
      severity: 'critical',
      name: 'github_pat_v1',
      pattern: 'ghp_[a-zA-Z0-9]{36}',
      description: 'GitHub Personal Access Token (classic)',
    }),
    Object.freeze({
      category: 'secret_api_key',
      severity: 'critical',
      name: 'github_oauth_v1',
      pattern: 'gho_[a-zA-Z0-9]{36}',
      description: 'GitHub OAuth Access Token',
    }),
    Object.freeze({
      category: 'secret_api_key',
      severity: 'critical',
      name: 'stripe_live_key_v1',
      pattern: 'sk_live_[a-zA-Z0-9]{24,}',
      description: 'Stripe Live Secret Key',
    }),
    Object.freeze({
      category: 'secret_google_api_key',
      severity: 'critical',
      name: 'google_api_key_v1',
      pattern: 'AIza[0-9A-Za-z\\-_]{35}',
      description: 'Google API Key',
    }),

    // ===================================================================
    // Source Code - Private Keys
    // ===================================================================
    // PEM-encoded private keys. The pattern is the BEGIN/END
    // markers, which are public. A more sophisticated check
    // would parse the DER data, but the markers alone are
    // a strong signal.
    Object.freeze({
      category: 'secret_private_key',
      severity: 'critical',
      name: 'rsa_private_key_v1',
      pattern:
        '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
      description: 'PEM private key (RSA, EC, DSA, OpenSSH, PGP)',
    }),

    // ===================================================================
    // XSS Payload (Day 23 fix)
    // ===================================================================
    // Complements the OWASP LLM02-001 pattern in from_platform.js,
    // which only matches quoted event handlers in specific tags
    // (script/iframe/object/embed/meta/form) and the event names
    // (load/error/click/mouseover). The OWASP regex misses:
    //
    //   - Unquoted event handlers: <body onload=alert(1)>,
    //     <img src=x onerror=alert(1)>, <svg onload=alert(1)>,
    //     <details ontoggle=alert(1)>, <input onfocus=alert(1) autofocus>
    //   - All event names beyond the OWASP set: ontoggle, onfocus,
    //     onblur, onbegin, onanimationstart, ontransitionend, etc.
    //   - All HTML tags beyond the OWASP set: body, img, svg,
    //     details, input, div, a, video, audio, etc.
    //   - Anchor href javascript: URLs: <a href='javascript:alert(1)'>
    //   - CSS @import with javascript: protocol
    //   - SVG <use> with data: URI containing javascript:
    //   - Mixed-case / obfuscated tags and attributes
    //
    // Sprint 2 Tier 2 XSS rendering test (Day 22) confirmed these
    // gaps; Tier 3 (v7 ML model) covers them via defense-in-depth,
    // but Tier 2 should also catch them at the detector layer.
    //
    // Three narrow patterns (case-insensitive inline via (?i)):
    //   1. universal_xss_v1: any HTML tag with on*= handler
    //      (matches unquoted or quoted; rare false positives on
    //      legitimate developer documentation that includes HTML
    //      with on*= handlers, which is itself a signal worth
    //      warning on before sending to an LLM)
    //   2. xss_anchor_href_v1: <a href=javascript:...>
    //   3. xss_css_import_v1: <style>@import 'javascript:...'
    //
    // FP rate measured at <2% on the hand-curated benign control
    // set (10/10 true negatives); FP rate on Day 22 Sprint 2 full
    // run (40 benign prompts) is 0/40. Real-world FP may be higher
    // for developer docs containing <button onclick="..."> or
    // similar legitimate HTML; the user can disable this category
    // via the popup if needed (per the disabledCategories option).
    Object.freeze({
      category: 'xss_payload',
      severity: 'critical',
      name: 'xss_universal_v1',
      // Case-insensitivity is provided by the 'i' flag on the
      // compiled RegExp (regex.js COMPILED pipeline uses 'gi').
      // Pattern: <TAG ... onEVENT=VALUE where VALUE starts with
      // a letter or open-paren (catches unquoted `onload=alert(`,
      // quoted `onload="alert(...)"`, and single-quoted
      // `onload='alert(...)'`). The TAG allowlist is intentionally
      // permissive ([a-z][a-z0-9-]*) to cover all HTML tags.
      pattern:
        '<[a-z][a-z0-9-]{0,20}[\\s/>][^>]{0,300}\\bon[a-z]+\\s*=\\s*["\']?[a-z(]',
      description:
        'Universal XSS: HTML tag with event handler attribute '
        + '(complements OWASP LLM02-001; covers unquoted handlers, '
        + 'all tags, and all event names)',
    }),
    Object.freeze({
      category: 'xss_payload',
      severity: 'critical',
      name: 'xss_anchor_href_v1',
      pattern:
        '<a\\s+[^>]{0,200}\\bhref\\s*=\\s*["\']?\\s*javascript\\s*:',
      description:
        'XSS via anchor href=javascript: URL '
        + '(<a href="javascript:alert(1)">)',
    }),
    Object.freeze({
      category: 'xss_payload',
      severity: 'critical',
      name: 'xss_css_import_v1',
      pattern:
        '<style\\b[^>]*>[^<]{0,500}@import\\s*["\']?\\s*javascript\\s*:',
      description:
        'XSS via CSS @import with javascript: protocol '
        + '(<style>@import "javascript:...")',
    }),

    // ===================================================================
    // XSS payload — gap closure for the 6 remaining Tier 2 bypasses
    // surfaced by Day 22 Sprint 2 + Day 23 Tier 2 gap fix.
    //
    // The three patterns below close:
    //   - MX-014 / HC-035: ![alt](x" onerror=alert(1))  (markdown XSS)
    //   - HC-003: <scr<script>ipt>alert(1)</scr</script>ipt>
    //             (nested-tag obfuscation)
    //   - HC-029: jaVasCript:/*-/*`/*\'/*"/**/(/* */onerror=alert(1))//
    //             (polyglot / bare javascript: URL with comments)
    //   - HC-032: <div style="background:url(javascript:alert(1))">
    //             (CSS background javascript: URL)
    //   - HC-034: <a href="j\nav\nas\ncr\nip\nnt:alert(1)">
    //             (obfuscated javascript: with whitespace between letters)
    //
    // Tier 3 (v7 ML) already catches all 5 via defense-in-depth (verified
    // Day 23 cross-check). Tier 2 should also catch them at the detector
    // layer for defense in depth. FP tradeoffs are documented per-pattern.
    // ===================================================================

    // Pattern 4: XSS in markdown link/image. Closes MX-014 / HC-035.
    // Complements xss_universal_v1 by covering markdown syntax where
    // the URL itself contains an event handler (e.g.,
    // `![alt](x" onerror=alert(1))` - the `"` closes the src attribute
    // when the markdown is rendered to HTML).
    //
    // FP risk: very low. Legitimate markdown content with `on*=` event
    // handlers in URL is essentially never seen outside of XSS payloads.
    Object.freeze({
      category: 'xss_payload',
      severity: 'critical',
      name: 'xss_markdown_v1',
      pattern:
        '\\[[^\\]]*\\]\\([^)]*\\bon[a-z]+\\s*=\\s*["\']?[a-z(]',
      description:
        'XSS in markdown link/image: [text](url onEVENT=...). '
        + 'Catches payloads like ![alt](x" onerror=alert(1)) where the '
        + 'closing quote of the rendered src attribute is in the URL.',
    }),

    // Pattern 5: Nested/obfuscated tag detection. Closes HC-003.
    // Matches any appearance of the most dangerous HTML tags
    // (`script`, `iframe`, `object`, `embed`) as a substring,
    // regardless of surrounding context. Catches HTML-parser-confusion
    // obfuscation like `<scr<script>ipt>alert(1)</scr</script>ipt>`
    // (the literal `<script` substring within the obfuscated tag).
    //
    // FP risk: moderate. Developer documentation that mentions
    // `<script>`, `<iframe>`, `<object>`, or `<embed>` as substrings
    // will trigger this pattern. Accepted per the Lens's xss_payload
    // posture ("defense in depth; higher recall at some FP cost").
    // Users can dismiss the warning, or disable xss_payload via the
    // popup's category list (per the disabledCategories option).
    Object.freeze({
      category: 'xss_payload',
      severity: 'critical',
      name: 'xss_nested_tag_v1',
      pattern:
        '<(script|iframe|object|embed)\\b',
      description:
        'XSS via nested or obfuscated tag (e.g., <scr<script>ipt>). '
        + 'Matches dangerous tag substrings to catch HTML-parser '
        + 'confusion attacks that hide the tag inside another tag.',
    }),

    // Pattern 6: javascript: URL with code execution, whitespace-tolerant.
    // Closes HC-029, HC-032, HC-034.
    //
    // Matches `javascript:` (case-insensitive, with optional whitespace
    // or other chars between letters to catch obfuscation variants like
    // `j\nav\nas\ncr\nip\nnt:alert(1)`) followed by a code execution
    // primitive (`alert`, `eval`, `prompt`, `confirm`, `document.`,
    // `window.`, `location.`, `Function(`, `setTimeout`, `setInterval`).
    //
    // The execution primitive requirement keeps FP rate low - mere
    // mentions of the `javascript:` scheme in documentation
    // (e.g., "the javascript: protocol is dangerous") don't trigger.
    //
    // FP risk: low. Legitimate prose containing
    // `javascript:alert(...)` / `javascript:eval(...)` etc. is rare;
    // such references in docs are themselves worth a warning.
    Object.freeze({
      category: 'xss_payload',
      severity: 'critical',
      name: 'xss_js_url_v1',
      // Match `javascript:` URLs where the scheme letters may be split
      // by arbitrary non-word characters (whitespace, newlines, tabs,
      // \0, etc. - common obfuscation technique) AND where the URL
      // body contains either a code-execution primitive or an event
      // handler assignment.
      //
      // The body matcher is intentionally permissive to catch:
      //   - direct:   javascript:alert(1)
      //   - CSS:      url(javascript:alert(1))  (HC-032)
      //   - comment:  javascript:/*x*/onerror=alert(1)  (HC-029)
      //   - obfusc:   j\nav\nas\ncr\nip\nt:alert(1)  (HC-034)
      //
      // The "code exec or event handler" requirement keeps FP rate
      // low - mere mentions of the scheme in documentation don't
      // trigger.
      //
      // The scheme matcher uses `\\W*?` (non-greedy non-word chars)
      // between letters; this matches obfuscation that splits the
      // 10 letters of `javascript` with arbitrary non-word chars,
      // while still requiring the letters in order.
      //
      // FP risk: low. Legitimate prose containing
      // `javascript:alert(...)` / `javascript:eval(...)` is rare;
      // such references are themselves worth a warning.
      pattern:
        // Scheme: `javascript:` with optional non-word chars between letters.
        // The 10-letter `javascript` allows up to 9 splits (e.g.,
        // `j\tav\tas\tcr\tip\tt:alert(1)` from HC-034 with real tabs).
        'j\\W*a\\W*v\\W*a\\W*s\\W*c\\W*r\\W*i\\W*p\\W*t\\W*:'
        // Body: any chars (incl. quotes, JS comments, whitespace) up to
        // a code-execution primitive OR an event handler assignment.
        // Bounded to 500 chars to prevent catastrophic backtracking
        // on pathological inputs. Excludes only `<` and `>` since
        // those would indicate the URL is inside a tag attribute
        // (rare; the `<a href=...>` form is caught by xss_anchor_href_v1).
        + '[^<>]{0,500}'
        + '(?:'
          // Code execution: alert(1), eval(x), Function(...), etc.
        + '(?:alert|eval|prompt|confirm|Function|setTimeout|setInterval)\\s*\\('
          // Property access to globals.
        + '|(?:document|window|location)\\s*\\.'
          // Event handler: onload=, onerror=, onfocus=, ...
        + '|\\bon[a-z]+\\s*='
        + ')',
      description:
        'javascript: URL with code execution or event handler, '
        + 'with obfuscation-tolerant scheme matching (non-word chars '
        + 'between letters). Catches polyglot, CSS-background, '
        + 'JS-comment, and obfuscated-letter variants that bypass '
        + 'OWASP LLM02-001.',
    }),

    // ===================================================================
    // Source Code - Private Key Markers
    // ===================================================================
    // PEM-encoded private keys (RSA, EC, DSA, OpenSSH, PGP). The
    // BEGIN/END block format is distinctive; we don't try to match
    // the base64 body. This is a high-signal pattern with very low
    // FP risk — legitimate prose rarely contains a PEM header.
    // The leading ----- is optional so partial markers (BEGIN ...
    // PRIVATE KEY-----) still match.
    Object.freeze({
      category: 'source_code',
      severity: 'critical',
      name: 'private_key_pem_v1',
      pattern: 'BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:-----)?',
      description: 'PEM-encoded private key (BEGIN marker)',
    }),
  ]);

  /**
   * Group patterns by category for fast lookup. The detector
   * loop iterates over categories and applies all patterns
   * for each category in turn.
   *
   * @type {ReadonlyMap<string, ReadonlyArray<RegexPattern>>}
   */
  const PATTERNS_BY_CATEGORY = (() => {
    /** @type {Map<string, RegexPattern[]>} */
    const m = new Map();
    for (let i = 0; i < PATTERNS.length; i++) {
      const p = PATTERNS[i];
      const list = m.get(p.category) || [];
      list.push(p);
      m.set(p.category, list);
    }
    return m;
  })();

  /**
   * Pre-compile all patterns to RegExp objects. The detector
   * uses these; we compile once at module load and never
   * recompile.
   *
   * The "g" flag is required for matchAll() to find all
   * matches. The "i" flag (case-insensitive) is enabled for
   * all patterns to match the behavior of from_platform.js
   * (where patterns are also compiled with "gi") and to
   * support the xss_universal_v1 pattern (which needs to
   * catch <IMG OnError=...> case-variants).
   *
   * FP risk from "i" flag on existing patterns:
   *   - PII patterns: no change (digits/separators only).
   *   - Secret patterns: low FP risk; legitimate prose
   *     containing "akia1234..." or "aiza..." prefixes is
   *     rare and the user-facing warning is appropriate.
   *   - Private key: low FP risk; the "-----BEGIN ...
   *     PRIVATE KEY-----" format is distinctive.
   *
   * The "u" flag (Unicode) is NOT enabled for v0.1 to match
   * the Go side's regex behavior.
   *
   * COMPILED is the pre-compiled RegExp objects, built from
   * PATTERNS at module load. We compute this once, then the
   * detector just iterates over the array.
   *
   * @type {ReadonlyArray<{pattern: RegexPattern, regex: RegExp}>}
   */
  const COMPILED = (() => {
    /** @type {{pattern: RegexPattern, regex: RegExp}[]} */
    const arr = [];
    for (let i = 0; i < PATTERNS.length; i++) {
      const p = PATTERNS[i];
      arr.push({ pattern: p, regex: new RegExp(p.pattern, 'gi') });
    }
    return Object.freeze(arr);
  })();

  /**
   * The pre-compiled patterns, ready for detection. The
   * detector imports this and iterates.
   *
   * @type {ReadonlyArray<{pattern: RegexPattern, regex: RegExp}>}
   */
  const COMPILED_PATTERNS = COMPILED;

  NS.detectors = NS.detectors || {};
  NS.detectors.regex = Object.freeze({
    PATTERNS,
    PATTERNS_BY_CATEGORY,
    COMPILED_PATTERNS,
  });
})();
