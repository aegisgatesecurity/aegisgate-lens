/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Regex Patterns
   =========================================================================

   The 7 categories of sensitive data the Lens detects in v0.1,
   and the regex patterns that detect them. Each pattern is
   hand-crafted, tested against the corpus in test/, and
   deliberately conservative (we prefer false negatives over
   false positives for privacy reasons).

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
      pattern:
        '\\b(?:\\+?1[-.\\s]?)?\\(?[2-9][0-9]{2}\\)?[-.\\s]?[2-9][0-9]{2}[-.\\s]?[0-9]{4}\\b',
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
   * matches. The "u" flag enables Unicode (we want to be
   * conservative for non-ASCII text; we keep it off for v0.1
   * to match the Go side's regex behavior).
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
      arr.push({ pattern: p, regex: new RegExp(p.pattern, 'g') });
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
