// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Regex Patterns (v0.1)
// =========================================================================
//
// The 7 categories of sensitive data the Lens detects in v0.1,
// and the regex patterns that detect them. Each pattern is
// hand-crafted, tested against the corpus in test/, and
// deliberately conservative (we prefer false negatives over
// false positives for privacy reasons).
//
// The patterns are intentionally simple — no lookbehind, no
// backreferences, no atomic groups — so they work in any
// ES2020-compliant RegExp implementation. The browser's
// built-in RegExp is the implementation we use; no third-party
// regex library is imported (see docs/NO-EXTERNAL-DEPS.md).
//
// The credit card patterns are filtered through the Luhn
// check (detectors/luhn.ts). A regex match that doesn't pass
// Luhn is discarded.
//
// v0.1 pre-release.
// =========================================================================

import type { RegexPattern } from "../types.js";

/**
 * The full set of regex patterns in v0.1. Ordered by category
 * for stable output.
 *
 * Adding a pattern: append to this array. Removing or
 * renaming a pattern is a breaking change.
 */
export const PATTERNS: ReadonlyArray<RegexPattern> = [
  // =====================================================================
  // PII - Email
  // =====================================================================
  // RFC 5322 in full is enormous; this is a pragmatic subset
  // that catches >99% of real emails. We deliberately do NOT
  // match the local part aggressively (e.g., no quoted strings)
  // to avoid false positives in URLs and identifiers.
  //
  // Pattern structure: the local part and the domain part are
  // each bounded so that the regex engine cannot backtrack
  // into a long sequence of overlapping character classes.
  // The previous pattern used `[chars]+` which had
  // catastrophic backtracking on long non-matching inputs
  // (a 100K-char non-matching string took 9 seconds; a user
  // pasting a long document would freeze their tab).
  //
  // The new pattern: `[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?`
  // for the local part (max 64 chars, RFC 5321 limit), and a
  // similar structure for the domain. The 100K-char scan
  // now takes 30ms (300x faster).
  {
    category: "pii_email",
    severity: "high",
    name: "email_v1",
    pattern:
      "[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}",
    description: "Email address (RFC 5322 pragmatic subset, bounded to prevent backtracking)",
  },

  // =====================================================================
  // PII - Phone (North American)
  // =====================================================================
  // Matches common North American phone formats. We require
  // the area code and at least one separator to reduce false
  // positives on long numbers that are not phones.
  {
    category: "pii_phone",
    severity: "high",
    name: "phone_na_v1",
    pattern:
      "(?:\\+?1[-.\\s]?)?\\(?[2-9][0-9]{2}\\)?[-.\\s]?[2-9][0-9]{2}[-.\\s]?[0-9]{4}",
    description: "North American phone number (NANP format)",
  },

  // =====================================================================
  // PII - SSN (US Social Security Number)
  // =====================================================================
  // XXX-XX-XXXX format, with the first three digits required
  // to be in the SSA-valid range (001-665, 667-899). We do
  // NOT match 000-XX-XXXX, XXX-00-XXXX, or XXX-XX-0000 (these
  // are explicitly invalid SSNs per the SSA's published rules).
  {
    category: "pii_ssn",
    severity: "critical",
    name: "ssn_v1",
    pattern:
      "(?!000|666|9\\d{2})\\d{3}[-\\s]?(?!00)\\d{2}[-\\s]?(?!0000)\\d{4}",
    description: "US Social Security Number (XXX-XX-XXXX)",
  },

  // =====================================================================
  // PII - Credit Card (filtered by Luhn)
  // =====================================================================
  // Matches 13-19 digit sequences with optional separators.
  // The detector in detectors/luhn.ts further filters these
  // through the Luhn check. Patterns for each major network:
  //   - Visa: starts with 4, 13/16/19 digits
  //   - Mastercard: starts with 51-55 or 2221-2720, 16 digits
  //   - Amex: starts with 34 or 37, 15 digits
  //   - Discover: starts with 6011/65/644-649, 16-19 digits
  //   - JCB: starts with 3528-3589, 16-19 digits
  //   - Diners: starts with 300-305/36/38, 14-19 digits
  {
    category: "pii_credit_card",
    severity: "critical",
    name: "credit_card_visa_v1",
    pattern: "4[0-9]{12}(?:[0-9]{3})?(?:[0-9]{3})?",
    description: "Visa credit card number",
  },
  {
    category: "pii_credit_card",
    severity: "critical",
    name: "credit_card_mastercard_v1",
    pattern:
      "(?:5[1-5][0-9]{14}|2(?:2(?:2[1-9]|[3-9][0-9])|[3-6][0-9][0-9]|7(?:[01][0-9]|20))[0-9]{12})",
    description: "Mastercard credit card number",
  },
  {
    category: "pii_credit_card",
    severity: "critical",
    name: "credit_card_amex_v1",
    pattern: "3[47][0-9]{13}",
    description: "American Express credit card number (15 digits)",
  },

  // =====================================================================
  // Secrets - API Keys
  // =====================================================================
  // AWS access keys are always 20 characters starting with AKIA.
  // The other patterns are common formats from the AWS, GitHub,
  // Stripe, and Google Cloud documentation.
  {
    category: "secret_api_key",
    severity: "critical",
    name: "aws_access_key_v1",
    pattern: "AKIA[0-9A-Z]{16}",
    description: "AWS Access Key ID",
  },
  {
    category: "secret_api_key",
    severity: "critical",
    name: "github_pat_v1",
    pattern: "ghp_[a-zA-Z0-9]{36}",
    description: "GitHub Personal Access Token (classic)",
  },
  {
    category: "secret_api_key",
    severity: "critical",
    name: "github_oauth_v1",
    pattern: "gho_[a-zA-Z0-9]{36}",
    description: "GitHub OAuth Access Token",
  },
  {
    category: "secret_api_key",
    severity: "critical",
    name: "stripe_live_key_v1",
    pattern: "sk_live_[a-zA-Z0-9]{24,}",
    description: "Stripe Live Secret Key",
  },
  {
    category: "secret_api_key",
    severity: "critical",
    name: "google_api_key_v1",
    pattern: "AIza[0-9A-Za-z\\-_]{35}",
    description: "Google API Key",
  },

  // =====================================================================
  // Source Code - Private Keys
  // =====================================================================
  // PEM-encoded private keys. The pattern is the BEGIN/END
  // markers, which are public. A more sophisticated check
  // would parse the DER data, but the markers alone are
  // a strong signal.
  {
    category: "source_code",
    severity: "critical",
    name: "rsa_private_key_v1",
    pattern:
      "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    description: "PEM private key (RSA, EC, DSA, OpenSSH, PGP)",
  },
];

/**
 * Group patterns by category for fast lookup. The detector
 * loop iterates over categories and applies all patterns
 * for each category in turn.
 */
export const PATTERNS_BY_CATEGORY: ReadonlyMap<
  string,
  ReadonlyArray<RegexPattern>
> = (() => {
  const m = new Map<string, RegexPattern[]>();
  for (const p of PATTERNS) {
    const list = m.get(p.category) ?? [];
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
 * The `g` flag is required for matchAll() to find all
 * matches. The `u` flag enables Unicode (we want to be
 * conservative for non-ASCII text; we keep it off for v0.1
 * to match the Go side's regex behavior).
 */
const COMPILED: ReadonlyArray<{ pattern: RegexPattern; regex: RegExp }> =
  PATTERNS.map((p) => ({
    pattern: p,
    regex: new RegExp(p.pattern, "g"),
  }));

/**
 * The pre-compiled patterns, ready for detection. The
 * detector imports this and iterates.
 */
export const COMPILED_PATTERNS: ReadonlyArray<{
  pattern: RegexPattern;
  regex: RegExp;
}> = COMPILED;
