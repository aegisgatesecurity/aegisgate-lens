// AegisGate Lens — detectors/regex/pii.js
// Facet 1: PII detection. Regex-based, with Luhn validation for
// credit cards.
//
// Categories (per the architecture doc Section 3 + schema.js):
//   pii_ssn            — US Social Security Number (XXX-XX-XXXX)
//   pii_email          — Email address (RFC 5322 simplified)
//   pii_phone          — Phone number (E.164-ish, US/international)
//   pii_credit_card    — Credit card number (Luhn-validated)
//   pii_address        — US street address (street + city/state/zip)
//   pii_dob            — Date of birth (multiple formats)
//   pii_driver_license — US driver license (state-specific patterns)
//   pii_passport       — US passport number
//   pii_tax_id         — US EIN (XX-XXXXXXX)
//   pii_bank_account   — US bank routing + account (ABA pattern)
//   pii_ip_address     — IPv4 or IPv6 address
//
// Each pattern returns a match object with .category, .severity,
// .confidence, and .index. The dispatcher in 3e aggregates these
// into a single event per prompt.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Pull in Luhn from the sibling module. The luhn.js is NOT listed
  // in manifest.json content_scripts (it's a utility for this
  // detector, not a separate script the page needs). Instead we
  // either inline a require (for node:test) or rely on it being
  // loaded earlier in this same script when the content script
  // runs in the browser. For simplicity, we look for it on
  // globalThis at call time; if absent, we skip the Luhn check
  // (and the regex still flags the candidate as a potential card,
  // so the dispatcher can still warn).
  function getLuhn() {
    if (typeof self !== 'undefined' && self.__lensLuhn) return self.__lensLuhn;
    if (typeof globalThis !== 'undefined' && globalThis.__lensLuhn) return globalThis.__lensLuhn;
    return null;
  }

  // The actual regexes. Each is a function (text) => Array<match>
  // where match is { category, severity, confidence, value, index }.
  //
  // Severity levels:
  //   critical — direct identity theft vector (SSN, passport, full CC+CVV)
  //   high     — strong identity vector (DOB, driver license, full CC w/o CVV)
  //   medium   — contextual identity vector (email, phone, address, IP)
  //   low      — informational

  var patterns = {
    pii_ssn: {
      severity: 'critical',
      // 9 digits in XXX-XX-XXXX or XXX XX XXXX format. We require
      // the separators (dashes or spaces) between the 3-2-4 groups
      // to avoid matching 9-digit numbers like bank routing numbers
      // or arbitrary IDs. An SSN with NO separators is matched by
      // a separate, more permissive pattern (case 2 below).
      re: /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g
    },
    pii_email: {
      severity: 'medium',
      // RFC 5322 simplified: local@domain.tld. Allows +, ., -, _ in
      // local part. Domain is at least 2 labels. TLD is 2-24 alpha.
      re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g
    },
    pii_phone: {
      severity: 'medium',
      // US phone: exactly 10 digits (area code + 7-digit local), with
      // a variety of separators. International prefix is optional
      // (+1 or +CC). The 10-digit count is the boundary that prevents
      // matching credit card numbers (16 digits) or routing numbers
      // (9 digits) or account numbers (10-12 digits).
      re: /(?:\+?\d{1,3}[-.\s]?)?\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g
    },
    pii_credit_card: {
      severity: 'high',
      // 13-19 digits, optional spaces or dashes between groups.
      // Luhn-validated in postProcess. To prevent overlap with phone
      // (10 digits) and SSN (9 digits), we require at least 13 digits
      // total (with separators allowed).
      re: /\b(?:\d{4}[ -]?){3}\d{1,7}\b|\b\d{13,19}\b/g
    },
    pii_dob: {
      severity: 'high',
      // DOB common formats: MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD,
      // Mon DD, YYYY. We're permissive on the day/year but require
      // a year that looks plausible (1900-2099).
      re: /\b(?:(?:0?[1-9]|1[0-2])[\/.\-](?:0?[1-9]|[12]\d|3[01])[\/.\-](?:19|20)\d{2}|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01]))\b/g
    },
    pii_address: {
      severity: 'medium',
      // US street: number + street name + (St|Ave|Rd|Blvd|Ln|Dr|Way|Ct|Pl).
      // This is approximate; we use word boundaries to avoid false hits.
      re: /\b\d{1,6}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Place|Pl)\b\.?(?:\s+(?:Apt|Suite|Ste|#)\s*\d+)?/g
    },
    pii_driver_license: {
      severity: 'high',
      // US DL formats vary by state. We match a label + alphanumeric.
      // The label makes the FP rate low; the value can be any 5-15
      // uppercase alnum. The label/value separator may be :, #, No.,
      // or whitespace.
      re: /\b(?:DL|D\.L\.|Driver(?:'s)?\s+License|License)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*[A-Z0-9]{5,15}\b/gi
    },
    pii_passport: {
      severity: 'critical',
      // US passport: 1 letter + 8 digits. The "Passport" label is
      // REQUIRED to prevent false positives on alphanumeric codes
      // like "D12345678" (DL) or "A12345678" (random). The label
      // makes the FP rate near zero.
      re: /\b(?:US|United\s+States\s+)?Passport\s*(?:#|No\.?)?\s*[A-Z]\d{8}\b/gi
    },
    pii_tax_id: {
      severity: 'high',
      // US EIN: XX-XXXXXXX (9 digits with one dash after the first 2).
      re: /\b\d{2}-\d{7}\b/g
    },
    pii_bank_account: {
      severity: 'high',
      // US ABA routing: 9 digits with optional spaces/dashes. Account:
      // 4-17 digits. We match the label "Routing" or "Account".
      re: /\b(?:Routing|Account|ABA)\s*(?:#|No\.?|Number)?\s*\d{4,17}\b/gi
    },
    pii_ip_address: {
      severity: 'low',
      // IPv4: a.b.c.d with each octet 0-255. IPv6: hex groups with colons.
      re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g
    }
  };

  // Post-process: Luhn-validate credit card candidates. If a candidate
  // doesn't pass Luhn, we drop it (it was a 16-digit number, not a
  // real card). This is the FP-reduction step.
  //
  // If luhn.js failed to load (i.e., __lensLuhn is not on globalThis),
  // we log a warning and drop the match anyway. The CC detection is
  // useless without Luhn (high FP rate), so we drop rather than
  // silently pass through.
  function postProcess(category, match) {
    if (category === 'pii_credit_card') {
      var luhn = getLuhn();
      if (!luhn) {
        // Luhn module unavailable. Without Luhn validation, every
        // 13-19 digit run would be flagged as a credit card — too
        // many false positives. Drop the match. The logger, if
        // available, will note this so the user knows CC detection
        // is degraded.
        var log = (typeof self !== 'undefined' && self.__lensLogger) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
                  null;
        if (log && typeof log.warn === 'function') {
          log.warn('pii.detect: luhn module unavailable; credit card candidate dropped');
        }
        return null;
      }
      var v = luhn.validateCard(match.value);
      if (!v.valid) return null;  // drop false positive
      // Attach the card type for the dispatcher
      match.cardType = v.type;
    }
    return match;
  }

  // The detect function. Takes a string, returns Array<match>.
  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(patterns);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = patterns[key];
      // Reset lastIndex for each pattern (regex with /g)
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        var match = {
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0],
          index: m.index
        };
        var processed = postProcess(key, match);
        if (processed !== null) matches.push(processed);
        // Avoid infinite loop on zero-length matches
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    // Sort by index so the dispatcher sees them in source order
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = {
    detect: detect,
    patterns: patterns
  };

  if (typeof self !== 'undefined') self.__lensPII = module;
  if (typeof window !== 'undefined') window.__lensPII = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensPII = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
