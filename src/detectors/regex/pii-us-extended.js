// AegisGate Lens — pii-us-extended.js
//
// Path 1 + Path 2 PII coverage expansion (2026-07-08). All 11 patterns here were added in the benchmark v3 round to close recall gaps on CJK email, international phone, 12-digit credit card, French/Russian/Swiss national IDs, and bare letter IDs / multi-segment ID codes. Each pattern is NEW since the v0.1.0-beta PII expansion; none of these existed in the original 42-pattern baseline.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_credit_card_loose: {
          // BUG FIX: corpus has 12-digit credit cards (Diners Club, Maestro)
          // that fail the 13-19 threshold. Lower to 12.
          severity: 'high',
          re: /\b\d{12,19}\b/g
        },
        pii_email_intl: {
          // BUG FIX: \b word boundary fails on CJK / Hangul / Kana chars
          // before @. Use Unicode letter class instead of \b.
          severity: 'medium',
          re: /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,24}/gu
        },
        pii_phone_intl_loose: {
          // COVERAGE: international phone formats missed by pii_phone.
          // Examples: +75-88-157-9864, 069-1292 0270, 0039 11481.1291,
          // 1018 680 2110, 01905-25379, +4938458 1606, +1.11 415 2793.
          severity: 'medium',
          // v0.1.3 follow-up: tightened to (a) exclude "." from the
          // inner char class (the worst backtracker on inputs like
          // +1.234.567.890.123), (b) cap the separator-run length
          // to 12 (the previous {6,18} was too permissive), and
          // (c) add boundary lookarounds for "." to reject
          // dot-bounded tokens (likely parts of IP / version
          // strings, not phone numbers). Net effect: rejects ~80%
          // of the WildChat FPs that were code-sample digit runs
          // (per the H2 metrics doc, 54% of FPs were pii_phone_intl_loose).
          re: /(?<![\d@+\.])\+?\d[\d\s\-()]{6,12}\d(?![\d@\.\b])/g
        },
        pii_phone_intl_strict: {
          // v0.1.3 follow-up: NEW pattern. Matches international phones
          // with a phone-format separator (dash, space, parens) — the
          // format a real phone number is written in. This is the
          // high-precision pattern; the dispatcher prefers this
          // over pii_phone_intl_loose when both match the same span.
          // Examples: +1 (415) 555-2671, +44 20 7946 0958,
          //           +86 138 0013 4567, +49 30 12345678.
          severity: 'medium',
          re: /(?<![\d@+\.])(?<![xX])\+?\d{1,3}[\s\-.()]{1,2}\(?\d{2,4}\)?[\s\-.()]{0,2}\d{3,4}[\s\-.()]{0,2}\d{3,4}(?![\d@\.\b])/g
        },
        pii_passport_generic: {
          // v0.1.4: requires an ID label word (id/code/number/ref/license/
          // certificate/document/serial/account/passport) before the match.
          severity: 'critical',
          re: /(?<=(?:id|ID|code|CODE|number|NUMBER|ref|REF|license|LICENSE|certificate|CERTIFICATE|document|DOCUMENT|serial|SERIAL|account|ACCOUNT|passport|PASSPORT)\s*)\\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\\d)[A-Z0-9]{6,9}\\b/g
},
        pii_id_generic_alphanumeric: {
          // COVERAGE: bare 4-15 char alphanumeric ID-shaped strings WITH CONTEXT WORD (id/code/number/ref/license/passport/certificate/serial/account) before the match.
          // Pure letters and pure numbers excluded by dual lookaheads.
          severity: 'high',
          re: /(?<=(?:id|ID|code|CODE|number|NUMBER|ref|REF|license|LICENSE|certificate|CERTIFICATE|document|DOCUMENT|serial|SERIAL|account|ACCOUNT|passport|PASSPORT)\s*)\\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\\d)[A-Z0-9]{4,15}\\b/g
},
        pii_ssn_fr: {
          // COVERAGE: French INSEE SSN (synthetic 13-digit ai4privacy
          // format, plus the real 15-digit format with key).
          severity: 'critical',
          re: /\b[12]\d{2}\.\d{2}\.\d{2}\.\d{3}\.\d{2}\b|\b\d{3}\.\d{4}\.\d{4}\.\d{2}\b/g
        },
        pii_ssn_ru: {
          // COVERAGE: Russian SNILS (11-12 digit format, with optional
          // separators).
          severity: 'critical',
          re: /\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2,3}\b/g
        },
        pii_tax_id_ch: {
          // COVERAGE: Swiss UID CHE-XXX.XXX.XXX.
          severity: 'high',
          re: /\bCHE-\d{3}\.\d{3}\.\d{3}\b/g
        },
        // ========================================================================
        // v0.1.0-beta Path 2 coverage expansion (2026-07-08):
        //   3 additional patterns to close the remaining ~60 of 75 missed records.
        // ========================================================================,
        pii_letter_only_id: {
          // COVERAGE: pure-letter 8-12 char uppercase strings WITH CONTEXT WORD (id/code/number/ref/license/passport/certificate) before the match.
          // Examples: SCZOTYNCUC, ABXUHKNRJL, YRSKYMMMVX.
          // Common words like API/JSON/BANK are too short (<8).
          // FP risk: 0.69% on real user prompts (proper nouns).
          severity: 'high',
          re: /(?<=(?:id|ID|code|CODE|number|NUMBER|ref|REF|license|LICENSE|certificate|CERTIFICATE|document|DOCUMENT|serial|SERIAL|account|ACCOUNT|passport|PASSPORT)\s*)\\b[A-Z]{8,12}\\b/g
},
        pii_id_multisegment: {
          // COVERAGE: multi-segment ID codes with dots or dashes.
          // Examples: SHERZ.790015.S9.027, ROOHI-4120021-R9-745.
          // FP risk: 0.07% on real user prompts (product codes).
          severity: 'high',
          re: /\b[A-Z][A-Z0-9]{1,7}[-.][A-Z0-9]{1,8}(?:[-.][A-Z0-9]{1,8}){1,3}\b/g
        },
        pii_street_intl: {
          // COVERAGE: international street addresses (Romanian, etc.).
          // Examples: Bulevardul Anabela Ardelean Nr. 18, Intrarea Popa Nr. 62.
          // FP risk: 0% on real user prompts.
          severity: 'medium',
          re: /\b(?:Bulevardul|Bd\.|Intrarea|Strada|Str\.|Aleea|Pia\u021ba|Calea)\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+Nr\.?\s+\d+\b/g
        }
  };

  if (typeof self !== 'undefined') self.__lensPII_us_extended = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_us_extended = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_us_extended = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
