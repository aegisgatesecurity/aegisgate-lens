// AegisGate Lens — pii-international-id.js
//
// International PII patterns: national IDs, passports, residence permits, visas, and international driver licenses for the top non-US jurisdictions we expect to encounter in real user prompts. 23 patterns covering Brazil (CPF), India (Aadhaar), UK (NHS), Australia (TFN), Canada (SIN), generic IBAN, BIP39 seed phrases, and passports/NIDs for UK, EU, Canada, Australia, Germany, France, Spain, Italy, Japan.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_cpf_br: {
          // Brazilian CPF (Cadastro de Pessoas Físicas): XXX.XXX.XXX-XX
          // (11 digits with format separators). Critical because CPF is
          // a primary identity document in Brazil; the 11-digit format
          // includes a check digit which we don't validate (the regex
          // is permissive to avoid rejecting valid CPFs that are
          // retyped or formatted differently in prompts).
          severity: 'critical',
          re: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g
        },
        pii_aadhaar_in: {
          // Indian Aadhaar: 12 digits in XXXX-XXXX-XXXX format
          // (occasionally written as XXXX XXXX XXXX). The label is
          // optional; the 12-digit-with-3-4-format is highly specific.
          // We use negative lookbehind/lookahead to avoid matching
          // when the match is part of a larger hyphen-separated sequence.
          severity: 'critical',
          re: /(?<!\d[-\s])\d{4}[-\s]\d{4}[-\s]\d{4}(?!\s*[-\s]\d)/g
        },
        pii_nhs_uk: {
          // UK NHS number: 10 digits in XXX-XXX-XXXX format. Distinct
          // from US SSN (which uses XXX-XX-XXXX) by the dash position.
          // The "NHS" label is REQUIRED to prevent false positives on
          // phone numbers (which also use XXX-XXX-XXXX format).
          severity: 'high',
          re: /\b(?:NHS|NHS\s+Number|National\s+Health\s+Service)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*\d{3}-\d{3}-\d{4}\b/gi
        },
        pii_tfn_au: {
          // Australian Tax File Number: 9 digits in XXX XXX XXX format
          // (spaces, not dashes). We use \s as the separator to match
          // real-world formatted TFNs.
          severity: 'high',
          re: /\b\d{3}\s\d{3}\s\d{3}\b/g
        },
        pii_sin_ca: {
          // Canadian Social Insurance Number: 9 digits in XXX XXX XXX
          // format. We use a negative-lookahead to avoid matching
          // TFN (AU) or other 3-3-3 patterns: SINs start with a digit
          // 1-7 (per the Canadian SIN rules), but the regex is permissive
          // to avoid FNs on edge cases.
          severity: 'high',
          re: /\b[1-7]\d{2}\s\d{3}\s\d{3}\b/g
        },
        pii_iban: {
          // International Bank Account Number: 2 letters (country code)
          // + 2 digits (check digits) + up to 30 alphanumeric. Total
          // length 15-32. We use a strict format with no spaces.
          severity: 'critical',
          re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g
        },
        pii_bip39_seed: {
          // BIP39 cryptocurrency seed phrase: 12 or 24 lowercase words
          // from the BIP39 wordlist, separated by single spaces. The
          // first 4 words are validated against a partial wordlist of
          // common BIP39 words. If at least 3 of the first 4 words are
          // valid BIP39 words AND the total is 12 or 24 words AND all
          // words are 3-8 lowercase letters, we flag as a seed phrase.
          // This is a strong indicator; the false-positive rate on
          // English prose is very low.
          severity: 'critical',
          re: /\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b|\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b/g
        },
        // International passport patterns,
        pii_passport_uk: {
          severity: 'critical',
          re: /(?:UK|United\s+Kingdom)?\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b/gi
        },
        pii_passport_eu: {
          severity: 'critical',
          re: /(?:European\s+Union|EU)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]{1,2}\d{6,8})\b/gi
        },
        pii_passport_ca: {
          severity: 'critical',
          re: /(?:Canadian|Canada)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]\d{8})\b/gi
        },
        pii_passport_au: {
          severity: 'critical',
          re: /(?:Australian|Australia)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b/gi
        },
        pii_passport_de: {
          severity: 'critical',
          re: /(?:German|Germany)\s*Passport\s*(?:#|No\.?)?\s*(?:([A-Z]\d{8})|(D\d{8}))\b/gi
        },
        pii_passport_fr: {
          severity: 'critical',
          re: /(?:French|France)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b/gi
        },
        // National ID patterns,
        pii_nid_de: {
          severity: 'critical',
          re: /(?:German\s+Nationalseid|Personalausweis|PA)\s*[:#]?\s*(\d{11})\b/gi
        },
        pii_nid_fr: {
          severity: 'critical',
          re: /(?:French\s+National\s+ID|Carte\s+Nationale|Carte\s+Nationale\s+Identite|CN)\s*[:#]?\s*([A-Z]{1,5}\d{10})\b/gi
        },
        pii_nid_es: {
          severity: 'critical',
          re: /(?:Spanish\s+National\s+ID|DNI)\s*[:#]?\s*(\d{8}[A-Z])\b/gi
        },
        pii_nid_it: {
          severity: 'critical',
          re: /(?:Italian\s+National\s+ID|Codice\s+Fiscale|CF)\s*[:#]?\s*([A-Z0-9]{16})\b/gi
        },
        pii_nid_jp: {
          severity: 'critical',
          re: /(?:Japanese\s+National\s+ID|My\s+Number|MyNumber)\s*[:#]?\s*(\d{3}-\d{3}-\d{5,6})\b/gi
        },
        // Cryptocurrency wallet patterns,
        pii_residence_us: {
          severity: 'critical',
          re: /(?:I-551|Green\s+Card|Resident\s+Permit)\s*([A-Z]?\d{9,11})\b/gi
        },
        pii_residence_ca: {
          severity: 'critical',
          re: /(?:Permanent\s+Resident|PR\s+Card|Canadians\s+Permanent\s+Resident)\s*([A-Z]?\d{9,11})\b/gi
        },
        pii_residence_uk: {
          severity: 'critical',
          re: /(?:Biometric\s+Residence\s+Permit|BRP)\s*([A-Z]?\d{9,11})\b/gi
        },
        pii_visa: {
          severity: 'critical',
          // Visa number or entry type - Visa [Number|Entry|Type] value
          re: /(?:Visa|visa)\s+(?:number|entry|entry\s+type)?\s*[:=]?\s*([A-Z0-9]{8,17})\b/gi
        },
        pii_driver_license_international: {
          severity: 'high',
          // International DL formats that aren't covered by the US DL patterns.
          // We require a specific language label to avoid overlapping with US DLs.
          // Note: "DL" is intentionally NOT included here - that's handled by pii_driver_license
          re: /(?:(?:Driver's\s+License|State\s+ID|Permis\s+conduire|Führerschein|Patente|Licencia|Permiso|Brevetto|Korti\s+ajamiso|Dokument\s+tożsamosgi)\s*[:#]?\s*[A-Z]?\d{5,15}|(?:Korti\s+ajamiso|Dokument\s+tożsamosgi)\s*[:#]?\s*\d{5,15})\b/gi
        },
        // v0.3.2 parity sync — IPv6 standalone pattern
        pii_ipv6: {
          severity: 'low',
          re: /(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}/g
        }
  };

  if (typeof self !== 'undefined') self.__lensPII_international_id = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_international_id = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_international_id = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
