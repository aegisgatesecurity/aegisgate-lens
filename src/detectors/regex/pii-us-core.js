// AegisGate Lens — pii-us-core.js
//
// US high-priority PII patterns: SSN, email, phone, credit card, DOB, street address, driver license, US passport, EIN tax ID, bank account, IP address. These are the patterns that fire most often in real US user prompts. Loaded by pii.js (the aggregator) BEFORE any other pii-* sub-file so the patterns object is built up in alphabetical group order.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

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
        // ========================================================================
        // v0.1.0-beta Path 1 coverage expansion (2026-07-08, per benchmark v3):
        //   8 new patterns to close the top-3 recall gaps (phone, ID, passport)
        //   and fix two detector bugs (CJK email, 12-digit credit card).
        //   All 8 patterns are NEW entries; existing patterns unchanged.
        // ========================================================================,
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
        },
        // ====================================================================
        // CPT/HCPCS Medical Billing Codes (v0.3.1 addition, 2026-08-13)
        // Healthcare fraud detection: billing codes in AI prompts
        // ====================================================================
        // L-9 fix: Removed unlabeled pii_cpt_code (was matching ANY 5-digit number).
        // Use pii_cpt_code_label instead (requires CPT/procedure code label).
        pii_cpt_code_label: {
          severity: 'high',
          // CPT with label
          re: /(?:CPT|procedure\s+code)\s*[:=]?\s*[0-9]{5}\b/gi
        },
        // L-9 fix: Removed unlabeled pii_hcpcs_level2 (was matching any letter+4digits).
        // Use pii_hcpcs_level2_label instead (requires HCPCS label).
        pii_hcpcs_level2_label: {
          severity: 'high',
          // HCPCS with label
          re: /(?:HCPCS|healthcare\s+procedure\s+code)\s*[:=]?\s*[A-Z][0-9]{4}\b/gi
        },
        pii_hcpcs_level3: {
          severity: 'low',
          // HCPCS Level III: 1 letter + 4 digits + 1 letter
          re: /\b[A-Z][0-9]{4}[A-Z]\b/g
        },
        pii_cpt_cat2: {
          severity: 'low',
          // CPT Category II: 4 digits + F
          re: /\b[0-9]{4}F\b/g
        },
        pii_cpt_cat3: {
          severity: 'low',
          // CPT Category III: 4 digits + T
          re: /\b[0-9]{4}T\b/g
        },
        pii_cpt_evaluation: {
          severity: 'medium',
          // CPT evaluation/management codes (office visits)
          re: /\b9(?:920[34]|921[1-5]|930[0-5]|940[1-4])\b/g
        },
        pii_cpt_lab: {
          severity: 'medium',
          // CPT laboratory/pathology codes
          re: /\b8(?:0053|1000|2000|3000|4000|5000|6000|7000|8000)\b/g
        },
        pii_cpt_radiology: {
          severity: 'medium',
          // CPT radiology codes (X-ray, CT, MRI)
          re: /\b7(?:0000|1000|2000|3000|4000|5000|6000|7000|8000)\b/g
        },
        pii_cpt_surgery: {
          severity: 'high',
          // CPT surgery codes (high-value procedures)
          re: /\b(?:10004|20000|30000|40000|50000|60000)\b/g
        },
        // ====================================================================
        // v0.3.2 parity sync — patterns added for Platform/Rampart parity
        // ====================================================================
        pii_icd10_code: {
          severity: 'medium',
          // ICD-10-CM diagnosis code
          re: /\b[A-TV-Z][0-9][0-9AB]\.[0-9A-TV-Z]{1,4}\b/g
        },
        pii_mrn: {
          severity: 'high',
          // Medical Record Number (requires label)
          re: /\b(?:MRN|Medical\s+Record\s+(?:Number|No\.?|#)|Patient\s+(?:ID|Number|No\.?|#))\b\s*[:=#]?\s*[A-Z0-9][A-Z0-9\-]{4,10}[A-Z0-9]\b/gi
        },
        pii_npi: {
          severity: 'medium',
          // National Provider Identifier (US healthcare)
          re: /\b(?:NPI|National\s+Provider\s+(?:ID|Identifier|Number))\s*[:=#]?\s*[0-9]{10}\b/gi
        },
        pii_ssn_last4: {
          severity: 'high',
          // SSN last-4 digits (requires keyword context)
          re: /\b(?:SSN|Social\s+Security)\s+(?:last|final)\s+(?:4|four)\s*(?:[:=#]|is|was|are|of|equals)?\s*[0-9]{4}\b/gi
        },
  };

  if (typeof self !== 'undefined') self.__lensPII_us_core = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_us_core = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_us_core = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
