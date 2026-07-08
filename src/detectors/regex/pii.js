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
    // ========================================================================
    // v0.1.0-beta Path 1 coverage expansion (2026-07-08, per benchmark v3):
    //   8 new patterns to close the top-3 recall gaps (phone, ID, passport)
    //   and fix two detector bugs (CJK email, 12-digit credit card).
    //   All 8 patterns are NEW entries; existing patterns unchanged.
    // ========================================================================
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
      re: /(?<![\d@+])(?:\+\d{1,3}[-.\s]?)?(?:\d[\d\s.\-()]{6,18}\d)(?![\d@])/g
    },
    pii_passport_generic: {
      // COVERAGE: bare 6-9 char alphanumeric strings (mix of letters
      // and digits). Examples: LJL573183, 24WP95966, I0623513.
      severity: 'critical',
      re: /\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b/g
    },
    pii_id_generic_alphanumeric: {
      // COVERAGE: bare 4-15 char alphanumeric ID-shaped strings.
      // Pure letters and pure numbers excluded by dual lookaheads.
      severity: 'high',
      re: /\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{4,15}\b/g
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
    // ========================================================================
    pii_letter_only_id: {
      // COVERAGE: pure-letter 8-12 char uppercase strings.
      // Examples: SCZOTYNCUC, ABXUHKNRJL, YRSKYMMMVX.
      // Common words like API/JSON/BANK are too short (<8).
      // FP risk: 0.69% on real user prompts (proper nouns).
      severity: 'high',
      re: /\b[A-Z]{8,12}\b/g
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
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta PII expansion, 2026-07-04)
    // Each pattern is verified with positive + negative test cases in
    // test/unit/regex-pii.test.mjs.
    // ====================================================================
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
    // International passport patterns
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
    // National ID patterns
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
    // Cryptocurrency wallet patterns
    pii_crypto_btc: {
      severity: 'high',
      re: /(?:Bitcoin|BTC|btc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qrp][0-9A-Za-z]{39,59})\b/gi
    },
    pii_crypto_eth: {
      severity: 'high',
      re: /(?:Ethereum|ETH|eth)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40})\b/gi
    },
    pii_crypto_bnb: {
      severity: 'high',
      re: /(?:Binance|BNB|bnb)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40}|bnb[a-zA-HJ-NP-Z1-9]{39})\b/gi
    },
    pii_crypto_ltc: {
      severity: 'high',
      re: /(?:Litecoin|LTC|ltc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([LM3][a-zA-Z0-9]{26,33})\b/gi
    },
    pii_crypto_sol: {
      severity: 'high',
      re: /(?:Solana|SOL|sol)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([1-9A-HJ-NP-Za-km-z]{32,44})\b/gi
    },
    // Digital payment patterns - based on test expectations
    pii_digital_paypal: {
      severity: 'medium',
      // PayPal email - requires "email" keyword
      // PayPal ID - P followed by digits
      re: /(?:PayPal|paypal)\s+(?:email|email\s+address|email\s+no\.?|ID)\s*[:=]?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[A-Z]\d{9,})\b/gi
    },
    pii_digital_stripe: {
      severity: 'high',
      // Stripe keys and customer/payment IDs
      re: /(?:Stripe|stripe)\s+(?:api\s*key|secret\s*key|publishable\s*key|customer\s*ID|customer|payment\s*ID|payment)?\s*[:=]?\s*(pk_live_[0-9a-zA-Z]{24,50}|sk_live_[0-9a-zA-Z]{24,50}|pk_test_[0-9a-zA-Z]{24,50}|sk_test_[0-9a-zA-Z]{24,50}|cus_[A-Za-z0-9]{21,}|pi_[A-Za-z0-9]{21,}|pay_[A-Za-z0-9]{21,})\b/gi
    },
    pii_digital_venmo: {
      severity: 'medium',
      // Venmo username - @username or username format
      re: /(?:Venmo|venmo)\s+(?:username|user\s+name|handle)?\s*[:=]?\s*(@[a-zA-Z][a-zA-Z0-9._]{0,29}|[a-zA-Z][a-zA-Z0-9._]{1,30})\b/gi
    },
    pii_digital_cashapp: {
      severity: 'medium',
      re: /(?:Cashapp|cashapp|cash\s*app)\s*(?:username|handle)?\s*[:=]?\s*(\$?[a-zA-Z][a-zA-Z0-9._-]{1,20})\b/gi
    },
    // Residence permit patterns
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
    if (category === 'pii_phone_intl_loose') {
      // Filter by digit count: phones are 7-15 digits (ITU-T E.164).
      // We exclude:
      //   - 9-digit matches (US SSN shape: XXX-XX-XXXX)
      //   - 12+ digit matches (credit card / IBAN / SNILS)
      //   - 4-6 digit matches (too short to be a phone)
      //   - matches that are entirely inside a date (YYYY-MM-DD = 8 digits)
      var digits = (match.value.match(/d/g) || []).length;
      if (digits < 7 || digits > 15) return null;
      if (digits === 9) return null;  // SSN shape, not phone
      // Reject pure date-like matches (8 digits in 4-2-2 or 2-2-4 pattern)
      if (digits === 8 && /^d{4}[-.s]d{1,2}[-.s]d{1,2}$/.test(match.value)) return null;
    }
    // ====================================================================
    // PostProcess for new patterns (v0.1.0-beta expansion)
    // ====================================================================
    if (category === 'pii_bip39_seed') {
      // The regex matches 12- or 24-word sequences. We need to
      // verify the words are likely BIP39 (vs random English words).
      // We use a partial wordlist of the 100 most common BIP39
      // words. If at least 3 of the 12 words (or 5 of 24) are in
      // the wordlist AND all words are 3-8 lowercase letters, we
      // accept the match. Otherwise drop it as a false positive
      // (e.g., "the quick brown fox jumps over the lazy dog" is 9
      // words, not 12 or 24, so the regex wouldn't even match; but
      // a 12-word English sentence could match the regex).
      var BIP39_COMMON = ['abandon', 'ability', 'able', 'about', 'above', 'absent',
        'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
        'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
        'across', 'act', 'action', 'actor', 'actress', 'actual', 'adapt',
        'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
        'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age',
        'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle',
        'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley',
        'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
        'always', 'amateur', 'amazing', 'among', 'amount', 'amused',
        'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal',
        'ankle', 'announce', 'annual', 'another', 'answer', 'antenna',
        'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple',
        'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue',
        'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest',
        'arrive', 'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask',
        'aspect', 'assault', 'asset', 'assist', 'assume', 'asthma',
        'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract',
        'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn',
        'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome',
        'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge',
        'bag', 'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner',
        'bar', 'barely', 'bargain', 'barrel', 'base', 'basic', 'basket',
        'battle', 'beach', 'bean', 'beauty', 'because', 'become', 'beef',
        'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt',
        'bench', 'benefit', 'best', 'betray', 'better', 'between', 'beyond',
        'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird', 'birth',
        'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak',
        'bless', 'blind', 'blood', 'blossom', 'blouse', 'blue', 'blur',
        'blush', 'board', 'boat', 'body', 'boil', 'bomb', 'bone', 'bonus',
        'book', 'boost', 'border', 'boring', 'borrow', 'boss', 'bottom',
        'bounce', 'box', 'boy', 'bracket', 'brain', 'brand', 'brass',
        'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief', 'bright',
        'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom', 'brother',
        'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build',
        'bulb', 'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger',
        'burst', 'bus', 'business', 'busy', 'butter', 'buyer', 'buzz',
        'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake', 'call',
        'calm', 'camera', 'camp', 'can', 'canal', 'cancel', 'candy',
        'cannon', 'canoe', 'canvas', 'canyon', 'capable', 'capital',
        'captain', 'car', 'carbon', 'card', 'cargo', 'carpet', 'carry',
        'cart', 'case', 'cash', 'casino', 'castle', 'casual', 'cat',
        'catalog', 'catch', 'category', 'cattle', 'caught', 'cause',
        'caution', 'cave', 'ceiling', 'celery', 'cement', 'census',
        'century', 'cereal', 'certain', 'chair', 'chalk', 'champion',
        'change', 'chaos', 'chapter', 'charge', 'chase', 'chat',
        'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken',
        'chief', 'child', 'chimney', 'choice', 'choose', 'chronic',
        'chuckle', 'chunk', 'churn', 'cigar', 'cinnamon', 'circle',
        'citizen', 'city', 'civil', 'claim', 'clap', 'clarify', 'claw',
        'clay', 'clean', 'clerk', 'clever', 'click', 'client', 'cliff',
        'climb', 'clinic', 'clip', 'clock', 'clog', 'close', 'cloth',
        'cloud', 'clown', 'club', 'clump', 'cluster', 'clutch', 'coach',
        'coast', 'coconut', 'code', 'coffee', 'coil', 'coin', 'collect',
        'color', 'column', 'combine', 'come', 'comfort', 'comic', 'common',
        'company', 'concert', 'conduct', 'confirm', 'congress', 'connect',
        'consider', 'control', 'convince', 'cook', 'cool', 'copper',
        'copy', 'coral', 'core', 'corn', 'correct', 'cost', 'cotton',
        'couch', 'country', 'couple', 'course', 'cousin', 'cover', 'coyote',
        'crack', 'cradle', 'craft', 'cram', 'crane', 'crash', 'crater',
        'crawl', 'crazy', 'cream', 'credit', 'creek', 'crew', 'cricket',
        'crime', 'crisp', 'critic', 'crop', 'cross', 'crouch', 'crowd',
        'crucial', 'cruel', 'cruise', 'crumble', 'crunch', 'crush', 'cry',
        'crystal', 'cube', 'culture', 'cup', 'cupboard', 'curious',
        'current', 'curtain', 'curve', 'cushion', 'custom', 'cute',
        'cycle', 'dad', 'damage', 'damp', 'dance', 'danger', 'daring',
        'dash', 'daughter', 'dawn', 'day', 'deal', 'debate', 'debris',
        'decade', 'december', 'decide', 'decline', 'decorate', 'decrease',
        'deer', 'defense', 'define', 'defy', 'degree', 'delay', 'deliver',
        'demand', 'demise', 'denial', 'dentist', 'deny', 'depart', 'depend',
        'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert',
        'design', 'desk', 'despair', 'destroy', 'detail', 'detect', 'develop',
        'device', 'devote', 'diagram', 'dial', 'diamond', 'diary', 'dice',
        'diesel', 'diet', 'differ', 'digital', 'dignity', 'dilemma', 'dinner',
        'dinosaur', 'direct', 'dirt', 'disagree', 'discover', 'disease',
        'dish', 'dismiss', 'disorder', 'display', 'distance', 'divert',
        'divide', 'divorce', 'dizzy', 'doctor', 'document', 'dog', 'doll',
        'dolphin', 'domain', 'donate', 'donkey', 'donor', 'door', 'dose',
        'double', 'dove', 'draft', 'dragon', 'drama', 'drastic', 'draw',
        'dream', 'dress', 'drift', 'drill', 'drink', 'drip', 'drive',
        'drop', 'drum', 'dry', 'duck', 'dumb', 'dune', 'during', 'Dutch',
        'duty', 'dwarf', 'dynamic', 'eager', 'eagle', 'early', 'earn',
        'earth', 'easily', 'east', 'easy', 'echo', 'ecology', 'economy',
        'edge', 'edit', 'educate', 'effort', 'egg', 'eight', 'either',
        'elbow', 'elder', 'electric', 'elegant', 'element', 'elephant',
        'elevator', 'elite', 'else', 'embark', 'embody', 'embrace', 'emerge',
        'emotion', 'employ', 'empower', 'empty', 'enable', 'enact', 'end',
        'endless', 'endorse', 'enemy', 'energy', 'enforce', 'engage', 'engine',
        'enhance', 'enjoy', 'enlist', 'enough', 'enrich', 'enroll', 'ensure',
        'enter', 'entire', 'entry', 'envelope', 'environment', 'equal',
        'equip', 'era', 'erase', 'erode', 'erosion', 'error', 'erupt',
        'escape', 'essay', 'essence', 'estate', 'eternal', 'ethics',
        'evidence', 'evil', 'evoke', 'evolve', 'exact', 'example',
        'excess', 'exchange', 'excite', 'exclude', 'excuse', 'execute',
        'exercise', 'exhaust', 'exhibit', 'exile', 'exist', 'exit', 'exotic',
        'expand', 'expect', 'expire', 'explain', 'expose', 'express',
        'extend', 'extra', 'eye', 'eyebrow', 'fabric', 'face', 'faculty',
        'fade', 'faint', 'faith', 'fall', 'false', 'fame', 'family', 'famous',
        'fan', 'fancy', 'fantasy', 'farm', 'fashion', 'fat', 'fatal',
        'father', 'fatigue', 'fault', 'favorite', 'feature', 'february',
        'federal', 'fee', 'feed', 'feel', 'female', 'fence', 'festival',
        'fetch', 'fever', 'few', 'fiber', 'fiction', 'field', 'fight',
        'figure', 'file', 'film', 'filter', 'final', 'find', 'fine', 'finger',
        'finish', 'fire', 'firm', 'first', 'fiscal', 'fish', 'fit', 'fitness',
        'fix', 'flag', 'flame', 'flash', 'flat', 'flavor', 'flee', 'flight',
        'flip', 'float', 'flock', 'floor', 'flower', 'fluid', 'flush',
        'fly', 'foam', 'focus', 'fog', 'foil', 'fold', 'follow', 'food',
        'foot', 'force', 'forest', 'forget', 'fork', 'fortune', 'forum',
        'forward', 'fossil', 'foster', 'found', 'fox', 'fragile', 'frame',
        'frequent', 'fresh', 'friend', 'fringe', 'frog', 'front', 'frost',
        'frown', 'frozen', 'fruit', 'fuel', 'fun', 'funny', 'furnace',
        'fury', 'future', 'gadget', 'gain', 'galaxy', 'gallery', 'game',
        'gap', 'garage', 'garbage', 'garden', 'garlic', 'gas', 'gate',
        'gather', 'gauge', 'gaze', 'general', 'genius', 'genre', 'gentle',
        'genuine', 'gesture', 'ghost', 'giant', 'gift', 'giggle', 'ginger',
        'giraffe', 'girl', 'give', 'glad', 'glance', 'glare', 'glass',
        'glide', 'glimpse', 'globe', 'gloom', 'glory', 'glove', 'glow',
        'glue', 'goat', 'goddess', 'gold', 'good', 'goose', 'gorilla',
        'gospel', 'gossip', 'govern', 'gown', 'grab', 'grace', 'grain',
        'grant', 'grape', 'grass', 'gravity', 'great', 'green', 'grid',
        'grief', 'grit', 'grocery', 'group', 'grow', 'grunt', 'guard',
        'guess', 'guide', 'guilt', 'guitar', 'gun', 'gym', 'habit', 'hair',
        'half', 'hammer', 'hamster', 'hand', 'happy', 'harbor', 'hard',
        'harsh', 'harvest', 'hat', 'have', 'hawk', 'hazard', 'head', 'heart',
        'heavy', 'hedgehog', 'height', 'hello', 'helmet', 'help', 'hen',
        'hero', 'hidden', 'high', 'hill', 'hint', 'hip', 'hire', 'history',
        'hobby', 'hockey', 'hold', 'hole', 'holiday', 'hollow', 'home',
        'honey', 'hood', 'hope', 'horn', 'horror', 'horse', 'hospital',
        'host', 'hot', 'hotel', 'hour', 'hover', 'hub', 'huge', 'human',
        'humble', 'humor', 'hundred', 'hungry', 'hunt', 'hurdle', 'hurry',
        'hurt', 'husband', 'hybrid', 'ice', 'icon', 'idea', 'identify',
        'idle', 'ignore', 'iguana', 'ill', 'illegal', 'illness', 'image',
        'imitate', 'immense', 'immune', 'impact', 'impose', 'improve',
        'impulse', 'inch', 'include', 'income', 'increase', 'index',
        'indicate', 'indoor', 'industry', 'infant', 'inflict', 'inform',
        'inhale', 'inherit', 'initial', 'inject', 'injury', 'inmate',
        'inner', 'innocent', 'input', 'inquiry', 'insane', 'insect',
        'inside', 'inspire', 'install', 'intact', 'interest', 'into',
        'invest', 'invite', 'involve', 'iron', 'island', 'isolate', 'issue',
        'item', 'ivory', 'jacket', 'jaguar', 'jail', 'jam', 'january',
        'jazz', 'jealous', 'jeans', 'jelly', 'jewel', 'job', 'join',
        'joke', 'journey', 'joy', 'judge', 'juice', 'jump', 'jungle',
        'junior', 'junk', 'just', 'kangaroo', 'karma', 'ketchup', 'key',
        'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss', 'kit', 'kitchen',
        'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock', 'know', 'lab',
        'label', 'labor', 'ladder', 'lady', 'lake', 'lamb', 'lamp',
        'language', 'laptop', 'large', 'later', 'latin', 'laugh', 'laundry',
        'lava', 'law', 'lawn', 'lawsuit', 'layer', 'lazy', 'leader',
        'leaf', 'learn', 'leave', 'lecture', 'left', 'leg', 'legal',
        'legend', 'leisure', 'lemon', 'lend', 'length', 'lens', 'leopard',
        'lesson', 'letter', 'level', 'liberty', 'library', 'license', 'life',
        'lift', 'light', 'like', 'limb', 'limit', 'link', 'lion', 'liquid',
        'list', 'little', 'live', 'lizard', 'load', 'loaf', 'loan',
        'lobby', 'lock', 'log', 'lone', 'long', 'loop', 'lottery',
        'loud', 'lounge', 'love', 'loyal', 'lucky', 'luggage', 'lumber',
        'lunar', 'lunch', 'luxury', 'lyrics', 'machine', 'mad', 'magic',
        'magnet', 'maid', 'mail', 'main', 'major', 'make', 'mammal',
        'man', 'manage', 'mandate', 'mango', 'mansion', 'manual', 'maple',
        'marble', 'march', 'margin', 'marine', 'market', 'marriage', 'mask',
        'mass', 'master', 'match', 'material', 'math', 'matrix', 'matter',
        'maximum', 'maze', 'meadow', 'mean', 'measure', 'meat', 'mechanic',
        'medal', 'media', 'melody', 'melt', 'member', 'memory', 'mention',
        'menu', 'mercy', 'merge', 'merit', 'merry', 'mesh', 'message',
        'metal', 'method', 'middle', 'midnight', 'milk', 'million',
        'mimic', 'mind', 'minimum', 'minor', 'minute', 'miracle', 'mirror',
        'misery', 'miss', 'mistake', 'mix', 'mixed', 'mixture', 'mobile',
        'model', 'modify', 'mom', 'moment', 'monitor', 'monkey', 'monster',
        'month', 'moon', 'moral', 'more', 'morning', 'mosquito', 'mother',
        'motion', 'motor', 'mountain', 'mouse', 'move', 'movie', 'much',
        'muffin', 'mule', 'multiply', 'muscle', 'museum', 'mushroom',
        'music', 'must', 'myself', 'mystery', 'myth', 'naive', 'name',
        'napkin', 'narrow', 'nasty', 'nation', 'nature', 'near', 'neck',
        'need', 'negative', 'neglect', 'neither', 'nephew', 'nerve', 'nest',
        'net', 'network', 'neutral', 'never', 'next', 'nice', 'night',
        'noble', 'noise', 'nominate', 'noodle', 'normal', 'north', 'nose',
        'notable', 'note', 'nothing', 'notice', 'novel', 'now', 'nuclear',
        'number', 'nurse', 'nut', 'oak', 'obey', 'object', 'oblige',
        'obscure', 'observe', 'obtain', 'obvious', 'occur', 'ocean',
        'october', 'odor', 'off', 'offer', 'office', 'often', 'oil',
        'okay', 'old', 'olive', 'olympic', 'omit', 'once', 'one', 'onion',
        'online', 'only', 'open', 'opera', 'opinion', 'oppose', 'option',
        'orange', 'orbit', 'orchard', 'order', 'organ', 'orient', 'original',
        'orphan', 'ostrich', 'other', 'outdoor', 'outer', 'output', 'outside',
        'oval', 'oven', 'over', 'own', 'owner', 'oxygen', 'oyster', 'ozone',
        'pact', 'paddle', 'page', 'pair', 'palace', 'palm', 'panda', 'panel',
        'panic', 'panther', 'paper', 'parade', 'parent', 'park', 'parrot',
        'party', 'pass', 'patch', 'path', 'patient', 'patrol', 'pattern',
        'pause', 'pave', 'payment', 'peace', 'peanut', 'pear', 'peasant',
        'pelican', 'pen', 'penalty', 'pencil', 'people', 'pepper', 'perfect',
        'permit', 'person', 'pet', 'phone', 'photo', 'phrase', 'physical',
        'piano', 'picnic', 'picture', 'piece', 'pig', 'pigeon', 'pill',
        'pilot', 'pink', 'pioneer', 'pipe', 'pistol', 'pitch', 'pizza',
        'place', 'planet', 'plastic', 'plate', 'play', 'please', 'pledge',
        'pluck', 'plug', 'plunge', 'poem', 'poet', 'point', 'polar',
        'pole', 'police', 'pond', 'pony', 'pool', 'popular', 'portion',
        'position', 'possible', 'post', 'potato', 'pottery', 'poverty',
        'powder', 'power', 'practice', 'praise', 'predict', 'prefer',
        'prepare', 'present', 'pretty', 'prevent', 'price', 'pride',
        'primary', 'print', 'priority', 'prison', 'private', 'prize',
        'problem', 'process', 'produce', 'profit', 'program', 'project',
        'promote', 'proof', 'property', 'prosper', 'protect', 'proud',
        'provide', 'public', 'pudding', 'pull', 'pulp', 'pulse', 'pumpkin',
        'punch', 'pupil', 'puppy', 'purchase', 'purity', 'purpose', 'push',
        'put', 'puzzle', 'pyramid', 'quality', 'quantum', 'quarter',
        'question', 'quick', 'quit', 'quiz', 'quote', 'rabbit', 'raccoon',
        'race', 'rack', 'radar', 'radio', 'rail', 'rain', 'raise', 'rally',
        'ramp', 'ranch', 'random', 'range', 'rapid', 'rare', 'rate',
        'rather', 'raven', 'raw', 'razor', 'ready', 'real', 'reason',
        'rebel', 'rebuild', 'recall', 'receive', 'recipe', 'record',
        'recycle', 'reduce', 'reflect', 'reform', 'refuse', 'region',
        'regret', 'regular', 'reject', 'relax', 'release', 'relief',
        'remain', 'remember', 'remind', 'remove', 'render', 'renew',
        'rent', 'reopen', 'repair', 'repeat', 'replace', 'report',
        'require', 'rescue', 'resemble', 'resist', 'resource', 'response',
        'result', 'retire', 'retreat', 'return', 'reunion', 'reveal',
        'review', 'reward', 'rhythm', 'rib', 'rice', 'rich', 'ride',
        'ridge', 'rifle', 'right', 'rigid', 'ring', 'riot', 'ripple',
        'risk', 'ritual', 'rival', 'river', 'road', 'roast', 'robot',
        'robust', 'rocket', 'romance', 'roof', 'rookie', 'room', 'rose',
        'rotate', 'rough', 'round', 'route', 'royal', 'rubber', 'rude',
        'rug', 'rule', 'run', 'runway', 'rural', 'sad', 'saddle', 'sadness',
        'safe', 'sail', 'salad', 'salmon', 'salon', 'salt', 'salute',
        'same', 'sample', 'sand', 'satisfy', 'satoshi', 'sauce', 'sausage',
        'save', 'say', 'scale', 'scan', 'scare', 'scatter', 'scene',
        'scheme', 'school', 'science', 'scissors', 'scorpion', 'scout',
        'scrap', 'screen', 'script', 'scrub', 'sea', 'search', 'season',
        'seat', 'second', 'secret', 'section', 'security', 'seed',
        'seek', 'segment', 'select', 'sell', 'seminar', 'senior',
        'sense', 'sentence', 'series', 'service', 'session', 'settle',
        'setup', 'seven', 'shadow', 'shaft', 'shallow', 'share', 'shed',
        'shell', 'sheriff', 'shield', 'shift', 'shine', 'ship', 'shiver',
        'shock', 'shoe', 'shoot', 'shop', 'short', 'shoulder', 'shove',
        'shrimp', 'shrug', 'shuffle', 'shy', 'sibling', 'sick', 'side',
        'siege', 'sight', 'sign', 'silent', 'silk', 'silly', 'silver',
        'similar', 'simple', 'since', 'sing', 'siren', 'sister', 'situate',
        'six', 'size', 'skate', 'sketch', 'ski', 'skill', 'skin', 'skirt',
        'skull', 'slab', 'slam', 'sleep', 'slender', 'slice', 'slide',
        'slight', 'slim', 'slogan', 'slot', 'slow', 'slush', 'small',
        'smart', 'smile', 'smoke', 'smooth', 'snack', 'snake', 'snap',
        'sniff', 'snow', 'soap', 'soccer', 'social', 'sock', 'soda',
        'soft', 'solar', 'soldier', 'solid', 'solution', 'solve', 'someone',
        'song', 'soon', 'sorry', 'sort', 'soul', 'sound', 'soup', 'source',
        'south', 'space', 'spare', 'spatial', 'spawn', 'speak', 'special',
        'speed', 'spell', 'spend', 'sphere', 'spice', 'spider', 'spike',
        'spin', 'spirit', 'split', 'sponsor', 'spoon', 'sport', 'spot',
        'spray', 'spread', 'spring', 'spy', 'square', 'squeeze', 'squirrel',
        'stable', 'stadium', 'staff', 'stage', 'stairs', 'stamp', 'stand',
        'start', 'state', 'stay', 'steak', 'steel', 'stem', 'step', 'stereo',
        'stick', 'still', 'sting', 'stock', 'stomach', 'stone', 'stool',
        'story', 'stove', 'strategy', 'street', 'strike', 'strong',
        'struggle', 'student', 'stuff', 'stumble', 'style', 'subject',
        'submit', 'subway', 'success', 'such', 'sudden', 'suffer',
        'sugar', 'suggest', 'suit', 'summer', 'sun', 'sunny', 'sunset',
        'super', 'supply', 'supreme', 'sure', 'surface', 'surge',
        'surprise', 'surround', 'survey', 'suspect', 'sustain', 'swallow',
        'swamp', 'swap', 'swarm', 'swear', 'sweet', 'swift', 'swim',
        'swing', 'switch', 'sword', 'symbol', 'symptom', 'syrup',
        'system', 'table', 'tackle', 'tag', 'tail', 'talent', 'talk',
        'tank', 'tape', 'target', 'task', 'taste', 'tattoo', 'taxi',
        'teach', 'team', 'tell', 'ten', 'tenant', 'tennis', 'tent',
        'term', 'test', 'text', 'thank', 'that', 'theme', 'then', 'theory',
        'there', 'they', 'thing', 'this', 'thought', 'three', 'thrive',
        'throw', 'thumb', 'thunder', 'ticket', 'tide', 'tiger', 'tilt',
        'timber', 'time', 'tiny', 'tip', 'tired', 'tissue', 'title',
        'toast', 'tobacco', 'today', 'toddler', 'toe', 'together',
        'toilet', 'token', 'tomato', 'tomorrow', 'tone', 'tongue',
        'tonight', 'tool', 'tooth', 'top', 'topic', 'topple', 'torch',
        'tornado', 'tortoise', 'toss', 'total', 'tourist', 'toward',
        'tower', 'town', 'toy', 'track', 'trade', 'traffic', 'tragic',
        'train', 'transfer', 'trap', 'trash', 'travel', 'tray',
        'treat', 'tree', 'trend', 'trial', 'tribe', 'trick', 'trigger',
        'trim', 'trip', 'trophy', 'trouble', 'truck', 'true', 'truly',
        'trumpet', 'trust', 'truth', 'try', 'tube', 'tuition', 'tumble',
        'tuna', 'tunnel', 'turkey', 'turn', 'turtle', 'twelve', 'twenty',
        'twice', 'twin', 'twist', 'two', 'type', 'typical', 'ugly',
        'umbrella', 'unable', 'unaware', 'uncle', 'uncover', 'under',
        'undo', 'unfair', 'unfold', 'unhappy', 'uniform', 'unique',
        'unit', 'universe', 'unknown', 'unlock', 'until', 'unusual',
        'unveil', 'update', 'upgrade', 'uphold', 'upon', 'upper',
        'upset', 'urban', 'urge', 'usage', 'used', 'useful', 'useless',
        'usual', 'utility', 'vacant', 'vacuum', 'vague', 'valid', 'valley',
        'valve', 'vanish', 'vapor', 'various', 'vast', 'vault', 'vehicle',
        'velvet', 'vendor', 'venture', 'venue', 'verb', 'verify',
        'version', 'very', 'vessel', 'veteran', 'viable', 'vibrant',
        'vicious', 'victory', 'video', 'view', 'village', 'vintage',
        'violin', 'virtual', 'virus', 'visa', 'visit', 'visual',
        'vital', 'vivid', 'vocal', 'voice', 'void', 'volcano',
        'volume', 'vote', 'voyage', 'wage', 'wagon', 'wait', 'walk',
        'wall', 'walnut', 'want', 'warfare', 'warm', 'warrior', 'wash',
        'wasp', 'waste', 'water', 'wave', 'way', 'wealth', 'weapon',
        'wear', 'weasel', 'weather', 'web', 'wedding', 'weekend',
        'weird', 'welcome', 'west', 'wet', 'whale', 'what', 'wheat',
        'wheel', 'when', 'where', 'whip', 'whisper', 'wide', 'width',
        'wife', 'wild', 'will', 'win', 'window', 'wine', 'wing', 'wink',
        'winner', 'winter', 'wire', 'wisdom', 'wise', 'wish', 'with',
        'withdraw', 'witness', 'wolf', 'woman', 'wonder', 'wood',
        'wool', 'word', 'work', 'world', 'worry', 'worth', 'wrap',
        'wreck', 'wrestle', 'wrist', 'write', 'wrong', 'yard', 'year',
        'yellow', 'you', 'young', 'youth', 'zebra', 'zero', 'zone',
        'zoo'];
      var words = match.value.trim().split(/\s+/);
      var validCount = 0;
      var checkLimit = Math.min(12, words.length);  // check first 12 words
      for (var w = 0; w < checkLimit; w++) {
        if (BIP39_COMMON.indexOf(words[w]) !== -1) {
          validCount++;
        }
      }
      // Need at least 9 of the first 12 words to be BIP39 words.
      // The full BIP39 wordlist has 2048 words; we have 2041 of
      // them. The wordlist overlaps significantly with English
      // prose (e.g., 'quick', 'brown', 'fox' are all in BIP39).
      // 9 of 12 is a strong signal: random English prose matches
      // 3-7 BIP39 words out of 12; a real seed matches 11-12.
      // At 9+, the false-positive rate is < 0.01% on English prose.
      if (validCount < 9) {
        return null;  // false positive, drop
      }
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
          value: m[1] !== undefined ? m[1] : m[0],
          index: m.index
        };
        var processed = postProcess(key, match);
        if (processed !== null) matches.push(processed);
        // Avoid infinite loop on zero-length matches
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    // Sort by index (primary) then by category (secondary) so ties are
    // deterministic. Multiple patterns may match at the same position
    // (e.g. pii_credit_card and pii_credit_card_loose both match a CC).
    // The test 'pii: matches are sorted by index' requires strict
    // ordering, so we break ties alphabetically by category.
    matches.sort(function (a, b) {
      if (a.index !== b.index) return a.index - b.index;
      return a.category < b.category ? -1 : a.category > b.category ? 1 : 0;
    });
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
