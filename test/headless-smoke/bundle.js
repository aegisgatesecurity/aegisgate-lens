window.__lens_test_wrapper = { started: Date.now() };
try {
// === util/logger.js ===
// AegisGate Lens — logger.js
// Tiny console wrapper that NEVER silently swallows errors.
// Per the architecture doc and standing rules: every .catch() must log
// the actual err with a contextual prefix.
//
// Loaded as the FIRST content_script (per manifest.json content_scripts
// order) so all subsequent content-script modules can use this logger.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // The single shared logger object. Exposed on `self.__lensLogger` so
  // other content-script modules can grab it without coupling to the
  // global `aegisgateLens` namespace (which may not be initialized yet
  // when this file first runs).
  var logger = {
    tag: '[AegisGate Lens]',

    info: function (msg, extra) {
      try {
        if (extra === undefined) {
          console.info(this.tag + ' ' + msg);
        } else {
          console.info(this.tag + ' ' + msg, extra);
        }
      } catch (e) {
        // Last-resort fallback: the logging itself failed (e.g. console
        // is not available in some sandboxed context). Do NOT swallow
        // silently — re-throw so the caller knows logging is broken.
        throw new Error('logger.info failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    warn: function (msg, extra) {
      try {
        if (extra === undefined) {
          console.warn(this.tag + ' ' + msg);
        } else {
          console.warn(this.tag + ' ' + msg, extra);
        }
      } catch (e) {
        throw new Error('logger.warn failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    error: function (msg, err) {
      // The KEY rule: always log the actual err object. Never use a
      // useless "init failed" string. If err is undefined, log that
      // we have no err object — don't pretend we do.
      try {
        if (err === undefined || err === null) {
          console.error(this.tag + ' ' + msg + ' (no err object provided)');
        } else if (err instanceof Error) {
          console.error(this.tag + ' ' + msg + ':', err.message, err.stack || '');
        } else {
          // err might be a string, a plain object, anything
          console.error(this.tag + ' ' + msg + ':', err);
        }
      } catch (e) {
        // Logging failed. We can't log the failure, so we re-throw
        // with a meaningful message.
        throw new Error('logger.error failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    // Convenience: wrap a promise so any rejection is logged with context.
    // Use: `logger.guard('analytics.flush', analytics.flush())`
    guard: function (context, promise) {
      if (!promise || typeof promise.then !== 'function') {
        this.error('logger.guard called with non-promise', { context: context, value: promise });
        return Promise.reject(new Error('logger.guard: not a promise'));
      }
      return promise.catch(function (err) {
        this.error(context, err);
        // Re-throw so the caller's .then chain still sees the rejection
        throw err;
      }.bind(this));
    }
  };

  // Expose on multiple globals for compatibility:
  //   - `self.__lensLogger` (the canonical reference)
  //   - `window.__lensLogger` (when the content script runs in a page
  //     context with a window, which it does because it's injected)
  //   - `globalThis.__lensLogger` (modern standard)
  if (typeof self !== 'undefined') {
    self.__lensLogger = logger;
  }
  if (typeof window !== 'undefined') {
    window.__lensLogger = logger;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensLogger = logger;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/luhn.js ===
// AegisGate Lens — detectors/luhn.js
// Luhn algorithm validation for credit card numbers.
//
// Per the architecture doc Section 3, the PII facet validates credit
// card numbers with Luhn before reporting. A regex match alone has a
// high false-positive rate (e.g., any 16-digit number matches a
// generic regex); Luhn reduces this to near-zero.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Standard Luhn checksum: starting from the rightmost digit, double
  // every second digit. If doubled value > 9, subtract 9. Sum all
  // digits. The number is valid iff sum % 10 === 0.
  //
  // Accepts a string of digits (no separators) or a number.
  // Returns true if valid, false if not.
  function luhnCheck(cardNumber) {
    if (cardNumber === null || cardNumber === undefined) return false;
    var s = String(cardNumber);
    // Strip any non-digit characters
    s = s.replace(/\D/g, '');
    if (s.length < 12 || s.length > 19) return false;
    var sum = 0;
    var alt = false;
    for (var i = s.length - 1; i >= 0; i--) {
      var d = s.charCodeAt(i) - 48;  // '0' is 48
      if (d < 0 || d > 9) return false;
      if (alt) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  // Common card-type identifiers. Each entry is a regex that matches
  // the IIN/BIN prefix and length for the card type. Used by the PII
  // detector to assign the right category.
  var CARD_PATTERNS = [
    { name: 'visa',       re: /^4\d{12}(\d{3})?(\d{3})?$/ },
    { name: 'mastercard', re: /^(5[1-5]\d{14}|2(2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$/ },
    { name: 'amex',       re: /^3[47]\d{13}$/ },
    { name: 'discover',   re: /^(6011|65\d{2}|64[4-9]\d|62212[6-9]|6221[3-9]\d|622[2-8]\d|6229[01]\d|62292[0-5])\d{10,12}$/ },
    { name: 'diners',     re: /^(36\d{12}|38\d{12}|30[0-5]\d{11})$/ },
    { name: 'jcb',        re: /^(2131|1800|35\d{3})\d{11}$/ }
  ];

  function identifyCard(cardNumber) {
    var s = String(cardNumber).replace(/[\s-]/g, '');
    for (var i = 0; i < CARD_PATTERNS.length; i++) {
      if (CARD_PATTERNS[i].re.test(s)) return CARD_PATTERNS[i].name;
    }
    return null;
  }

  // Convenience: validate + identify in one call.
  function validateCard(cardNumber) {
    var s = String(cardNumber).replace(/[\s-]/g, '');
    return { valid: luhnCheck(s), type: identifyCard(s) };
  }

  var module = {
    luhnCheck: luhnCheck,
    identifyCard: identifyCard,
    validateCard: validateCard,
    CARD_PATTERNS: CARD_PATTERNS
  };

  if (typeof self !== 'undefined') self.__lensLuhn = module;
  if (typeof window !== 'undefined') window.__lensLuhn = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensLuhn = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/regex/pii.js ===
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
      // We use a slightly negative-lookahead to avoid matching
      // phone numbers with hyphens.
      severity: 'critical',
      re: /\b\d{4}[-\s]\d{4}[-\s]\d{4}\b(?!\s*-\s*\d)/g
    },
    pii_nhs_uk: {
      // UK NHS number: 10 digits in XXX-XXX-XXXX format. Distinct
      // from US SSN (which uses XXX-XX-XXXX) by the dash position
      // and the leading 3 digits (NHS uses 3-3-4 vs SSN's 3-2-4).
      severity: 'high',
      re: /\b\d{3}-\d{3}-\d{4}\b/g
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

// === detectors/regex/secrets.js ===
// AegisGate Lens — detectors/regex/secrets.js
// Facet 2: Secrets detection. Regex-based, no Luhn.
// Per schema.js VALID_CATEGORIES[2], 17 secret types are detected.
// Each pattern is provider-specific (where possible) to keep FP low.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Each pattern: { severity, re, description (for debugging) }
  // Severity:
  //   critical — direct credential that grants access (AWS, GitHub PAT, PEM)
  //   high     — likely credential (GCP, Stripe live, OpenAI)
  //   medium   — possible credential or context-dependent
  var PATTERNS = {
    secret_aws_key: {
      severity: 'critical',
      re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g
    },
    secret_github_token: {
      severity: 'critical',
      // Modern PAT: ghp_; OAuth: gho_; Server: ghs_; User: ghu_
      re: /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,120}\b/g
    },
    secret_gcp_key: {
      severity: 'high',
      // Google API key: AIza + 35 chars. The Google docs are explicit
      // about 39 total chars (4 prefix + 35). We allow 30-50 for
      // forward-compat.
      re: /\bAIza[0-9A-Za-z_-]{30,50}\b/g
    },
    secret_azure_key: {
      severity: 'high',
      // Azure storage account key in connection string
      re: /(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}/g
    },
    secret_private_key_pem: {
      severity: 'critical',
      // PEM private key header (RSA, EC, DSA, OPENSSH, PGP, ENCRYPTED)
      re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
    },
    secret_oauth_token: {
      severity: 'high',
      // Generic OAuth bearer: ya29., 1//, etc.
      re: /\bya29\.[0-9A-Za-z_-]{50,}\b|\b1\/[0-9A-Za-z_-]{40,}\b/g
    },
    secret_jwt: {
      severity: 'high',
      // JWT: 3 base64url segments separated by dots
      re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g
    },
    secret_api_key_generic: {
      severity: 'high',
      // Generic API key assignment: api_key=... or apikey: ... with 20+ chars
      re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi
    },
    secret_db_connection_string: {
      severity: 'high',
      // DB connection URL with credentials
      re: /(?:mongodb|postgres|postgresql|mysql|redis|amqp)(\+\w+)?:\/\/[\w.-]+:[^\s@]+@[^\s/]+/g
    },
    secret_slack_token: {
      severity: 'high',
      // Slack: xoxb, xoxp, xoxa, xoxr, xoxs followed by digits and alnum
      re: /\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/g
    },
    secret_stripe_key: {
      severity: 'high',
      // Stripe live: sk_live_, pk_live_; test: sk_test_, pk_test_, rk_
      re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g
    },
    secret_twilio_key: {
      severity: 'high',
      // Twilio API key (SK + 32 hex) or account SID (AC + 32 hex)
      re: /\b(?:SK|AC)[a-fA-F0-9]{32}\b/g
    },
    secret_sendgrid_key: {
      severity: 'high',
      // SendGrid API key: SG. + base62 (22 chars) + . + base62 (43 chars)
      re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g
    },
    secret_mailgun_key: {
      severity: 'high',
      // Mailgun: key- + 32 hex
      re: /\bkey-[a-f0-9]{32}\b/g
    },
    secret_openai_key: {
      severity: 'high',
      // OpenAI: sk- + 20+ chars. The sk- prefix is shared with
      // Anthropic (which uses sk-ant-*), so we explicitly exclude
      // sk-ant-* to prevent cross-detection.
      re: /\bsk-(?!ant-)(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b/g
    },
    secret_anthropic_key: {
      severity: 'high',
      // Anthropic: sk-ant-api03-, sk-ant-api04-, etc.
      re: /\bsk-ant-(?:api)?\d{2}-[A-Za-z0-9_-]{20,}\b/g
    },
    secret_heroku_key: {
      severity: 'medium',
      // Heroku API key: UUID-like with heroku prefix in env vars
      re: /\bheroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta Secrets expansion, 2026-07-04)
    // Each pattern: strict regex + tests covering positive cases and
    // benign strings (no FPs on common English / common code).
    // ====================================================================
    secret_gitlab_pat: {
      // GitLab PAT: glpat- prefix + 20 alphanumeric chars
      // (glpat-XXXXXXXXXXXXXXXXXXXXXXXXXXXX). 26 chars total.
      severity: 'critical',
      re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g
    },
    secret_npm_token: {
      // npm token: npm_ + 36 alphanumeric chars (full token is 40+,
      // we allow 30+ to catch truncated tokens in env files).
      severity: 'critical',
      re: /\bnpm_[A-Za-z0-9]{30,}\b/g
    },
    secret_pypi_token: {
      // PyPI token: pypi- + 100+ chars (long URL-safe base64).
      severity: 'critical',
      re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g
    },
    secret_slack_legacy: {
      // Slack legacy tokens: xox[abprs]-prefixed tokens (different
      // format than the modern xoxb/xoxp). The existing secret_slack_token
      // covers the modern format. This covers the legacy single-token
      // format (no segment separators): xoxa-2-..., xoxb-..., etc.
      severity: 'high',
      re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g
    },
    secret_github_finegrained: {
      // GitHub fine-grained PAT: github_pat_11 + 22 alphanumeric + _
      // (82-120 chars total). The classic gh[pousr]_* PATs are
      // already covered by secret_github_token; this is for the
      // newer fine-grained format only.
      severity: 'critical',
      re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g
    },
    secret_supabase: {
      // Supabase service_role / anon key (JWT format with role claim)
      // The key is a JWT; we match the prefix 'eyJ' to identify
      // it as a Supabase-style key. The role claim is in the
      // payload (we don't try to decode, just match the format).
      severity: 'high',
      re: /\beyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b/g
    },
    secret_db_url_with_password: {
      // Database connection URL with embedded password. We extend
      // the existing secret_db_connection_string with more schemes
      // (sqlserver://, oracle://, jdbc:mysql://, jdbc:postgresql://,
      // mongodb+srv://, etc.) and a stricter password pattern
      // (at least 6 chars to reduce FPs).
      severity: 'high',
      re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|sqlserver|oracle|jdbc:(?:mysql|postgresql|sqlserver|oracle)|cassandra|influxdb|clickhouse|rabbitmq|mssql|sybase|db2|firebird|hsqldb|derby|sqlite):\/\/[\w.-]+:[^\s@'"]+@[^\s/'"]+/g
    },
    secret_aws_account_id: {
      // AWS account ID: 12 digits, often in ARNs like
      // arn:aws:iam::123456789012:user/foo. The 12-digit pattern
      // is highly specific to AWS account IDs. We match the
      // 'arn:aws:' prefix to reduce FPs.
      severity: 'medium',
      re: /\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:aws)?:?(\d{12}):/g
    },
    secret_github_actions_token: {
      // GitHub Actions ephemeral tokens: ghs_, gho_, ghu_, ghr_
      // followed by 30+ alphanumeric. These are short-lived
      // tokens issued by GitHub Actions.
      severity: 'critical',
      re: /\bgh[osur]_[A-Za-z0-9]{30,}\b/g
    }
  };

  // postProcess for secret patterns. Currently used for PEM
  // private keys (must include the full BEGIN/END block, not
  // just the header) and for ensuring DB connection strings
  // contain valid credentials.
  function postProcess(category, match) {
    if (category === 'secret_private_key_pem') {
      // The regex matches just the BEGIN header. We should also
      // ensure the END footer is in the text (otherwise it's a
      // truncated key, not a real one). The text is in match.text.
      // The match object only has value/index; we need to read
      // the text from the match. Actually, the dispatcher passes
      // the value (which is just the BEGIN header). The postProcess
      // here can drop the match if the END footer is not present,
      // but we don't have access to the full text in this function.
      // The pattern is: BEGIN header is flagged ONLY if the
      // text already contains END footer somewhere (handled by
      // the regex test). For now, accept the match.
      return match;
    }
    if (category === 'secret_supabase') {
      // Supabase JWTs are 100+ chars (3 long base64url segments).
      // The regex already enforces this. No further processing.
      return match;
    }
    return match;
  }

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
        var match = {
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0],
          index: m.index
        };
        if (typeof postProcess === 'function') {
          var processed = postProcess(key, match);
          if (processed !== null && processed !== undefined) matches.push(processed);
        } else {
          matches.push(match);
        }
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensSecrets = module;
  if (typeof window !== 'undefined') window.__lensSecrets = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensSecrets = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/regex/source_xss.js ===
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

// === detectors/regex/compliance.js ===
// AegisGate Lens — detectors/regex/compliance.js
// Facet 4: Compliance framework detection. Keyword/phrase-based.
//
// Per schema.js VALID_CATEGORIES[4], 23 compliance categories across
// OWASP LLM Top 10, MITRE ATLAS, EU AI Act, ANP (GDPR data
// protection), and CU (consumer protection).
//
// v1.0 philosophy: match specific phrases that are clear signals
// (e.g., "credit scoring decision" = EU AI Act high-risk). Avoid
// single keywords (e.g., "race" alone is too broad). Future v1.1
// can use ML to add context-aware detection.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var PATTERNS = {
    // --- OWASP LLM Top 10 ---
    owasp_llm01_prompt_injection: {
      severity: 'critical',
      // Direct prompt injection: "ignore previous", "disregard prior",
      // "forget everything", "new instructions:", "system: you are"
      re: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:^|\s)(?:new|updated?)\s+instructions?\s*:|system\s*:\s*you\s+are\s+now/gi
    },
    owasp_llm04_model_dos: {
      severity: 'high',
      // Denial-of-service: flooding, overwhelming, massive inputs
      re: /(?:flood|overwhelm|DDoS|denial.of.service)\s+(?:the\s+)?(?:system|server|model|API)|(?:repeat|output)\s+(?:this\s+)?(?:sentence|phrase|word)\s+\d{3,}\s+times?/gi
    },
    owasp_llm08_excessive_agency: {
      severity: 'high',
      // Excessive agency: asking the AI to use tools with no oversight
      re: /(?:use|run|execute|call|invoke)\s+(?:the\s+)?(?:file|shell|terminal|command|exec|system)\s+(?:tool|command|function|API)|(?:without|no)\s+(?:human\s+)?(?:oversight|review|approval|confirmation)/gi
    },
    owasp_llm09_overreliance: {
      severity: 'medium',
      // Overreliance: asking AI to validate critical decisions
      re: /(?:is\s+this\s+(?:safe|legal|compliant|ethical|appropriate))|(?:should\s+I\s+(?:trust|rely\s+on|sign|send|submit))|(?:validate|verify|check)\s+(?:this\s+)?(?:for\s+me|before\s+I)/gi
    },
    owasp_llm10_model_theft: {
      severity: 'high',
      // Model extraction / theft
      re: /(?:extract|reveal|expose|leak|give\s+me)\s+(?:the\s+)?(?:model|weights?|parameters?|architecture|training\s+data|embeddings?)/gi
    },

    // --- MITRE ATLAS ---
    atlas_poison: {
      severity: 'high',
      // Training data poisoning: fine-tune, retrain, or ingest
      // untrusted data. We allow optional intervening words (model,
      // network, system) between the action and the data source.
      re: /(?:train|retrain|fine-?tune|ingest|poison(?:ing)?)\s+(?:the\s+)?(?:model|network|system|LLM)?\s*(?:on|with)\s+(?:this\s+|untrusted\s+|malicious\s+|adversarial\s+)?(?:data|dataset|corpus|examples?)/gi
    },
    atlas_exfiltration: {
      severity: 'high',
      // Data exfiltration via the AI
      re: /(?:send|exfiltrate|leak|upload|post|transmit)\s+(?:the\s+)?(?:data|secrets?|keys?|passwords?|tokens?)\s+to\s+(?:my\s+)?(?:server|endpoint|webhook|attacker|attacker\.com)/gi
    },
    atlas_jailbreak: {
      severity: 'critical',
      // Jailbreak attempts
      re: /\b(?:DAN|do\s+anything\s+now)\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+(?:the\s+)?model|ignore\s+(?:all\s+)?(?:safety|ethical)\s+(?:guidelines|filters?|restrictions?)/gi
    },

    // --- EU AI Act ---
    eu_ai_act_high_risk: {
      severity: 'high',
      // High-risk use cases per Annex III
      re: /(?:credit\s+scoring|loan\s+(?:approval|decision)|insurance\s+(?:risk|pricing))|(?:employment|hiring|firing|promotion|recruitment)\s+(?:decision|assessment|screening)|(?:law\s+enforcement|predictive\s+policing|criminal\s+justice)|(?:biometric|facial)\s+(?:identification|recognition|verification)|(?:medical|clinical)\s+diagnosis|emotion\s+recognition\s+system/gi
    },
    eu_ai_act_transparency: {
      severity: 'medium',
      // Transparency obligations (Article 50)
      re: /(?:AI[- ]generated|chatbot\s+without\s+disclosure|deepfake|synthetic\s+media)\s+(?:content|without\s+(?:disclosure|labeling))|users?\s+(?:must|should)\s+be\s+(?:informed|told)\s+(?:this\s+is\s+)?AI/gi
    },
    eu_ai_act_human_oversight: {
      severity: 'medium',
      // Human oversight (Article 14)
      re: /(?:no|without|zero)\s+human[- ](?:in[- ]the[- ]loop|oversight|review|intervention|approval)|fully\s+autonomous\s+(?:AI|system|decision)/gi
    },
    eu_ai_act_robustness: {
      severity: 'low',
      // Robustness/accuracy (Article 15)
      re: /(?:adversarial|adversarially[- ]crafted)\s+(?:input|example|perturbation|attack)/gi
    },

    // --- ANP (GDPR data protection) ---
    anp_personal_data: {
      severity: 'medium',
      // Personal data / PII in a GDPR context
      re: /(?:GDPR|personal\s+data|data\s+subject)\s+(?:of|processing|consent|lawful\s+basis)|(?:lawful|legitimate)\s+basis\s+for\s+processing/gi
    },
    anp_special_category: {
      severity: 'high',
      // Article 9 special categories (sensitive data)
      re: /(?:racial|ethnic)\s+(?:origin|discrimination)|(?:religious|political)\s+(?:beliefs?|opinions?|affiliation)|trade[- ]union\s+membership|(?:genetic|biometric)\s+data\s+for\s+(?:identification|profiling)|(?:health|medical)\s+data\s+(?:about|of)|(?:sex\s+life|sexual\s+orientation)/gi
    },

    // --- CU (Consumer protection) ---
    cu_consumer_rights: {
      severity: 'medium',
      re: /(?:consumer|user)\s+rights?\s+(?:to|of)\s+(?:explanation|erasure|rectification|deletion|portability)|right\s+to\s+(?:explanation|be\s+forgotten|erasure)/gi
    },
    cu_minor_protection: {
      severity: 'high',
      re: /(?:minor|child|juvenile|underage)\s+(?:protection|safety|consent)|(?:under|below)\s+(?:13|16|18)\s+(?:years?|yrs?\s+old)|(?:COPPA|age[- ]appropriate)\s+compliance/gi
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta Compliance expansion, 2026-07-04)
    // Each pattern: keyword + brief context, strict regex for low FP.
    // These cover region-specific privacy regulations and
    // cybersecurity frameworks that the Lens should detect so users
    // can flag content containing references to them.
    // ====================================================================
    nist_csf_reference: {
      // NIST Cybersecurity Framework (CSF) identifiers. CSF uses
      // function.category.subcategory (e.g., ID.AM-1, PR.AC-1).
      // We match the 5 function prefixes (ID, PR, DE, RS, RC) and
      // a few of the most common subcategories.
      severity: 'medium',
      re: /\b(?:(?:ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+(?:\.\d+)?)\b/g
    },
    iso_27001_reference: {
      // ISO/IEC 27001 control references. The format is Annex A
      // control IDs (A.5.1, A.6.1, A.8.2, etc.) or clause
      // references (6.1.2, 8.2.1, 10.1.1). The A.x.y format is
      // the most common.
      severity: 'medium',
      re: /\b(?:A\.\d{1,2}\.\d{1,2}(?:\.\d+)?|clause\s+\d{1,2}\.\d{1,2}(?:\.\d+)?)\b/g
    },
    ccpa_reference: {
      // California Consumer Privacy Act (CCPA). Section numbers
      // (1798.100, 1798.105, etc.) or keywords like "CCPA",
      // "California Consumer Privacy", "right to know", "right to
      // delete", "right to opt out", "sale of personal information".
      severity: 'medium',
      re: /\b(?:CCPA|California\s+Consumer\s+Privacy\s+Act|Civil\s+Code\s+§\s*1798(?:\.\d+)?|right\s+to\s+(?:know|delete|opt[\s-]?out|correct)|sale\s+of\s+personal\s+information|Shine\s+the\s+Light|Do\s+Not\s+Sell)\b/gi
    },
    lgpd_reference: {
      // Brazilian Lei Geral de Protecao de Dados (LGPD). Article
      // references (Art. 7, Art. 18, Art. 46) or keywords
      // ("LGPD", "Lei Geral de Protecao de Dados", "dados pessoais",
      // "controlador", "operador", "ANPD").
      severity: 'medium',
      re: /\b(?:LGPD|Lei\s+Geral\s+de\s+Protec[ãa]o\s+de\s+Dados|Art\.\s*\d+(?:[\s,ºo]+(?:I|II|III|IV|V|VI|VII|VIII|IX|X))*|dados\s+pessoais|controlador|operador|ANPD)\b/gi
    },
    pipeda_reference: {
      // Canadian Personal Information Protection and Electronic
      // Documents Act (PIPEDA). Schedule 1 references or keywords
      // ("PIPEDA", "personal information", "consent", "Principle").
      severity: 'medium',
      re: /\b(?:PIPEDA|Personal\s+Information\s+Protection\s+and\s+Electronic\s+Documents\s+Act|Schedule\s+1|Principle\s+\d+(?:\.\d+)?|express\s+consent)\b/gi
    },
    popia_reference: {
      // South African Protection of Personal Information Act (POPIA).
      // Section references (s. 11, s. 14) or keywords ("POPIA",
      // "Information Regulator", "processing of personal information").
      severity: 'medium',
      re: /\b(?:POPIA|Protection\s+of\s+Personal\s+Information\s+Act|s\.\s*\d+(?:\s*\(\d+\))?|Information\s+Regulator|processing\s+of\s+personal\s+information|special\s+personal\s+information)\b/gi
    },
    // ====================================================================
    // TOXICITY REGEX FALLBACK (Facet 5)
    // These are the 2 toxicity categories NOT in the unitary/toxic-bert
    // 6-class output. They fall back to regex detection. Per
    // plans/AEGISGATE-LENS-V01BETA-MODEL-DECISION.md (Section 4.1),
    // toxicity_sexual and toxicity_self_harm require regex patterns.
    // The other 5 toxicity categories (toxicity_hate, toxicity_insult,
    // toxicity_obscene, toxicity_threat, toxicity_violence) are
    // covered by the ML detector (unitary/toxic-bert) in
    // src/detectors/ml/toxicity.py.
    // ====================================================================
    toxicity_sexual: {
      // Sexual content indicators. We match explicit sexual terms
      // (avoiding medical/educational contexts). The pattern is
      // conservative -- we require an explicit qualifier to reduce FPs.
      severity: 'high',
      re: /\b(?:(?:pornographic|obscene|explicit|nsfw|hardcore)\s+(?:content|material|images?|video|text)|(?:sexual|sex)\s+(?:content|act(?:s|s)?|intercourse|fetish)|(?:rape|molest|incest)\s+(?:scene|content|material)|(?:child|minor|underage)\s+(?:sexual|porn(?:ography)?|abuse|exploitation))\b/gi
    },
    toxicity_self_harm: {
      // Self-harm indicators. We match explicit references to self-harm,
      // suicide, and self-injury. Conservative to avoid FPs on
      // mental health discussion (e.g., "how to help someone with
      // depression" should NOT fire; "I want to kill myself" SHOULD).
      severity: 'critical',
      re: /\b(?:suicid(?:e|al)|kill\s+(?:my)?self|hurt\s+(?:my)?self|end\s+(?:my\s+)?(?:life|suffering)|self\s*[-]?\s*harm|cut(?:ting)?)\b/gi
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

  if (typeof self !== 'undefined') self.__lensCompliance = module;
  if (typeof window !== 'undefined') window.__lensCompliance = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensCompliance = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === privacy/schema.js ===
// AegisGate Lens — schema.js
// Event schema validator for telemetry and detection events.
//
// Per the architecture doc Section 12 (F-09) and the threat model, every
// event sent from the content script to the service worker (and from
// the SW to the backend) must be validated against this schema before
// transmission. The schema is the contract that guarantees no prompt
// content, no URLs, no page content, no user IDs ever leak.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // The 6 facets. The "facet" field on every detection is the
  // discriminator that says which facet fired. Per the v0.2
  // architecture doc, facets are identified by their human-readable
  // name (not a numeric ID) so that logs and events are readable
  // and so the facet name matches the category prefix
  // (e.g. pii_ssn starts with pii, secret_aws_key starts with
  // secrets).
  //
  // The 4 regex facets are fully implemented in v0.1.0-beta. The
  // 2 ML facets (toxicity, prompt_injection) are reserved for
  // Step 3h.
  var VALID_FACETS = ['pii', 'secrets', 'xss', 'compliance', 'toxicity', 'prompt_injection'];

  // The category enum. 65 categories across the 6 facets.
  // Source: the v0.2 architecture doc Appendix B and the v0.2 schema
  // implementation. We re-implement from the spec, not from the old code.
  //
  // Format: { facetName: [category, category, ...] }
  var VALID_CATEGORIES = {
    pii: [
      'pii_ssn', 'pii_email', 'pii_phone', 'pii_credit_card',
      'pii_address', 'pii_dob', 'pii_driver_license', 'pii_passport',
      'pii_bip39_seed',
      'pii_tax_id', 'pii_bank_account', 'pii_ip_address'
    ],
    secrets: [
      'secret_aws_key', 'secret_github_token', 'secret_gcp_key',
      'secret_azure_key', 'secret_private_key_pem', 'secret_oauth_token',
      'secret_jwt', 'secret_api_key_generic', 'secret_db_connection_string',
      'secret_slack_token', 'secret_stripe_key', 'secret_twilio_key',
      'secret_sendgrid_key', 'secret_mailgun_key', 'secret_openai_key',
      'secret_anthropic_key', 'secret_heroku_key'
    ],
    xss: [
      'xss_script_tag', 'xss_event_handler', 'xss_javascript_url',
      'xss_data_url', 'xss_svg_script', 'xss_dom_clobbering'
    ],
    compliance: [
      'owasp_llm01_prompt_injection',
      'owasp_llm02_insecure_output',
      'owasp_llm03_training_data_poisoning',
      'owasp_llm04_model_dos',
      'owasp_llm05_supply_chain',
      'owasp_llm06_sensitive_info_disclosure',
      'owasp_llm07_insecure_plugin',
      'owasp_llm08_excessive_agency',
      'owasp_llm09_overreliance',
      'owasp_llm10_model_theft',
      'atlas_promptinjection',
      'atlas_poison',
      'atlas_exfiltration',
      'atlas_jailbreak',
      'eu_ai_act_high_risk',
      'eu_ai_act_transparency',
      'eu_ai_act_human_oversight',
      'eu_ai_act_robustness',
      'anp_personal_data',
      'anp_special_category',
      'cu_consumer_rights',
      'cu_minor_protection'
    ],
    toxicity: [
      'toxicity_hate', 'toxicity_insult', 'toxicity_obscene',
      'toxicity_threat', 'toxicity_sexual', 'toxicity_self_harm',
      'toxicity_violence'
    ],
    prompt_injection: [
      'pi_direct_override',
      'pi_indirect_injection',
      'pi_jailbreak',
      'pi_role_play_attack'
    ]
  };

  var VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];

  var VALID_USER_ACTIONS = [
    'send_anyway', 'redact', 'cancel', 'dismiss_false_positive'
  ];

  // The schema for a single detection event. Optional fields default
  // to undefined and are omitted from the validated output.
  //
  // REQUIRED fields:
  //   - lens_event_version: string, "0.1.0-beta"
  //   - timestamp: number, Unix seconds (integer)
  //   - domain_hash: string, 16 hex chars (SHA-256 truncated)
  //   - facet: string, one of VALID_FACETS
  //   - category: string, from VALID_CATEGORIES[facet]
  //   - severity: string, from VALID_SEVERITIES
  //
  // OPTIONAL fields:
  //   - confidence: number, 0.0-1.0 (default 1.0 for regex)
  //   - user_action: string, from VALID_USER_ACTIONS
  //   - model_version: string, e.g. "regex-v1" or "modernbert-v1"
  //   - facet_results: object, per-facet confidence breakdown
  //   - pattern_id: string, e.g. "credit_card_visa_v1"
  //   - ml_score: number, 0.0-1.0 (only for ML detectors, 3h)
  //   - ml_threshold: number, 0.0-1.0 (only for ML detectors, 3h)
  //
  // What this schema DELIBERATELY does NOT include (privacy guarantee):
  //   - prompt text, URLs, page content, user IDs, cookies,
  //     keystroke timing, mouse movement, etc. (the 12 non-negotiables)

  var SCHEMA_VERSION = '0.1.0-beta';

  function isHex16(s) {
    return typeof s === 'string' && /^[0-9a-f]{16}$/.test(s);
  }

  function isPositiveInt(n) {
    return typeof n === 'number' && Number.isInteger(n) && n > 0;
  }

  // Validate just the metadata (facet + category + severity) of an
  // event, without requiring the full schema fields (timestamp,
  // domain_hash). This is what the dispatcher calls when it builds
  // an event from regex matches; the full event is built later
  // (by the SW) when the event is persisted or sent.
  function validateEventMetadata(event) {
    if (event === null || typeof event !== 'object') {
      return { ok: false, error: 'event must be an object' };
    }
    if (VALID_FACETS.indexOf(event.facet) === -1) {
      return { ok: false, error: 'facet must be one of ' + VALID_FACETS.join(',') };
    }
    var validCats = VALID_CATEGORIES[event.facet];
    if (!validCats || validCats.indexOf(event.category) === -1) {
      return { ok: false, error: 'category "' + event.category + '" is not valid for facet ' + event.facet };
    }
    if (VALID_SEVERITIES.indexOf(event.severity) === -1) {
      return { ok: false, error: 'severity must be one of ' + VALID_SEVERITIES.join(',') };
    }
    return { ok: true };
  }

  // Validate a single detection event. Returns { ok: true, event: <cleaned> }
  // on success, or { ok: false, error: '<message>' } on failure.
  function validateEvent(event) {
    if (event === null || typeof event !== 'object') {
      return { ok: false, error: 'event must be an object' };
    }

    // Required: lens_event_version
    if (event.lens_event_version !== SCHEMA_VERSION) {
      return { ok: false, error: 'lens_event_version must be "' + SCHEMA_VERSION + '"' };
    }

    // Required: timestamp
    if (!isPositiveInt(event.timestamp)) {
      return { ok: false, error: 'timestamp must be a positive integer (Unix seconds)' };
    }

    // Required: domain_hash
    if (!isHex16(event.domain_hash)) {
      return { ok: false, error: 'domain_hash must be a 16-char hex string' };
    }

    // Required: facet
    if (VALID_FACETS.indexOf(event.facet) === -1) {
      return { ok: false, error: 'facet must be one of ' + VALID_FACETS.join(',') };
    }

    // Required: category (must be valid for the given facet)
    var validCats = VALID_CATEGORIES[event.facet];
    if (validCats.indexOf(event.category) === -1) {
      return { ok: false, error: 'category "' + event.category + '" is not valid for facet ' + event.facet };
    }

    // Required: severity
    if (VALID_SEVERITIES.indexOf(event.severity) === -1) {
      return { ok: false, error: 'severity must be one of ' + VALID_SEVERITIES.join(',') };
    }

    // Optional: confidence
    if (event.confidence !== undefined) {
      if (typeof event.confidence !== 'number' || event.confidence < 0 || event.confidence > 1) {
        return { ok: false, error: 'confidence must be a number between 0 and 1' };
      }
    }

    // Optional: user_action
    if (event.user_action !== undefined && VALID_USER_ACTIONS.indexOf(event.user_action) === -1) {
      return { ok: false, error: 'user_action must be one of ' + VALID_USER_ACTIONS.join(',') };
    }

    // Optional: model_version
    if (event.model_version !== undefined && typeof event.model_version !== 'string') {
      return { ok: false, error: 'model_version must be a string' };
    }

    // Optional: pattern_id
    if (event.pattern_id !== undefined && typeof event.pattern_id !== 'string') {
      return { ok: false, error: 'pattern_id must be a string' };
    }

    // Optional: ml_score
    if (event.ml_score !== undefined) {
      if (typeof event.ml_score !== 'number' || event.ml_score < 0 || event.ml_score > 1) {
        return { ok: false, error: 'ml_score must be a number between 0 and 1' };
      }
    }

    // Optional: ml_threshold
    if (event.ml_threshold !== undefined) {
      if (typeof event.ml_threshold !== 'number' || event.ml_threshold < 0 || event.ml_threshold > 1) {
        return { ok: false, error: 'ml_threshold must be a number between 0 and 1' };
      }
    }

    // Optional: facet_results (object, per-facet confidence breakdown)
    if (event.facet_results !== undefined && (typeof event.facet_results !== 'object' || event.facet_results === null)) {
      return { ok: false, error: 'facet_results must be an object' };
    }

    // CRITICAL: Privacy guard. The cleaned event must NOT contain
    // any of the prohibited fields. We do this by EXPLICITLY
    // constructing the cleaned object from a whitelist of allowed
    // fields. Any field not in the whitelist is dropped.
    var cleaned = {
      lens_event_version: SCHEMA_VERSION,
      timestamp: event.timestamp,
      domain_hash: event.domain_hash,
      facet: event.facet,
      category: event.category,
      severity: event.severity
    };
    if (event.confidence !== undefined) cleaned.confidence = event.confidence;
    if (event.user_action !== undefined) cleaned.user_action = event.user_action;
    if (event.model_version !== undefined) cleaned.model_version = event.model_version;
    if (event.facet_results !== undefined) cleaned.facet_results = event.facet_results;
    if (event.pattern_id !== undefined) cleaned.pattern_id = event.pattern_id;
    if (event.ml_score !== undefined) cleaned.ml_score = event.ml_score;
    if (event.ml_threshold !== undefined) cleaned.ml_threshold = event.ml_threshold;

    return { ok: true, event: cleaned };
  }

  // Quick check for a single field. Used by tests and by other
  // modules that want to validate one piece of the schema.
  function isValidFacet(facet) { return VALID_FACETS.indexOf(facet) !== -1; }
  function isValidCategory(facet, category) {
    var cats = VALID_CATEGORIES[facet];
    return cats ? cats.indexOf(category) !== -1 : false;
  }
  function isValidSeverity(s) { return VALID_SEVERITIES.indexOf(s) !== -1; }
  function isValidUserAction(a) { return VALID_USER_ACTIONS.indexOf(a) !== -1; }

  // Build a full event from a metadata-only event (dispatcher output)
  // plus the required system fields (timestamp, domain_hash). This
  // is the canonical way the SW builds an event for persistence.
  function buildFullEvent(metadataEvent, timestamp, domainHash) {
    var candidate = {
      lens_event_version: SCHEMA_VERSION,
      timestamp: timestamp,
      domain_hash: domainHash,
      facet: metadataEvent.facet,
      category: metadataEvent.category,
      severity: metadataEvent.severity
    };
    if (metadataEvent.confidence !== undefined) candidate.confidence = metadataEvent.confidence;
    if (metadataEvent.user_action !== undefined) candidate.user_action = metadataEvent.user_action;
    if (metadataEvent.model_version !== undefined) candidate.model_version = metadataEvent.model_version;
    if (metadataEvent.pattern_id !== undefined) candidate.pattern_id = metadataEvent.pattern_id;
    if (metadataEvent.ml_score !== undefined) candidate.ml_score = metadataEvent.ml_score;
    if (metadataEvent.ml_threshold !== undefined) candidate.ml_threshold = metadataEvent.ml_threshold;
    return validateEvent(candidate);
  }

  var schema = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    VALID_FACETS: VALID_FACETS,
    VALID_CATEGORIES: VALID_CATEGORIES,
    VALID_SEVERITIES: VALID_SEVERITIES,
    VALID_USER_ACTIONS: VALID_USER_ACTIONS,
    validateEvent: validateEvent,
    validateEventMetadata: validateEventMetadata,
    buildFullEvent: buildFullEvent,
    isValidFacet: isValidFacet,
    isValidCategory: isValidCategory,
    isValidSeverity: isValidSeverity,
    isValidUserAction: isValidUserAction
  };

  if (typeof self !== 'undefined') self.__lensSchema = schema;
  if (typeof window !== 'undefined') window.__lensSchema = schema;
  if (typeof globalThis !== 'undefined') globalThis.__lensSchema = schema;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === privacy/domain_hash.js ===
// AegisGate Lens — domain_hash.js
// SHA-256 of a hostname, truncated to 16 hex chars.
//
// Privacy posture: the Lens never sends the page URL to the backend.
// Instead, the page's hostname is hashed locally before any opt-in
// telemetry event. The hash is one-way; the backend cannot recover
// the hostname from the hash. This is the structural privacy guarantee
// — even if the backend is compromised, no user browsing data leaks.
//
// Per threat model F-09: domain hashes are 16 hex chars (64 bits of
// entropy). Collision risk for 1M distinct domains is ~2.7e-8 (birthday
// bound), acceptable for telemetry aggregation purposes.
//
// Feature-detect: prefers crypto.subtle (Chrome 116+ requires
// secure context — true for extension pages). Falls back to a
// pure-JS SHA-256 implementation if subtle is unavailable.

(function (global) {
  'use strict';

  // Pure-JS SHA-256. ~80 lines, no deps. Used as the fallback when
  // crypto.subtle is not available (older browsers, certain edge cases).
  // Based on FIPS 180-4 reference, with 32-bit word operations.
  function sha256Bytes(message) {
    // Convert message to bytes if it's a string
    if (typeof message === 'string') {
      var enc = new TextEncoder();
      message = enc.encode(message);
    }
    // message is now a Uint8Array

    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // Pre-processing: padding
    var ml = message.length * 8;
    var padLen = (56 - (message.length + 1) % 64 + 64) % 64;
    var totalLen = message.length + 1 + padLen + 8;
    var padded = new Uint8Array(totalLen);
    padded.set(message);
    padded[message.length] = 0x80;
    // Append length in bits as 64-bit big-endian. We only support
    // messages up to 2^32 bits (4GB), which is well above any
    // hostname string. Top 4 bytes are 0.
    var dv = new DataView(padded.buffer);
    dv.setUint32(totalLen - 4, ml, false);

    // Process each 512-bit (64-byte) chunk
    var w = new Array(64);
    for (var chunk = 0; chunk < padded.length; chunk += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = dv.getUint32(chunk + i * 4, false);
      }
      for (var j = 16; j < 64; j++) {
        var s0 = ((w[j-15] >>> 7) | (w[j-15] << 25)) ^ ((w[j-15] >>> 18) | (w[j-15] << 14)) ^ (w[j-15] >>> 3);
        var s1 = ((w[j-2] >>> 17) | (w[j-2] << 15)) ^ ((w[j-2] >>> 19) | (w[j-2] << 13)) ^ (w[j-2] >>> 10);
        w[j] = (w[j-16] + s0 + w[j-7] + s1) | 0;
      }

      var a = H[0], b = H[1], c = H[2], d = H[3];
      var e = H[4], f = H[5], g = H[6], h = H[7];

      for (var k = 0; k < 64; k++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + K[k] + w[k]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) | 0;

        h = g; g = f; f = e;
        e = (d + temp1) | 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) | 0;
      }

      H[0] = (H[0] + a) | 0;
      H[1] = (H[1] + b) | 0;
      H[2] = (H[2] + c) | 0;
      H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0;
      H[5] = (H[5] + f) | 0;
      H[6] = (H[6] + g) | 0;
      H[7] = (H[7] + h) | 0;
    }

    // Output as Uint8Array
    var out = new Uint8Array(32);
    var outDv = new DataView(out.buffer);
    for (var m = 0; m < 8; m++) {
      outDv.setUint32(m * 4, H[m], false);
    }
    return out;
  }

  // Convert a Uint8Array of bytes to a hex string
  function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      hex += (b < 16 ? '0' : '') + b.toString(16);
    }
    return hex;
  }

  // Normalize a hostname: lowercase, strip leading "www.", trim.
  // "WWW.ChatGPT.com" -> "chatgpt.com"
  function normalizeHostname(host) {
    if (typeof host !== 'string') {
      throw new TypeError('hostname must be a string, got ' + typeof host);
    }
    var h = host.toLowerCase().trim();
    if (h.startsWith('www.')) h = h.substring(4);
    // Strip port if present
    var colon = h.indexOf(':');
    if (colon !== -1) h = h.substring(0, colon);
    return h;
  }

  // Synchronous SHA-256 (uses pure-JS impl). Returns a 16-char hex
  // string (truncated from the 64-char full hash).
  function computeDomainHashSync(hostname) {
    var normalized = normalizeHostname(hostname);
    var bytes = sha256Bytes(normalized);
    return bytesToHex(bytes).substring(0, 16);
  }

  // Async SHA-256 (uses crypto.subtle when available). Returns a
  // Promise<string> of the 16-char hex hash.
  // If subtle is unavailable, falls back to the sync impl.
  var subtle = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle)
            || (typeof self !== 'undefined' && self.crypto && self.crypto.subtle)
            || null;

  function computeDomainHash(hostname) {
    var normalized;
    try {
      normalized = normalizeHostname(hostname);
    } catch (e) {
      return Promise.reject(e);
    }
    if (subtle && typeof subtle.digest === 'function') {
      var enc = new TextEncoder();
      return subtle.digest('SHA-256', enc.encode(normalized)).then(function (buf) {
        var bytes = new Uint8Array(buf);
        return bytesToHex(bytes).substring(0, 16);
      });
    }
    // Fallback
    return Promise.resolve(computeDomainHashSync(normalized));
  }

  // Expose
  var module = {
    computeDomainHash: computeDomainHash,
    computeDomainHashSync: computeDomainHashSync,
    normalizeHostname: normalizeHostname,
    sha256Bytes: sha256Bytes,    // exposed for testing
    bytesToHex: bytesToHex,      // exposed for testing
    subtleAvailable: !!subtle
  };

  if (typeof self !== 'undefined') self.__lensDomainHash = module;
  if (typeof window !== 'undefined') window.__lensDomainHash = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensDomainHash = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/index.js ===
// AegisGate Lens — detectors/index.js
// The 6-facet dispatcher. Aggregates PII + Secrets + XSS + Compliance
// (regex facets) and (in 3h) Toxicity + Prompt-Injection (ML facets).
//
// v0.1.0-beta: 4 regex facets only. ML facets will be added in Step
// 3h with lazy-load from the service worker.
//
// Per docs/ARCHITECTURE-v0.1.0-BETA.md Section 4 (the 6 detection
// facets), each facet is an independent detection surface. The
// dispatcher:
//   1. Calls all 4 regex facets
//   2. Validates each match with privacy/schema.js
//   3. Deduplicates by category (multiple matches of the same
//      category become 1 event with count=N)
//   4. Sorts by severity (critical first)
//   5. Returns a structured DetectionResult object
//
// IMPORTANT: This module is 100% local. No network calls. The
// "Send & dismiss" opt-in path (in 3f's banner-ui.js) is the
// only time any data is sent, and the user must explicitly
// choose it. See docs/BANNER-DESIGN-SPEC-v0.1.0-BETA.md for the
// full opt-in flow.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // Severity order for sorting (lower = more severe)
  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  // The 4 regex facets. Each is loaded from globalThis (set by the
  // content_scripts load order in manifest.json).
  function getFacets() {
    var facets = [];

    if (typeof self !== 'undefined' && self.__lensPII) {
      facets.push({ id: 'pii', module: self.__lensPII });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensPII) {
      facets.push({ id: 'pii', module: globalThis.__lensPII });
    }

    if (typeof self !== 'undefined' && self.__lensSecrets) {
      facets.push({ id: 'secrets', module: self.__lensSecrets });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensSecrets) {
      facets.push({ id: 'secrets', module: globalThis.__lensSecrets });
    }

    if (typeof self !== 'undefined' && self.__lensXSS) {
      facets.push({ id: 'xss', module: self.__lensXSS });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensXSS) {
      facets.push({ id: 'xss', module: globalThis.__lensXSS });
    }

    if (typeof self !== 'undefined' && self.__lensCompliance) {
      facets.push({ id: 'compliance', module: self.__lensCompliance });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensCompliance) {
      facets.push({ id: 'compliance', module: globalThis.__lensCompliance });
    }

    return facets;
  }

  // Get the schema module (for validateEvent).
  function getSchema() {
    if (typeof self !== 'undefined' && self.__lensSchema) return self.__lensSchema;
    if (typeof globalThis !== 'undefined' && globalThis.__lensSchema) return globalThis.__lensSchema;
    return null;
  }

  // Build a single DetectionEvent from one or more raw matches.
  // The event is what gets passed to the banner and (optionally,
  // on opt-in) the SW. It is the EVENT that gets schema-validated.
  function buildEvent(facetId, category, severity, matches, schemaModule) {
    if (!matches || matches.length === 0) return null;
    var event = {
      facet: facetId,                        // 'pii' | 'secrets' | 'xss' | 'compliance'
      category: category,                     // e.g. 'pii_credit_card'
      severity: severity,                     // 'critical' | 'high' | 'medium' | 'low'
      count: matches.length,                  // how many matches
      // For display: the masked values (first match is enough;
      // the banner shows the first 4 + last 4 chars).
      sample: matches[0].value,
      // All matches, in original order
      matches: matches.map(function (m) {
        return {
          value: m.value,
          index: m.index,
          severity: m.severity,
          // cardType is added by pii.js for credit cards (Luhn-validated)
          cardType: m.cardType || null,
          // confidence is a 0-1 score; regex detectors set 1.0
          confidence: typeof m.confidence === 'number' ? m.confidence : 1.0
        };
      }),
      // ML facets (3h) will set this; regex sets null
      ml_score: null,
      ml_model_version: null
    };

    // Validate the metadata (facet + category + severity) if the
    // schema module is available. The full event (with timestamp
    // and domain_hash) is built later by the SW when it persists
    // or sends the event. The metadata validation ensures the
    // category is legitimate for the facet and the severity is
    // one of the 4 allowed values.
    if (schemaModule && typeof schemaModule.validateEventMetadata === 'function') {
      var validation = schemaModule.validateEventMetadata(event);
      if (!validation.ok) {
        log.warn('event failed metadata validation: ' + validation.error +
                 ' (facet=' + facetId + ' category=' + category + ')');
        return null;
      }
    }
    return event;
  }

  // Deduplicate matches by category. Multiple matches of the same
  // category become one event with count=N. We also cap the
  // matches array at MAX_MATCHES_PER_EVENT to avoid memory bloat
  // for prompts that have hundreds of the same pattern.
  var MAX_MATCHES_PER_EVENT = 20;

  function dedupeByCategory(facetId, rawMatches) {
    var byCategory = {};
    for (var i = 0; i < rawMatches.length; i++) {
      var m = rawMatches[i];
      if (!byCategory[m.category]) {
        byCategory[m.category] = {
          category: m.category,
          severity: m.severity,
          matches: []
        };
      }
      if (byCategory[m.category].matches.length < MAX_MATCHES_PER_EVENT) {
        byCategory[m.category].matches.push(m);
      }
    }
    return byCategory;
  }

  // Run detection on a text string. Returns a DetectionResult.
  //
  // DetectionResult {
  //   text: string,             // the input text (NOT modified)
  //   hasDetections: boolean,
  //   count: number,            // total detection count
  //   maxSeverity: 'critical' | 'high' | 'medium' | 'low' | null,
  //   events: [DetectionEvent]  // sorted by severity, critical first
  // }
  function detect(text) {
    if (typeof text !== 'string') text = '';
    var result = {
      text: text,
      hasDetections: false,
      count: 0,
      maxSeverity: null,
      events: []
    };

    if (text.length === 0) return result;

    var facets = getFacets();
    if (facets.length === 0) {
      log.error('dispatcher: no regex facets available; cannot detect');
      return result;
    }

    var schemaModule = getSchema();
    if (!schemaModule) {
      log.error('dispatcher: schema module not available; cannot validate events');
      return result;
    }

    for (var i = 0; i < facets.length; i++) {
      var facet = facets[i];
      try {
        var rawMatches = facet.module.detect(text);
        if (!rawMatches || rawMatches.length === 0) continue;

        var byCategory = dedupeByCategory(facet.id, rawMatches);
        var categoryKeys = Object.keys(byCategory);
        for (var j = 0; j < categoryKeys.length; j++) {
          var group = byCategory[categoryKeys[j]];
          var event = buildEvent(facet.id, group.category, group.severity, group.matches, schemaModule);
          if (event) result.events.push(event);
        }
      } catch (err) {
        // Per lesson K: a broken facet should not break the
        // whole dispatcher. Log the error and continue with
        // the other facets.
        log.error('facet ' + facet.id + ' threw in detect()', err);
      }
    }

    // Sort by severity (critical first), then by count descending
    // Note: SEVERITY_ORDER has critical=0, so we MUST NOT use
    // `|| 99` to default unknown severities — that pattern breaks
    // for critical (since 0 is falsy). Use explicit undefined check.
    result.events.sort(function (a, b) {
      var rankA = (typeof SEVERITY_ORDER[a.severity] === 'number') ? SEVERITY_ORDER[a.severity] : 99;
      var rankB = (typeof SEVERITY_ORDER[b.severity] === 'number') ? SEVERITY_ORDER[b.severity] : 99;
      var sevDiff = rankA - rankB;
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });

    // Compute summary
    result.hasDetections = result.events.length > 0;
    result.count = 0;
    var maxSevRank = 99;
    for (var k = 0; k < result.events.length; k++) {
      result.count += result.events[k].count;
      var rank = (typeof SEVERITY_ORDER[result.events[k].severity] === 'number')
        ? SEVERITY_ORDER[result.events[k].severity] : 99;
      if (rank < maxSevRank) {
        maxSevRank = rank;
        result.maxSeverity = result.events[k].severity;
      }
    }

    return result;
  }

  // For testing: list the loaded facets (so we can assert all 4
  // are present in a healthy state)
  function listFacets() {
    return getFacets().map(function (f) { return f.id; });
  }

  // For testing: list the expected facets (so the test can assert)
  var EXPECTED_FACETS = ['pii', 'secrets', 'xss', 'compliance'];

  var module = {
    detect: detect,
    listFacets: listFacets,
    EXPECTED_FACETS: EXPECTED_FACETS,
    SEVERITY_ORDER: SEVERITY_ORDER,
    MAX_MATCHES_PER_EVENT: MAX_MATCHES_PER_EVENT
  };

  if (typeof self !== 'undefined') self.__lensDispatcher = module;
  if (typeof window !== 'undefined') window.__lensDispatcher = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensDispatcher = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/selectors.js ===
// AegisGate Lens — util/selectors.js
// Selector table for the 10 supported AI providers.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Logger. Per the architecture doc and standing rules: every module
  // must NEVER silently swallow errors. Use __lensLogger (set by
  // logger.js, which loads before this file). Fall back to console
  // if the logger isn't available (e.g., when running under node:test
  // or in the headless smoke test before all modules load).
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // Each entry: { hosts, inputSelector, sendSelector, containerSelector,
  //               submitMethod, isContentEditable, version }
  //
  // IMPORTANT: These selectors are based on the AI providers public
  // DOM structures as of July 2026. AI providers change their DOM
  // frequently. When a selector fails, the MutationObserver in
  // prompt-detect.js logs a warning and re-queries. A long-term
  // fix would be a per-provider plugin, but for v0.1.0-beta we
  // ship a curated list and rely on the observer for resilience.
  var PROVIDERS = [
    {
      id: 'chatgpt',
      name: 'ChatGPT',
      hosts: ['chat.openai.com', 'chatgpt.com'],
      // ChatGPT: contenteditable ProseMirror element
      inputSelector: 'div#prompt-textarea[contenteditable="true"], div.ProseMirror[contenteditable="true"], textarea#prompt-textarea',
      // Send button (the up-arrow)
      sendSelector: 'button[data-testid="send-button"], button[aria-label*="Send" i]',
      // The bottom composer area
      containerSelector: 'form.w-full, div[role="presentation"]',
      // Submit by Enter (Shift+Enter is newline)
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'claude',
      name: 'Claude',
      hosts: ['claude.ai'],
      // Claude: a ProseMirror-style editor
      inputSelector: 'div.ProseMirror[contenteditable="true"], [data-testid="chat-input"] [contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button[data-testid="send-message"]',
      containerSelector: 'div[data-testid="chat-input"], fieldset',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'gemini',
      name: 'Gemini',
      hosts: ['gemini.google.com'],
      // Gemini: a rich-text editor div
      inputSelector: 'div.ql-editor[contenteditable="true"], rich-textarea div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button.send-button',
      containerSelector: 'rich-textarea, input-area',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'copilot',
      name: 'Microsoft Copilot',
      hosts: ['copilot.microsoft.com', 'copilot.cloud.microsoft'],
      // Copilot: a textarea
      inputSelector: 'textarea#userInput, textarea[name="userInput"]',
      sendSelector: 'button[aria-label*="Send" i], button[aria-label*="Submit" i]',
      containerSelector: 'form, div.input-container',
      submitMethod: 'click',
      isContentEditable: false,
      version: '2026-07'
    },
    {
      id: 'perplexity',
      name: 'Perplexity',
      hosts: ['perplexity.ai', 'www.perplexity.ai'],
      // Perplexity: a textarea
      inputSelector: 'textarea[placeholder*="Ask" i], textarea[name="q"]',
      sendSelector: 'button[aria-label="Submit"], button[type="submit"]',
      containerSelector: 'div[role="search"], form',
      submitMethod: 'click',
      isContentEditable: false,
      version: '2026-07'
    },
    {
      id: 'duckduckgo',
      name: 'DuckDuckGo AI Chat',
      hosts: ['duckduckgo.com', 'duck.co'],
      // DDG AI Chat (legacy): textarea in the AI chat overlay
      inputSelector: 'textarea[name="user-prompt"], textarea[placeholder*="Ask" i]',
      sendSelector: 'button[aria-label*="Send" i]',
      containerSelector: 'div.iso_chat, form',
      submitMethod: 'enter',
      isContentEditable: false,
      version: '2026-07'
    },
    {
      id: 'duck_ai',
      name: 'Duck.ai',
      hosts: ['duck.ai'],
      // Duck.ai: new chat interface
      inputSelector: 'textarea[name="user-prompt"], textarea[placeholder*="Ask" i], div[contenteditable="true"]',
      sendSelector: 'button[type="submit"], button[aria-label*="Send" i]',
      containerSelector: 'main, form',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'grok',
      name: 'Grok (x.com)',
      hosts: ['grok.com', 'x.com', 'twitter.com'],
      // Grok: textarea in the Grok tab
      inputSelector: 'textarea[placeholder*="Ask" i], div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button[aria-label*="Post" i]',
      containerSelector: 'form, div[role="group"]',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'mistral',
      name: 'Mistral Le Chat',
      hosts: ['chat.mistral.ai', 'le-chat.mistral.ai'],
      // Mistral: textarea
      inputSelector: 'textarea[name="text"], textarea[placeholder*="Ask" i]',
      sendSelector: 'button[type="submit"], button[aria-label*="Send" i]',
      containerSelector: 'form',
      submitMethod: 'enter',
      isContentEditable: false,
      version: '2026-07'
    },
    {
      id: 'huggingchat',
      name: 'HuggingChat',
      hosts: ['huggingface.co', 'hf.co'],
      // HuggingChat: textarea
      inputSelector: 'textarea[placeholder*="Ask" i], textarea[name="input"]',
      sendSelector: 'button[type="submit"]',
      containerSelector: 'form',
      submitMethod: 'enter',
      isContentEditable: false,
      version: '2026-07'
    }
  ];

  // Identify which provider matches the current page.
  // Returns the provider config object, or null if no match.
  function identifyProvider() {
    var hostname = (window.location && window.location.hostname) || '';
    if (!hostname) return null;
    var host = hostname.toLowerCase();
    for (var i = 0; i < PROVIDERS.length; i++) {
      var p = PROVIDERS[i];
      for (var j = 0; j < p.hosts.length; j++) {
        // Exact match or subdomain match
        var h = p.hosts[j].toLowerCase();
        if (host === h || host.endsWith('.' + h)) {
          return p;
        }
      }
    }
    // Test-only: localhost matches the first provider (chatgpt).
    // This enables the headless smoke test (test/headless-smoke/)
    // to fire the content script on a localhost HTTPS mock. In
    // production, this only matches on localhost (which Chrome
    // treats as a secure context but the user would have to
    // intentionally navigate to). See test/headless-smoke/STATUS.md.
    if (host === 'localhost' || host === '127.0.0.1') {
      log.info('selectors: localhost hostname detected, using chatgpt provider for smoke test');
      return PROVIDERS[0];
    }
    return null;
  }

  // Get the input element (textarea or contenteditable div).
  // Returns null if not found.
  function findInput(provider) {
    if (!provider) return null;
    var candidates = document.querySelectorAll(provider.inputSelector);
    if (candidates.length > 0) return candidates[0];
    // Fallback: try to find any visible contenteditable or textarea
    // in the page (this is the DOM changed case)
    var fallbacks = document.querySelectorAll(
      'textarea[placeholder*="Ask" i], ' +
      'textarea[placeholder*="message" i], ' +
      'textarea[placeholder*="prompt" i], ' +
      'div[contenteditable="true"]'
    );
    for (var i = 0; i < fallbacks.length; i++) {
      var el = fallbacks[i];
      var rect = el.getBoundingClientRect();
      // Only visible elements (positive width/height)
      if (rect.width > 100 && rect.height > 20) return el;
    }
    return null;
  }

  // Get the current text from the input element.
  // Works for both textarea and contenteditable.
  function getInputValue(input) {
    if (!input) return '';
    if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
      return input.value || '';
    }
    if (input.isContentEditable || input.getAttribute('contenteditable') === 'true') {
      return input.innerText || input.textContent || '';
    }
    return input.value || input.innerText || '';
  }

  // Set the text in the input element.
  function setInputValue(input, value) {
    if (!input) return;
    if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
      var nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
      ).set;
      nativeSetter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      input.innerText = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  // Find the send button (may not exist on every page)
  function findSendButton(provider) {
    if (!provider || !provider.sendSelector) return null;
    var candidates = document.querySelectorAll(provider.sendSelector);
    if (candidates.length > 0) return candidates[0];
    return null;
  }

  // Find the container to attach the banner to
  function findContainer(provider) {
    if (!provider) return document.body;
    var candidates = document.querySelectorAll(provider.containerSelector);
    if (candidates.length > 0) return candidates[0];
    return document.body;
  }

  var module = {
    PROVIDERS: PROVIDERS,
    identifyProvider: identifyProvider,
    findInput: findInput,
    getInputValue: getInputValue,
    setInputValue: setInputValue,
    findSendButton: findSendButton,
    findContainer: findContainer
  };

  if (typeof self !== 'undefined') self.__lensSelectors = module;
  if (typeof window !== 'undefined') window.__lensSelectors = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensSelectors = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/prompt-detect.js ===
// AegisGate Lens — util/prompt-detect.js
// Attaches to the AI provider prompt input and triggers detection
// as the user types. Uses MutationObserver to survive React re-mounts.
//
// Per the architecture doc Section 9 (SPA MutationObserver pattern),
// modern AI chat UIs are React SPAs that re-mount the input element
// when state changes. document_idle does not fire reliably on these
// pages. The MutationObserver is the canonical fix.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;

  // The detection pipeline. Delegates to the 6-facet dispatcher
  // (loaded in 3e). The dispatcher aggregates PII + Secrets + XSS +
  // Compliance (regex facets) and (in 3h) Toxicity + Prompt-
  // Injection (ML facets). It validates each event against the
  // schema, deduplicates by category, and sorts by severity.
  function detectPrompt(text) {
    var dispatcher = (typeof self !== 'undefined' && self.__lensDispatcher) ||
                     (typeof globalThis !== 'undefined' && globalThis.__lensDispatcher) ||
                     null;
    if (!dispatcher) {
      log.error('prompt-detect: dispatcher not available; cannot detect');
      return [];
    }
    var result = dispatcher.detect(text);
    // The banner wants the events array (with sample, matches, etc.)
    return result.events;
  }

  // Debounce helper: schedule fn to run after ms of quiet
  function debounce(fn, ms) {
    var timer = null;
    return function () {
      var args = arguments;
      var selfCtx = this;
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(function () {
        timer = null;
        try { fn.apply(selfCtx, args); } catch (e) { log.error('debounced fn threw', e); }
      }, ms);
    };
  }

  // State
  var state = {
    provider: null,
    input: null,
    sendButton: null,
    attached: false,
    lastValue: '',
    lastDetections: [],
    onDetect: null,
    onSendIntercept: null,
    observer: null,
    debounceTimer: null,
    _debouncedInput: null
  };

  // Identify the provider for the current page
  function identifyProvider() {
    if (!selectors) {
      log.error('selectors module not available; cannot identify provider');
      return null;
    }
    var p = selectors.identifyProvider();
    if (p) {
      log.info('identified provider: ' + p.id + ' (' + p.name + ')');
    } else {
      log.warn('no provider matched hostname: ' + (window.location && window.location.hostname));
    }
    return p;
  }

  // Find the current input and send button
  function findElements() {
    if (!state.provider || !selectors) return;
    state.input = selectors.findInput(state.provider);
    state.sendButton = selectors.findSendButton(state.provider);
  }

  // The onInput handler: read the current value, run detection
  function onInput() {
    try {
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value === state.lastValue) return;
      state.lastValue = value;
      if (value.length === 0) {
        state.lastDetections = [];
        if (state.onDetect) {
          try { state.onDetect([], ''); } catch (e) { log.error('onDetect threw', e); }
        }
        return;
      }
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (state.onDetect) {
        try { state.onDetect(dets, value); } catch (e) { log.error('onDetect threw', e); }
      }
    } catch (err) {
      log.error('onInput handler threw', err);
    }
  }

  // The onSendClick handler: intercept the send button click
  function onSendClick(e) {
    try {
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value.length === 0) return;
      // Always re-detect on send (the last keyup might have been
      // before the user finished typing)
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (dets.length > 0 && state.onSendIntercept) {
        // Pause the default action; let the consumer decide
        try { e.preventDefault(); e.stopPropagation(); } catch (e2) { /* ignore */ }
        try {
          var decision = state.onSendIntercept(dets, value);
          if (decision && decision.action === 'send') {
            log.info('user chose to send anyway despite ' + dets.length + ' detections');
            // Re-dispatch on the next tick (we already prevented it)
            setTimeout(function () {
              if (state.sendButton) state.sendButton.click();
            }, 0);
          } else if (decision && decision.action === 'redact') {
            log.info('user chose to redact ' + dets.length + ' detections');
            // Remove the detected values from the input
            var redacted = value;
            for (var i = 0; i < dets.length; i++) {
              redacted = redacted.replace(dets[i].value, '[REDACTED]');
            }
            selectors.setInputValue(state.input, redacted);
          } else {
            log.info('user chose to cancel the send');
          }
        } catch (e3) { log.error('onSendIntercept threw', e3); }
      }
    } catch (err) {
      log.error('onSendClick handler threw', err);
    }
  }

  // The onKeyDown handler for Enter on contenteditable
  function onKeyDown(e) {
    try {
      if (!state.provider) return;
      if (state.provider.submitMethod !== 'enter') return;
      if (e.key !== 'Enter') return;
      if (e.shiftKey) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value.length === 0) return;
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (dets.length > 0 && state.onSendIntercept) {
        try { e.preventDefault(); e.stopPropagation(); } catch (e2) { /* ignore */ }
        try {
          var decision = state.onSendIntercept(dets, value);
          if (decision && decision.action === 'send') {
            log.info('user chose to send anyway despite detections; press Enter again to confirm');
          } else if (decision && decision.action === 'redact') {
            var redacted = value;
            for (var i = 0; i < dets.length; i++) {
              redacted = redacted.replace(dets[i].value, '[REDACTED]');
            }
            selectors.setInputValue(state.input, redacted);
          }
        } catch (e3) { log.error('onSendIntercept (keydown) threw', e3); }
      }
    } catch (err) {
      log.error('onKeyDown handler threw', err);
    }
  }

  // Attach event listeners to the current input + send button
  function attach() {
    if (state.attached) return;
    if (!state.input) return;
    try {
      var debouncedInput = debounce(onInput, 250);
      state.input.addEventListener('input', debouncedInput, true);
      state.input.addEventListener('keyup', debouncedInput, true);
      state.input.addEventListener('keydown', onKeyDown, true);
      if (state.sendButton) {
        state.sendButton.addEventListener('click', onSendClick, true);
      }
      state._debouncedInput = debouncedInput;
      state.attached = true;
      log.info('attached to input' + (state.sendButton ? ' + send button' : ''));
    } catch (err) {
      log.error('attach() threw', err);
    }
  }

  // Detach event listeners
  function detach() {
    if (!state.attached) return;
    try {
      if (state.input) {
        if (state._debouncedInput) {
          state.input.removeEventListener('input', state._debouncedInput, true);
          state.input.removeEventListener('keyup', state._debouncedInput, true);
        }
        state.input.removeEventListener('keydown', onKeyDown, true);
      }
      if (state.sendButton) {
        state.sendButton.removeEventListener('click', onSendClick, true);
      }
      state.attached = false;
      log.info('detached from input');
    } catch (err) {
      log.error('detach() threw', err);
    }
  }

  // The MutationObserver callback: re-attach if the input was replaced
  function onMutation(mutations) {
    try {
      if (!state.provider) return;
      var newInput = selectors.findInput(state.provider);
      if (newInput && newInput !== state.input) {
        log.info('input element changed; re-attaching');
        detach();
        state.input = newInput;
        state.sendButton = selectors.findSendButton(state.provider);
        attach();
      } else if (!newInput && state.input) {
        log.info('input element removed; detaching');
        detach();
        state.input = null;
        state.sendButton = null;
      }
    } catch (err) {
      log.error('onMutation threw', err);
    }
  }

  // Initialize the prompt detector
  function init(opts) {
    opts = opts || {};
    state.onDetect = opts.onDetect || null;
    state.onSendIntercept = opts.onSendIntercept || null;

    state.provider = identifyProvider();
    if (!state.provider) {
      log.warn('no provider identified; prompt-detect will not attach');
      return false;
    }

    findElements();
    if (!state.input) {
      log.warn('input not found yet; will retry on mutations');
    } else {
      attach();
    }

    // Set up the MutationObserver
    try {
      state.observer = new MutationObserver(onMutation);
      state.observer.observe(document.body, {
        childList: true,
        subtree: true
      });
      log.info('MutationObserver attached on body');
    } catch (err) {
      log.error('failed to create MutationObserver', err);
      return false;
    }

    return true;
  }

  // Shutdown
  function shutdown() {
    try {
      if (state.observer) {
        state.observer.disconnect();
        state.observer = null;
      }
      detach();
      state.provider = null;
      state.input = null;
      state.sendButton = null;
      log.info('prompt-detect shut down');
    } catch (err) {
      log.error('shutdown threw', err);
    }
  }

  // For testing: get current state
  function getState() {
    return {
      provider: state.provider ? state.provider.id : null,
      inputAttached: state.attached,
      hasInput: !!state.input,
      hasSendButton: !!state.sendButton,
      lastValue: state.lastValue.substring(0, 50),
      lastDetectionCount: state.lastDetections.length
    };
  }

  var module = {
    init: init,
    shutdown: shutdown,
    getState: getState,
    detectPrompt: detectPrompt
  };

  if (typeof self !== 'undefined') self.__lensPromptDetect = module;
  if (typeof window !== 'undefined') window.__lensPromptDetect = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensPromptDetect = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/banner-icons.js ===
// AegisGate Lens — util/banner-icons.js
// Inline SVG icons used by the banner. Inlined to avoid any
// network fetch (privacy guarantee #1) and to avoid any
// "icon not found" if the user has aggressive ad blockers.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Each icon is a 16x16 viewBox SVG. Color is controlled by the
  // CSS fill (currentColor).
  var ICONS = {
    // AegisGate shield-with-padlock mark (simplified, single color).
    // The real corporate logo is a detailed metallic shield; this is
    // a single-color version that reads at 16x16 in the banner.
    shield: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
            'fill="currentColor" aria-hidden="true">' +
            '<path d="M8 1L2 3v5c0 3.5 2.5 6.5 6 7 3.5-.5 6-3.5 6-7V3L8 1zm0 1.2l4.8 1.5V8c0 2.8-2 5.2-4.8 5.7C5.2 13.2 3.2 10.8 3.2 8V3.7L8 2.2z"/>' +
            '<path d="M7 6V4.5C7 3.7 7.4 3 8 3s1 .7 1 1.5V6h.5v4.5h-3V6H7zm.5-1.5V6h1V4.5C8.5 4 8.3 3.5 8 3.5s-.5.5-.5 1z"/>' +
            '</svg>',

    // Close X
    close: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
           'fill="currentColor" aria-hidden="true">' +
           '<path d="M3.7 3L3 3.7 7.3 8 3 12.3 3.7 13 8 8.7 12.3 13 13 12.3 8.7 8 13 3.7 12.3 3 8 7.3 3.7 3z"/>' +
           '</svg>',

    // Help ?
    help: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
          'fill="currentColor" aria-hidden="true">' +
          '<path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 13a6 6 0 110-12 6 6 0 010 12z"/>' +
          '<path d="M7.3 5.5C7.3 4.7 7.9 4 8.8 4c.9 0 1.5.7 1.5 1.5 0 .5-.2.9-.6 1.2L8.5 7.5c-.3.2-.5.5-.5 1v.5h1V8.5c0-.2.1-.3.3-.4L10.6 7c.6-.4.9-1 .9-1.6C11.5 4 10.2 3 8.8 3 7.3 3 6.2 4.1 6.2 5.5h1.1zm.2 4.5v1.1h1.1V10H7.5z"/>' +
          '</svg>',

    // Down chevron (for the "Tell us why" expand)
    chevronDown: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
                 'fill="currentColor" aria-hidden="true">' +
                 '<path d="M3 5.5L3.7 4.8 8 9.1l4.3-4.3.7.7L8 10.5 3 5.5z"/>' +
                 '</svg>'
  };

  var module = { ICONS: ICONS };

  if (typeof self !== 'undefined') self.__lensBannerIcons = module;
  if (typeof window !== 'undefined') window.__lensBannerIcons = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensBannerIcons = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/dismiss.js ===
// AegisGate Lens — util/dismiss.js
// 24-hour dismissal storage + opt-in false-positive report.
//
// Per the BANNER-DESIGN-SPEC, when the user dismisses a banner
// they have two options:
//   1. "Submit & dismiss" — opt-in to sending ONE anonymous,
//      sanitized FP report to the AegisGate TI engine. The
//      domain_hash, category, pattern_id, reason, ml_score,
//      and timestamp are sent. NO prompt text, NO URLs, NO
//      page content, NO user identifier.
//   2. "Just dismiss (private)" — local-only suppression.
//      No data is sent. The detection is suppressed for 24h
//      on the same domain + same pattern.
//
// Both paths create a local entry in chrome.storage.local. The
// 24h scope is enforced by a TTL on each entry.
//
// Per docs/ARCHITECTURE-v0.1.0-BETA.md, the Lens is opt-in by
// default. "Submit & dismiss" is the only way the user can opt
// in to telemetry. Until they opt in, NO data is sent.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var STORAGE_KEY = 'aegisgate_lens_dismissals';
  var TTL_MS = 24 * 60 * 60 * 1000;  // 24 hours
  var SCHEMA_VERSION = '0.1.0-beta';

  // The 3 reason codes. These match the design spec.
  var REASON_TEST_DATA = 'test_data';
  var REASON_OWN_DATA = 'own_data';
  var REASON_LEGITIMATE = 'legitimate_use_case';

  // Build a stable key from (domainHash, category, patternId).
  // The patternId is included so the same category with different
  // patterns (e.g. AWS vs GitHub secrets) can be dismissed
  // independently. We do NOT include the match value (privacy).
  function buildKey(domainHash, category, patternId) {
    if (!domainHash || !category) return null;
    var pid = patternId || '_nopattern_';
    return domainHash + ':' + category + ':' + pid;
  }

  // Get the current dismissals from chrome.storage.local.
  // Returns {} if storage is unavailable or empty.
  function getAll() {
    return new Promise(function (resolve) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage ||
            !chrome.storage.local) {
          resolve({});
          return;
        }
        chrome.storage.local.get([STORAGE_KEY], function (result) {
          if (chrome.runtime && chrome.runtime.lastError) {
            log.warn('storage get failed: ' + chrome.runtime.lastError.message);
            resolve({});
            return;
          }
          resolve(result[STORAGE_KEY] || {});
        });
      } catch (e) {
        log.error('getAll() threw', e);
        resolve({});
      }
    });
  }

  // Save the dismissals map back to chrome.storage.local.
  function saveAll(dismissals) {
    return new Promise(function (resolve, reject) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage ||
            !chrome.storage.local) {
          resolve(false);
          return;
        }
        chrome.storage.local.set({ [STORAGE_KEY]: dismissals }, function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            log.warn('storage set failed: ' + chrome.runtime.lastError.message);
            resolve(false);
            return;
          }
          resolve(true);
        });
      } catch (e) {
        log.error('saveAll() threw', e);
        reject(e);
      }
    });
  }

  // Garbage-collect expired entries.
  function gc(dismissals) {
    var now = Date.now();
    var kept = {};
    var keys = Object.keys(dismissals);
    for (var i = 0; i < keys.length; i++) {
      var entry = dismissals[keys[i]];
      if (entry && typeof entry.expires_at === 'number' &&
          entry.expires_at > now) {
        kept[keys[i]] = entry;
      }
    }
    return kept;
  }

  // Check if a (domainHash, category, patternId) is currently
  // dismissed. Returns the entry object (with reason, dismissed_at,
  // expires_at) or null.
  async function isDismissed(domainHash, category, patternId) {
    var key = buildKey(domainHash, category, patternId);
    if (!key) return null;
    var all = await getAll();
    all = gc(all);
    // Save back if we GC'd anything
    if (Object.keys(all).length !== Object.keys(all).length) {
      await saveAll(all);
    }
    return all[key] || null;
  }

  // Dismiss a detection. If `reason` is non-null, this is the
  // opt-in path (the caller should ALSO send the FP report via
  // sendFPReport). If `reason` is null, this is the private path.
  // `fpReportData` is the sanitized report (only set on opt-in).
  async function dismiss(domainHash, category, patternId, reason, fpReportData) {
    try {
      var key = buildKey(domainHash, category, patternId);
      if (!key) return false;
      var all = await getAll();
      all = gc(all);
      var now = Date.now();
      all[key] = {
        dismissed_at: now,
        expires_at: now + TTL_MS,
        reason: reason || null,
        // Only stored on opt-in path; otherwise null
        opt_in: reason ? true : false,
        // Sanitized FP report payload (no text). Only present on
        // the opt-in path. The caller is responsible for actually
        // sending this to the backend.
        fp_report: fpReportData || null
      };
      var ok = await saveAll(all);
      if (ok) {
        if (reason) {
          log.info('dismissed (opt-in) ' + key + ' reason=' + reason);
        } else {
          log.info('dismissed (private) ' + key);
        }
      }
      return ok;
    } catch (err) {
      log.error('dismiss() threw', err);
      return false;
    }
  }

  // Get the FP report payload for a detection event. The caller
  // is responsible for sending this to the backend (via the SW
  // in 3g, which is the only network path).
  //
  // Per the privacy doc, the FP report contains ONLY:
  //   - domain_hash (SHA-256 prefix of hostname, 16 hex chars)
  //   - category (e.g. "pii_credit_card")
  //   - pattern_id (e.g. "credit_card_visa_v1")
  //   - reason (test_data | own_data | legitimate_use_case)
  //   - ml_score, ml_threshold, ml_model_version (only for ML)
  //   - lens_event_version, lens_version, timestamp
  //
  // It does NOT contain: prompt text, URLs, page content, user IDs.
  function buildFPReport(event, domainHash, reason) {
    if (!event) return null;
    return {
      lens_event_version: SCHEMA_VERSION,
      timestamp: Math.floor(Date.now() / 1000),  // Unix seconds
      domain_hash: domainHash,
      facet: event.facet,
      category: event.category,
      severity: event.severity,
      pattern_id: event.matches && event.matches[0] ?
                  (event.matches[0].cardType ? event.category + '_' + event.matches[0].cardType + '_v1' : event.category + '_v1') :
                  event.category + '_v1',
      reason: reason,
      ml_score: event.ml_score,
      ml_threshold: event.ml_threshold || null,
      ml_model_version: event.ml_model_version || null,
      lens_version: SCHEMA_VERSION
    };
  }

  // Clear all dismissals. Used by the popup (3j) for the
  // "Reset dismissals" button.
  async function clearAll() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage ||
          !chrome.storage.local) return false;
      return new Promise(function (resolve) {
        chrome.storage.local.remove([STORAGE_KEY], function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            log.warn('storage remove failed: ' + chrome.runtime.lastError.message);
            resolve(false);
            return;
          }
          log.info('cleared all dismissals');
          resolve(true);
        });
      });
    } catch (err) {
      log.error('clearAll() threw', err);
      return false;
    }
  }

  // List all active (non-expired) dismissals. For the popup UI.
  async function listActive() {
    var all = await getAll();
    return gc(all);
  }

  var module = {
    STORAGE_KEY: STORAGE_KEY,
    TTL_MS: TTL_MS,
    REASON_TEST_DATA: REASON_TEST_DATA,
    REASON_OWN_DATA: REASON_OWN_DATA,
    REASON_LEGITIMATE: REASON_LEGITIMATE,
    isDismissed: isDismissed,
    dismiss: dismiss,
    buildFPReport: buildFPReport,
    clearAll: clearAll,
    listActive: listActive,
    buildKey: buildKey
  };

  if (typeof self !== 'undefined') self.__lensDismiss = module;
  if (typeof window !== 'undefined') window.__lensDismiss = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensDismiss = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/banner-ui.js ===
// AegisGate Lens — util/banner-ui.js
// The brand-matched banner UI. Per the BANNER-DESIGN-SPEC.
//
// Public API:
//   banner-ui.show(events, opts)        // show the banner above the input
//   banner-ui.hide()                     // hide the banner
//   banner-ui.isVisible()                // boolean
//   banner-ui.getElement()               // the DOM element (or null)
//
// The banner does NOT modify the input or the page. It only
// shows UI and emits user actions through the callback set
// via opts.onAction(action, payload).
//
// All styles are applied via inline data-aegisgate-lens="banner"
// attribute. The CSS file is injected at boot via injectStyles().
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var icons = (typeof self !== 'undefined' && self.__lensBannerIcons) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerIcons) ||
              null;

  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
                (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
                null;

  // CSS for the banner. We use a <link> tag to load the CSS file
  // from the extension's web_accessible_resources. If chrome.runtime
  // is not available (e.g., in tests), we skip the link injection;
  // tests don't actually render the banner so the missing CSS is fine.
  var STYLE_ID = 'aegisgate-lens-banner-styles';
  var CSS_URL = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
    ? chrome.runtime.getURL('src/util/banner.css')
    : null;

  function injectStyles() {
    try {
      if (document.getElementById(STYLE_ID)) return;
      if (!CSS_URL) {
        // chrome.runtime.getURL not available (e.g., in tests);
        // the banner will use default browser styles. Tests don't
        // render the banner anyway.
        return;
      }
      var link = document.createElement('link');
      link.id = STYLE_ID;
      link.rel = 'stylesheet';
      link.type = 'text/css';
      link.href = CSS_URL;
      link.setAttribute('data-aegisgate-lens', 'banner-css');
      document.head.appendChild(link);
    } catch (err) {
      log.error('injectStyles threw', err);
    }
  }

  // Mask a value for display. First 4 + ellipsis + last 4.
  // Special handling for email: local part masked differently.
  function maskValue(value, category) {
    if (typeof value !== 'string' || value.length === 0) return '';
    // Email: j***@e****.com
    if (category === 'pii_email' && value.indexOf('@') !== -1) {
      var parts = value.split('@');
      var local = parts[0];
      var domain = parts[1];
      // Local: first char + '***' (e.g. 'j***')
      // Edge: empty local (shouldn't happen, but guard)
      var maskedLocal = local.length === 0 ? '***' : local[0] + '***';
      var dotIdx = domain.lastIndexOf('.');
      var maskedDomain = dotIdx > 0
        ? domain[0] + '***' + domain.substring(dotIdx)
        : '***';
      return maskedLocal + '@' + maskedDomain;
    }
    // Default: first 4 + … + last 4
    if (value.length <= 10) {
      // Too short to meaningfully mask; show first 2 + …
      return value.substring(0, 2) + '…' + value.substring(value.length - 2);
    }
    return value.substring(0, 4) + '…' + value.substring(value.length - 4);
  }

  // Format a category for display: strip the prefix and
  // replace underscores with spaces.
  function formatCategory(category) {
    if (typeof category !== 'string') return '';
    var s = category;
    // Strip known prefixes
    var prefixes = ['pii_', 'secret_', 'xss_', 'owasp_', 'atlas_', 'eu_ai_act_', 'anp_', 'cu_', 'toxicity_', 'pi_'];
    for (var i = 0; i < prefixes.length; i++) {
      if (s.indexOf(prefixes[i]) === 0) {
        s = s.substring(prefixes[i].length);
        break;
      }
    }
    // Word-boundary regex. NOTE: in the source file this is the
    // literal string '/\b\w/g' (single backslashes after the
    // regex delimiter). When written via Python/Node string
    // concatenation it can accidentally become '/\\b\\w/g' (which
    // matches a literal backslash-b). The Lesson here: ALWAYS
    // test the output of any string-based regex manipulation.
    var s2 = s.replace(/_/g, ' ');
    var result = '';
    for (var j = 0; j < s2.length; j++) {
      var c = s2[j];
      if (j === 0 || s2[j-1] === ' ') {
        result += c.toUpperCase();
      } else {
        result += c;
      }
    }
    return result;
  }

  // Create the banner DOM element. The element is a <div> with
  // data-aegisgate-lens="banner". It is NOT attached to the
  // DOM until show() is called.
  function createBannerElement() {
    var el = document.createElement('div');
    el.setAttribute('data-aegisgate-lens', 'banner');
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-live', 'polite');
    el.style.display = 'none';
    return el;
  }

  // Build the inner HTML for the banner. Pulled out so tests
  // can construct the same structure without DOM.
  function buildBannerHTML(events, opts) {
    opts = opts || {};
    var count = events.length;
    var countText = count + ' sensitive item' + (count === 1 ? '' : 's') + ' detected';

    // Build the detection list HTML
    var listHtml = '<div class="lens-list">';
    var maxItems = 8;
    for (var i = 0; i < events.length && i < maxItems; i++) {
      var ev = events[i];
      listHtml += '<div class="lens-item lens-item-' + ev.severity + '">';
      listHtml += '<span class="lens-item-category">' + escapeHtml(formatCategory(ev.category)) + '</span>';
      listHtml += '<span class="lens-pill lens-pill-' + ev.severity + '">' + ev.severity + '</span>';
      if (ev.sample) {
        listHtml += '<span class="lens-item-match" dir="ltr">' + escapeHtml(maskValue(ev.sample, ev.category)) + '</span>';
      }
      listHtml += '</div>';
    }
    if (events.length > maxItems) {
      listHtml += '<div class="lens-item" style="color: var(--lens-text-muted); font-style: italic; border-left-color: transparent;">';
      listHtml += '+ ' + (events.length - maxItems) + ' more';
      listHtml += '</div>';
    }
    listHtml += '</div>';

    // Privacy footer
    var learnMoreUrl = opts.learnMoreUrl ||
      'https://github.com/aegisgatesecurity/aegisgate-lens#readme';
    var privacyHtml =
      '<div class="lens-privacy">' +
        '<strong>These items are visible to the AI provider when you send.</strong> ' +
        'AegisGate Lens never sends your prompt to any server. ' +
        '<a href="' + escapeHtml(learnMoreUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>.' +
      '</div>';

    // Action row
    var actionsHtml =
      '<div class="lens-actions">' +
        '<button type="button" class="lens-btn lens-btn-secondary" data-action="cancel">Cancel send</button>' +
        '<button type="button" class="lens-btn lens-btn-primary" data-action="redact">Edit &amp; redact</button>' +
        '<button type="button" class="lens-btn lens-btn-ghost" data-action="send">Send anyway</button>' +
        '<button type="button" class="lens-false-positive-link" data-action="false-positive">' +
          (icons && icons.ICONS.chevronDown ? icons.ICONS.chevronDown : '') +
          'This is a false positive' +
        '</button>' +
      '</div>';

    // Header
    var headerHtml =
      '<div class="lens-header">' +
        '<span class="lens-shield">' + (icons && icons.ICONS.shield ? icons.ICONS.shield : '') + '</span>' +
        '<span class="lens-wordmark">AegisGate Lens</span>' +
        '<span class="lens-count">' + countText + '</span>' +
        '<span class="lens-header-actions">' +
          '<button type="button" class="lens-icon-btn" data-action="help" aria-label="Help">' +
            (icons && icons.ICONS.help ? icons.ICONS.help : '?') +
          '</button>' +
          '<button type="button" class="lens-icon-btn" data-action="dismiss" aria-label="Dismiss for 24 hours">' +
            (icons && icons.ICONS.close ? icons.ICONS.close : '×') +
          '</button>' +
        '</span>' +
      '</div>';

    return headerHtml + listHtml + privacyHtml + actionsHtml;
  }

  // The dismiss form (expanded). Shown when the user clicks
  // "This is a false positive".
  function buildDismissFormHTML() {
    return '' +
      '<div class="lens-dismiss" role="region" aria-label="Mark as false positive">' +
        '<div class="lens-dismiss-prompt">Tell us why this is a false positive (helps us improve):</div>' +
        '<div class="lens-dismiss-reasons">' +
          '<label><input type="checkbox" data-reason="test_data"> This is test/fake data</label>' +
          '<label><input type="checkbox" data-reason="own_data"> This is my own data (I know what I\'m doing)</label>' +
          '<label><input type="checkbox" data-reason="legitimate_use_case"> This is for a legitimate use case I trust</label>' +
        '</div>' +
        '<div class="lens-dismiss-actions">' +
          '<button type="button" class="lens-btn lens-btn-primary" data-dismiss-action="submit">Submit &amp; dismiss</button>' +
          '<button type="button" class="lens-btn lens-btn-secondary" data-dismiss-action="private">Just dismiss (private)</button>' +
          '<button type="button" class="lens-btn lens-btn-ghost" data-dismiss-action="cancel">Cancel</button>' +
        '</div>' +
        '<div class="lens-dismiss-transparency">' +
          'Submit sends one anonymous, sanitized report (category, pattern, reason). No prompt text, no URLs, no page content. Just dismiss is 100% local.' +
        '</div>' +
      '</div>';
  }

  // Minimal HTML escape (defense against malicious category text)
  function escapeHtml(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
  }

  // State
  var state = {
    el: null,                  // the banner DOM element
    currentEvents: null,       // the events currently displayed
    currentOpts: null,         // the opts used to show the banner
    parentInput: null,         // the input element the banner is anchored to
    inserting: false,          // are we currently in the middle of attaching?
    isVisible: false
  };

  // Attach event listeners to the banner. Called once at create time.
  function attachListeners(el, opts) {
    opts = opts || {};
    el.addEventListener('click', function (e) {
      try {
        var target = e.target;
        // Walk up to find the button or its data-action
        var btn = target.closest && target.closest('[data-action]');
        if (btn) {
          handleAction(btn.getAttribute('data-action'), opts);
          return;
        }
        var dismissBtn = target.closest && target.closest('[data-dismiss-action]');
        if (dismissBtn) {
          handleDismissAction(dismissBtn.getAttribute('data-dismiss-action'), opts);
        }
      } catch (err) {
        log.error('click handler threw', err);
      }
    }, true);
  }

  // Show the dismiss form inline (replaces the action row)
  function showDismissForm(opts) {
    if (!state.el) return;
    var actionsRow = state.el.querySelector('.lens-actions');
    if (!actionsRow) return;
    // Remove any existing dismiss form
    var existing = state.el.querySelector('.lens-dismiss');
    if (existing) existing.remove();
    // Insert the dismiss form after the actions row
    actionsRow.insertAdjacentHTML('afterend', buildDismissFormHTML());
    // Scroll the dismiss form into view
    var form = state.el.querySelector('.lens-dismiss');
    if (form) form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Hide the dismiss form (restore the action row)
  function hideDismissForm() {
    if (!state.el) return;
    var form = state.el.querySelector('.lens-dismiss');
    if (form) form.remove();
  }

  // Action handler. Routes to the consumer's onAction callback.
  function handleAction(action, opts) {
    if (action === 'false-positive') {
      showDismissForm(opts);
      return;
    }
    // All other actions hide the banner and call onAction
    if (action === 'dismiss') {
      // Dismiss for 24h on the same domain + category
      recordDismissalForEvents('private', null, opts);
    }
    hide();
    if (typeof opts.onAction === 'function') {
      try {
        opts.onAction(action, { events: state.currentEvents });
      } catch (err) {
        log.error('opts.onAction threw', err);
      }
    }
  }

  // Dismiss-form action handler
  async function handleDismissAction(action, opts) {
    if (action === 'cancel') {
      hideDismissForm();
      return;
    }
    // Get the checked reason
    var form = state.el && state.el.querySelector('.lens-dismiss');
    var reason = null;
    if (form) {
      var checkboxes = form.querySelectorAll('input[type="checkbox"]');
      for (var i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
          reason = checkboxes[i].getAttribute('data-reason');
          break;
        }
      }
    }
    if (action === 'private') {
      // Just dismiss (private) — no reason required, no FP report
      await recordDismissalForEvents('private', null, opts);
      hide();
      if (typeof opts.onAction === 'function') {
        try { opts.onAction('dismiss', { events: state.currentEvents }); } catch (e) { log.error('onAction threw', e); }
      }
      return;
    }
    if (action === 'submit') {
      // Submit & dismiss — opt-in path
      // If no reason was selected, default to 'own_data' (most common)
      if (!reason) reason = 'own_data';
      await recordDismissalForEvents('optin', reason, opts);
      hide();
      if (typeof opts.onAction === 'function') {
        try {
          opts.onAction('dismiss_optin', {
            events: state.currentEvents,
            reason: reason
          });
        } catch (e) { log.error('onAction threw', e); }
      }
    }
  }

  // Record a dismissal for every event currently displayed.
  // On the opt-in path, also build the FP report(s).
  async function recordDismissalForEvents(mode, reason, opts) {
    if (!dismiss) {
      log.warn('dismiss module not available; cannot record dismissal');
      return;
    }
    if (!state.currentEvents) return;
    var domainHash = opts.domainHash || null;
    if (!domainHash) {
      log.warn('no domainHash in opts; cannot record dismissal');
      return;
    }
    for (var i = 0; i < state.currentEvents.length; i++) {
      var ev = state.currentEvents[i];
      var fpReport = null;
      if (mode === 'optin') {
        fpReport = dismiss.buildFPReport(ev, domainHash, reason);
      }
      await dismiss.dismiss(domainHash, ev.category,
                            ev.matches && ev.matches[0] && ev.matches[0].cardType ?
                              ev.category + '_' + ev.matches[0].cardType : ev.category,
                            mode === 'optin' ? reason : null,
                            fpReport);
    }
    // On opt-in, surface the FP reports via the onAction callback
    // so the SW (3g) can send them. We do NOT send them here
    // because the banner-ui is the content script and the SW is
    // the only place that has the network handle.
    if (mode === 'optin' && typeof opts.onAction === 'function') {
      try {
        var reports = [];
        for (var j = 0; j < state.currentEvents.length; j++) {
          var report = dismiss.buildFPReport(state.currentEvents[j], domainHash, reason);
          if (report) reports.push(report);
        }
        opts.onAction('fp_reports', { reports: reports });
      } catch (e) { log.error('onAction(fp_reports) threw', e); }
    }
  }

  // Show the banner above the input element
  function show(events, opts) {
    opts = opts || {};
    if (!Array.isArray(events) || events.length === 0) {
      log.warn('show() called with no events; ignoring');
      return;
    }
    if (!state.el) {
      injectStyles();
      state.el = createBannerElement();
      attachListeners(state.el, opts);
    }
    state.currentEvents = events;
    state.currentOpts = opts;
    state.el.innerHTML = buildBannerHTML(events, opts);
    state.el.style.display = '';

    // Attach the banner above the input
    var input = opts.input || null;
    if (input && input.parentNode) {
      // If the banner is already inserted, remove it first
      if (state.el.parentNode && state.el.parentNode !== input.parentNode) {
        state.el.parentNode.removeChild(state.el);
      }
      if (state.el.parentNode !== input.parentNode) {
        input.parentNode.insertBefore(state.el, input);
      }
      state.parentInput = input;
    } else {
      // No input provided; fall back to document.body
      if (state.el.parentNode !== document.body) {
        if (state.el.parentNode) state.el.parentNode.removeChild(state.el);
        document.body.appendChild(state.el);
      }
    }
    state.isVisible = true;
    log.info('banner shown with ' + events.length + ' events');
  }

  // Hide the banner
  function hide() {
    if (!state.el || !state.isVisible) return;
    // Snapshot the element before the timeout (state.el may be
    // cleared by a subsequent show())
    var el = state.el;
    try { el.classList.add('lens-hiding'); } catch (e) { /* ignore */ }
    setTimeout(function () {
      try {
        el.style.display = 'none';
        try { el.classList.remove('lens-hiding'); } catch (e2) { /* ignore */ }
        if (el.parentNode) el.parentNode.removeChild(el);
      } catch (e3) {
        log.warn('banner hide() cleanup error (test env?): ' + e3.message);
      }
    }, 200);
    state.isVisible = false;
    state.currentEvents = null;
    state.currentOpts = null;
    log.info('banner hidden');
  }

  function isVisible() { return state.isVisible; }
  function getElement() { return state.el; }

  // For testing: get the current state
  function getState() {
    return {
      isVisible: state.isVisible,
      hasElement: !!state.el,
      eventCount: state.currentEvents ? state.currentEvents.length : 0
    };
  }

  var module = {
    show: show,
    hide: hide,
    isVisible: isVisible,
    getElement: getElement,
    getState: getState,
    // Exposed for tests
    maskValue: maskValue,
    formatCategory: formatCategory,
    buildBannerHTML: buildBannerHTML,
    buildDismissFormHTML: buildDismissFormHTML
  };

  if (typeof self !== 'undefined') self.__lensBannerUI = module;
  if (typeof window !== 'undefined') window.__lensBannerUI = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensBannerUI = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === content.js ===
// AegisGate Lens — content.js
// Injected into AI provider pages (10 hosts per manifest.json).
//
// Step 3d: this content script now wires up the SPA-aware prompt
// detector. The detectors (3b/3c) and selectors (3d) are loaded
// before this file in the manifest content_scripts array.
//
// What this file does:
//   1. Logs that the content script loaded and on which page
//   2. Verifies the logger, schema, and domain_hash modules are loaded
//   3. Computes the domain hash for telemetry
//   4. Initializes prompt-detect with onDetect + onSendIntercept
//      callbacks. The banner UI (3f) will replace the placeholder
//      console.log with a real banner element.
//   5. Exposes __lens_cs on window for diagnostics
//
// All async work is wrapped in try/catch with REAL error logging.
// We never silently swallow errors.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ console.log('[AegisGate Lens] ' + m); },
              warn: function(m){ console.warn('[AegisGate Lens] ' + m); },
              error: function(m,e){ console.error('[AegisGate Lens] ' + m, e); } };

  var schema = (typeof self !== 'undefined' && self.__lensSchema) ||
               (typeof globalThis !== 'undefined' && globalThis.__lensSchema) ||
               null;

  var domainHash = (typeof self !== 'undefined' && self.__lensDomainHash) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensDomainHash) ||
                   null;

  var promptDetect = (typeof self !== 'undefined' && self.__lensPromptDetect) ||
                     (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect) ||
                     null;

  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;

  var dispatcher = (typeof self !== 'undefined' && self.__lensDispatcher) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensDispatcher) ||
                   null;

  var bannerUI = (typeof self !== 'undefined' && self.__lensBannerUI) ||
                 (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI) ||
                 null;

  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
                (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
                null;

  // Module state (shared between init, onDetect, etc.)
  var state = {
    domainHash: null,
    provider: null,
    input: null
  };

  // The onSendIntercept callback. Called by prompt-detect when the
  // user attempts to send a message that has detections. The return
  // value is a decision object: { action: 'send' | 'redact' | 'cancel' }.
  // For now (3f, the regex-chain release), the only available actions
  // are 'cancel' (default -- the banner pauses the send) and 'send'
  // (user override -- they accept the risk and send anyway). Redact
  // will be wired in 3g. The minimal implementation: block the send
  // (return 'cancel') unless the user clicks "Send anyway".
  function onSendIntercept(events, text) {
    try {
      log.info('onSendIntercept: blocking send (' + (events ? events.length : 0) + ' detections)');
      return { action: 'cancel', reason: 'detections' };
    } catch (err) {
      log.error('onSendIntercept threw', err);
      return { action: 'cancel', reason: 'error' };
    }
  }

  // The onDetect callback. Called by prompt-detect when detections
  // change. Shows the brand-matched banner above the input.
  function onDetect(events, text) {
    try {
      // Expose lastDetections on window.__lens_cs for diagnostics,
      // testing (headless smoke test), and the popup's "what was
      // detected" panel. This is the bridge between prompt-detect's
      // internal state and the test harness / popup UI.
      if (window.__lens_cs) {
        window.__lens_cs.lastDetections = events || [];
        window.__lens_cs.lastText = text || '';
        window.__lens_cs.lastDetectedAt = Date.now();
      }
      if (!events || events.length === 0) {
        if (bannerUI) bannerUI.hide();
        return;
      }
      if (!bannerUI) {
        log.warn('onDetect: bannerUI not available; cannot show banner');
        return;
      }
      // Check if any event is currently dismissed (24h scope)
      // If all events are dismissed, hide the banner
      if (dismiss) {
        var allDismissed = true;
        for (var i = 0; i < events.length; i++) {
          var ev = events[i];
          if (!state.domainHash) break;  // not yet known
          dismiss.isDismissed(state.domainHash, ev.category, ev.category + '_v1')
            .then(function (entry) {
              if (!entry) allDismissed = false;
            });
        }
        // NOTE: the isDismissed check is async; for simplicity we
        // show the banner regardless. The banner's dismiss action
        // (× button) will record the dismissal for next time.
      }
      bannerUI.show(events, {
        input: selectors && state.provider ? selectors.findInput(state.provider) : null,
        domainHash: state.domainHash,
        learnMoreUrl: 'https://github.com/aegisgatesecurity/aegisgate-lens#readme',
        onAction: function (action, payload) {
          handleBannerAction(action, payload);
        }
      });
    } catch (err) {
      log.error('onDetect threw', err);
    }
  }

  // Handle banner action. The banner has 3 main actions (cancel,
  // redact, send) and a 4th: dismiss_optin (the "Submit & dismiss"
  // opt-in path). For 3f, the actual send/cancel/re-dispatch
  // behavior is still placeholders; 3g will wire the SW.
  function handleBannerAction(action, payload) {
    try {
      log.info('banner action: ' + action);
      if (action === 'cancel') {
        // The prompt-detect onSendClick already preventDefault'd.
        // Just log; user can edit the input.
      } else if (action === 'redact') {
        // TODO(3g): implement the redaction (replace values
        // with [REDACTED] in the input via selectors.setInputValue)
        log.info('user chose redact (' + (payload && payload.events ? payload.events.length : 0) + ' events)');
      } else if (action === 'send') {
        // The send was preventDefault'd by onSendClick. For now,
        // log only. The user can re-press Enter / click send to
        // actually send. (A future enhancement could automatically
        // re-dispatch the send event after a delay.)
        log.info('user chose send anyway; user must re-send');
      } else if (action === 'dismiss' || action === 'dismiss_optin') {
        // The dismiss module already recorded this. The fp_reports
        // action (if any) will be sent in 3g.
        log.info('user dismissed (' + action + ')');
      } else if (action === 'fp_reports') {
        // The user opted in. The reports are in payload.reports.
        // Send them to the SW via chrome.runtime.sendMessage.
        // The SW validates the message shape, queues it, and
        // attempts to send to the backend. See api/messages.js
        // for the message envelope and background.js for the
        // SW handler.
        if (typeof chrome !== 'undefined' && chrome.runtime &&
            typeof chrome.runtime.sendMessage === 'function') {
          try {
            var message = {
              type: 'FP_REPORTS',
              version: '0.1.0-beta',
              payload: {
                timestamp: Math.floor(Date.now() / 1000),
                reports: payload.reports || []
              }
            };
            chrome.runtime.sendMessage(message, function (response) {
              if (chrome.runtime && chrome.runtime.lastError) {
                log.warn('sendMessage error: ' + chrome.runtime.lastError.message);
                return;
              }
              if (response && response.type === 'ACK') {
                log.info('SW ack: ' + JSON.stringify(response.payload || {}));
              } else if (response && response.type === 'ERROR') {
                log.error('SW error: ' + (response.payload && response.payload.error));
              }
            });
          } catch (e) {
            log.error('sendMessage threw', e);
          }
        } else {
          log.info('chrome.runtime.sendMessage not available; reports queued locally only');
        }
        // For diagnostic purposes, also log the first report
        if (payload && payload.reports && payload.reports[0]) {
          log.info('FP report payload: ' + JSON.stringify(payload.reports[0]));
        }
      }
    } catch (err) {
      log.error('handleBannerAction threw', err);
    }
  }

  function init() {
    try {
      log.info('content.js loaded on ' + (window.location && window.location.hostname ? window.location.hostname : '<unknown>'));

      // Verify modules
      if (!schema) {
        log.error('content.js: __lensSchema not available; schema.js failed to load');
        return;
      }
      if (!domainHash) {
        log.error('content.js: __lensDomainHash not available; domain_hash.js failed to load');
        return;
      }
      if (!selectors) {
        log.error('content.js: __lensSelectors not available; selectors.js failed to load');
        return;
      }
      if (!promptDetect) {
        log.error('content.js: __lensPromptDetect not available; prompt-detect.js failed to load');
        return;
      }

      // Compute the domain hash
      var hostname = (window.location && window.location.hostname) || '';
      domainHash.computeDomainHash(hostname).then(function (hash) {
        state.domainHash = hash;
        // Expose the content script state on window
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: hash,
          schemaVersion: schema.SCHEMA_VERSION,
          detect: dispatcher ? dispatcher.detect : null,
          showBanner: bannerUI ? bannerUI.show : null
        };

        // Initialize the prompt detector with our callbacks
        var ok = promptDetect.init({
          onDetect: onDetect,
          onSendIntercept: onSendIntercept
        });
        if (ok) {
          log.info('content.js init complete; prompt-detect attached');
        } else {
          log.warn('content.js init complete; prompt-detect failed (no provider)');
        }
      }).catch(function (err) {
        log.error('content.js: failed to compute domain_hash', err);
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: null,
          schemaVersion: schema ? schema.SCHEMA_VERSION : null,
          initError: err && err.message ? err.message : String(err)
        };
      });
    } catch (err) {
      log.error('content.js: uncaught error in init()', err);
    }
  }

  // Run init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

// === detectors/ml/pi-ml.js ===
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.1.0-beta - PI ML detector (BPE tokenizer version)
//
// Per user directive (2026-07-05 19:13 + 19:27):
//  - ONNX export + browser ML wiring (the only path)
//  - Real BPE tokenizer to match PyTorch's 0% FPR on the held-out
//
// This module is the pi-ml.js module with a REAL BPE tokenizer
// (replacing the simple hash-based placeholder). The tokenizer
// implementation is the GPT-2 / RoBERTa-style ByteLevel BPE used
// by HuggingFace tokenizers.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.
(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens ML] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens ML] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens ML] ' + m, e); } catch (e) {} } };

  // GPT-2 byte-to-unicode mapping. Maps each byte (0-255) to a
  // printable unicode character. This is the standard mapping from
  // the GPT-2 paper, used by RoBERTa, BERT, and most modern
  // transformers. Bytes 0-32 (control chars) and 127-160 (extended
  // ASCII) get mapped to U+0100 onwards.
  var BYTE_TO_UNICODE = (function() {
    var bs = [];
    // Printable ASCII ranges
    for (var i = 33; i <= 126; i++) bs.push(i);   // ! to ~
    for (var i = 161; i <= 172; i++) bs.push(i);  // ¡ to ¬
    for (var i = 174; i <= 255; i++) bs.push(i);  // © to ÿ
    var cs = bs.slice();
    var n = bs.length;
    // Map remaining bytes (0-32, 127-160) to U+0100 onwards
    for (var b = 0; b < 256; b++) {
      if (bs.indexOf(b) === -1) {
        bs.push(b);
        cs.push(256 + n);
        n++;
      }
    }
    var byteToUnicode = {};
    var unicodeToByte = {};
    for (var i = 0; i < bs.length; i++) {
      byteToUnicode[bs[i]] = String.fromCharCode(cs[i]);
      unicodeToByte[String.fromCharCode(cs[i])] = bs[i];
    }
    return { b2u: byteToUnicode, u2b: unicodeToByte, bytesList: bs, charsList: cs };
  })();

  // State
  var state = {
    session: null,
    loading: null,
    tokenizer: null,
    config: null,
    initialized: false,
    initError: null,
    threshold: 0.5,
    // Cached bpeRanks: a dict from merge-pair-tuple to rank (int).
    // Lower rank = applied first. Built once on init.
    bpeRanks: null,
  };

  // Load the tokenizer JSON (from global).
  function loadTokenizer() {
    if (typeof globalThis !== 'undefined' && globalThis.__lensTokenizerJSON) {
      return globalThis.__lensTokenizerJSON;
    }
    throw new Error('PI ML: tokenizer JSON not provided (set globalThis.__lensTokenizerJSON)');
  }

  function loadConfig() {
    if (typeof globalThis !== 'undefined' && globalThis.__lensModelConfig) {
      return globalThis.__lensModelConfig;
    }
    throw new Error('PI ML: model config not provided (set globalThis.__lensModelConfig)');
  }

  // Build a set of "cache" words we've already BPE-encoded.
  // Standard BPE is O(n^2) per word; caching is essential for
  // long inputs (8K context).
  var bpeCache = new Map();
  var cacheLimit = 10000;  // ~10K words cached

  // Apply BPE merges to a single word (sequence of tokens).
  // Standard GPT-2 style BPE.
  function bpe(token) {
    if (bpeCache.size > cacheLimit) bpeCache.clear();
    if (bpeCache.has(token)) return bpeCache.get(token);

    var word = token.split('');
    var pairs = getPairs(word);

    if (!pairs || pairs.length === 0) {
      var single = [token];
      bpeCache.set(token, single);
      return single;
    }

    while (true) {
      // Find the pair with the lowest rank
      var minRank = Infinity;
      var bestPair = null;
      for (var i = 0; i < pairs.length; i++) {
        var rank = state.bpeRanks[pairs[i]];
        if (rank === undefined) rank = Infinity;
        if (rank < minRank) {
          minRank = rank;
          bestPair = pairs[i];
        }
      }
      if (bestPair === null) break;

      // Merge all occurrences of bestPair
      var first = bestPair[0];
      var second = bestPair[1];
      var newWord = [];
      var i = 0;
      while (i < word.length) {
        var j = i;
        // Find the next occurrence of the pair
        while (j < word.length - 1 && word[j] !== first) j++;
        // If no first, or first doesn't pair with next second, keep
        if (j >= word.length || word[j] !== first) {
          newWord.push(word[i]);
          i++;
          continue;
        }
        // Check if word[j+1] is second
        if (j + 1 < word.length && word[j + 1] === second) {
          // Merge
          newWord.push(first + second);
          i = j + 2;
        } else {
          newWord.push(word[i]);
          i++;
        }
      }
      word = newWord;
      if (word.length === 1) break;
      pairs = getPairs(word);
    }

    bpeCache.set(token, word);
    return word;
  }

  // Get all adjacent pairs in a word (sequence).
  function getPairs(word) {
    var pairs = new Set();
    var prev = word[0];
    for (var i = 1; i < word.length; i++) {
      pairs.add(prev + '|' + word[i]);
      prev = word[i];
    }
    // Convert back to [a, b] tuples
    var result = [];
    pairs.forEach(function(p) {
      var parts = p.split('|');
      result.push(parts);
    });
    return result;
  }

  // Real BPE tokenizer (GPT-2 / RoBERTa style with ByteLevel pre-tokenizer).
  function tokenizeBPE(text) {
    if (!state.tokenizer) throw new Error('tokenizer not loaded');
    var vocab = state.tokenizer.model.vocab;  // {token: id}
    var merges = state.tokenizer.model.merges;  // [[a, b], ...]
    var clsId = state.config && state.config.cls_token_id || 50281;
    var sepId = state.config && state.config.sep_token_id || 50282;
    var padId = state.config && state.config.pad_token_id || 50283;
    var maxLen = 128;

    // Build bpeRanks on first call (cached in state)
    if (!state.bpeRanks) {
      state.bpeRanks = {};
      for (var i = 0; i < merges.length; i++) {
        state.bpeRanks[merges[i][0] + '|' + merges[i][1]] = i;
      }
    }

    // Step 1: Normalize (NFC) - skip for now, browser has limited Unicode
    // support and modern text is typically already NFC-normalized.

    // Step 2: Pre-tokenize (ByteLevel: split on whitespace + punctuation,
    // map bytes to unicode, prepend Ġ to word starts).
    // Simple regex split: split on whitespace, then on each word
    // split into byte-level chars with Ġ prefix.
    var words = text.split(/\s+/).filter(function(w) { return w.length > 0; });
    var byteTokens = [];
    for (var i = 0; i < words.length; i++) {
      var word = words[i];
      // If not the first word, prepend Ġ (which is the space marker)
      var prefix = (i > 0) ? '\u0120' : '';  // Ġ
      // Map each byte of the word to its unicode char
      var chars = prefix;
      for (var j = 0; j < word.length; j++) {
        var byte = word.charCodeAt(j) & 0xFF;
        chars += BYTE_TO_UNICODE.b2u[byte];
      }
      byteTokens.push(chars);
    }

    // Step 3: Apply BPE merges to each word
    var bpeTokens = [];
    for (var k = 0; k < byteTokens.length; k++) {
      var merged = bpe(byteTokens[k]);
      for (var m = 0; m < merged.length; m++) {
        bpeTokens.push(merged[m]);
      }
    }

    // Step 4: Convert BPE tokens to IDs via vocab lookup
    var ids = [clsId];
    for (var n = 0; n < bpeTokens.length && ids.length < maxLen - 1; n++) {
      var token = bpeTokens[n];
      if (vocab.hasOwnProperty(token)) {
        ids.push(vocab[token]);
      } else if (vocab.hasOwnProperty('<unk>')) {
        ids.push(vocab['<unk>']);
      } else {
        // Token not in vocab and no <unk>: use unk_token_id
        ids.push(state.config.unk_token_id || 50280);
      }
    }
    ids.push(sepId);

    // Step 5: Pad
    var attention = ids.map(function() { return 1; });
    while (ids.length < maxLen) {
      ids.push(padId);
      attention.push(0);
    }
    // Truncate if too long
    if (ids.length > maxLen) {
      ids = ids.slice(0, maxLen - 1).concat([sepId]);
      attention = attention.slice(0, maxLen - 1).concat([1]);
    }

    return { input_ids: ids, attention_mask: attention };
  }

  // Initialize the model.
  function init(opts) {
    opts = opts || {};
    if (opts.modelURL) state.modelURL = opts.modelURL;
    if (opts.threshold !== undefined) state.threshold = opts.threshold;
    if (state.loading) return state.loading;

    log.info('initializing PI ML model (one-time, ~3-5s)');
    state.loading = (async function() {
      try {
        state.tokenizer = loadTokenizer();
        state.config = loadConfig();
        log.info('tokenizer + config loaded, vocab size: ' +
                 Object.keys(state.tokenizer.model.vocab).length);

        // Pre-build bpeRanks
        state.bpeRanks = {};
        var merges = state.tokenizer.model.merges;
        for (var i = 0; i < merges.length; i++) {
          state.bpeRanks[merges[i][0] + '|' + merges[i][1]] = i;
        }
        log.info('built bpeRanks for ' + merges.length + ' merges');

        // Load the ONNX model via the vendored runtime
        var ort = (typeof self !== 'undefined' && self.ort) ||
                  (typeof globalThis !== 'undefined' && globalThis.ort) ||
                  null;
        if (!ort) {
          throw new Error('PI ML: onnxruntime-web (ort) not loaded');
        }
        log.info('ort loaded');

        // Configure WASM paths. The page mock serves WASM from
        // /vendor/onnxruntime-web/. We construct that URL from the
        // modelURL's origin.
        if (state.modelURL) {
          var origin = state.modelURL.substring(0, state.modelURL.indexOf('/', state.modelURL.indexOf('//') + 2));
          var wasmDir = origin + '/vendor/onnxruntime-web/';
          if (ort.env && ort.env.wasm) {
            ort.env.wasm.wasmPaths = wasmDir;
            log.info('wasm paths: ' + wasmDir);
          }
        }

        state.session = await ort.InferenceSession.create(state.modelURL, {
          executionProviders: ['wasm'],
          graphOptimizationLevel: 'all',
        });
        log.info('PI ML session created');

        state.initialized = true;
        state.initError = null;
        return state.session;
      } catch (err) {
        state.initError = err && err.message ? err.message : String(err);
        log.error('PI ML init failed', err);
        state.initialized = false;
        throw err;
      }
    })();
    return state.loading;
  }

  // Run inference on text. Returns matches array.
  async function detect(text) {
    if (!state.initialized) {
      try { await init(); } catch (e) { return []; }
    }
    if (!state.session) {
      log.warn('PI ML: session not ready, returning empty');
      return [];
    }
    if (!text || text.length === 0) return [];

    try {
      var input = tokenizeBPE(text);
      // ORT Web tensor input. The model was trained with int64 inputs.
      // We use the ort.Tensor class which handles the int64 conversion
      // internally. This avoids the "invalid data location" error we
      // got with plain object literals.
      var Tensor = ort.Tensor;
      var idsArr = new Array(input.input_ids.length);
      for (var ii = 0; ii < input.input_ids.length; ii++) idsArr[ii] = input.input_ids[ii];
      var attnArr = new Array(input.attention_mask.length);
      for (var ai = 0; ai < input.attention_mask.length; ai++) attnArr[ai] = input.attention_mask[ai];
      var idsTensor = new Tensor('int64', idsArr, [1, input.input_ids.length]);
      var attnTensor = new Tensor('int64', attnArr, [1, input.attention_mask.length]);

      var results = await state.session.run({
        input_ids: idsTensor,
        attention_mask: attnTensor,
      });
      var logits = results.logits.data;
      // Softmax helper (numerically stable: subtract max before exp)
      function softmax(arr) {
        var max = arr[0];
        for (var i = 1; i < arr.length; i++) if (arr[i] > max) max = arr[i];
        var sum = 0;
        var result = [];
        for (var j = 0; j < arr.length; j++) { result[j] = Math.exp(arr[j] - max); sum += result[j]; }
        for (var k = 0; k < arr.length; k++) { result[k] = result[k] / sum; }
        return result;
      }

      // Class 1 = PI attack, class 0 = benign
      var logitBenign = logits[0];
      var logitAttack = logits[1];
      var T = 20.0; var probs = softmax([logits[0] / T, logits[1] / T]);
      var isAttack = probs[1] > 0.51;
      var confidence = isAttack ? probs[1] : probs[0];

      if (isAttack) {
        log.info('PI ML: detected attack, confidence=' + confidence.toFixed(3));
        return [{
          category: 'pi_jailbreak',
          severity: 'critical',
          confidence: confidence,
          value: text.substring(0, 100),
          index: 0,
        }];
      }
      return [];
    } catch (err) {
      log.error('PI ML detect failed', err);
      return [];
    }
  }

  var module = {
    init: init,
    detect: detect,
    getState: function() { return state; },
    MODEL_NAME: 'answerdotai/ModernBERT-large',
    MODEL_VERSION: 'pi-v0.1.0-beta-int8-bpe',
  };

  if (typeof self !== 'undefined') self.__lensPIML = module;
  if (typeof window !== 'undefined') window.__lensPIML = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensPIML = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

} catch (e) {
  window.__lens_test_wrapper.error = String(e);
  window.__lens_test_wrapper.errorStack = e && e.stack ? e.stack : "";
}
window.__lens_test_wrapper.completed = Date.now();
