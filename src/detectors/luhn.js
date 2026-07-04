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
