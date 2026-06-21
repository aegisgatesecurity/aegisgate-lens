// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Luhn Algorithm (Credit Card Validation)
// =========================================================================
//
// The Luhn algorithm is the checksum that credit card numbers
// use to detect typos. It is NOT a security mechanism — anyone
// can construct a Luhn-valid number — but it's a strong signal
// that a sequence of digits is probably a credit card number
// and not, e.g., a phone number or a tracking ID.
//
// The Lens uses Luhn to filter the regex matches for the
// "pii_credit_card" category. A regex match that doesn't pass
// Luhn is discarded (it's almost certainly a false positive,
// e.g., a 16-digit tracking number or an order ID).
//
// The implementation is the standard Luhn algorithm:
//
//   1. Starting from the rightmost digit, double every second
//      digit. If the doubled value is > 9, subtract 9.
//   2. Sum all the digits.
//   3. The number is Luhn-valid if the sum is divisible by 10.
//
// v0.1 pre-release.
// =========================================================================

/**
 * Check whether a string of digits is a Luhn-valid number.
 *
 * Non-digit characters are stripped before the check. The
 * caller is expected to have already extracted the digit
 * sequence (e.g., via the credit card regex).
 *
 * @param s The candidate string (e.g., "4111-1111-1111-1111"
 *          or "4111111111111111"). Non-digit characters are
 *          ignored.
 * @returns true if the digit sequence passes the Luhn check.
 */
export function isLuhnValid(s: string): boolean {
  if (typeof s !== "string" || s.length === 0) {
    return false;
  }
  // Strip non-digit characters.
  let digits = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x30 && c <= 0x39) {
      digits += s[i];
    }
  }
  if (digits.length < 2) {
    return false; // Luhn requires at least 2 digits.
  }
  // The Luhn algorithm: starting from the RIGHTMOST digit,
  // double every second digit. "Every second" means positions
  // 1, 3, 5, ... from the right (the rightmost itself is
  // position 0 and is NOT doubled).
  //
  // This is the well-known "Mod 10" algorithm. The Wikipedia
  // example "4242 4242 4242 4242" is Luhn-valid; the previous
  // (buggy) implementation had the wrong index parity and
  // rejected every real credit card number.
  let sum = 0;
  let shouldDouble = false; // Rightmost (position 0) is NOT doubled.
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 0x30;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Canonical credit card test numbers from the major networks.
 * These are the test card numbers published in the network's
 * documentation; they pass Luhn but are not real cards.
 *
 * Used by the test suite. NOT used in production.
 */
export const TEST_CARDS: ReadonlyArray<{ network: string; number: string }> = [
  { network: "Visa (test)", number: "4111-1111-1111-1111" },
  { network: "Visa (test, 13-digit)", number: "4222-2222-2222-2" },
  { network: "Mastercard (test)", number: "5555-5555-5555-4444" },
  { network: "Mastercard (2-series test)", number: "5105-1051-0510-5100" },
  { network: "Amex (test)", number: "3782-822463-10005" },
  { network: "Discover (test)", number: "6011-1111-1111-1117" },
  { network: "JCB (test)", number: "3530-1113-3330-0000" },
  { network: "Diners Club (test)", number: "3056-9309-0259-04" },
];

/**
 * A few well-known Luhn-INVALID numbers used for negative tests.
 * These are real-looking digit sequences that do NOT pass the
 * Luhn check (e.g., transposed digits, off-by-one errors).
 */
export const INVALID_CARDS: ReadonlyArray<string> = [
  "4111-1111-1111-1112", // Last digit wrong.
  "5555-5555-5555-4445", // Last digit wrong.
  "3782-822463-10006",   // Last digit wrong.
  "1234-5678-9012-3456", // Sequential digits, not Luhn-valid.
];
