// AegisGate Lens — ml/char-normalizer.js
// Character-level normalizer for the Char CNN-BiLSTM threat detection model.
//
// Port of pkg/ml/normalizer.go from AegisGate Platform v4.5.0 (v13 model).
// Converts raw text into a fixed-length Int32Array suitable for ONNX inference.
//
// Input pipeline:
//   raw text → normalize → truncate/pad → char IDs → [1, 256] int32 tensor
//
// Character vocabulary: 256 Latin-1 characters (0-255).
// Printable ASCII [32-126] mapped directly.
// Latin-1 supplement [128-255] mapped directly.
// Non-printable ASCII and non-Latin-1 characters mapped to UNK token (id=1).
// Padding is done with PAD token (id=0).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var MAX_SEQ_LEN = 256;
  var PAD_ID = 0;
  var UNK_ID = 1;
  var VOCAB_SIZE = 256;  // Latin-1 (0-255)

  // keyWalkReverse maps QWERTY right-shifted keys back to their original
  // position. This is the exact inverse of the keyboardWalkShift transform
  // used in the augmentation engine and the evasion suite.
  // Both use RIGHT shift (a→s, s→d, etc.), so we reverse with LEFT shift
  // (s→a, d→s, etc.). Includes mappings for ; and , (the shifted outputs
  // of l and m), plus uppercase.
  //
  // Ported from:
  //   - Platform: upstream/aegisgate/pkg/scanner/normalize.go (line 127)
  //   - Rampart:  internal/detectors/normalize.go (line 53)
  //
  // Used by reverseKeyboardWalk() for regex-level evasion resistance.
  // NOT applied to ML model input (the model learns to handle obfuscation
  // via training data augmentation). Used by regex facets to catch
  // keyboard-walked evasion like "sjnpef" → "ignore".
  var keyWalkReverse = {
    // Home row (lowercase): s→a, d→s, f→d, g→f, h→g, j→h, k→j, l→k, ;→l
    's': 'a', 'd': 's', 'f': 'd', 'g': 'f', 'h': 'g', 'j': 'h', 'k': 'j', 'l': 'k', ';': 'l',
    // Top row (lowercase): w→q, e→w, r→e, t→r, y→t, u→y, i→u, o→i, p→o
    'w': 'q', 'e': 'w', 'r': 'e', 't': 'r', 'y': 't', 'u': 'y', 'i': 'u', 'o': 'i', 'p': 'o',
    // Bottom row (lowercase): x→z, c→x, v→c, b→v, n→b, m→n, ,→m
    'x': 'z', 'c': 'x', 'v': 'c', 'b': 'v', 'n': 'b', 'm': 'n', ',': 'm',
    // Uppercase (same shifts, uppercase output)
    'S': 'A', 'D': 'S', 'F': 'D', 'G': 'F', 'H': 'G', 'J': 'H', 'K': 'J', 'L': 'K', ':': 'L',
    'W': 'Q', 'E': 'W', 'R': 'E', 'T': 'R', 'Y': 'T', 'U': 'Y', 'I': 'U', 'O': 'I', 'P': 'O',
    'X': 'Z', 'C': 'X', 'V': 'C', 'B': 'V', 'N': 'B', 'M': 'N', '<': 'M'
  };

  // reverseKeyboardWalk shifts each key one position LEFT on QWERTY.
  // This reverses the "keyboard walk right" evasion technique where an
  // attacker shifts each character one key to the right on the keyboard
  // (a→s, s→d, etc.) to evade regex pattern matching.
  //
  // Example: "sjnpef" → "ignore" (each key shifted right on QWERTY).
  //
  // This is a DESTRUCTIVE normalization — it will corrupt normal text
  // that happens to contain shifted characters. Callers should scan
  // BOTH the original text and the reversed variant, not just the
  // reversed version. See normalizeAllVariants().
  function reverseKeyboardWalk(text) {
    if (typeof text !== 'string') return '';
    var result = '';
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (keyWalkReverse.hasOwnProperty(ch)) {
        result += keyWalkReverse[ch];
      } else {
        result += ch;
      }
    }
    return result;
  }

  // decodeHexEscapes converts \xNN escape sequences back to their
  // actual characters. This reverses the hex_escape_encode evasion
  // transform (which encodes every 4th non-space ASCII char as \xNN).
  //
  // Example: "\x61ct \x61s \x61n \x41I" → "act as an AI"
  //
  // This is the JavaScript equivalent of what Platform's multi-layer
  // normalization achieves through its 13+ variants — by seeing the
  // decoded text, regex patterns can match "act as", "ignore", etc.
  // that would otherwise be invisible behind \x escapes.
  function decodeHexEscapes(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/\\x([0-9A-Fa-f]{2})/g, function(_, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }

  // nfkcNormalize applies Unicode NFKC normalization to convert
  // compatibility characters to their canonical forms. This catches
  // fullwidth Unicode evasion (Ｉｇｎｏｒｅ → Ignore), superscripts,
  // ligatures, and other visually-confusable character substitutions.
  //
  // Platform uses NFKC normalization in its CharNormalizer (normalizer.go)
  // before encoding text for ML inference. Lens previously lacked this,
  // causing fullwidth Unicode payloads (V450.UNI.001) to score 0.0023
  // instead of being recognized as adversarial.
  //
  // JavaScript's String.normalize('NFKC') is built-in and O(n).
  function nfkcNormalize(text) {
    if (typeof text !== 'string') return '';
    try {
      return text.normalize('NFKC');
    } catch (e) {
      return text;
    }
  }

  // stripZeroWidth removes zero-width and invisible Unicode characters.
  // NFKC does NOT remove these (they're formatting controls, not
  // compatibility characters). Without this, zero-width evasion
  // (U+200B/U+200C/U+200D between every char) defeats both regex
  // and ML detection. The ML model maps zero-width chars to UNK,
  // diluting the signal. Ported from Platform scanner/normalize.go.
  function stripZeroWidth(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/[\u200B\u200C\u200D\u200E\u200F\u2028\u2029\u202A\u202B\u202C\u202D\u202E\u00AD\uFEFF\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u00A0\u180E]/g, '');
  }

  // normalizeAllVariants returns the original text plus normalized
  // variants for regex scanning. The caller should scan each variant
  // against detection patterns and union the results.
  //
  // This mirrors Platform's NormalizeAllVariants() and Rampart's
  // NormalizeAllVariants() — providing the same evasion-resistant
  // scanning surface in the browser extension.
  //
  // Variants:
  //   1. Original text (as-is)
  //   2. reverseKeyboardWalk (keyboard-walk evasion reversal)
  //   3. NFKC normalization (fullwidth Unicode → ASCII)
  //   4. Hex-escape decoded (\xNN → char)
  //   5. NFKC + hex-escape decoded (combined)
  //   6. NFKC + keyboard-walk reversal (combined)
  //   7. Sliding ROT13 variants (up to 5, partial ROT13 on 4+ char runs)
  //
  // Platform returns 13+ variants. Lens now includes sliding ROT13 which
  // is critical for catching char_delete_vowels edge cases — the model
  // scores ROT13-encoded fragments (e.g. "zbqry" for "model") at >0.99.
  function slidingROT13(text) {
    if (typeof text !== 'string' || text.length < 4) return [];
    // Find runs of 4+ consecutive alphabetic characters
    var runs = [];
    var i = 0;
    while (i < text.length) {
      var ch = text.charCodeAt(i);
      var isLetter = (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122);
      if (isLetter) {
        var start = i;
        while (i < text.length) {
          var c2 = text.charCodeAt(i);
          if ((c2 >= 65 && c2 <= 90) || (c2 >= 97 && c2 <= 122)) {
            i++;
          } else {
            break;
          }
        }
        if (i - start >= 4) {
          runs.push({ start: start, end: i });
        }
      } else {
        i++;
      }
    }
    if (runs.length === 0) return [];

    var variants = [];
    var seen = {};
    for (var r = 0; r < runs.length; r++) {
      var run = runs[r];
      var out = '';
      for (var j = 0; j < text.length; j++) {
        if (j >= run.start && j < run.end) {
          var c = text.charCodeAt(j);
          if (c >= 65 && c <= 90) {
            out += String.fromCharCode((c - 65 + 13) % 26 + 65);
          } else if (c >= 97 && c <= 122) {
            out += String.fromCharCode((c - 97 + 13) % 26 + 97);
          } else {
            out += text[j];
          }
        } else {
          out += text[j];
        }
      }
      if (out !== text && !seen[out]) {
        seen[out] = true;
        variants.push(out);
        if (variants.length >= 5) break;
      }
    }
    return variants;
  }

  function normalizeAllVariants(text) {
    if (typeof text !== 'string') return [text];
    var variants = [text];

    // Zero-width stripping (critical for zero-width evasion transforms)
    var stripped = stripZeroWidth(text);
    if (stripped !== text && stripped !== '') {
      variants.push(stripped);
    }

    // Keyboard-walk reversal
    var kw = reverseKeyboardWalk(text);
    if (kw !== text) variants.push(kw);

    // NFKC normalization (fullwidth → ASCII, compatibility decomposition)
    var nfkc = nfkcNormalize(text);
    if (nfkc !== text && nfkc !== '') {
      variants.push(nfkc);
      // NFKC + keyboard walk
      var nfkcKw = reverseKeyboardWalk(nfkc);
      if (nfkcKw !== nfkc && nfkcKw !== text) variants.push(nfkcKw);
    }

    // Hex-escape decoding (\xNN → char)
    var hexDecoded = decodeHexEscapes(text);
    if (hexDecoded !== text && hexDecoded !== '') {
      variants.push(hexDecoded);
      // Hex-decoded + keyboard walk
      var hexKw = reverseKeyboardWalk(hexDecoded);
      if (hexKw !== hexDecoded && hexKw !== text) variants.push(hexKw);
    }

    // NFKC + hex-escape decoding (combined — catches fullwidth + hex)
    if (nfkc !== text && nfkc !== '') {
      var combined = decodeHexEscapes(nfkc);
      if (combined !== nfkc && combined !== text && combined !== hexDecoded) {
        variants.push(combined);
      }
    }

    // Sliding ROT13 variants (parity with Platform — catches partial ROT13)
    var sliding = slidingROT13(text);
    for (var si = 0; si < sliding.length; si++) {
      if (sliding[si] !== text) variants.push(sliding[si]);
    }

    return variants;
  }

  // Normalize preprocesses text for model input.
  // Steps:
  //   1. Convert to lowercase
  //   2. Strip leading/trailing whitespace
  //   3. Collapse multiple whitespace
  //   4. Truncate to max length (256 chars)
  //
  // Note: This is the ML input normalizer. It does NOT apply
  // keyWalkReverse — the model learns to handle keyboard-walk
  // obfuscation through training data augmentation. The regex
  // scanner uses normalizeAllVariants() instead.
  function normalize(text) {
    if (typeof text !== 'string') return '';
    // NFKC normalization — converts fullwidth Unicode (Ｉ→I), compatibility
    // characters, and other visually-confusable forms to their canonical
    // ASCII equivalents. This mirrors Platform's CharNormalizer which
    // applies NFKC before encoding for ONNX inference.
    // Without this, fullwidth payloads (V450.UNI.001) score ~0.002 instead
    // of being recognized as adversarial — the model only knows Latin-1.
    try {
      text = text.normalize('NFKC');
    } catch (e) { /* normalize not available — skip */ }
    // Lowercase
    text = text.toLowerCase();
    // Strip leading/trailing whitespace
    text = text.trim();
    // Collapse multiple whitespace
    text = text.replace(/\s+/g, ' ');
    // Truncate to MAX_SEQ_LEN (256) characters
    if (text.length > MAX_SEQ_LEN) {
      text = text.substring(0, MAX_SEQ_LEN);
    }
    return text;
  }

  // Encode converts normalized text to a fixed-length Int32Array for model input.
  // Characters are mapped to their ASCII code if in range [32, 126] (printable ASCII),
  // otherwise to UNK_ID. Result is padded to MAX_SEQ_LEN with PAD_ID.
  function encode(text) {
    var normalized = normalize(text);
    var result = new Int32Array(MAX_SEQ_LEN);
    // Int32Array is zero-initialized, so PAD_ID (0) is the default

    for (var i = 0; i < normalized.length && i < MAX_SEQ_LEN; i++) {
      var code = normalized.charCodeAt(i);
      if (code >= 32 && code <= 126) {
        // Printable ASCII → map directly
        result[i] = code;
      } else if (code >= 128 && code <= 255) {
        // Latin-1 supplement → map directly (v9 model uses Latin-1 vocab)
        result[i] = code;
      } else {
        // Non-printable ASCII or non-Latin-1 → UNK
        result[i] = UNK_ID;
      }
    }

    return result;
  }

  // Encode multiple texts into a batch [batch_size, MAX_SEQ_LEN].
  // Returns an object with a flat Int32Array and batch dimensions.
  function encodeBatch(texts) {
    var batchSize = texts.length;
    var flat = new Int32Array(batchSize * MAX_SEQ_LEN);
    for (var i = 0; i < batchSize; i++) {
      var encoded = encode(texts[i]);
      flat.set(encoded, i * MAX_SEQ_LEN);
    }
    return {
      data: flat,
      dims: [batchSize, MAX_SEQ_LEN]
    };
  }

  // Decode reverses the encoding (for debugging/verification only).
  // Not used in production inference.
  function decode(ids) {
    var result = '';
    for (var i = 0; i < ids.length; i++) {
      var id = ids[i];
      if (id === PAD_ID) continue; // Skip padding
      if (id === UNK_ID) {
        result += '\uFFFD'; // Replacement character
        continue;
      }
      if (id >= 32 && id <= 126) {
        result += String.fromCharCode(id);
      } else if (id >= 128 && id <= 255) {
        // Latin-1 supplement
        result += String.fromCharCode(id);
      }
    }
    return result;
  }

  var module = {
    MAX_SEQ_LEN: MAX_SEQ_LEN,
    PAD_ID: PAD_ID,
    UNK_ID: UNK_ID,
    VOCAB_SIZE: VOCAB_SIZE,
    normalize: normalize,
    encode: encode,
    encodeBatch: encodeBatch,
    decode: decode,
    reverseKeyboardWalk: reverseKeyboardWalk,
    normalizeAllVariants: normalizeAllVariants,
    decodeHexEscapes: decodeHexEscapes,
    nfkcNormalize: nfkcNormalize,
    stripZeroWidth: stripZeroWidth,
    slidingROT13: slidingROT13,
    keyWalkReverse: keyWalkReverse
  };

  if (typeof self !== 'undefined') self.__lensCharNormalizer = module;
  if (typeof window !== 'undefined') window.__lensCharNormalizer = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensCharNormalizer = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);