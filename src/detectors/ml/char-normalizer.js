// AegisGate Lens — ml/char-normalizer.js
// Character-level normalizer for the Char CNN-BiLSTM threat detection model.
//
// Port of pkg/ml/normalizer.go from AegisGate Platform v4.4.0 (v11b model).
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

  // Normalize preprocesses text for model input.
  // Steps:
  //   1. Convert to lowercase
  //   2. Strip leading/trailing whitespace
  //   3. Collapse multiple whitespace
  //   4. Truncate to max length (256 chars)
  function normalize(text) {
    if (typeof text !== 'string') return '';
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
    decode: decode
  };

  if (typeof self !== 'undefined') self.__lensCharNormalizer = module;
  if (typeof window !== 'undefined') window.__lensCharNormalizer = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensCharNormalizer = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);