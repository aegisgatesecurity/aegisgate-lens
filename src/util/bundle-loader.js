/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Single-File Bundle Loader
   v0.2 (multi-key support added 2026-06-30)
   =========================================================================

   CHANGES from v0.1:
   - Now supports MULTIPLE Ed25519 signing public keys (a key ring)
   - Each bundle's header `signing_public_key` field identifies which key
     signed it; the loader tries each key in the ring until one verifies
   - The original single-key (PI bundle, key id lens-v02-2026-06-29) is
     preserved as the first key
   - A second key (toxicity bundle, key id lens-v02-c6c3ab5a) is added
   - Future bundles can add new keys without breaking old ones

   This is BACKWARD COMPATIBLE: the existing PI bundle's signature still
   validates against the original key, no re-sign required.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens =
    (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens || {};
  const log = NS.logger || console;

  // Ed25519 Public Key Ring.
  // Each entry: { id: <signing_pub_key_id from header>, b64: <32-byte raw public key, base64> }
  // A bundle is valid if its header.signing_public_key matches the
  // raw-bytes form of one of these keys, AND signature verifies under that key.
  //
  // IMPORTANT: When adding a new key, also update bundle-registry.js with
  // the bundle's signing_pub_key_id (it identifies which key to use).
  const SIGNING_KEY_RING = Object.freeze([
    // PI bundle key (v0.2.0-rc1, generated 2026-06-29, shipped in vendor/bundles)
    { id: 'lens-v02-2026-06-29', b64: 'aKzukcm1ElgBZDMlG7IROw12CyjPHfkuKv+Bj8I70+c=' },
    // Toxicity bundle key (v0.2.0, generated 2026-06-30, lens-v02-c6c3ab5a)
    { id: 'lens-v02-c6c3ab5a',    b64: 'LdOjF1LXqqfUHB8yfI2WanpRvi1kaugKMWJ32dfMfQU=' },
  ]);

  // Backward-compat: the v0.1 single-key variable is preserved as an alias
  // to the FIRST key in the ring (the PI key). v0.1 callers that read
  // SIGNING_PUBLIC_KEY_B64 directly will see the PI key, matching the v0.1
  // behavior of bundle verification.
  let SIGNING_PUBLIC_KEY_B64 = SIGNING_KEY_RING[0].b64;

  function base64Decode(b64) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const lookup = new Uint8Array(256);
    for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
    const len = b64.length;
    let bufferLength = (len * 3) / 4;
    if (b64[len - 1] === '=') bufferLength--;
    if (b64[len - 2] === '=') bufferLength--;
    const bytes = new Uint8Array(bufferLength);
    let p = 0;
    for (let i = 0; i < len; i += 4) {
      const e1 = lookup[b64.charCodeAt(i)];
      const e2 = lookup[b64.charCodeAt(i + 1)];
      const e3 = (b64.charCodeAt(i + 2) === 61) ? 0 : lookup[b64.charCodeAt(i + 2)];
      const e4 = (b64.charCodeAt(i + 3) === 61) ? 0 : lookup[b64.charCodeAt(i + 3)];
      bytes[p++] = (e1 << 2) | (e2 >> 4);
      if (b64.charCodeAt(i + 2) !== 61) bytes[p++] = ((e2 & 15) << 4) | (e3 >> 2);
      if (b64.charCodeAt(i + 3) !== 61) bytes[p++] = ((e3 & 3) << 6) | e4;
    }
    return bytes;
  }

  // Convert raw 32-byte public key to base64 (for comparison with header.signing_public_key)
  function rawToBase64(raw) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    let i = 0;
    for (; i + 2 < raw.length; i += 3) {
      const b1 = raw[i], b2 = raw[i + 1], b3 = raw[i + 2];
      result += chars[b1 >> 2];
      result += chars[((b1 & 3) << 4) | (b2 >> 4)];
      result += chars[((b2 & 15) << 2) | (b3 >> 6)];
      result += chars[b3 & 63];
    }
    if (i < raw.length) {
      const b1 = raw[i];
      result += chars[b1 >> 2];
      if (i + 1 < raw.length) {
        const b2 = raw[i + 1];
        result += chars[((b1 & 3) << 4) | (b2 >> 4)];
        result += chars[(b2 & 15) << 2];
        result += '=';
      } else {
        result += chars[(b1 & 3) << 4];
        result += '==';
      }
    }
    return result;
  }

  async function ed25519Verify(publicKey, message, signature) {
    const key = await crypto.subtle.importKey(
      'raw', publicKey, { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify']
    );
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
  }

  async function sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map(function (b) { return b.toString(16).padStart(2, '0'); })
      .join('');
  }

  // The magic value we search for (with optional whitespace flexibility)
  const MAGIC_VALUE = 'AEGISGATE_LENS_BUNDLE_V1';

  // Find the header by searching for the magic value in the bytes.
  // Returns the index of the opening '{' of the JSON header.
  //
  // The magic value is always a top-level key in the JSON header. To find
  // the ROOT '{' (not a nested '{' inside the files array), we walk back
  // from the magic value while tracking JSON nesting depth: count unmatched
  // '}' and ']' (delimiters that close ahead of us) and '[' and '{'
  // (delimiters that open ahead of us). When we hit an opener with
  // depth_close == 0, that's the root.
  //
  // History: the original implementation used a naive "walk back to
  // nearest '{'" which broke on bundles where the magic value is pushed
  // deep into the header by alphabetical key sorting. See
  // plans/AEGISGATE-LENS-V03-CRITICAL-BUNDLE-PARSER-BUG-2026-06-30.md.
  function findHeaderStart(bytes) {
    const valueBytes = new TextEncoder().encode(MAGIC_VALUE);
    outer: for (let i = 0; i <= bytes.length - valueBytes.length; i++) {
      for (let j = 0; j < valueBytes.length; j++) {
        if (bytes[i + j] !== valueBytes[j]) continue outer;
      }
      // Found the magic value at position i. Walk back to find the root '{'.
      return findRootOpenBrace(bytes, i);
    }
    return -1;
  }

  /**
   * Walk back from a position inside the magic string and find the index
   * of the ROOT '{' of the JSON object that contains the magic key.
   *
   * @param {Uint8Array} bytes - the bundle bytes
   * @param {number} magicPos - position of the first byte of MAGIC_VALUE
   * @returns {number} index of the root '{', or -1 if not found
   */
  function findRootOpenBrace(bytes, magicPos) {
    // Step 1: walk back to the opening '"' of the magic value string.
    let k = magicPos - 1;
    while (k >= 0 && bytes[k] !== 34 /* " */) k--;
    if (k < 0) return -1;
    // Step 2: walk back from k-1, tracking string-state and bracket depth.
    let depthClose = 0;
    let inString = false;
    let i = k - 1;
    while (i >= 0) {
      const b = bytes[i];
      if (inString) {
        if (b === 34 /* " */) {
          // Check for escaped quote (preceded by odd number of backslashes).
          let bs = 0;
          for (let j = i - 1; j >= 0 && bytes[j] === 92 /* \ */; j--) bs++;
          if (bs % 2 === 0) inString = false;
        }
        i--;
        continue;
      }
      if (b === 34 /* " */) {
        inString = true;
        i--;
        continue;
      }
      if (b === 125 /* } */ || b === 93 /* ] */) {
        depthClose++;
      } else if (b === 123 /* { */ || b === 91 /* [ */) {
        if (depthClose === 0) return i;
        depthClose--;
      }
      i--;
    }
    return -1;
  }

  // Find the end of a JSON object starting at startIdx.
  function findJsonEnd(bytes, startIdx) {
    let depth = 0;
    let inString = false;
    let escape = false;
    for (let i = startIdx; i < bytes.length; i++) {
      const b = bytes[i];
      if (escape) { escape = false; continue; }
      if (inString) {
        if (b === 92) escape = true;
        else if (b === 34) inString = false;
        continue;
      }
      if (b === 34) inString = true;
      else if (b === 123) depth++;
      else if (b === 125) {
        depth--;
        if (depth === 0) return i + 1;
      }
    }
    return -1;
  }

  // Find the signing public key in the key ring that matches the bundle's
  // header field. Returns the raw 32 bytes if found, null if not in the
  // ring.
  //
  // Two header formats exist in the wild:
  //   NEW (v0.2 standard):
  //     header.signing_public_key (raw 32 bytes, hex-encoded)
  //   OLD (legacy, pre-multi-key, used by the toxicity bundle):
  //     header.signing_pub_key_b64 (raw 32 bytes, base64-encoded)
  //
  // The check tries both fields. The ring key comparison is done in
  // canonical hex form to avoid base64 padding ambiguity.
  function findKeyForBundle(header) {
    // Build the canonical hex form of the bundle's claimed public key,
    // accepting either the new or the old header field.
    let headerPubHex = null;
    if (typeof header.signing_public_key === 'string' && /^[0-9a-fA-F]{64}$/.test(header.signing_public_key)) {
      // New format: already hex
      headerPubHex = header.signing_public_key.toLowerCase();
    } else if (typeof header.signing_pub_key_b64 === 'string') {
      // Old format: base64 — decode and re-encode as hex
      try {
        const raw = base64Decode(header.signing_pub_key_b64);
        if (raw && raw.length === 32) {
          headerPubHex = Array.from(raw)
            .map(function (b) { return b.toString(16).padStart(2, '0'); })
            .join('');
        }
      } catch (e) {
        // Malformed base64 — fall through, headerPubHex stays null
      }
    }
    if (!headerPubHex) return null;
    for (let i = 0; i < SIGNING_KEY_RING.length; i++) {
      const ringRaw = base64Decode(SIGNING_KEY_RING[i].b64);
      const ringHex = Array.from(ringRaw)
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
      if (ringHex === headerPubHex) {
        return { id: SIGNING_KEY_RING[i].id, raw: ringRaw };
      }
    }
    return null;
  }

  async function parseBundle(bundleBytes) {
    const bytes = new Uint8Array(bundleBytes);
    const bundleNoSig = bytes.slice(0, bytes.length - 64);
    const signature = bytes.slice(bytes.length - 64);

    const headerStart = findHeaderStart(bytes);
    if (headerStart < 0) {
      throw new Error('Bundle header not found (missing magic value: ' + MAGIC_VALUE + ')');
    }

    const headerEnd = findJsonEnd(bytes, headerStart);
    if (headerEnd < 0) {
      throw new Error('Bundle header is malformed (no closing brace)');
    }

    const headerBytes = bytes.slice(headerStart, headerEnd);
    const headerText = new TextDecoder('utf-8').decode(headerBytes);
    let header;
    try {
      header = JSON.parse(headerText);
    } catch (e) {
      throw new Error('Bundle header is not valid JSON: ' + e.message);
    }

    if (header.magic !== MAGIC_VALUE) {
      throw new Error('Invalid bundle magic: ' + header.magic);
    }

    // Find the right key in the ring based on header.signing_public_key
    const keyInfo = findKeyForBundle(header);
    if (!keyInfo) {
      // Build a helpful error message that includes whichever field was set.
      const claimedHex = header.signing_public_key
        || (header.signing_pub_key_b64 ? '(base64 form: ' + header.signing_pub_key_b64 + ')' : '(none)');
      const ringIds = SIGNING_KEY_RING.map(function (k) { return k.id; }).join(', ');
      throw new Error(
        'No signing key in key ring matches bundle. ' +
        'Bundle claims public key: ' + claimedHex + '. ' +
        'Ring has keys: ' + ringIds + '. ' +
        'Bundle may be from an untrusted source or signed with an un-registered key.'
      );
    }

    const isValid = await ed25519Verify(keyInfo.raw, bundleNoSig, signature);
    if (!isValid) {
      throw new Error('Bundle signature verification FAILED for key ' + keyInfo.id + ' - bundle may be tampered');
    }

    const payloadStart = headerEnd;
    const payloadEnd = payloadStart + header.total_payload_size;
    const payload = bytes.slice(payloadStart, payloadEnd);
    const actualPayloadSha = await sha256(payload);
    if (actualPayloadSha !== header.payload_sha256) {
      throw new Error('Payload SHA-256 mismatch - bundle is corrupted');
    }

    const models = [];
    const rawFiles = {};
    for (let i = 0; i < header.files.length; i++) {
      const fileInfo = header.files[i];
      const fileStart = payloadStart + fileInfo.offset;
      const fileEnd = fileStart + fileInfo.size;
      const fileBytes = bytes.slice(fileStart, fileEnd);
      const fileSha = await sha256(fileBytes);
      if (fileSha !== fileInfo.sha256) {
        throw new Error('File ' + fileInfo.name + ' SHA-256 mismatch');
      }
      if (fileInfo.name.endsWith('.onnx') || fileInfo.name.endsWith('.bin')) {
        rawFiles[fileInfo.name] = fileBytes;
        models.push({ name: fileInfo.name, data: { _binary: true, size: fileInfo.size } });
      } else if (fileInfo.name.endsWith('.json')) {
        // Only files that explicitly have a .json extension are JSON.
        // Other text files (e.g., vocab.txt, merges.txt, tokenizer.model
        // for some architectures) are kept as raw text under rawFiles
        // and exposed as a string in the models list.
        const fileText = new TextDecoder('utf-8').decode(fileBytes);
        const fileData = JSON.parse(fileText);
        models.push({ name: fileInfo.name, data: fileData });
      } else {
        // Plain text file (vocab.txt, etc.). Keep raw bytes accessible
        // for callers that need the text (tokenizer can re-decode), but
        // also store the decoded text in models so legacy callers see it.
        const fileText = new TextDecoder('utf-8').decode(fileBytes);
        rawFiles[fileInfo.name] = fileBytes;
        models.push({ name: fileInfo.name, data: fileText });
      }
    }

    log.info('[AegisGate Lens] Bundle verified: v' + header.bundle_version +
             ' (' + (bytes.length / 1024 / 1024).toFixed(2) + ' MB, ' +
             header.n_files + ' files, key=' + keyInfo.id + ')');

    return { header: header, models: models, rawFiles: rawFiles, keyId: keyInfo.id };
  }

  function reconstructModels(parsed) {
    const byName = {};
    for (let i = 0; i < parsed.models.length; i++) {
      byName[parsed.models[i].name] = parsed.models[i].data;
    }

    const config = byName['ensemble_config.json'] || {
      model_names: ['lr', 'mlp_a', 'mlp_b', 'mlp_c', 'mlp_d'],
      threshold: 0.85,
      strategy: 'average',
    };

    const models = [];
    for (let i = 0; i < config.model_names.length; i++) {
      const name = config.model_names[i];
      const cfg = byName[name + '_config.json'];
      const vocab = byName[name + '_vocabulary.json'];
      const idf = byName[name + '_idf.json'];
      if (!cfg || !vocab || !idf) {
        throw new Error('Missing artifacts for model ' + name);
      }
      if (cfg.type === 'lr') {
        const coefs = byName[name + '_coefficients.json'];
        models.push({
          type: 'lr', vocabulary: vocab, idf: idf, coefficients: coefs, config: cfg,
        });
      } else if (cfg.type === 'mlp') {
        const weights = [];
        const biases = [];
        for (let j = 0; j < cfg.n_layers; j++) {
          weights.push(byName[name + '_weights_' + j + '.json']);
          biases.push(byName[name + '_biases_' + j + '.json']);
        }
        models.push({
          type: 'mlp', vocabulary: vocab, idf: idf, config: cfg, weights: weights, biases: biases,
        });
      } else {
        throw new Error('Unknown model type: ' + cfg.type);
      }
    }
    return { models: models, config: config };
  }

  async function loadBundle(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch bundle: ' + response.status);
    const buffer = await response.arrayBuffer();
    return await parseBundle(buffer);
  }

  NS.bundleLoader = {
    loadBundle: loadBundle,
    reconstructModels: reconstructModels,
    parseBundle: parseBundle,
    _base64Decode: base64Decode,
    _rawToBase64: rawToBase64,
    _findHeaderStart: findHeaderStart,
    _findJsonEnd: findJsonEnd,
    _keyRing: SIGNING_KEY_RING,
    _findKeyForBundle: findKeyForBundle,
  };

  NS.util = NS.util || {};
  NS.util.bundleLoader = NS.bundleLoader;
  // Allow tests to override the FIRST signing public key (backward compat).
  // For multi-key testing, use _setKeyRing() instead.
  NS.util.bundleLoader._setSigningPublicKey = function (b64) {
    SIGNING_PUBLIC_KEY_B64 = b64;
    // Also rebuild the ring so the new key is the primary
    const newRing = [{ id: 'test-override', b64: b64 }];
    for (let i = 1; i < SIGNING_KEY_RING.length; i++) {
      newRing.push(SIGNING_KEY_RING[i]);
    }
    // Mutate the ring contents in place (since the const ref is frozen by Object.freeze)
    for (let i = 0; i < newRing.length; i++) {
      SIGNING_KEY_RING[i] = newRing[i];
    }
  };
  NS.util.bundleLoader._setKeyRing = function (newRing) {
    for (let i = 0; i < newRing.length; i++) {
      SIGNING_KEY_RING[i] = newRing[i];
    }
  };
  NS.util.bundleLoader._getKeyRing = function () {
    return SIGNING_KEY_RING.map(function (k) { return { id: k.id, b64: k.b64 }; });
  };
})();
