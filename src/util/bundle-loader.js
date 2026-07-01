/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Single-File Bundle Loader
   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens =
    (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens || {};
  const log = NS.logger || console;

  // Ed25519 Public Key (32 bytes, base64-encoded).
  // Override via NS.util.bundleLoader._setSigningPublicKey(b64) for testing.
  let SIGNING_PUBLIC_KEY_B64 = 'aKzukcm1ElgBZDMlG7IROw12CyjPHfkuKv+Bj8I70+c=';

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
      const e3 = lookup[b64.charCodeAt(i + 2)];
      const e4 = lookup[b64.charCodeAt(i + 3)];
      bytes[p++] = (e1 << 2) | (e2 >> 4);
      if (b64.charCodeAt(i + 2) !== 61) bytes[p++] = ((e2 & 15) << 4) | (e3 >> 2);
      if (b64.charCodeAt(i + 3) !== 61) bytes[p++] = ((e3 & 3) << 6) | e4;
    }
    return bytes;
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
  // The first '{' in the byte array IS the root, but we need to verify it
  // by walking back, because a deeply-nested bundle could in principle
  // have a sibling '{' before the root (e.g., a string field containing
  // literal '{' chars). In practice the JSON we sign never has that, but
  // the depth check is the safe approach.
  //
  // History: the original implementation (v0.1) used a naive "walk back
  // to nearest '{'" which broke on bundles where the magic value is
  // pushed deep into the header by alphabetical key sorting. See
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
   * The magic value is the value of a top-level "magic" key. We start
   * inside the string literal `"AEGISGATE_LENS_BUNDLE_V1"`. We need to
   * walk back past:
   *   - the opening '"' of the value string
   *   - the "magic" key string
   *   - the ':' separator
   *   - any preceding key-value pairs (and their nested arrays/objects)
   * until we find the root '{'.
   *
   * We track JSON nesting depth by counting unmatched closing brackets
   * (}, ]) we pass going backwards. Each closing bracket we pass means
   * its matching opener is also behind us, so the root is one bracket
   * "deeper". When we hit an opening bracket and depth_close == 0, we
   * found the root.
   *
   * @param {Uint8Array} bytes - the bundle bytes
   * @param {number} magicPos - position of the first byte of MAGIC_VALUE
   * @returns {number} index of the root '{', or -1 if not found
   */
  function findRootOpenBrace(bytes, magicPos) {
    // Step 1: walk back to the opening '"' of the magic value string.
    // We're inside the string at magicPos; the opening '"' is somewhere
    // before magicPos (skipping the closing '"' immediately before).
    let k = magicPos - 1;
    while (k >= 0 && bytes[k] !== 34 /* " */) k--;
    if (k < 0) return -1;
    // k is now the position of the opening '"' of the value string.
    // Step 2: walk back from k-1, tracking string-state and bracket depth.
    let depthClose = 0;  // count of unmatched }, ] we've passed
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
      // Not in a string.
      if (b === 34 /* " */) {
        inString = true;
        i--;
        continue;
      }
      if (b === 125 /* } */ || b === 93 /* ] */) {
        depthClose++;
      } else if (b === 123 /* { */ || b === 91 /* [ */) {
        if (depthClose === 0) {
          // This is the root opener.
          return i;
        }
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

    const publicKey = base64Decode(SIGNING_PUBLIC_KEY_B64);
    const isValid = await ed25519Verify(publicKey, bundleNoSig, signature);
    if (!isValid) {
      throw new Error('Bundle signature verification FAILED - bundle may be tampered');
    }

    const payloadStart = headerEnd;
    const payloadEnd = payloadStart + header.total_payload_size;
    const payload = bytes.slice(payloadStart, payloadEnd);
    const actualPayloadSha = await sha256(payload);
    if (actualPayloadSha !== header.payload_sha256) {
      throw new Error('Payload SHA-256 mismatch - bundle is corrupted');
    }

    const models = [];
    const rawFiles = {};  // name → raw Uint8Array (for binary files like .onnx)
    for (let i = 0; i < header.files.length; i++) {
      const fileInfo = header.files[i];
      const fileStart = payloadStart + fileInfo.offset;
      const fileEnd = fileStart + fileInfo.size;
      const fileBytes = bytes.slice(fileStart, fileEnd);
      const fileSha = await sha256(fileBytes);
      if (fileSha !== fileInfo.sha256) {
        throw new Error('File ' + fileInfo.name + ' SHA-256 mismatch');
      }
      // Binary files (e.g., .onnx) keep their raw bytes; JSON files parse as text.
      // Plain text files (e.g., vocab.txt) keep as raw text.
      if (fileInfo.name.endsWith('.onnx') || fileInfo.name.endsWith('.bin')) {
        rawFiles[fileInfo.name] = fileBytes;
        // Still expose a placeholder object so v0.1 callers see this file.
        models.push({ name: fileInfo.name, data: { _binary: true, size: fileInfo.size } });
      } else if (fileInfo.name.endsWith('.json')) {
        const fileText = new TextDecoder('utf-8').decode(fileBytes);
        const fileData = JSON.parse(fileText);
        models.push({ name: fileInfo.name, data: fileData });
      } else {
        // Plain text file (vocab.txt, merges.txt, etc.). Keep raw bytes
        // accessible for callers that need the text (tokenizer can re-decode),
        // and also store the decoded text in models for legacy callers.
        const fileText = new TextDecoder('utf-8').decode(fileBytes);
        rawFiles[fileInfo.name] = fileBytes;
        models.push({ name: fileInfo.name, data: fileText });
      }
    }

    log.info('[AegisGate Lens] Bundle verified: v' + header.bundle_version +
             ' (' + (bytes.length / 1024 / 1024).toFixed(2) + ' MB, ' +
             header.n_files + ' files)');

    return { header: header, models: models, rawFiles: rawFiles };
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
    _findHeaderStart: findHeaderStart,
    _findJsonEnd: findJsonEnd,
  };

  // Compat alias: model-loader.js (v0.2) reads NS.util.bundleLoader.
  // The v0.1 export surface (NS.bundleLoader) is preserved above for
  // backwards compatibility with v0.1 callers.
  NS.util = NS.util || {};
  NS.util.bundleLoader = NS.bundleLoader;
  // Allow tests to override the signing public key. Production builds
  // never call this; the default key is hardcoded above.
  NS.util.bundleLoader._setSigningPublicKey = function (b64) {
    SIGNING_PUBLIC_KEY_B64 = b64;
  };
})();
