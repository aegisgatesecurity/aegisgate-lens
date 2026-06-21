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

  // Ed25519 Public Key (32 bytes, base64-encoded)
  const SIGNING_PUBLIC_KEY_B64 = 'aKzukcm1ElgBZDMlG7IROw12CyjPHfkuKv+Bj8I70+c=';

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
  function findHeaderStart(bytes) {
    // Search for "magic" : "AEGISGATE_LENS_BUNDLE_V1" with flexible whitespace
    // We do this by searching for the value and walking back
    const valueBytes = new TextEncoder().encode(MAGIC_VALUE);
    outer: for (let i = 0; i <= bytes.length - valueBytes.length; i++) {
      for (let j = 0; j < valueBytes.length; j++) {
        if (bytes[i + j] !== valueBytes[j]) continue outer;
      }
      // Found the value. Walk back to find the opening '{' of the JSON object.
      // We need to skip back past: "magic" : "..." but the '{' could be far back
      // if there's a leading comment. For our format, it's right before "magic".
      let k = i - 1;
      while (k >= 0 && bytes[k] !== 123) k--;  // 123 = '{'
      if (k >= 0) return k;
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
    for (let i = 0; i < header.files.length; i++) {
      const fileInfo = header.files[i];
      const fileStart = payloadStart + fileInfo.offset;
      const fileEnd = fileStart + fileInfo.size;
      const fileBytes = bytes.slice(fileStart, fileEnd);
      const fileSha = await sha256(fileBytes);
      if (fileSha !== fileInfo.sha256) {
        throw new Error('File ' + fileInfo.name + ' SHA-256 mismatch');
      }
      const fileText = new TextDecoder('utf-8').decode(fileBytes);
      const fileData = JSON.parse(fileText);
      models.push({ name: fileInfo.name, data: fileData });
    }

    log.info('[AegisGate Lens] Bundle verified: v' + header.bundle_version +
             ' (' + (bytes.length / 1024 / 1024).toFixed(2) + ' MB, ' +
             header.n_files + ' files)');

    return { header: header, models: models };
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
})();
