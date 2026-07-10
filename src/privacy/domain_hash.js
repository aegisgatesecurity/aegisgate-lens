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
  /**
   * @type {import("./typedefs").LensDomainHash}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensDomainHash = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
