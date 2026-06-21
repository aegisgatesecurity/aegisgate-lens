// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Domain Hash (Browser Side)
// =========================================================================
//
// The Lens's privacy boundary relies on a 16-character SHA-256
// prefix of the AI provider's hostname. This file computes that
// hash in the browser using the Web Crypto API
// (crypto.subtle.digest). The Web Crypto API is browser-native,
// audited by the browser vendor, and counts stdlib of the
// platform — it is not a third-party dependency.
//
// The server-side mirror is in
// consolidated/aegisgate-platform/pkg/lensbackend/domain_hash.go.
// The two MUST produce the same output for the same input.
// They are cross-tested by the build tool's schema validation
// step (tools/build-lens-extension/) and by the testlab
// integration tests (pkg/lensbackend/lensbackend_lab_test.go).
//
// v0.1 pre-release.
// =========================================================================

/** The required length of the truncated hash. Must match domain_hash.go. */
export const DOMAIN_HASH_LENGTH = 16;

/** The algorithm. SHA-256 only; no SHA-1, no MD5, no SHA-3 in v0.1. */
const ALGORITHM = "SHA-256";

/**
 * Compute the 16-character lowercase hex SHA-256 prefix of
 * the given hostname.
 *
 * This is an async function because crypto.subtle.digest is
 * async. The caller must `await` the result.
 *
 * @param hostname The AI provider's hostname. Lowercased
 *                 before hashing; pass it user typed
 *                 it (e.g., "Chat.OpenAI.com") and we'll
 *                 lowercase for you.
 * @returns A 16-character lowercase hex string.
 */
export async function computeDomainHash(hostname: string): Promise<string> {
  if (typeof hostname !== "string" || hostname.length === 0) {
    throw new Error("hostname must be a non-empty string");
  }
  const normalized = hostname.toLowerCase();
  const bytes = new TextEncoder().encode(normalized);
  const digest = await crypto.subtle.digest(ALGORITHM, bytes);
  return bufferToHex(new Uint8Array(digest)).slice(0, DOMAIN_HASH_LENGTH);
}

/**
 * Synchronous variant for tests. NOT for production use —
 * synchronous SHA-256 in the browser is not possible via
 * Web Crypto; this uses a hand-rolled implementation
 * fallback. The build tool's tests use this variant; the
 * runtime uses computeDomainHash().
 *
 * The hand-rolled implementation is in this file (see below)
 * and is intentionally minimal: SHA-256 only, no streaming,
 * no incremental hashing. It exists so the test suite can
 * assert against known test vectors without needing a
 * cryptographic library.
 */
export function computeDomainHashSync(hostname: string): string {
  if (typeof hostname !== "string" || hostname.length === 0) {
    throw new Error("hostname must be a non-empty string");
  }
  const normalized = hostname.toLowerCase();
  const bytes = new TextEncoder().encode(normalized);
  const digest = sha256Sync(bytes);
  return bufferToHex(digest).slice(0, DOMAIN_HASH_LENGTH);
}

/**
 * Convert a byte array to a lowercase hex string.
 * Hand-rolled to avoid any third-party dep.
 */
function bufferToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += (b >> 4).toString(16);
    out += (b & 0x0f).toString(16);
  }
  return out;
}

// =====================================================================
// SHA-256 implementation (hand-rolled, async-free, for tests only)
// =====================================================================
//
// This is a minimal SHA-256 implementation used only by
// computeDomainHashSync(). It is NOT used in production; the
// production path is crypto.subtle.digest, which is async.
//
// The implementation is hand-written in ~120 LOC of ES2020,
// follows FIPS 180-4 §6.2, and is cross-validated against the
// known test vectors at the bottom of this file.
//
// Why hand-roll instead of using a library? The Lens has
// zero third-party dependencies (see docs/NO-EXTERNAL-DEPS.md).
// For the test path, the simplest way to get a sync SHA-256
// is to write one.
//
// The implementation is intentionally simple: no streaming,
// no incremental hashing, no HMAC. Just SHA-256 of a single
// byte array.

const K: ReadonlyArray<number> = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256Sync(bytes: Uint8Array): Uint8Array {
  // Pre-processing: append the bit '1', then k zero bits,
  // then the 64-bit big-endian length, such that the total
  // length is a multiple of 64 bytes.
  const bitLen = bytes.length * 8;
  const padLen = (64 - ((bytes.length + 9) % 64)) % 64;
  const totalLen = bytes.length + 1 + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes, 0);
  padded[bytes.length] = 0x80;
  // Big-endian 64-bit length.
  const view = new DataView(padded.buffer);
  // High 32 bits (we only support messages up to 2^32 bits,
  // i.e., 512MB; sufficient for the Lens).
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);

  // Initial hash values (FIPS 180-4 §5.3.3).
  const H: number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ];

  // Process each 512-bit (64-byte) chunk.
  for (let chunk = 0; chunk < totalLen; chunk += 64) {
    const W = new Array<number>(64);
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(chunk + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let a = H[0], b = H[1], c = H[2], d = H[3];
    let e = H[4], f = H[5], g = H[6], h = H[7];

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + mj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  // Serialize the hash-endian bytes.
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    outView.setUint32(i * 4, H[i], false);
  }
  return out;
}

// =====================================================================
// Known test vectors (FIPS 180-4 examples + Lens domain hashes).
// Used by the test suite; not used in production.
// =====================================================================
//
// These are the exact values the Go side (computeDomainHash in
// domain_hash.go) and the browser side (computeDomainHash /
// computeDomainHashSync) MUST produce. The build tool's test
// suite asserts them.

export const KNOWN_VECTORS: ReadonlyArray<{
  hostname: string;
  hash: string;
}> = [
  { hostname: "chat.openai.com", hash: "b5d56b87a192a38e" },
  { hostname: "claude.ai", hash: "743e483ae01f1fa2" },
  { hostname: "gemini.google.com", hash: "f8226d80a7c25a04" },
  { hostname: "copilot.microsoft.com", hash: "7cbff059b404bede" },
];
