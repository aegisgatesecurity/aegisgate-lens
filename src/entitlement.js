// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens — Entitlement Verifier ("Lens for Business", Phase 4a)
// =========================================================================
//
// Verifies Platform-signed entitlement attestations locally, offline.
// Design: research/LENS-ENTITLEMENT-DESIGN-2026-11-26.md — Platform mints
// a signed EntitlementAttestation (ECDSA P-256, same key infrastructure
// as IOC gossip bundles); it is delivered (a) riding the IOC pull
// response ("entitlement" field) or (b) as a static attestation JSON in
// MDM managed storage ("licenseKey" — bootstrap/fallback). One verifier,
// two delivery paths; the freshest valid attestation wins.
//
// Cryptography: WebCrypto ECDSA P-256 with SHA-256. The attestation's
// signature is ASN.1 DER (Go encoding); WebCrypto expects raw r||s, so
// this module converts. The canonical payload is reproduced byte-exactly
// from the received wire JSON (fields in Go's marshal order, times taken
// verbatim, HTML-escaped like Go's encoding/json) — proven against a
// Go-generated fixture (test/unit/fixtures/entitlement-fixture.json).
//
// Business features degrade at expiresAt + 72h grace (ratified design).
// Consumer users are unaffected: no managed config, no pull, no license.
// =========================================================================

var ENTITLEMENT = (function () {
  'use strict';

  var GRACE_MS = 72 * 60 * 60 * 1000; // 72h grace past expiresAt (ratified)
  var STORAGE_KEY = 'aegisgate_lens_entitlement';

  var state = {
    attestation: null, // most recent VALID attestation (wire shape)
    verified: false,   // signature verified for current attestation
    source: null       // 'pull' | 'managed'
  };

  // --- Canonical payload (MUST byte-match Go EntitlementAttestation.Payload) ---

  function goEscape(s) {
    // Go's encoding/json escapes <, >, & by default (HTML escaping).
    return s.replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
  }

  function buildPayload(att) {
    // Field order mirrors the Go struct (json.Marshal is field-order
    // stable). Times are used VERBATIM from the wire — Go RFC3339Nano
    // strings round-trip unchanged, so byte-equality holds.
    var obj = {
      v: att.v,
      serial: att.serial,
      tenantId: att.tenantId,
      seatId: att.seatId,
      tier: att.tier
    };
    if (att.features && att.features.length) {
      obj.features = att.features;
    }
    obj.issuedAt = att.issuedAt;
    obj.expiresAt = att.expiresAt;
    obj.publicKey = {
      algorithm: att.publicKey.algorithm,
      keyId: att.publicKey.keyId,
      value: att.publicKey.value
    };
    obj.signature = { algorithm: '', keyId: '', value: '' };
    return goEscape(JSON.stringify(obj));
  }

  // --- DER (ASN.1 SEQUENCE of two INTEGERs) -> raw r||s (64 bytes) ---

  function derToRaw(der) {
    if (der.length < 8 || der[0] !== 0x30) return null;
    var idx = 2; // skip SEQUENCE header (assume short-form length < 128)
    if (der[1] & 0x80) idx = 2 + (der[1] & 0x7f);
    function readInt() {
      if (der[idx] !== 0x02) return null;
      idx++;
      var len = der[idx]; idx++;
      if (len & 0x80) return null; // long-form lengths unsupported (never produced)
      var bytes = der.slice(idx, idx + len);
      idx += len;
      // Strip leading zero padding
      var i = 0;
      while (i < bytes.length - 1 && bytes[i] === 0) i++;
      bytes = bytes.slice(i);
      while (bytes.length < 32) { // left-pad to 32
        var padded = new Uint8Array(32);
        padded.set(bytes, 32 - bytes.length);
        bytes = padded;
      }
      return bytes;
    }
    var r = readInt();
    var s = readInt();
    if (!r || !s) return null;
    var raw = new Uint8Array(64);
    raw.set(r, 0);
    raw.set(s, 32);
    return raw;
  }

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // --- Verification ---

  function isWellFormed(att) {
    return !!(att && att.v === 1 && att.tenantId && att.tier &&
              att.issuedAt && att.expiresAt &&
              att.publicKey && att.publicKey.value &&
              att.signature && att.signature.value);
  }

  function withinValidity(att, nowMs) {
    var issued = Date.parse(att.issuedAt);
    var expires = Date.parse(att.expiresAt);
    if (isNaN(issued) || isNaN(expires)) return false;
    if (nowMs < issued) return false;          // not yet valid
    if (nowMs > expires + GRACE_MS) return false; // beyond grace
    return true;
  }

  // verifyAttestation: crypto verification only (signature over payload).
  // Returns Promise<boolean>.
  function verifyAttestation(att) {
    if (!isWellFormed(att)) return Promise.resolve(false);
    var payload = buildPayload(att);
    var data = new TextEncoder().encode(payload);
    var sigRaw;
    try {
      sigRaw = derToRaw(b64ToBytes(att.signature.value));
    } catch (e) {
      return Promise.resolve(false);
    }
    if (!sigRaw) return Promise.resolve(false);
    var pubBytes;
    try {
      pubBytes = b64ToBytes(att.publicKey.value);
    } catch (e) {
      return Promise.resolve(false);
    }
    if (pubBytes.length !== 65 || pubBytes[0] !== 0x04) return Promise.resolve(false);

    return crypto.subtle
      .importKey('raw', pubBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      .then(function (key) {
        return crypto.subtle.verify(
          { name: 'ECDSA', hash: { name: 'SHA-256' } },
          key,
          sigRaw,
          data
        );
      })
      .catch(function () { return false; });
  }

  // --- Module state + storage ---

  function storageSet(key, value) {
    return new Promise(function (resolve) {
      try {
        chrome.storage.local.set({ [key]: value }, function () { resolve(); });
      } catch (e) { resolve(); }
    });
  }

  function storageGet(key) {
    return new Promise(function (resolve) {
      try {
        chrome.storage.local.get(key, function (items) {
          resolve((items && items[key]) || null);
        });
      } catch (e) { resolve(null); }
    });
  }

  // ingest: accept a candidate attestation (from the IOC pull response
  // or MDM managed config). If it verifies and is newer than the cached
  // one, it becomes the active entitlement. Returns whether the
  // business features are currently unlocked.
  function ingest(att, source) {
    if (!att) return Promise.resolve(false);
    return verifyAttestation(att).then(function (ok) {
      if (!ok) return isUnlocked();
      var now = Date.now();
      if (!withinValidity(att, now)) return isUnlocked();
      var cached = state.attestation;
      var newer = !cached ||
        Date.parse(att.issuedAt) >= Date.parse(cached.issuedAt) ||
        (source === 'pull' && state.source !== 'pull');
      if (newer) {
        state.attestation = att;
        state.verified = true;
        state.source = source;
        storageSet(STORAGE_KEY, att);
      }
      return isUnlocked();
    });
  }

  // ingestWire: accept a raw JSON string (MDM licenseKey carries the
  // attestation JSON exported from GET /api/v1/entitlement).
  function ingestWire(jsonStr, source) {
    if (!jsonStr || typeof jsonStr !== 'string') return Promise.resolve(false);
    try {
      return ingest(JSON.parse(jsonStr), source);
    } catch (e) {
      return Promise.resolve(false);
    }
  }

  // isUnlocked: synchronous business-feature check against the cached,
  // verified attestation (validity window + grace enforced).
  function isUnlocked() {
    var att = state.attestation;
    if (!att || !state.verified) return false;
    return withinValidity(att, Date.now());
  }

  function hasFeature(feature) {
    if (!isUnlocked() || !state.attestation) return false;
    var feats = state.attestation.features || [];
    // Empty features list = tier default set (all business features).
    if (feats.length === 0) return true;
    for (var i = 0; i < feats.length; i++) {
      if (feats[i] === feature) return true;
    }
    return false;
  }

  // init: restore cached entitlement, then ingest the MDM licenseKey
  // bootstrap (if present). Returns whether business features are on.
  function init(managed) {
    return storageGet(STORAGE_KEY).then(function (cached) {
      if (cached) {
        state.attestation = cached;
        state.verified = true; // was verified before caching
        state.source = 'cached';
      }
      if (managed && managed.licenseKey) {
        return ingestWire(managed.licenseKey, 'managed');
      }
      return isUnlocked();
    });
  }

  return {
    ingest: ingest,
    ingestWire: ingestWire,
    isUnlocked: isUnlocked,
    hasFeature: hasFeature,
    init: init,
    // test hooks
    _buildPayload: buildPayload,
    _derToRaw: derToRaw,
    _setState: function (att, verified, source) {
      state.attestation = att; state.verified = verified; state.source = source;
    },
    _getState: function () { return state; }
  };
})();

// Export: browser service-worker/global (like ioc-pull.js) + CommonJS for tests.
if (typeof self !== 'undefined') {
  self.__aegisgateEntitlement = ENTITLEMENT;
}
if (typeof globalThis !== 'undefined') {
  globalThis.__aegisgateEntitlement = ENTITLEMENT;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ENTITLEMENT;
}
