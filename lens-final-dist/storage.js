/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - chrome.storage Wrapper (v0.2.0)
   =========================================================================

   Abstraction over chrome.storage.sync (small, synced) and
   chrome.storage.local (large, per-device).

   v0.2 changes:
     - Adds fp_opt_in_prompt_seen (for FP telemetry UX)
     - Same shape as v0.1; lens_event_version field remains '0.2.0'
     - Returns Promises (compatible with both callback and Promise stubs)
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const MAX_LOCAL_AUDIT_ENTRIES = 1000;
  const KEY_OPT_IN = 'lens.optIn.enabled';

  /**
   * @typedef {'info'|'low'|'medium'|'high'|'critical'} Severity
   * @typedef {'pii_email'|'pii_phone'|'pii_ssn'|'pii_credit_card'|'secret_api_key'|'source_code'} Category
   */

  /**
   * Read opt-in state from chrome.storage.sync. Returns a Promise that
   * resolves to the state object (or { enabled: false } if unset).
   * Compatible with both callback and Promise chrome.storage APIs.
   */
  function getOptInState(cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      if (cb) cb(null);
      return Promise.resolve(null);
    }
    try {
      const result = chrome.storage.sync.get(KEY_OPT_IN);
      if (result && typeof result.then === 'function') {
        return result.then((r) => {
          const stored = r && r[KEY_OPT_IN];
          const v = stored || { enabled: false };
          if (cb) cb(v);
          return v;
        });
      }
    } catch (_) { /* fall through to callback */ }
    // Fallback: callback API
    return new Promise((resolve) => {
      chrome.storage.sync.get(KEY_OPT_IN, (result) => {
        const stored = result && result[KEY_OPT_IN];
        const v = stored || { enabled: false };
        if (cb) cb(v);
        resolve(v);
      });
    });
  }

  /**
   * Set opt-in state in chrome.storage.sync. Returns a Promise.
   */
  function setOptInState(state, cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      if (cb) cb();
      return Promise.resolve();
    }
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      enabled: !!state.enabled,
      opted_in_at: state.opted_in_at || (state.enabled ? now : null),
      last_changed_at: now,
      lens_version: '0.2.0',
    };
    try {
      const r = chrome.storage.sync.set({ [KEY_OPT_IN]: payload });
      if (r && typeof r.then === 'function') {
        return r.then(() => { if (cb) cb(); });
      }
    } catch (_) {}
    return new Promise((resolve) => {
      chrome.storage.sync.set({ [KEY_OPT_IN]: payload }, () => {
        if (cb) cb();
        resolve();
      });
    });
  }

  /**
   * Get the bearer token from chrome.storage.local. Returns a Promise.
   * Per Privacy Policy §8.1: per-device, not synced.
   */
  function getBearerToken(cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb(null);
      return Promise.resolve(null);
    }
    try {
      const r = chrome.storage.local.get('lens.api.bearerToken');
      if (r && typeof r.then === 'function') {
        return r.then((result) => {
          const t = (result && result['lens.api.bearerToken']) || null;
          if (cb) cb(t);
          return t;
        });
      }
    } catch (_) {}
    return new Promise((resolve) => {
      chrome.storage.local.get('lens.api.bearerToken', (result) => {
        const t = (result && result['lens.api.bearerToken']) || null;
        if (cb) cb(t);
        resolve(t);
      });
    });
  }

  function setBearerToken(token, cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb();
      return Promise.resolve();
    }
    try {
      const r = token
        ? chrome.storage.local.set({ 'lens.api.bearerToken': token })
        : chrome.storage.local.remove('lens.api.bearerToken');
      if (r && typeof r.then === 'function') {
        return r.then(() => { if (cb) cb(); });
      }
    } catch (_) {}
    return new Promise((resolve) => {
      const op = token
        ? (cb2) => chrome.storage.local.set({ 'lens.api.bearerToken': token }, cb2)
        : (cb2) => chrome.storage.local.remove('lens.api.bearerToken', cb2);
      op(() => { if (cb) cb(); resolve(); });
    });
  }

  /**
   * Append a detection to the local audit log. Returns a Promise.
   * Caps at MAX_LOCAL_AUDIT_ENTRIES (F-04 mitigation).
   * Compatible with both callback and Promise chrome.storage APIs.
   */
  function appendAuditLog(entry, cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb();
      return Promise.resolve();
    }
    // v0.1 test compat: 'lens.local_audit' (underscore). v0.2 also accepts 'lens.localAudit'.
    return _storageGet(['lens.localAudit', 'lens.local_audit']).then((result) => {
      const log = (result && (result['lens.localAudit'] || result['lens.local_audit'])) || [];
      log.push(entry);
      const pruned = log.length > MAX_LOCAL_AUDIT_ENTRIES
        ? log.slice(log.length - MAX_LOCAL_AUDIT_ENTRIES)
        : log;
      return _storageSet({
        'lens.localAudit': pruned,
        'lens.local_audit': pruned,
      }).then(() => { if (cb) cb(); });
    });
  }

  function getAuditLog(cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb([]);
      return Promise.resolve([]);
    }
    return _storageGet(['lens.localAudit', 'lens.local_audit']).then((result) => {
      const v = (result && (result['lens.localAudit'] || result['lens.local_audit'])) || [];
      if (cb) cb(v);
      return v;
    });
  }

  /** Internal: chrome.storage.local.get that returns Promise (regardless of stub style). */
  function _storageGet(key) {
    return new Promise((resolve) => {
      try {
        const r = chrome.storage.local.get(key);
        if (r && typeof r.then === 'function') {
          r.then(resolve);
          return;
        }
      } catch (_) {}
      chrome.storage.local.get(key, (r) => resolve(r));
    });
  }

  /** Internal: chrome.storage.local.set that returns Promise. */
  function _storageSet(data) {
    return new Promise((resolve) => {
      try {
        const r = chrome.storage.local.set(data);
        if (r && typeof r.then === 'function') {
          r.then(resolve);
          return;
        }
      } catch (_) {}
      chrome.storage.local.set(data, () => resolve());
    });
  }

  /** v0.2: get/set FP-telemetry opt-in (separate from main telemetry opt-in). */
  function getFPOptIn(cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb(null);
      return Promise.resolve(null);
    }
    return _storageGet(['lens.fpTelemetry.enabled', 'lens.fpOptInPromptSeen']).then((result) => {
      const v = {
        enabled: !!(result && result['lens.fpTelemetry.enabled']),
        promptSeen: !!(result && result['lens.fpOptInPromptSeen']),
      };
      if (cb) cb(v);
      return v;
    });
  }

  function setFPOptIn(opts, cb) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb();
      return Promise.resolve();
    }
    const payload = {};
    if (opts.enabled !== undefined) payload['lens.fpTelemetry.enabled'] = !!opts.enabled;
    if (opts.promptSeen !== undefined) payload['lens.fpOptInPromptSeen'] = !!opts.promptSeen;
    return _storageSet(payload).then(() => { if (cb) cb(); });
  }

  NS.storage = {
    getOptInState,
    setOptInState,
    getBearerToken,
    setBearerToken,
    appendAuditLog,
    getAuditLog,
    getFPOptIn,
    setFPOptIn,
    MAX_LOCAL_AUDIT_ENTRIES,
    KEY_OPT_IN,
  };
})();
