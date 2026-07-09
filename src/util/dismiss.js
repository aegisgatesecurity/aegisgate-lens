// AegisGate Lens — util/dismiss.js
// 24-hour dismissal storage + opt-in false-positive report.
//
// Per the BANNER-DESIGN-SPEC, when the user dismisses a banner
// they have two options:
//   1. "Submit & dismiss" — opt-in to sending ONE anonymous,
//      sanitized FP report to the AegisGate TI engine. The
//      domain_hash, category, pattern_id, reason, ml_score,
//      and timestamp are sent. NO prompt text, NO URLs, NO
//      page content, NO user identifier.
//   2. "Just dismiss (private)" — local-only suppression.
//      No data is sent. The detection is suppressed for 24h
//      on the same domain + same pattern.
//
// v0.1.1 item 25: storage now uses chrome.storage.session (not
// chrome.storage.local). Session storage is automatically cleared
// when the browser restarts, which is a defense-in-depth check on
// top of the 24h TTL. This matches the user's intent ("dismiss
// for this session") and reduces the chance of a stale entry
// surviving a long period of browser inactivity. The 24h TTL
// is still enforced by gc() (entry.expires_at), so session
// storage is purely belt-and-suspenders.
//
// Per docs/ARCHITECTURE-v0.1.0-BETA.md, the Lens is opt-in by
// default. "Submit & dismiss" is the only way the user can opt
// in to telemetry. Until they opt in, NO data is sent.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                       (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                       null;

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var STORAGE_KEY = (constants && constants.STORAGE_KEYS && constants.STORAGE_KEYS.DISMISSALS) || 'aegisgate_lens_dismissals';
  var TTL_MS = (constants && constants.DISMISS_TTL_MS) || (24 * 60 * 60 * 1000);  // 24h (from constants.js)
  var SCHEMA_VERSION = (constants && constants.STORAGE_SCHEMA_VERSION) || '0.1.0-beta';

  // The 3 reason codes. These match the design spec.
  var REASON_TEST_DATA = 'test_data';
  var REASON_OWN_DATA = 'own_data';
  var REASON_LEGITIMATE = 'legitimate_use_case';

  // Resolve the storage area to use. v0.1.1 item 25: prefer
  // chrome.storage.session (auto-cleared on browser restart),
  // fall back to chrome.storage.local for older Chrome versions
  // (pre-Chrome 116). chrome.storage.session is available since
  // Chrome 102, so the fallback is purely defensive.
  function getStorageArea() {
    if (typeof chrome === 'undefined' || !chrome.storage) return null;
    if (chrome.storage.session) return chrome.storage.session;
    if (chrome.storage.local) return chrome.storage.local;
    return null;
  }

  // Build a stable key from (domainHash, category, patternId).
  // The patternId is included so the same category with different
  // patterns (e.g. AWS vs GitHub secrets) can be dismissed
  // independently. We do NOT include the match value (privacy).
  function buildKey(domainHash, category, patternId) {
    if (!domainHash || !category) return null;
    var pid = patternId || '_nopattern_';
    return domainHash + ':' + category + ':' + pid;
  }

  // Get the current dismissals from chrome.storage.local.
  // Returns {} if storage is unavailable or empty.
  function getAll() {
    return new Promise(function (resolve) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage ||
            !getStorageArea()) {
          resolve({});
          return;
        }
        getStorageArea().get([STORAGE_KEY], function (result) {
          if (chrome.runtime && chrome.runtime.lastError) {
            var err = chrome.runtime.lastError.message;
            if (err.includes('Extension context invalidated')) {
              log.warn('storage get failed: Extension context invalidated (extension reloaded)');
              resolve({});
            } else {
              log.warn('storage get failed: ' + err);
              resolve({});
            }
            return;
          }
          resolve(result[STORAGE_KEY] || {});
        });
      } catch (e) {
        if (e.message && e.message.includes('Extension context invalidated')) {
          log.warn('getAll() caught: Extension context invalidated');
          resolve({});
        } else {
          log.error('getAll() threw', e);
          resolve({});
        }
      }
    });
  }

  // Save the dismissals map back to chrome.storage.local.
  function saveAll(dismissals) {
    return new Promise(function (resolve, reject) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage ||
            !getStorageArea()) {
          resolve(false);
          return;
        }
        getStorageArea().set({ [STORAGE_KEY]: dismissals }, function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            var err = chrome.runtime.lastError.message;
            if (err.includes('Extension context invalidated')) {
              log.warn('storage set failed: Extension context invalidated (extension reloaded)');
              resolve(false);
            } else {
              log.warn('storage set failed: ' + err);
              resolve(false);
            }
            return;
          }
          resolve(true);
        });
      } catch (e) {
        if (e.message && e.message.includes('Extension context invalidated')) {
          log.warn('saveAll() caught: Extension context invalidated');
          resolve(false);
        } else {
          log.error('saveAll() threw', e);
          reject(e);
        }
      }
    });
  }

  // Garbage-collect expired entries.
  function gc(dismissals) {
    var now = Date.now();
    var kept = {};
    var keys = Object.keys(dismissals);
    for (var i = 0; i < keys.length; i++) {
      var entry = dismissals[keys[i]];
      if (entry && typeof entry.expires_at === 'number' &&
          entry.expires_at > now) {
        kept[keys[i]] = entry;
      }
    }
    return kept;
  }

  // Check if a (domainHash, category, patternId) is currently
  // dismissed. Returns the entry object (with reason, dismissed_at,
  // expires_at) or null.
  async function isDismissed(domainHash, category, patternId) {
    var key = buildKey(domainHash, category, patternId);
    if (!key) return null;
    var all = await getAll();
    all = gc(all);
    // Save back if we GC'd anything
    if (Object.keys(all).length !== Object.keys(all).length) {
      await saveAll(all);
    }
    return all[key] || null;
  }

  // Dismiss a detection. If `reason` is non-null, this is the
  // opt-in path (the caller should ALSO send the FP report via
  // sendFPReport). If `reason` is null, this is the private path.
  // `fpReportData` is the sanitized report (only set on opt-in).
  async function dismiss(domainHash, category, patternId, reason, fpReportData) {
    try {
      var key = buildKey(domainHash, category, patternId);
      if (!key) return false;
      var all = await getAll();
      all = gc(all);
      var now = Date.now();
      all[key] = {
        dismissed_at: now,
        expires_at: now + TTL_MS,
        reason: reason || null,
        // Only stored on opt-in path; otherwise null
        opt_in: reason ? true : false,
        // Sanitized FP report payload (no text). Only present on
        // the opt-in path. The caller is responsible for actually
        // sending this to the backend.
        fp_report: fpReportData || null
      };
      var ok = await saveAll(all);
      if (ok) {
        if (reason) {
          log.info('dismissed (opt-in) ' + key + ' reason=' + reason);
        } else {
          log.info('dismissed (private) ' + key);
        }
      }
      return ok;
    } catch (err) {
      if (err.message && err.message.includes('Extension context invalidated')) {
        log.warn('dismiss() caught: Extension context invalidated');
        return false;
      }
      log.error('dismiss() threw', err);
      return false;
    }
  }

  // Get the FP report payload for a detection event. The caller
  // is responsible for sending this to the backend (via the SW
  // in 3g, which is the only network path).
  //
  // Per the privacy doc, the FP report contains ONLY:
  //   - domain_hash (SHA-256 prefix of hostname, 16 hex chars)
  //   - category (e.g. "pii_credit_card")
  //   - pattern_id (e.g. "credit_card_visa_v1")
  //   - reason (test_data | own_data | legitimate_use_case)
  //   - ml_score, ml_threshold, ml_model_version (only for ML)
  //   - lens_event_version, lens_version, timestamp
  //
  // It does NOT contain: prompt text, URLs, page content, user IDs.
  function buildFPReport(event, domainHash, reason) {
    if (!event) return null;
    return {
      lens_event_version: SCHEMA_VERSION,
      timestamp: Math.floor(Date.now() / 1000),  // Unix seconds
      domain_hash: domainHash,
      facet: event.facet,
      category: event.category,
      severity: event.severity,
      pattern_id: event.matches && event.matches[0] ?
                  (event.matches[0].cardType ? event.category + '_' + event.matches[0].cardType + '_v1' : event.category + '_v1') :
                  event.category + '_v1',
      reason: reason,
      ml_score: event.ml_score,
      ml_threshold: event.ml_threshold || null,
      ml_model_version: event.ml_model_version || null,
      lens_version: SCHEMA_VERSION
    };
  }

  // Clear all dismissals. Used by the popup (3j) for the
  // "Reset dismissals" button.
  async function clearAll() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage ||
          !getStorageArea()) return false;
      return new Promise(function (resolve) {
        getStorageArea().remove([STORAGE_KEY], function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            var err = chrome.runtime.lastError.message;
            if (err.includes('Extension context invalidated')) {
              log.warn('storage remove failed: Extension context invalidated (extension reloaded)');
              resolve(false);
            } else {
              log.warn('storage remove failed: ' + err);
              resolve(false);
            }
            return;
          }
          log.info('cleared all dismissals');
          resolve(true);
        });
      });
    } catch (err) {
      if (err.message && err.message.includes('Extension context invalidated')) {
        log.warn('clearAll() caught: Extension context invalidated');
        return false;
      }
      log.error('clearAll() threw', err);
      return false;
    }
  }

  // List all active (non-expired) dismissals. For the popup UI.
  async function listActive() {
    var all = await getAll();
    return gc(all);
  }

  var module = {
    STORAGE_KEY: STORAGE_KEY,
    TTL_MS: TTL_MS,
    REASON_TEST_DATA: REASON_TEST_DATA,
    REASON_OWN_DATA: REASON_OWN_DATA,
    REASON_LEGITIMATE: REASON_LEGITIMATE,
    isDismissed: isDismissed,
    dismiss: dismiss,
    buildFPReport: buildFPReport,
    clearAll: clearAll,
    listActive: listActive,
    buildKey: buildKey
  };

  if (typeof self !== 'undefined') self.__lensDismiss = module;
  if (typeof window !== 'undefined') window.__lensDismiss = module;
  /**
   * @type {import("./typedefs").LensDismiss}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensDismiss = module;
  if (typeof globalThis !== 'undefined' && globalThis.__lensConstants) module.__lensConstants = globalThis.__lensConstants;
})(typeof globalThis !== 'undefined' ? globalThis : this);
