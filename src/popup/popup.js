// AegisGate Lens — popup.js
// Browser action popup. Step 3a: minimal. Shows the opt-in state and
// the lens version. Full settings (facet toggles, threat-intel feed,
// EP transparency) come in 3j.
//
// Includes upgrade CTA to AegisGate Platform.
//
// v0.1.2 F-2: the opt-in storage key is now the canonical
// STORAGE_KEYS.OPT_IN key (aegisgate_lens_opt_in). welcome.js,
// popup.js, and background.js all read/write the same key + shape.
//
// v0.1.2 F-10: the popup now asks the SW for the opt-in state via
// chrome.runtime.sendMessage(GET_OPT_IN_STATE) instead of reading
// chrome.storage.local directly. The SW is the single source of
// truth; the popup gets a consistent view regardless of SW sleep
// state. There is a defensive fallback to a direct storage read if
// the SW doesn't respond within 500ms (e.g., SW is being reactivated,
// or the extension is being reloaded).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

/**
 * @module LensPopup
 * @type {{init: () => void, version: string}}
 */
(function () {
  'use strict';

  function getChrome() {
    return (typeof chrome !== 'undefined') ? chrome : null;
  }

  // v0.1.2 F-2: the canonical storage key for the opt-in state.
  // Used as a fallback in readOptInViaStorage() if the SW doesn't
  // respond. Centralized here so a typo doesn't silently desync.
  // (The constants module is loaded by the content script; on the
  // popup page it isn't always available at load time, so we fall
  // back to the literal string. The test suite asserts the literal
  // matches constants.js.)
  function getOptInStorageKey() {
    return (typeof globalThis !== 'undefined' && globalThis.__lensConstants &&
            globalThis.__lensConstants.STORAGE_KEYS &&
            globalThis.__lensConstants.STORAGE_KEYS.OPT_IN) ||
            'aegisgate_lens_opt_in';
  }

  // v0.1.2 F-10: the canonical message version. Mirrors
  // api/messages.js MESSAGE_VERSION. Centralized as a constant
  // so the message envelope and the SW handler agree.
  function getMessageVersion() {
    return (typeof globalThis !== 'undefined' && globalThis.__lensConstants &&
            globalThis.__lensConstants.STORAGE_SCHEMA_VERSION) ||
            '0.1.1';
  }

  // v0.1.2 F-10: how long to wait for the SW to respond to
  // GET_OPT_IN_STATE before falling back to a direct storage read.
  // 500ms is short enough to feel instant to a user opening the
  // popup and long enough to survive a SW reactivation (which
  // MV3 can do on the first message after idle). Tuned via
  // ad-hoc testing in Chrome 130+; 250ms was too aggressive
  // (false fallbacks), 1000ms was too slow (visible delay).
  var SW_MESSAGE_TIMEOUT_MS = 500;

  // v0.1.2 F-10: the primary path. Send GET_OPT_IN_STATE to the SW
  // and resolve with the response. The SW is the single source of
  // truth for the opt-in state.
  //
  // Returns a Promise<{ enabled, lastChangedAt, lensVersion }>.
  // Resolves with a { enabled: false, ... } default if the SW
  // responds with a malformed payload (defensive).
  // Rejects only on hard errors (no chrome.runtime, no sendMessage).
  function readOptInViaMessage() {
    return new Promise(function (resolve, reject) {
      var cr = getChrome();
      if (!cr || !cr.runtime || typeof cr.runtime.sendMessage !== 'function') {
        reject(new Error('chrome.runtime.sendMessage not available'));
        return;
      }
      try {
        cr.runtime.sendMessage(
          {
            type: 'GET_OPT_IN_STATE',
            version: getMessageVersion(),
            payload: {}
          },
          function (response) {
            // chrome.runtime.lastError is set if the SW isn't
            // available (e.g., during reactivation). The caller
            // (readOptIn) catches this and falls back to storage.
            if (cr.runtime && cr.runtime.lastError) {
              reject(new Error('SW sendMessage error: ' +
                (cr.runtime.lastError.message || 'unknown')));
              return;
            }
            if (!response || typeof response !== 'object') {
              resolve({ enabled: false, lastChangedAt: null, lensVersion: null });
              return;
            }
            if (response.type !== 'OPT_IN_STATE' || !response.payload) {
              resolve({ enabled: false, lastChangedAt: null, lensVersion: null });
              return;
            }
            var p = response.payload;
            // The SW response shape (v0.1.2 F-2):
            //   { opted_in: bool,        // backwards-compat alias
            //     enabled: bool,
            //     last_changed_at: number|null,
            //     lens_version: string|null }
            resolve({
              enabled: p.enabled === true || p.opted_in === true,
              lastChangedAt: typeof p.last_changed_at === 'number' ? p.last_changed_at : null,
              lensVersion: typeof p.lens_version === 'string' ? p.lens_version : null
            });
          }
        );
      } catch (e) {
        reject(e);
      }
    });
  }

  // v0.1.2 F-10: the fallback path. Read the canonical storage
  // key directly. Used when the SW doesn't respond to
  // GET_OPT_IN_STATE within SW_MESSAGE_TIMEOUT_MS (e.g., during
  // SW reactivation or when the extension is being reloaded).
  //
  // Returns a Promise<{ enabled, lastChangedAt, lensVersion }>.
  // Rejects only on hard errors (no chrome.storage).
  function readOptInViaStorage() {
    return new Promise(function (resolve, reject) {
      var cr = getChrome();
      if (!cr || !cr.storage || !cr.storage.local) {
        reject(new Error('chrome.storage.local not available'));
        return;
      }
      var key = getOptInStorageKey();
      cr.storage.local.get([key], function (result) {
        if (cr.runtime && cr.runtime.lastError) {
          reject(new Error(cr.runtime.lastError.message || 'unknown chrome.storage error'));
          return;
        }
        var opt = result && result[key];
        if (!opt) {
          resolve({ enabled: false, lastChangedAt: null, lensVersion: null });
        } else if (typeof opt === 'boolean') {
          // v0.1.0-beta backwards-compat: bare boolean. Treat as enabled.
          resolve({ enabled: opt === true, lastChangedAt: null, lensVersion: null });
        } else if (typeof opt === 'object') {
          resolve({
            enabled: opt.enabled === true,
            lastChangedAt: typeof opt.last_changed_at === 'number' ? opt.last_changed_at : null,
            lensVersion: typeof opt.lens_version === 'string' ? opt.lens_version : null
          });
        } else {
          resolve({ enabled: false, lastChangedAt: null, lensVersion: null });
        }
      });
    });
  }

  // v0.1.2 F-10: race the message path against a timeout. If the
  // SW doesn't respond within SW_MESSAGE_TIMEOUT_MS, fall back to
  // the direct storage read. The race is best-effort: whichever
  // resolves first wins. We never call both in parallel because
  // a popup that hangs the SW (even briefly) is a worse user
  // experience than a slightly stale read.
  function readOptIn() {
    return new Promise(function (resolve, reject) {
      var resolved = false;
      var safeResolve = function (val) {
        if (resolved) return;
        resolved = true;
        resolve(val);
      };
      var safeReject = function (err) {
        if (resolved) return;
        resolved = true;
        reject(err);
      };
      // Try the message path
      readOptInViaMessage().then(safeResolve, function () {
        // SW didn't respond or responded with an error.
        // Fall back to direct storage read.
        readOptInViaStorage().then(safeResolve, safeReject);
      });
      // Belt-and-suspenders timeout. If both paths hang (e.g., the
      // message path takes >500ms and the storage read also takes
      // >500ms), reject so the popup can show an error state.
      setTimeout(function () {
        if (resolved) return;
        // Try one more time with the storage path
        readOptInViaStorage().then(safeResolve, function (err) {
          safeReject(new Error('readOptIn timed out (SW + storage both unresponsive): ' +
            (err && err.message ? err.message : 'unknown')));
        });
      }, SW_MESSAGE_TIMEOUT_MS);
    });
  }

  function setStatus(text) {
    var el = document.getElementById('status-value');
    if (el) el.textContent = text;
  }

  function setTelemetry(text) {
    var el = document.getElementById('telemetry-value');
    if (el) el.textContent = text;
  }

  function setUpgradeBanner() {
    // Show upgrade banner for Lens users (free tier)
    var banner = document.getElementById('upgrade-banner');
    if (banner) {
      banner.classList.remove('hidden');
    }
  }

  function onLoad() {
    readOptIn().then(function (opt) {
      if (opt.enabled) {
        setStatus('Active');
        setTelemetry('Opted in');
      } else {
        setStatus('Detect-only');
        document.getElementById('status') && document.getElementById('status').classList.add('off');
        setTelemetry('Off (opt-in available)');
      }
      // Show upgrade CTA for all Lens users
      setUpgradeBanner();
    }).catch(function (err) {
      setStatus('Error');
      setTelemetry('Storage unavailable');
      console.error('[AegisGate Lens popup] readOptIn failed:', err);
    });
    // v0.1.4: bind the indicator toggle. Independent of opt-in state
    // so the UI is usable even when storage is partially broken.
    bindShowIndicator();
  }

  // -----------------------------------------------------------------
  // v0.1.4: "Hide Lens active indicator" toggle.
  //
  // Storage key is the canonical STORAGE_KEYS.SHOW_INDICATOR. We
  // hardcode the literal as a fallback (the constants module isn't
  // always available at popup load time per the v0.1.2 F-2 comment).
  // -----------------------------------------------------------------
  function getShowIndicatorStorageKey() {
    return (typeof globalThis !== 'undefined' && globalThis.__lensConstants &&
            globalThis.__lensConstants.STORAGE_KEYS &&
            globalThis.__lensConstants.STORAGE_KEYS.SHOW_INDICATOR) ||
            'aegisgate_lens_show_indicator';
  }

  // Read the current setting. Resolves to { showIndicator: bool }.
  // Default true (show indicator) on any error or missing key.
  function readShowIndicator() {
    return new Promise(function (resolve) {
      try {
        var cr = getChrome();
        if (!cr || !cr.storage || !cr.storage.local) {
          resolve({ showIndicator: true });
          return;
        }
        cr.storage.local.get([getShowIndicatorStorageKey()], function (result) {
          try {
            var k = getShowIndicatorStorageKey();
            if (result && Object.prototype.hasOwnProperty.call(result, k)) {
              resolve({ showIndicator: result[k] !== false });
            } else {
              resolve({ showIndicator: true });
            }
          } catch (e) { resolve({ showIndicator: true }); }
        });
      } catch (e) { resolve({ showIndicator: true }); }
    });
  }

  // Persist the toggle value. Resolves to { ok: bool }.
  function setShowIndicator(value) {
    return new Promise(function (resolve) {
      try {
        var cr = getChrome();
        if (!cr || !cr.storage || !cr.storage.local) {
          resolve({ ok: false, reason: 'no chrome.storage' });
          return;
        }
        var k = getShowIndicatorStorageKey();
        cr.storage.local.set({ [k]: value === false ? false : true }, function () {
          if (cr.runtime && cr.runtime.lastError) {
            resolve({ ok: false, reason: cr.runtime.lastError.message || 'unknown' });
            return;
          }
          resolve({ ok: true });
        });
      } catch (e) { resolve({ ok: false, reason: e.message || 'unknown' }); }
    });
  }

  // Apply the toggle state to the checkbox in the popup UI.
  function applyShowIndicatorToUI(value) {
    var cb = document.getElementById('show-indicator-toggle');
    if (cb) cb.checked = value !== false;
  }

  // v0.1.4: read the toggle on popup open, set the checkbox, and
  // wire the change listener to persist. Defensive against test
  // mocks that return elements without addEventListener.
  function bindShowIndicator() {
    var cb = document.getElementById('show-indicator-toggle');
    if (!cb) return;
    readShowIndicator().then(function (s) {
      applyShowIndicatorToUI(s.showIndicator);
    });
    if (typeof cb.addEventListener === 'function') {
      cb.addEventListener('change', function () {
        var desired = cb.checked;
        setShowIndicator(desired).then(function (r) {
          if (!r.ok) {
            // Roll back the UI on persistence failure so the displayed
            // state matches the persisted state.
            applyShowIndicatorToUI(!desired);
          }
        });
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onLoad);
  } else {
    onLoad();
  }
})();
