// AegisGate Lens — popup.js
// Browser action popup. Step 3a: minimal. Shows the opt-in state and
// the lens version. Full settings (facet toggles, threat-intel feed,
// EP transparency) come in 3j.
//
// Includes upgrade CTA to AegisGate Platform.
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

  // v0.1.2 F-2: the canonical storage key for the opt-in state. Was
  // a bare 'opt_in' key that conflicted with the SW's
  // 'aegisgate_lens_opt_in' key. Now unified on the constants.js
  // STORAGE_KEYS.OPT_IN key. The popup still reads storage directly
  // here (F-10 will switch this to a chrome.runtime.sendMessage
  // GET_OPT_IN_STATE call to the SW).
  function getOptInStorageKey() {
    return (typeof globalThis !== 'undefined' && globalThis.__lensConstants &&
            globalThis.__lensConstants.STORAGE_KEYS &&
            globalThis.__lensConstants.STORAGE_KEYS.OPT_IN) ||
            'aegisgate_lens_opt_in';
  }

  function readOptIn() {
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
      banner.style.display = 'block';
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
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onLoad);
  } else {
    onLoad();
  }
})();
