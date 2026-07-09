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

  function readOptIn() {
    return new Promise(function (resolve, reject) {
      var cr = getChrome();
      if (!cr || !cr.storage || !cr.storage.local) {
        reject(new Error('chrome.storage.local not available'));
        return;
      }
      cr.storage.local.get(['opt_in'], function (result) {
        if (cr.runtime && cr.runtime.lastError) {
          reject(new Error(cr.runtime.lastError.message || 'unknown chrome.storage error'));
          return;
        }
        var opt = result && result.opt_in;
        if (!opt) {
          resolve({ enabled: false, lastChangedAt: null, lensVersion: null });
        } else {
          resolve({
            enabled: opt.enabled === true,
            lastChangedAt: opt.last_changed_at || null,
            lensVersion: opt.lens_version || null
          });
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
