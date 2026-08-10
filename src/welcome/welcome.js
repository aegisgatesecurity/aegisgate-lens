// AegisGate Lens — welcome.js
// First-install welcome page. Loaded by welcome.html.
//
// Two buttons: "Opt in" and "Dismiss". Both close the welcome tab and
// persist the user's choice. The choice is stored in chrome.storage.local
// (on-device; never synced off-device) per the privacy policy.
//
// v0.1.2 F-2: the storage key is now STORAGE_KEYS.OPT_IN (aegisgate_lens_opt_in)
// — the same canonical key the SW and popup use. Previously welcome.js wrote
// to a bare 'opt_in' key while background.js read from
// 'aegisgate_lens_opt_in'; the two states never synced. The fix unifies
// on a single nested-object shape { enabled, last_changed_at, lens_version }.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

/**
 * @module LensWelcome
 * @type {{init: () => void, version: string}}
 */
(function () {
  'use strict';

  function getLogger() {
    return (typeof self !== 'undefined' && self.__lensLogger) ||
           (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
           null;
  }

  function getChrome() {
    return (typeof chrome !== 'undefined') ? chrome : null;
  }

  // The canonical storage key for the user's threat-intel opt-in state.
  // Per v0.1.2 F-2, this is the same key the SW and popup use, so the
  // three modules see one consistent opt-in state. Centralized here so
  // a typo in one place doesn't silently desync the state.
  // (The constants module is loaded by the content script; on the
  // welcome page it isn't always available at load time, so we fall
  // back to the literal string. The test suite asserts the literal
  // matches constants.js.)
  var OPT_IN_KEY = (typeof globalThis !== 'undefined' && globalThis.__lensConstants &&
                    globalThis.__lensConstants.STORAGE_KEYS &&
                    globalThis.__lensConstants.STORAGE_KEYS.OPT_IN) ||
                    'aegisgate_lens_opt_in';

  // v0.1.4: read the manifest version at runtime so the welcome
  // page auto-updates on every install. The manifest's "version" field
  // is the CWS-required semver (e.g., "0.1.0" for v0.1.0/v0.1.1/v0.1.2/v0.1.3).
  // We display the marketing version (e.g., "v0.1.4") by mapping the
  // semver -> marketing version via a small lookup. If the lookup fails,
  // we fall back to the semver as-is.
  function getMarketingVersion() {
    try {
      var cr = getChrome();
      if (!cr || !cr.runtime || !cr.runtime.getManifest) return 'v0.1.4';
      var manifest = cr.runtime.getManifest();
      var semver = manifest && manifest.version ? manifest.version : '0.1.0';
      // Map the CWS semver to the marketing version. Update this table
      // when a new marketing version ships.
      var SEMVER_TO_MARKETING = {
        '0.1.0': 'v0.1.4',
        '0.3.0': 'v0.3.0'
      };
      return SEMVER_TO_MARKETING[semver] || ('v' + semver);
    } catch (e) {
      return 'v0.1.4';
    }
  }

  function persistChoice(enabled) {
    return new Promise(function (resolve, reject) {
      var cr = getChrome();
      if (!cr || !cr.storage || !cr.storage.local) {
        reject(new Error('chrome.storage.local not available'));
        return;
      }
      var payload = {
        // v0.1.2 F-2: use the canonical STORAGE_KEYS.OPT_IN key (was 'opt_in').
        // The shape is unchanged: nested { enabled, last_changed_at, lens_version }.
        [OPT_IN_KEY]: {
          enabled: enabled,
          last_changed_at: Math.floor(Date.now() / 1000),
          lens_version: getMarketingVersion()
        }
      };
      cr.storage.local.set(payload, function () {
        if (cr.runtime && cr.runtime.lastError) {
          reject(new Error(cr.runtime.lastError.message || 'unknown chrome.storage error'));
          return;
        }
        resolve();
      });
    });
  }

  function closeWelcome() {
    var cr = getChrome();
    if (cr && cr.tabs && typeof cr.tabs.getCurrent === 'function') {
      cr.tabs.getCurrent(function (tab) {
        if (tab && cr.tabs.remove) {
          cr.tabs.remove(tab.id, function () { /* ignore */ });
        }
        // Fallback: window.close()
        try { window.close(); } catch (e) { /* ignore */ }
      });
    } else {
      try { window.close(); } catch (e) { /* ignore */ }
    }
  }

  function onOptIn() {
    var log = getLogger();
    persistChoice(true).then(function () {
      if (log) log.info('user opted in to threat intel');
      closeWelcome();
    }).catch(function (err) {
      if (log) log.error('failed to persist opt-in', err);
      // Even on storage failure, close the tab. The user can re-opt
      // in via the popup.
      closeWelcome();
    });
  }

  function onDismiss() {
    var log = getLogger();
    persistChoice(false).then(function () {
      if (log) log.info('user dismissed opt-in (detect-only mode)');
      closeWelcome();
    }).catch(function (err) {
      if (log) log.error('failed to persist opt-in dismissal', err);
      closeWelcome();
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    // v0.1.4: update the visible version tag from the manifest at runtime
    var versionEl = document.getElementById('lens-version-tag');
    if (versionEl) versionEl.textContent = getMarketingVersion();

    var optInBtn = document.getElementById('opt-in');
    var dismissBtn = document.getElementById('dismiss');
    if (optInBtn) optInBtn.addEventListener('click', onOptIn);
    if (dismissBtn) dismissBtn.addEventListener('click', onDismiss);
  });
})();
