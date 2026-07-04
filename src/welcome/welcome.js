// AegisGate Lens — welcome.js
// First-install welcome page. Loaded by welcome.html.
//
// Two buttons: "Opt in" and "Dismiss". Both close the welcome tab and
// persist the user's choice. The choice is stored in chrome.storage.local
// (on-device; never synced off-device) per the privacy policy.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

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

  function persistChoice(enabled) {
    return new Promise(function (resolve, reject) {
      var cr = getChrome();
      if (!cr || !cr.storage || !cr.storage.local) {
        reject(new Error('chrome.storage.local not available'));
        return;
      }
      var payload = {
        opt_in: {
          enabled: enabled,
          last_changed_at: Math.floor(Date.now() / 1000),
          lens_version: '0.1.0-beta'
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
    var optInBtn = document.getElementById('opt-in');
    var dismissBtn = document.getElementById('dismiss');
    if (optInBtn) optInBtn.addEventListener('click', onOptIn);
    if (dismissBtn) dismissBtn.addEventListener('click', onDismiss);
  });
})();
