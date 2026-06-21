/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Welcome Page Controller
   =========================================================================

   The welcome page is shown on first install (opened by
   service-worker.js via chrome.tabs.create). It presents:

     1. The AegisGate Lens value proposition
     2. The privacy non-negotiables (no prompt/URL/page content)
     3. A button to enable telemetry (opt-in)
     4. A button to dismiss and stay in detect-only mode

   No background work happens here. The page simply lets the
   user make their first opt-in decision.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const log = NS.logger || console;
  const Storage = NS.storage;

  const SafeStorage = Storage || {
    getOptInState: async () => ({ enabled: false, opted_in_at: 0, last_changed_at: 0, lens_version: '0.0.0' }),
    setOptInState: async () => {},
  };

  /** Pull the LENS_VERSION from the manifest if available. */
  const LENS_VERSION =
    (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest &&
      chrome.runtime.getManifest().version) || '0.0.0';

  function el(id) {
    return document.getElementById(id);
  }

  /**
   * Persist the user's opt-in decision and close the tab.
   *
   * @param {boolean} enabled
   */
  async function setOptIn(enabled) {
    const now = Math.floor(Date.now() / 1000);
    const current = await SafeStorage.getOptInState().catch(() => ({}));
    await SafeStorage.setOptInState({
      enabled: !!enabled,
      opted_in_at: enabled ? now : (current.opted_in_at || 0),
      last_changed_at: now,
      lens_version: LENS_VERSION,
    });
  }

  function init() {
    const versionEl = el('version');
    if (versionEl) versionEl.textContent = 'v' + LENS_VERSION;

    const enableBtn = el('enable-button');
    if (enableBtn) {
      enableBtn.addEventListener('click', async () => {
        enableBtn.disabled = true;
        try {
          await setOptIn(true);
          log.info('[AegisGate Lens] user opted in via welcome page');
          window.close();
        } catch (err) {
          log.warn('[AegisGate Lens] opt-in failed:', err);
          enableBtn.disabled = false;
        }
      });
    }

    const dismissBtn = el('dismiss-button');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', async () => {
        dismissBtn.disabled = true;
        try {
          await setOptIn(false);
          log.info('[AegisGate Lens] user dismissed welcome page (detect-only mode)');
          window.close();
        } catch (err) {
          log.warn('[AegisGate Lens] dismiss failed:', err);
          dismissBtn.disabled = false;
        }
      });
    }

    // If the user already opted in (e.g., reinstalled), close
    // the welcome tab automatically.
    SafeStorage.getOptInState().then((state) => {
      if (state && state.enabled) {
        window.close();
      }
    }).catch(() => {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  NS.welcome = Object.freeze({ init, setOptIn });
})();