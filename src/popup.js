/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Popup UI Controller
   =========================================================================

   The popup is the user-facing settings panel that appears when
   the user clicks the Lens icon in the Chrome toolbar. It shows:

     1. The current opt-in state and a toggle to enable/disable
     2. The Lens version
     3. A short privacy notice and link to the full policy
     4. A "Send test event" button for support diagnostics

   The popup is its own document with its own JS scope. It loads
   storage.js for state access, but does NOT load the detectors
   (the popup is not on an AI provider page).

   Privacy: the popup never displays prompt content, URLs, or
   page content. The "Send test event" button sends a synthetic
   event with category=health_check and severity=info so the
   backend can verify the bearer token works.

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

  /** Fallback if storage.js failed to load. */
  const SafeStorage = Storage || {
    getOptInState: async () => ({ enabled: false, opted_in_at: 0, last_changed_at: 0, lens_version: '0.0.0' }),
    setOptInState: async () => {},
    getBearerToken: async () => '',
    appendLocalAudit: async () => {},
    getLocalAudit: async () => [],
    clearLocalAudit: async () => {},
    generateBearerToken: () => 'no-storage',
  };

  /** Pull the LENS_VERSION from the manifest if available. */
  const LENS_VERSION =
    (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest &&
      chrome.runtime.getManifest().version) || '0.0.0';

  /**
   * Send a one-shot message to the service worker and await
   * its reply via a single-use callback registry.
   *
   * @param {string} type  Message type (e.g., "lens.test_event").
   * @param {Object} [payload]
   * @returns {Promise<unknown>}
   */
  function sendMessage(type, payload) {
    return new Promise((resolve, reject) => {
      if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
        reject(new Error('chrome.runtime.sendMessage unavailable'));
        return;
      }
      chrome.runtime.sendMessage({ type, payload: payload || {} }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response);
      });
    });
  }

  /**
   * @param {string} id
   * @returns {HTMLElement|null}
   */
  function el(id) {
    return document.getElementById(id);
  }

  /**
   * Render the opt-in state into the toggle UI.
   *
   * @param {{enabled: boolean}} state
   */
  function renderOptIn(state) {
    const toggle = el('opt-in-toggle');
    const status = el('opt-in-status');
    const explanation = el('opt-in-explanation');
    if (!toggle || !status) return;

    toggle.checked = !!state.enabled;
    if (state.enabled) {
      status.textContent = 'Enabled';
      status.dataset.state = 'enabled';
    } else {
      status.textContent = 'Disabled (no telemetry is sent)';
      status.dataset.state = 'disabled';
    }
    if (explanation) {
      explanation.textContent = state.enabled
        ? 'The Lens sends anonymized detection metadata to the AegisGate Lens backend. ' +
          'No prompt content, URLs, or page content is ever transmitted. ' +
          'You can disable this at any time.'
        : 'The Lens is in detect-only mode. Detections are shown in-page but no ' +
          'metadata is sent to the AegisGate Lens backend.';
    }
  }

  /**
   * Wire up event handlers after the DOM is ready.
   */
  function init() {
    // Version banner.
    const versionEl = el('version');
    if (versionEl) {
      versionEl.textContent = 'v' + LENS_VERSION;
    }

    // Initial opt-in render.
    SafeStorage.getOptInState().then(renderOptIn).catch((err) => {
      log.warn('[AegisGate Lens] failed to read opt-in state:', err);
    });

    // Opt-in toggle.
    const toggle = el('opt-in-toggle');
    if (toggle) {
      toggle.addEventListener('change', async () => {
        const now = Math.floor(Date.now() / 1000);
        const current = await SafeStorage.getOptInState().catch(() => ({}));
        const next = {
          enabled: !!toggle.checked,
          opted_in_at: toggle.checked ? now : (current.opted_in_at || 0),
          last_changed_at: now,
          lens_version: LENS_VERSION,
        };
        try {
          await SafeStorage.setOptInState(next);
          renderOptIn(next);
        } catch (err) {
          log.warn('[AegisGate Lens] failed to write opt-in state:', err);
        }
      });
    }

    // "Send test event" button — diagnostics only.
    const testBtn = el('test-event-button');
    if (testBtn) {
      testBtn.addEventListener('click', async () => {
        testBtn.disabled = true;
        const result = el('test-event-result');
        try {
          const r = await sendMessage('lens.test_event', {});
          if (result) result.textContent = 'Test event sent OK.';
          log.info('[AegisGate Lens] test event result:', r);
        } catch (err) {
          if (result) result.textContent = 'Test event failed: ' + (err && err.message || String(err));
          log.warn('[AegisGate Lens] test event failed:', err);
        } finally {
          testBtn.disabled = false;
        }
      });
    }

    // "Clear local audit log" button.
    const clearBtn = el('clear-audit-button');
    if (clearBtn) {
      clearBtn.addEventListener('click', async () => {
        clearBtn.disabled = true;
        try {
          await SafeStorage.clearLocalAudit();
          const audit = el('audit-count');
          if (audit) audit.textContent = '0';
        } catch (err) {
          log.warn('[AegisGate Lens] failed to clear audit log:', err);
        } finally {
          clearBtn.disabled = false;
        }
      });
    }

    // Show local audit count.
    SafeStorage.getLocalAudit().then((entries) => {
      const audit = el('audit-count');
      if (audit) audit.textContent = String((entries || []).length);
    }).catch(() => {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  NS.popup = Object.freeze({ init, renderOptIn });
})();