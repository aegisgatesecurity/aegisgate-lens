/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Welcome Page Controller (v0.3.0)
   =========================================================================

   The welcome page is shown on first install (opened by
   service-worker.js via chrome.tabs.create). It presents:

     1. The AegisGate Lens value proposition
     2. The 12 privacy non-negotiables (no prompt/URL/page content)
     3. Three opt-in choices:
        a. Detect-only (no telemetry)
        b. Tier 1: anonymized metadata (helps improve detection)
        c. Tier 2: full event details (power users)
     4. A "Decide later" link to close the tab without choosing

   No background work happens here. The page simply lets the
   user make their first opt-in decision.

   Plain JavaScript, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const log = NS.logger || console;
  const OptIn = NS.util && NS.util.optIn;

  // ============================================================================
  // Helpers
  // ============================================================================

  function el(id) {
    return document.getElementById(id);
  }

  function getLensVersion() {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest) {
        return chrome.runtime.getManifest().version || '0.0.0';
      }
    } catch (_) {}
    return '0.0.0';
  }

  // ============================================================================
  // Button handlers
  // ============================================================================

  async function chooseDetectOnly() {
    log.info('[AegisGate Lens] user chose detect-only mode');
    if (OptIn && OptIn.setOptInStateV03) {
      // Set both tiers to false explicitly
      await OptIn.setOptInStateV03({
        tier1_enabled: false,
        tier2_enabled: false,
      });
    }
    // Also clear v0.1 compat key
    if (OptIn && OptIn.setOptInState) {
      await OptIn.setOptInState({ enabled: false });
    }
    closeTab();
  }

  async function chooseTier1() {
    log.info('[AegisGate Lens] user opted in to Tier 1 telemetry');
    if (OptIn && OptIn.setOptInStateV03) {
      await OptIn.setOptInStateV03({
        tier1_enabled: true,
        tier2_enabled: false,
      });
    }
    // Maintain v0.1 compat (enabled=true means at least Tier 1)
    if (OptIn && OptIn.setOptInState) {
      await OptIn.setOptInState({ enabled: true });
    }
    closeTab();
  }

  async function chooseTier2() {
    log.info('[AegisGate Lens] user opted in to Tier 2 telemetry');
    // Tier 2 requires Tier 1
    if (OptIn && OptIn.setOptInStateV03) {
      await OptIn.setOptInStateV03({
        tier1_enabled: true,
        tier2_enabled: true,
      });
    }
    if (OptIn && OptIn.setOptInState) {
      await OptIn.setOptInState({ enabled: true });
    }
    closeTab();
  }

  async function decideLater() {
    log.info('[AegisGate Lens] user deferred opt-in decision');
    // Do NOT persist any state — just close the tab.
    // User will see the welcome page again on next install/reset.
    closeTab();
  }

  function closeTab() {
    if (typeof window !== 'undefined' && window.close) {
      window.close();
    }
  }

  // ============================================================================
  // Init
  // ============================================================================

  function init() {
    // Set version
    const versionEl = el('version');
    if (versionEl) versionEl.textContent = getLensVersion();

    // Auto-close if already opted in
    if (OptIn && OptIn.getOptInStateV03) {
      OptIn.getOptInStateV03().then((state) => {
        if (state && (state.tier1_enabled || state.tier2_enabled)) {
          log.info('[AegisGate Lens] user already opted in; auto-closing welcome tab');
          window.close();
        }
      }).catch(() => {});
    }

    // Wire buttons
    const btnDetectOnly = el('btn-detect-only');
    if (btnDetectOnly) btnDetectOnly.addEventListener('click', chooseDetectOnly);

    const btnTier1 = el('btn-tier1');
    if (btnTier1) btnTier1.addEventListener('click', chooseTier1);

    const btnTier2 = el('btn-tier2');
    if (btnTier2) btnTier2.addEventListener('click', chooseTier2);

    const btnLater = el('btn-later');
    if (btnLater) btnLater.addEventListener('click', decideLater);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  NS.welcome = Object.freeze({ init });
})();