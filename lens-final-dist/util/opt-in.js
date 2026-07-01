/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Telemetry Opt-In State Manager (v0.3.0)
   =========================================================================

   Manages the user's opt-in state for telemetry collection. Based on v0.1's
   architecture but extended for v0.3:

     v0.1: Single opt-in flag (detect-only vs telemetry-on)
     v0.3: Two-tier opt-in (TI metadata only vs full event details)

   Privacy guarantees (per docs/PRIVACY-POLICY.md):
     1. Default OFF. No telemetry without explicit user consent.
     2. Never sends: prompt text, URLs, page content, user IDs.
     3. Sends only: anonymized metadata (domain_hash, category, severity, etc.)
     4. Storage: chrome.storage.sync (10 MB per origin, persistent across installs).
     5. Rate-limited client-side: 100 events/min per installation.

   Plain JavaScript, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const log = NS.logger || console;

  // v0.1 storage keys (kept for backward compat)
  const KEY_OPT_IN = 'lens.optIn.enabled';
  const KEY_OPT_IN_V03 = 'lens.optIn.v03';  // v0.3 metadata

  // ============================================================================
  // v0.1-compatible: simple opt-in (detect-only vs telemetry-on)
  // ============================================================================

  async function getOptInState() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      log.warn('[AegisGate Lens] chrome.storage.sync unavailable; defaulting to opt-out');
      return { enabled: false, lens_version: '0.0.0' };
    }
    return new Promise((resolve) => {
      chrome.storage.sync.get(KEY_OPT_IN, (result) => {
        const stored = result && result[KEY_OPT_IN];
        if (!stored) {
          resolve({ enabled: false, lens_version: getLensVersion() });
          return;
        }
        resolve(stored);
      });
    });
  }

  async function setOptInState(state) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      log.warn('[AegisGate Lens] chrome.storage.sync unavailable; cannot persist opt-in');
      return;
    }
    // Read existing state first to preserve opted_in_at when disabling
    const current = await getOptInState().catch(() => ({}));
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      enabled: !!state.enabled,
      opted_in_at: state.enabled ? now : (state.opted_in_at != null ? state.opted_in_at : (current.opted_in_at || 0)),
      last_changed_at: now,
      lens_version: getLensVersion(),
    };
    return new Promise((resolve, reject) => {
      chrome.storage.sync.set({ [KEY_OPT_IN]: payload }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        log.info('[AegisGate Lens] opt-in saved:', payload);
        resolve(payload);
      });
    });
  }

  // ============================================================================
  // v0.3 extension: tiered opt-in
  //   Tier 1: sendFPTelemetry (anonymized metadata only)
  //   Tier 2: sendFullEvent (richer event details, requires Tier 1)
  // ============================================================================

  async function getOptInStateV03() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      return defaultOptInStateV03();
    }
    return new Promise((resolve) => {
      chrome.storage.sync.get(KEY_OPT_IN_V03, (result) => {
        const stored = result && result[KEY_OPT_IN_V03];
        if (!stored) {
          resolve(defaultOptInStateV03());
          return;
        }
        resolve(stored);
      });
    });
  }

  async function setOptInStateV03(state) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      log.warn('[AegisGate Lens] cannot persist v0.3 opt-in state');
      return;
    }
    const current = await getOptInStateV03();
    const merged = {
      tier1_enabled: state.tier1_enabled !== undefined ? !!state.tier1_enabled : current.tier1_enabled,
      tier2_enabled: state.tier2_enabled !== undefined ? !!state.tier2_enabled : current.tier2_enabled,
      opted_in_at_tier1: state.tier1_enabled ? Math.floor(Date.now() / 1000) : current.opted_in_at_tier1,
      opted_in_at_tier2: state.tier2_enabled ? Math.floor(Date.now() / 1000) : current.opted_in_at_tier2,
      last_changed_at: Math.floor(Date.now() / 1000),
      lens_version: getLensVersion(),
    };
    return new Promise((resolve, reject) => {
      chrome.storage.sync.set({ [KEY_OPT_IN_V03]: merged }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        log.info('[AegisGate Lens] v0.3 opt-in saved:', merged);
        resolve(merged);
      });
    });
  }

  function defaultOptInStateV03() {
    return {
      tier1_enabled: false,           // Default: opt-out for both tiers
      tier2_enabled: false,
      opted_in_at_tier1: 0,
      opted_in_at_tier2: 0,
      last_changed_at: 0,
      lens_version: getLensVersion(),
    };
  }

  // ============================================================================
  // Helpers
  // ============================================================================

  function getLensVersion() {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest) {
        return chrome.runtime.getManifest().version || '0.0.0';
      }
    } catch (_) {}
    return '0.0.0';
  }

  /**
   * Check if any telemetry is enabled (either tier).
   * Used by content.js / service-worker to decide whether to send anything.
   */
  async function isTelemetryEnabled() {
    const v1 = await getOptInState();
    if (v1 && v1.enabled) return true;
    const v03 = await getOptInStateV03();
    return v03.tier1_enabled || v03.tier2_enabled;
  }

  NS.util = NS.util || {};
  NS.util.optIn = Object.freeze({
    // v0.1 API (backward compat)
    getOptInState,
    setOptInState,
    // v0.3 API (two-tier)
    getOptInStateV03,
    setOptInStateV03,
    isTelemetryEnabled,
    // Constants (for tests)
    KEY_OPT_IN,
    KEY_OPT_IN_V03,
  });
})();