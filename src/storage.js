/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - chrome.storage Wrapper
   =========================================================================

   The storage module is the Lens's interface to chrome.storage.
   It abstracts over the two storage areas we use:

     - chrome.storage.sync: small, synced across the user's
       signed-in devices. Used for the OptInState (so the
       opt-in is consistent across devices) and the bearer
       token (so we don't make the user re-auth on every
       device).
     - chrome.storage.local: large, per-device. Used for the
       local audit log (last N events) and the local-only
       configuration that should NOT sync.

   Privacy notes:

     - The OptInState is the only piece of user-facing state
       in chrome.storage.sync. It contains no PII; it is a
       boolean plus timestamps.
     - The bearer token is a per-installation secret. It is
       generated on first opt-in and stored in
       chrome.storage.local. It is NOT sent to any server
       other than the configured Lens backend.
     - The local audit log (LocalAuditEntry[]) is stored in
       chrome.storage.local. It is NEVER sent to the
       backend. It exists so the user can see what the
       extension has detected locally.

   Non-negotiables (see legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md
   §4): no logging of prompt content, URLs, or page content;
   no transmission of the match substring; no telemetry of
   anything that identifies the user. The local audit log is
   metadata-only (category, severity, user_action) by design.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * @typedef {'pii_email'|'pii_phone'|'pii_ssn'|'pii_credit_card'|'secret_api_key'|'source_code'} Category
   *   The 7 categories of sensitive data the Lens detects in v0.1.
   *   Adding a new category is a breaking change.
   */

  /**
   * @typedef {'info'|'low'|'medium'|'high'|'critical'} Severity
   */

  /**
   * @typedef {'send_anyway'|'edit'|'cancel'|'dismiss'} UserAction
   */

  /**
   * @typedef {Object} OptInState
   * @property {boolean} enabled           Master opt-in flag.
   * @property {number} opted_in_at        Unix seconds.
   * @property {number} last_changed_at    Unix seconds.
   * @property {string} lens_version       Lens version string.
   */

  /**
   * @typedef {Object} LocalAuditEntry
   * @property {number} timestamp
   * @property {string} domain_hash
   * @property {Category} category
   * @property {Severity} severity
   * @property {UserAction} user_action
   */

  /** The maximum size of the local audit log. Older entries are pruned. */
  const MAX_LOCAL_AUDIT_ENTRIES = 1000;

  /** The chrome.storage.sync key for the opt-in state. */
  const KEY_OPT_IN = 'lens.opt_in';

  /**
   * The chrome.storage.local key for the bearer token. The
   * token is per-device (stored in chrome.storage.local) and
   * is NOT synced across the user's signed-in Chrome devices.
   * This is a deliberate privacy choice: a synced token
   * would be a quasi-identifier that lets the backend
   * correlate the user's device fleet, and a token leaked
   * from one device could impersonate the user's other
   * devices. Per-device tokens eliminate both risks. The
   * opt-in state IS synced (it's just a boolean plus
   * timestamps; no secret, no identifier).
   *
   * See plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md §8.1
   * for the full disclosure.
   */
  const KEY_BEARER_TOKEN = 'lens.bearer_token';

  /** The chrome.storage.local key for the audit log. */
  const KEY_LOCAL_AUDIT = 'lens.local_audit';

  /** The chrome.storage.local key for the per-category disabled flags. */
  const KEY_DISABLED_CATEGORIES = 'lens.disabled_categories';

  /** The chrome.storage.local key for the dev-only base URL override. */
  const KEY_BASE_URL_OVERRIDE = 'lens.__base_url_override';

  /**
   * Storage is the Lens's typed wrapper over chrome.storage.
   * All chrome.storage calls in the extension go through this
   * module so the keys are not magic strings scattered around.
   */
  class Storage {
    /**
     * Get the current opt-in state. If the user has never
     * opted in, returns a default state with enabled=false.
     * The returned state is a copy; mutating it does not
     * persist; call setOptInState() to save.
     *
     * @returns {Promise<OptInState>}
     */
    async getOptInState() {
      const result = await chrome.storage.sync.get(KEY_OPT_IN);
      const stored = result[KEY_OPT_IN];
      if (stored && typeof stored === 'object') {
        return stored;
      }
      // Default: not opted in.
      return {
        enabled: false,
        opted_in_at: 0,
        last_changed_at: 0,
        lens_version: '0.1.0',
      };
    }

    /**
     * Save the opt-in state. The state is merged with the
     * existing state; pass the full state object.
     *
     * @param {OptInState} state
     * @returns {Promise<void>}
     */
    async setOptInState(state) {
      await chrome.storage.sync.set({ [KEY_OPT_IN]: state });
    }

    /**
     * Get the bearer token. If no token has been generated,
     * returns an empty string. The token is generated on
     * first opt-in by the service worker.
     *
     * The token is stored in chrome.storage.LOCAL (not sync).
     * See the comment above KEY_BEARER_TOKEN for the privacy
     * rationale.
     *
     * @returns {Promise<string>}
     */
    async getBearerToken() {
      const result = await chrome.storage.local.get(KEY_BEARER_TOKEN);
      return result[KEY_BEARER_TOKEN] || '';
    }

    /**
     * Save the bearer token. Called by the service worker
     * after generating the token on first opt-in. Stored in
     * chrome.storage.LOCAL (not sync) for the privacy
     * reasons documented above KEY_BEARER_TOKEN.
     *
     * @param {string} token
     * @returns {Promise<void>}
     */
    async setBearerToken(token) {
      await chrome.storage.local.set({ [KEY_BEARER_TOKEN]: token });
    }

    /**
     * Append an entry to the local audit log. The log is
     * pruned to the most recent MAX_LOCAL_AUDIT_ENTRIES
     * entries. The entry is stored in chrome.storage.local
     * and is NEVER sent to the backend.
     *
     * @param {LocalAuditEntry} entry
     * @returns {Promise<void>}
     */
    async appendLocalAudit(entry) {
      const result = await chrome.storage.local.get(KEY_LOCAL_AUDIT);
      const log = result[KEY_LOCAL_AUDIT] || [];
      log.push(entry);
      if (log.length > MAX_LOCAL_AUDIT_ENTRIES) {
        log.splice(0, log.length - MAX_LOCAL_AUDIT_ENTRIES);
      }
      await chrome.storage.local.set({ [KEY_LOCAL_AUDIT]: log });
    }

    /**
     * Read the local audit log. Returns a copy in reverse
     * chronological order (newest first).
     *
     * @returns {Promise<ReadonlyArray<LocalAuditEntry>>}
     */
    async getLocalAudit() {
      const result = await chrome.storage.local.get(KEY_LOCAL_AUDIT);
      const log = result[KEY_LOCAL_AUDIT] || [];
      return log.slice().reverse();
    }

    /**
     * Clear the local audit log. Used by the "Clear local
     * history" button in the popup.
     *
     * @returns {Promise<void>}
     */
    async clearLocalAudit() {
      await chrome.storage.local.remove(KEY_LOCAL_AUDIT);
    }

    /**
     * Get the set of disabled categories. Categories in
     * this set are NOT detected.
     *
     * @returns {Promise<ReadonlySet<Category>>}
     */
    async getDisabledCategories() {
      const result = await chrome.storage.local.get(KEY_DISABLED_CATEGORIES);
      const arr = result[KEY_DISABLED_CATEGORIES] || [];
      return new Set(arr);
    }

    /**
     * Set the disabled categories.
     *
     * @param {ReadonlySet<Category>} cats
     * @returns {Promise<void>}
     */
    async setDisabledCategories(cats) {
      await chrome.storage.local.set({
        [KEY_DISABLED_CATEGORIES]: Array.from(cats),
      });
    }

    /**
     * Get the base URL override (for development only).
     * Returns an empty string in production.
     *
     * @returns {Promise<string>}
     */
    async getBaseUrlOverride() {
      const result = await chrome.storage.local.get(KEY_BASE_URL_OVERRIDE);
      return result[KEY_BASE_URL_OVERRIDE] || '';
    }

    /**
     * Set the base URL override (for development only).
     *
     * @param {string} url
     * @returns {Promise<void>}
     */
    async setBaseUrlOverride(url) {
      await chrome.storage.local.set({ [KEY_BASE_URL_OVERRIDE]: url });
    }

    /**
     * Generate a cryptographically random bearer token.
     * Used by the service worker on first opt-in.
     *
     * 32 bytes = 256 bits of entropy, hex-encoded to 64 chars.
     *
     * @returns {Promise<string>}
     */
    static async generateBearerToken() {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      let out = '';
      for (let i = 0; i < bytes.length; i++) {
        out += (bytes[i] >> 4).toString(16);
        out += (bytes[i] & 0x0f).toString(16);
      }
      return out;
    }
  }

  NS.storage = NS.storage || {};
  NS.storage.Storage = Storage;
})();
