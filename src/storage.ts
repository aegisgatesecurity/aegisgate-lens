// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - chrome.storage Wrapper
// =========================================================================
//
// The storage module is the Lens's interface to chrome.storage.
// It abstracts over the two storage areas we use:
//
//   - chrome.storage.sync: small, synced across the user's
//     signed-in devices. Used for the OptInState (so the
//     opt-in is consistent across devices) and the bearer
//     token (so we don't make the user re-auth on every
//     device).
//   - chrome.storage.local: large, per-device. Used for the
//     local audit log (last N events) and the local-only
//     configuration that should NOT sync.
//
// Privacy notes:
//
//   - The OptInState is the only piece of user-facing state
//     in chrome.storage.sync. It contains no PII; it is a
//     boolean plus timestamps.
//   - The bearer token is a per-installation secret. It is
//     generated on first opt-in and stored in
//     chrome.storage.sync. It is NOT sent to any server
//     other than the configured Lens backend.
//   - The local audit log (LocalAuditEntry[]) is stored in
//     chrome.storage.local. It is NEVER sent to the
//     backend. It exists so the user can see what the
//     extension has detected locally.
//
// v0.1 pre-release.
// =========================================================================

import type { OptInState, LocalAuditEntry, Category } from "./types.js";

/** The maximum size of the local audit log. Older entries are pruned. */
const MAX_LOCAL_AUDIT_ENTRIES = 1000;

/** The chrome.storage.sync key for the opt-in state. */
const KEY_OPT_IN = "lens.opt_in";

/** The chrome.storage.sync key for the bearer token. */
const KEY_BEARER_TOKEN = "lens.bearer_token";

/** The chrome.storage.local key for the audit log. */
const KEY_LOCAL_AUDIT = "lens.local_audit";

/** The chrome.storage.local key for the per-category disabled flags. */
const KEY_DISABLED_CATEGORIES = "lens.disabled_categories";

/** The chrome.storage.local key for the dev-only base URL override. */
const KEY_BASE_URL_OVERRIDE = "lens.__base_url_override";

/** The current Lens version. Bumped per release. */
const LENS_VERSION = "0.1.0";

/**
 * Storage is the Lens's typed wrapper over chrome.storage.
 * All chrome.storage calls in the extension go through this
 * module so the keys are not magic strings scattered around.
 */
export class Storage {
  /**
   * Get the current opt-in state. If the user has never
   * opted in, returns a default state with enabled=false.
   * The returned state is a copy; mutating it does not
   * persist; call setOptInState() to save.
   */
  async getOptInState(): Promise<OptInState> {
    const result = await chrome.storage.sync.get(KEY_OPT_IN);
    const stored = result[KEY_OPT_IN] as OptInState | undefined;
    if (stored && typeof stored === "object") {
      return stored;
    }
    // Default: not opted in.
    return {
      enabled: false,
      opted_in_at: 0,
      last_changed_at: 0,
      lens_version: LENS_VERSION,
    };
  }

  /**
   * Save the opt-in state. The state is merged with the
   * existing state; pass the full state object.
   */
  async setOptInState(state: OptInState): Promise<void> {
    await chrome.storage.sync.set({ [KEY_OPT_IN]: state });
  }

  /**
   * Get the bearer token. If no token has been generated,
   * returns an empty string. The token is generated on
   * first opt-in by the service worker.
   */
  async getBearerToken(): Promise<string> {
    const result = await chrome.storage.sync.get(KEY_BEARER_TOKEN);
    return (result[KEY_BEARER_TOKEN] as string) ?? "";
  }

  /**
   * Save the bearer token. Called by the service worker
   * after generating the token on first opt-in.
   */
  async setBearerToken(token: string): Promise<void> {
    await chrome.storage.sync.set({ [KEY_BEARER_TOKEN]: token });
  }

  /**
   * Append an entry to the local audit log. The log is
   * pruned to the most recent MAX_LOCAL_AUDIT_ENTRIES
   * entries. The entry is stored in chrome.storage.local
   * and is NEVER sent to the backend.
   */
  async appendLocalAudit(entry: LocalAuditEntry): Promise<void> {
    const result = await chrome.storage.local.get(KEY_LOCAL_AUDIT);
    const log = (result[KEY_LOCAL_AUDIT] as LocalAuditEntry[] | undefined) ?? [];
    log.push(entry);
    if (log.length > MAX_LOCAL_AUDIT_ENTRIES) {
      log.splice(0, log.length - MAX_LOCAL_AUDIT_ENTRIES);
    }
    await chrome.storage.local.set({ [KEY_LOCAL_AUDIT]: log });
  }

  /**
   * Read the local audit log. Returns a copy in reverse
   * chronological order (newest first).
   */
  async getLocalAudit(): Promise<ReadonlyArray<LocalAuditEntry>> {
    const result = await chrome.storage.local.get(KEY_LOCAL_AUDIT);
    const log = (result[KEY_LOCAL_AUDIT] as LocalAuditEntry[] | undefined) ?? [];
    return [...log].reverse();
  }

  /**
   * Clear the local audit log. Used by the "Clear local
   * history" button in the popup.
   */
  async clearLocalAudit(): Promise<void> {
    await chrome.storage.local.remove(KEY_LOCAL_AUDIT);
  }

  /**
   * Get the set of disabled categories. Categories in
   * this set are NOT detected.
   */
  async getDisabledCategories(): Promise<ReadonlySet<Category>> {
    const result = await chrome.storage.local.get(KEY_DISABLED_CATEGORIES);
    const arr = (result[KEY_DISABLED_CATEGORIES] as Category[] | undefined) ?? [];
    return new Set(arr);
  }

  /**
   * Set the disabled categories.
   */
  async setDisabledCategories(cats: ReadonlySet<Category>): Promise<void> {
    await chrome.storage.local.set({
      [KEY_DISABLED_CATEGORIES]: [...cats],
    });
  }

  /**
   * Get the base URL override (for development only).
   * Returns an empty string in production.
   */
  async getBaseUrlOverride(): Promise<string> {
    const result = await chrome.storage.local.get(KEY_BASE_URL_OVERRIDE);
    return (result[KEY_BASE_URL_OVERRIDE] as string) ?? "";
  }

  /**
   * Set the base URL override (for development only).
   */
  async setBaseUrlOverride(url: string): Promise<void> {
    await chrome.storage.local.set({ [KEY_BASE_URL_OVERRIDE]: url });
  }

  /**
   * Generate a cryptographically random bearer token.
   * Used by the service worker on first opt-in.
   *
   * 32 bytes = 256 bits of entropy, hex-encoded to 64 chars.
   */
  static async generateBearerToken(): Promise<string> {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += (bytes[i] >> 4).toString(16);
      out += (bytes[i] & 0x0f).toString(16);
    }
    return out;
  }
}
