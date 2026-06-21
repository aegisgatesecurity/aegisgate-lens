// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Service Worker
// =========================================================================
//
// The service worker is the message broker. It is the ONLY
// module that talks to the backend. Content scripts send
// messages via chrome.runtime.sendMessage; the service
// worker applies the rate limit and the auth header, then
// forwards to the backend via api/client.ts.
//
// The service worker also handles:
//
//   - First-run setup: generates the bearer token, sets
//     the initial opt-in state, opens the welcome page.
//   - Opt-in/opt-out: updates the opt-in state.
//   - Health check on startup: calls /api/v1/lens/healthz
//     and logs the result.
//   - Local audit log rotation: appends each event to the
//     local log (chrome.storage.local) for the popup UI.
//
// v0.1 pre-release.
// =========================================================================

import { APIClient } from "./api/client.js";
import { Storage } from "./storage.js";
import type { LensEvent, OptInState } from "./types.js";

/**
 * The current Lens version.
 *
 * KEPT IN SYNC by tools/build-lens-extension in the
 * Platform monorepo. DO NOT EDIT THIS LINE; the build tool
 * templates it from version.txt at the Platform monorepo root.
 */
const LENS_VERSION = "0.1.0";

/** The default backend URL. Production deployments override. */
const DEFAULT_BACKEND_URL = "https://lens.aegisgatesecurity.io";

/** The storage layer. */
const storage = new Storage();

/**
 * Run on service worker startup. Note: we do NOT cache the
 * APIClient across calls. The service worker can be
 * terminated and restarted at any time by the browser
 * (MV3 reality), so a cached client with a stale token is
 * a footgun. Every call to getClient() reads the current
 * token from chrome.storage.local. The APIClient itself
 * is cheap to construct.
 */

/** Run on service worker startup. */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    onFirstInstall().catch((err) =>
      console.warn("[AegisGate Lens] onFirstInstall failed:", err),
    );
  } else if (details.reason === "update") {
    onUpdate(details.previousVersion ?? "").catch((err) =>
      console.warn("[AegisGate Lens] onUpdate failed:", err),
    );
  }
});

/** Run on every service worker startup (including cold starts). */
chrome.runtime.onStartup.addListener(() => {
  onStartup().catch((err) =>
    console.warn("[AegisGate Lens] onStartup failed:", err),
  );
});

/**
 * First-install handler. Generates the bearer token and
 * sets the initial opt-in state (default OFF).
 */
async function onFirstInstall(): Promise<void> {
  await storage.setBearerToken(await Storage.generateBearerToken());
  const now = Math.floor(Date.now() / 1000);
  const state: OptInState = {
    enabled: false,
    opted_in_at: 0,
    last_changed_at: now,
    "lens_version": LENS_VERSION,
  };
  await storage.setOptInState(state);
  // Open the welcome page in a new tab.
  await chrome.tabs.create({
    url: chrome.runtime.getURL("welcome.html"),
  });
}

/**
 * Update handler. Bumps the lens_version in the opt-in
 * state; does not change the enabled flag.
 */
async function onUpdate(previousVersion: string): Promise<void> {
  const state = await storage.getOptInState();
  if (state.lens_version !== LENS_VERSION) {
    state.lens_version = LENS_VERSION;
    state.last_changed_at = Math.floor(Date.now() / 1000);
    await storage.setOptInState(state);
  }
  // We could show a "what's new" page here in a future
  // version. For now, no UI.
  void previousVersion; // unused for v0.1
}

/**
 * Startup handler. Calls /healthz to confirm the backend
 * is reachable. Logs the result.
 */
async function onStartup(): Promise<void> {
  const baseUrl = (await storage.getBaseUrlOverride()) || DEFAULT_BACKEND_URL;
  const token = await storage.getBearerToken();
  if (!token) return; // not yet set up
  const client = new APIClient({ baseUrl, bearerToken: token });
  try {
    const h = await client.healthz();
    console.info(
      `[AegisGate Lens] backend reachable: ${h.version} (${h.status})`,
    );
  } catch (err) {
    // Log but do not surface to the user; the service worker
    // has no UI. The content scripts will continue to work
    // locally (detection + local audit) even if the backend
    // is unreachable.
    console.warn("[AegisGate Lens] backend unreachable:", err);
  }
}

/** Listen for messages from content scripts and the popup. */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  switch (msg.type) {
    case "lens.telemetry":
      handleTelemetry(msg.event).catch((err) =>
        console.warn("[AegisGate Lens] telemetry failed:", err),
      );
      sendResponse({ accepted: true });
      return false; // synchronous response
    case "lens.optIn":
      handleOptIn(msg.enabled).catch((err) =>
        console.warn("[AegisGate Lens] optIn failed:", err),
      );
      sendResponse({ accepted: true });
      return false;
    case "lens.getState":
      handleGetState().then(sendResponse).catch((err) => {
        console.warn("[AegisGate Lens] getState failed:", err);
        sendResponse({ error: String(err) });
      });
      return true; // async response
    case "lens.stats":
      handleStats().then(sendResponse).catch((err) => {
        console.warn("[AegisGate Lens] stats failed:", err);
        sendResponse({ error: String(err) });
      });
      return true;
    case "lens.clearLocalAudit":
      storage.clearLocalAudit().then(
        () => sendResponse({ ok: true }),
        (err) => sendResponse({ error: String(err) }),
      );
      return true;
    default:
      return false;
  }
});

/**
 * Handle a telemetry event from a content script. Steps:
 *   1. Check the opt-in state; reject if disabled.
 *   2. Build an APIClient (lazy).
 *   3. Append to the local audit log.
 *   4. Send to the backend via the APIClient.
 */
async function handleTelemetry(event: LensEvent): Promise<void> {
  const optIn = await storage.getOptInState();
  if (!optIn.enabled) {
    return; // silently drop; the content script should not
            // have sent this in the first place, but if it
            // did (race condition), we honor the opt-in.
  }
  // Append to local audit log. The entry contains ONLY
  // metadata (category, severity, user_action). NEVER any
  // prompt text, URL, or page content. The privacy policy
  // §10.2 requires this; the CI grep check enforces it.
  await storage.appendLocalAudit({
    timestamp: event.timestamp * 1000,
    domain_hash: event.domain_hash,
    category: event.category,
    severity: event.severity,
    user_action: event.user_action,
  });
  // Forward to the backend.
  const client = await getClient();
  try {
    await client.sendEvent(event);
  } catch (err) {
    // Log and drop. We do NOT retry; the privacy policy
    // commits to a single transmission attempt, and the
    // local audit log already has the record.
    console.warn("[AegisGate Lens] sendEvent failed:", err);
  }
}

/**
 * Handle an opt-in/opt-out change from the popup.
 */
async function handleOptIn(enabled: boolean): Promise<void> {
  const state = await storage.getOptInState();
  const now = Math.floor(Date.now() / 1000);
  state.enabled = enabled;
  state.last_changed_at = now;
  if (enabled && state.opted_in_at === 0) {
    state.opted_in_at = now;
  }
  await storage.setOptInState(state);
}

/**
 * Handle a get-state request from the popup. Returns the
 * current opt-in state and the local audit log.
 */
async function handleGetState() {
  // Simplified from Promise<{...}> to remove the return type
  // so the stripper can handle it.
  const optIn = await storage.getOptInState();
  const localAudit = await storage.getLocalAudit();
  const disabledCategories = await storage.getDisabledCategories();
  return {
    optIn,
    localAudit,
    disabledCategories: [...disabledCategories],
  };
}

/**
 * Handle a stats request from the popup. Calls the
 * backend's /api/v1/lens/stats endpoint and returns the
 * result. Returns an error if the user is not opted in.
 */
async function handleStats(): Promise<unknown> {
  const optIn = await storage.getOptInState();
  if (!optIn.enabled) {
    return { error: "not opted in" };
  }
  const client = await getClient();
  return await client.getStats();
}

/**
 * Get the APIClient for the current token. Re-reads the
 * token from chrome.storage.local on every call (the
 * service worker is not guaranteed to live between calls).
 */
async function getClient(): Promise<APIClient> {
  const baseUrl =
    (await storage.getBaseUrlOverride()) || DEFAULT_BACKEND_URL;
  const token = await storage.getBearerToken();
  return new APIClient({ baseUrl, bearerToken: token });
}
