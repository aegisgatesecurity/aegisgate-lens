/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Service Worker
   =========================================================================

   The service worker is the message broker. It is the ONLY
   module that talks to the backend. Content scripts send
   messages via chrome.runtime.sendMessage; the service
   worker applies the rate limit and the auth header, then
   forwards to the backend via api/client.js.

   The service worker also handles:

     - First-run setup: generates the bearer token, sets
       the initial opt-in state, opens the welcome page.
     - Opt-in/opt-out: updates the opt-in state.
     - Health check on startup: calls /api/v1/lens/healthz
       and logs the result.
     - Local audit log rotation: appends each event to the
       local log (chrome.storage.local) for the popup UI.

   MV3 reality: the service worker can be terminated and
   restarted at any time by the browser. We do NOT cache
   the APIClient across calls; every getClient() reads the
   current token from chrome.storage.local.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

// importScripts is the classic-script way to load other JS
// files. It blocks the current script until all imports
// finish. The manifest lists files in load order for
// modules that aren't loaded here.
importScripts(
  'util/logger.js',
  'storage.js',
  'privacy/schema.js',
  'api/client.js'
);

(function () {
  const NS = (typeof self !== 'undefined' ? self : this).AegisGateLens =
    (typeof self !== 'undefined' ? self : this).AegisGateLens || {};

  const log = NS.logger || console;
  const Storage = NS.storage;
  const APIClient = NS.APIClient;

  if (!Storage || !APIClient) {
    log.warn('[AegisGate Lens] modules missing; service worker cannot start');
    return;
  }

  /**
   * The current Lens version. Kept in sync by the build tool.
   */
  const LENS_VERSION =
    (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest &&
      chrome.runtime.getManifest().version) || '0.1.0';

  /** The default backend URL. Production deployments override. */
  const DEFAULT_BACKEND_URL = 'https://lens.aegisgatesecurity.io';

  /** The storage layer. */
  const storage = new Storage();

  /**
   * First-install handler. Generates the bearer token and
   * sets the initial opt-in state (default OFF).
   */
  async function onFirstInstall() {
    await storage.setBearerToken(Storage.generateBearerToken());
    const now = Math.floor(Date.now() / 1000);
    const state = {
      enabled: false,
      opted_in_at: 0,
      last_changed_at: now,
      lens_version: LENS_VERSION,
    };
    await storage.setOptInState(state);
    // Open the welcome page in a new tab.
    if (chrome && chrome.tabs && chrome.tabs.create) {
      await chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') });
    }
  }

  /**
   * Update handler. Bumps the lens_version in the opt-in
   * state; does not change the enabled flag.
   */
  async function onUpdate(previousVersion) {
    const state = await storage.getOptInState();
    if (state.lens_version !== LENS_VERSION) {
      state.lens_version = LENS_VERSION;
      state.last_changed_at = Math.floor(Date.now() / 1000);
      await storage.setOptInState(state);
    }
    void previousVersion; // unused for v0.1
  }

  /**
   * Startup handler. Runs a health check against the
   * backend; logs but does not fail.
   */
  async function onStartup() {
    const optIn = await storage.getOptInState();
    if (!optIn.enabled) {
      return; // detect-only mode; no network calls
    }
    const baseUrl =
      (await storage.getBaseUrlOverride().catch(() => null)) || DEFAULT_BACKEND_URL;
    const token = await storage.getBearerToken().catch(() => '');
    if (!token) return;
    const client = new APIClient({ baseUrl: baseUrl, bearerToken: token });
    try {
      await client.healthz();
    } catch (err) {
      log.warn('[AegisGate Lens] healthz failed:', err && err.message);
    }
  }

  /**
   * Get the APIClient for the current token.
   */
  async function getClient() {
    const baseUrl =
      (await storage.getBaseUrlOverride().catch(() => null)) || DEFAULT_BACKEND_URL;
    const token = await storage.getBearerToken().catch(() => '');
    return new APIClient({ baseUrl: baseUrl, bearerToken: token });
  }

  /**
   * Handle a telemetry event from a content script.
   */
  async function handleTelemetry(event) {
    const optIn = await storage.getOptInState();
    if (!optIn.enabled) {
      return; // silently drop; honor opt-in
    }
    await storage.appendLocalAudit({
      timestamp: event.timestamp * 1000,
      domain_hash: event.domain_hash,
      category: event.category,
      severity: event.severity,
      user_action: event.user_action,
    });
    const client = await getClient();
    try {
      await client.sendEvent(event);
    } catch (err) {
      log.warn('[AegisGate Lens] sendEvent failed:', err && err.message);
    }
  }

  /**
   * Handle an opt-in/opt-out change from the popup.
   */
  async function handleOptIn(enabled) {
    const state = await storage.getOptInState();
    const now = Math.floor(Date.now() / 1000);
    state.enabled = !!enabled;
    state.last_changed_at = now;
    if (enabled && state.opted_in_at === 0) {
      state.opted_in_at = now;
    }
    await storage.setOptInState(state);
  }

  /**
   * Handle a get-state request from the popup.
   */
  async function handleGetState() {
    const optIn = await storage.getOptInState();
    const localAudit = await storage.getLocalAudit();
    const disabled = await storage.getDisabledCategories();
    return {
      optIn: optIn,
      localAudit: localAudit,
      disabledCategories: [].concat(disabled || []),
    };
  }

  /**
   * Handle a stats request from the popup.
   */
  async function handleStats() {
    const optIn = await storage.getOptInState();
    if (!optIn.enabled) {
      return { error: 'not opted in' };
    }
    const client = await getClient();
    return await client.getStats();
  }

  /**
   * Handle a test event from the popup (diagnostics).
   */
  async function handleTestEvent() {
    const optIn = await storage.getOptInState();
    if (!optIn.enabled) {
      return { sent: false, reason: 'not opted in' };
    }
    const baseUrl =
      (await storage.getBaseUrlOverride().catch(() => null)) || DEFAULT_BACKEND_URL;
    const token = await storage.getBearerToken().catch(() => '');
    const client = new APIClient({ baseUrl: baseUrl, bearerToken: token });
    const event = {
      domain_hash: '0000000000000000',
      category: 'health_check',
      severity: 'info',
      user_action: 'send_anyway',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: LENS_VERSION + '+regex-v1',
      lens_version: LENS_VERSION,
      confidence: 1.0,
    };
    try {
      await client.sendEvent(event);
      return { sent: true };
    } catch (err) {
      return { sent: false, reason: err && err.message || String(err) };
    }
  }

  // =====================================================================
  // Wire up listeners (only if chrome APIs are available).
  // =====================================================================

  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.onInstalled.addListener(function (details) {
      if (details && details.reason === 'install') {
        onFirstInstall().catch(function (err) {
          log.warn('[AegisGate Lens] onFirstInstall failed:', err);
        });
      } else if (details && details.reason === 'update') {
        onUpdate(details.previousVersion || '').catch(function (err) {
          log.warn('[AegisGate Lens] onUpdate failed:', err);
        });
      }
    });

    chrome.runtime.onStartup.addListener(function () {
      onStartup().catch(function (err) {
        log.warn('[AegisGate Lens] onStartup failed:', err);
      });
    });

    chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
      if (!msg || typeof msg.type !== 'string') {
        sendResponse({ error: 'invalid message' });
        return false;
      }
      const reply = (function () {
        if (msg.type === 'lens.telemetry') {
          return handleTelemetry(msg.event || msg.payload || {});
        } else if (msg.type === 'lens.opt_in') {
          return handleOptIn(!!(msg.payload && msg.payload.enabled));
        } else if (msg.type === 'lens.get_state') {
          return handleGetState();
        } else if (msg.type === 'lens.stats') {
          return handleStats();
        } else if (msg.type === 'lens.test_event') {
          return handleTestEvent();
        }
        return Promise.resolve({ error: 'unknown message type: ' + msg.type });
      })();
      Promise.resolve(reply).then(
        function (result) { sendResponse(result || {}); },
        function (err) { sendResponse({ error: err && err.message || String(err) }); },
      );
      return true; // async response
    });
  }
})();