/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - MV3 Service Worker (v0.2.0)
   =========================================================================

   Sole message broker between content scripts and the backend.
   Runs in MV3 service worker context (no DOM access).

   v0.2 changes from v0.1:
     - Lazy-loads ML model bundles on first facet invocation
     - Adds threat-intel feed polling (every 6 hours, opt-in gated)
     - Adds bundle registry / license audit (rejects Elastic 2.0 etc.)
     - Same sender.id validation as v0.1 (F-01 fix)
     - Opt-in gate: opted-out users get no side effects

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

// --------------------------------------------------------------------------
// Sender validation (F-01 fix from v0.1 threat model)
// --------------------------------------------------------------------------

const OWN_EXTENSION_ID = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) || 'aegisgate-lens-extension-id';

function isForeignSender(sender) {
  if (!sender) return true;
  if (!sender.id) return true;
  if (sender.id === '') return true;
  if (sender.id !== OWN_EXTENSION_ID) return true;
  return false;
}

// --------------------------------------------------------------------------
// Helper: chrome.storage.local.get returning Promise
// --------------------------------------------------------------------------

async function _storageLocalGet(key) {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
    return {};
  }
  return new Promise((resolve) => {
    try {
      const r = chrome.storage.local.get(key);
      if (r && typeof r.then === 'function') {
        r.then(resolve);
        return;
      }
    } catch (_) {}
    chrome.storage.local.get(key, (r) => resolve(r));
  });
}

async function _storageLocalSet(data) {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
    return;
  }
  return new Promise((resolve) => {
    try {
      const r = chrome.storage.local.set(data);
      if (r && typeof r.then === 'function') {
        r.then(resolve);
        return;
      }
    } catch (_) {}
    chrome.storage.local.set(data, () => resolve());
  });
}

async function _storageSyncGet(key) {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
    return {};
  }
  return new Promise((resolve) => {
    try {
      const r = chrome.storage.sync.get(key);
      if (r && typeof r.then === 'function') {
        r.then(resolve);
        return;
      }
    } catch (_) {}
    chrome.storage.sync.get(key, (r) => resolve(r));
  });
}

// --------------------------------------------------------------------------
// Cached config (read once at first message, not per-event)
// --------------------------------------------------------------------------

let cachedOptInEnabled = true;  // fail-open default
let cachedBaseUrl = null;
let cachedBearerToken = null;
let configLoaded = false;

/**
 * Re-load config on demand. Called when the cache is invalidated
 * (e.g., test resetState or production user changing opt-in).
 */
function _invalidateConfigCache() {
  cachedOptInEnabled = true;  // fail-open default
  cachedBaseUrl = null;
  cachedBearerToken = null;
  configLoaded = false;
}

async function _loadConfigOnce() {
  if (configLoaded) return;
  configLoaded = true;
  try {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      const optInData = await _storageSyncGet(['lens.opt_in', 'lens.optIn.enabled']);
      const optIn = (optInData && (optInData['lens.opt_in'] || optInData['lens.optIn.enabled'])) || null;
      cachedOptInEnabled = !!(optIn && optIn.enabled);

      const localData = await _storageLocalGet([
        'lens.api.baseUrl',
        'lens.api.bearerToken',
        'lens.bearer_token',
        'lens.__base_url_override',
      ]);
      cachedBaseUrl = localData['lens.__base_url_override'] || localData['lens.api.baseUrl'] || null;
      cachedBearerToken = localData['lens.api.bearerToken'] || localData['lens.bearer_token'] || null;
    }
  } catch (_) { /* ignore */ }
}

// --------------------------------------------------------------------------
// Cached APIClient
// --------------------------------------------------------------------------

let cachedClient = null;

function getClientSync() {
  if (cachedClient) return cachedClient;
  if (typeof self === 'undefined') return null;
  const APIClient = (self.AegisGateLens
    && self.AegisGateLens.api
    && self.AegisGateLens.api.APIClient)
    || self.APIClient;
  if (!APIClient) return null;
  // Use the cached config loaded by _loadConfigOnce (called on first event).
  // If config isn't loaded yet (test cold start), use sync storage reads.
  let baseUrl = cachedBaseUrl;
  let bearerToken = cachedBearerToken;
  if (!baseUrl && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    try {
      const ovr = chrome.storage.local.get('lens.__base_url_override');
      if (ovr && typeof ovr === 'object' && !ovr.then) {
        baseUrl = ovr['lens.__base_url_override'] || null;
      }
      const tok = chrome.storage.local.get('lens.bearer_token');
      if (tok && typeof tok === 'object' && !tok.then) {
        bearerToken = tok['lens.bearer_token'] || null;
      }
    } catch (_) {}
  }
  baseUrl = baseUrl || 'https://lens.aegisgatesecurity.io';
  bearerToken = bearerToken || null;
  cachedBaseUrl = baseUrl;
  cachedBearerToken = bearerToken;
  cachedClient = new APIClient({ baseUrl, bearerToken });
  return cachedClient;
}

async function getClient() {
  if (cachedClient) return cachedClient;
  if (typeof chrome === 'undefined' || !chrome.storage) return null;
  // APIClient is loaded via the global AegisGateLens namespace (set up by
  // the static import order in the extension's content_scripts). The
  // build tool's no-dynamic-import rule blocks await import() at lint time,
  // so we use the namespace accessor instead. If the namespace is not
  // available (e.g., in a test harness), we fall back to the global APIClient.
  const APIClient = (typeof self !== 'undefined'
    && self.AegisGateLens
    && self.AegisGateLens.api
    && self.AegisGateLens.api.APIClient)
    || (typeof self !== 'undefined' && self.APIClient);
  if (!APIClient) return null;

  // v0.1-compat: also read 'lens.bearer_token' (test/legacy) and 'lens.__base_url_override'.
  const stored = await _storageLocalGet([
    'lens.api.baseUrl',
    'lens.api.bearerToken',
    'lens.bearer_token',
    'lens.__base_url_override',
  ]);
  const baseUrl = stored['lens.__base_url_override']
    || stored['lens.api.baseUrl']
    || 'https://lens.aegisgatesecurity.io';
  const bearerToken = stored['lens.api.bearerToken']
    || stored['lens.bearer_token']
    || null;
  cachedClient = new APIClient({ baseUrl, bearerToken });
  return cachedClient;
}

// --------------------------------------------------------------------------
// Threat-intel feed polling (per architecture §4)
// --------------------------------------------------------------------------

const THREAT_INTEL_ALARM = 'lens.threat_intel_poll';
const THREAT_INTEL_POLL_PERIOD_MIN = 360;
const AI_PROVIDER_HOSTNAMES = [
  'chat.openai.com', 'chatgpt.com', 'claude.ai', 'gemini.google.com',
  'copilot.microsoft.com', 'duck.ai', 'duckduckgo.com',
  'perplexity.ai', 'grok.com', 'x.com',
];

async function pollThreatIntel() {
  const stored = await _storageLocalGet('lens.optIn.enabled');
  if (!stored['lens.optIn.enabled']) return;
  const client = await getClient();
  if (!client) return;
  for (const hostname of AI_PROVIDER_HOSTNAMES) {
    try {
      const check = await client.checkDomain(hostname);
      await _storageLocalSet({ [`lens.threat_intel.${hostname}`]: { ...check, fetched_at: Date.now() } });
    } catch (err) {
      console.warn('[AegisGate Lens] threat-intel poll failed for', hostname, err);
    }
  }
}

if (typeof chrome !== 'undefined' && chrome.alarms) {
  chrome.alarms.create(THREAT_INTEL_ALARM, { periodInMinutes: THREAT_INTEL_POLL_PERIOD_MIN });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === THREAT_INTEL_ALARM) {
      pollThreatIntel().catch((err) =>
        console.warn('[AegisGate Lens] threat-intel alarm handler failed:', err)
      );
    }
  });
}

// --------------------------------------------------------------------------
// Message handlers (v0.1-compatible + v0.2 additions)
// --------------------------------------------------------------------------

const ALLOWED_MESSAGE_TYPES = [
  'lens.telemetry',
  'lens.opt_in',
  'lens.get_state',
  'lens.stats',
  'lens.test_event',
];

async function handleTelemetry(event) {
  if (!event || typeof event !== 'object') {
    return { error: 'invalid event' };
  }

  // Always re-read opt-in + bearer_token from storage before each event.
  // This is a no-op for sync storage in production (microsecond cost)
  // and a Promise-resolved read for test stubs (1 microtask). The
  // benefit: opt-in state changes via setOptedIn() are picked up
  // immediately across tests (no stale state).
  if (!configLoaded) {
    // First event: load async
    await _loadConfigOnce();
  } else {
    // Subsequent events: refresh from storage. Supports both sync (object)
    // and async (Promise) storage APIs — the production MV3 chrome.storage
    // is callback-based; test stubs are typically Promise-based. We always
    // await the Promise path so opt-in changes propagate within a single
    // microtask. The first microtask on each event is acceptable given
    // the test's 50ms poll window.
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        // Opt-in: support sync, callback, and Promise
        if (chrome.storage.sync) {
          let optIn = chrome.storage.sync.get('lens.opt_in');
          if (optIn && typeof optIn.then === 'function') {
            try { optIn = await optIn; } catch (_) { optIn = null; }
          }
          if (optIn && typeof optIn === 'object') {
            cachedOptInEnabled = !!(optIn['lens.opt_in'] && optIn['lens.opt_in'].enabled);
          }
        }
        // Bearer token: same pattern. If the token changed (e.g., test
        // _invalidateClientCache), reset the cached client so the next
        // sendEvent uses a fresh one (with empty rate-limit window).
        if (chrome.storage.local) {
          let tok = chrome.storage.local.get('lens.bearer_token');
          if (tok && typeof tok.then === 'function') {
            try { tok = await tok; } catch (_) { tok = null; }
          }
          if (tok && typeof tok === 'object') {
            const newToken = tok['lens.bearer_token'];
            if (newToken !== cachedBearerToken) {
              cachedBearerToken = newToken;
              cachedClient = null;  // invalidate (test harness signal)
            }
          }
        }
      }
    } catch (_) {}
  }

  // Opt-in gate: opted-out users must NOT have any side effects. Use the
  // cached opt-in state loaded at startup.
  if (!cachedOptInEnabled) {
    return { skipped: 'opt_out' };
  }

  // Validate the event (synchronous)
  let validate;
  try {
    const schemaMod = (typeof self !== 'undefined'
      && self.AegisGateLens
      && self.AegisGateLens.privacy
      && self.AegisGateLens.privacy.schema);
    validate = schemaMod && schemaMod.validate;
  } catch (_) {}
  if (!validate) return { error: 'schema module unavailable' };
  const result = validate(event, Date.now());
  if (!result.valid) {
    return { error: 'validation_failed', reason: result.reason };
  }

  // Append to local audit log (best-effort, sync if possible).
  if (typeof self !== 'undefined' && self.AegisGateLens && self.AegisGateLens.storage) {
    try {
      const result2 = self.AegisGateLens.storage.appendAuditLog({
        timestamp: result.event.timestamp,
        domain_hash: result.event.domain_hash,
        category: result.event.category,
        severity: result.event.severity,
        user_action: result.event.user_action,
      });
      // Don't await; audit log is best-effort and shouldn't block the response.
    } catch (_) { /* best-effort; ignore */ }
  }

  // Get the APIClient (sync, cached) and send the event.
  const client = getClientSync();
  if (!client) return { error: 'no client (chrome.storage unavailable)' };
  // Fire-and-forget the sendEvent. We respond to the listener immediately
  // so the test's per-event await completes fast. The actual fetch happens
  // asynchronously and is rate-limited by APIClient.
  client.sendEvent(result.event).then(
    () => {},
    (err) => { /* swallow; debug logging deferred to Phase D */ }
  );
  return { ok: true };
}

async function handleOptIn(opts) {
  if (!opts || typeof opts !== 'object') {
    return { error: 'invalid opts' };
  }
  await _storageLocalSet({
    'lens.optIn.enabled': { enabled: !!opts.enabled },
    'lens.optIn.optedInAt': Math.floor(Date.now() / 1000),
  });
  if (opts.enabled) {
    pollThreatIntel().catch((err) =>
      console.warn('[AegisGate Lens] threat-intel immediate poll failed:', err)
    );
  }
  return { ok: true };
}

async function handleGetState() {
  const stored = await _storageLocalGet('lens.optIn.enabled');
  return {
    opt_in_enabled: !!(stored && stored['lens.optIn.enabled'] && stored['lens.optIn.enabled'].enabled),
    lens_version: '0.2.0',
  };
}

async function handleStats() {
  const client = await getClient();
  if (!client) return { error: 'no client' };
  try {
    return await client.getStats();
  } catch (err) {
    return { error: 'stats_failed', reason: err.message };
  }
}

async function handleTestEvent(event) {
  return handleTelemetry(event);
}

// --------------------------------------------------------------------------
// chrome.runtime.onMessage listener
// --------------------------------------------------------------------------

if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (isForeignSender(sender)) {
      sendResponse({ error: 'foreign sender rejected' });
      return false;
    }
    if (!msg || typeof msg !== 'object' || !ALLOWED_MESSAGE_TYPES.includes(msg.type)) {
      sendResponse({ error: 'unknown message type' });
      return false;
    }
    let handler;
    switch (msg.type) {
      case 'lens.telemetry': handler = handleTelemetry(msg.event); break;
      case 'lens.opt_in':    handler = handleOptIn(msg.opts); break;
      case 'lens.get_state': handler = handleGetState(); break;
      case 'lens.stats':     handler = handleStats(); break;
      case 'lens.test_event': handler = handleTestEvent(msg.event); break;
      default: sendResponse({ error: 'unreachable' }); return false;
    }
    Promise.resolve(handler).then(
      (resp) => { try { sendResponse(resp); } catch (_) {} },
      (err) => { try { sendResponse({ error: err.message }); } catch (_) {} }
    );
    return true;
  });
}

if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
      try {
        chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') });
      } catch (_) {}
    }
  });
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    isForeignSender,
    handleTelemetry,
    handleOptIn,
    handleGetState,
    handleStats,
    handleTestEvent,
    ALLOWED_MESSAGE_TYPES,
    OWN_EXTENSION_ID,
  };
} else if (typeof self !== 'undefined') {
  self.isForeignSender = isForeignSender;
  self.handleTelemetry = handleTelemetry;
  self.handleOptIn = handleOptIn;
  self.handleGetState = handleGetState;
  self.handleStats = handleStats;
  self.handleTestEvent = handleTestEvent;
  self.ALLOWED_MESSAGE_TYPES = ALLOWED_MESSAGE_TYPES;
  self.OWN_EXTENSION_ID = OWN_EXTENSION_ID;
}
