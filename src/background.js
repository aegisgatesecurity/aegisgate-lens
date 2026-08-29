// AegisGate Lens — background.js (the MV3 service worker)
//
// Per docs/ARCHITECTURE-v0.1.3.md Section 8, the SW:
//   1. Receives messages from the content script (validated)
//   2. Owns chrome.storage.local (content scripts cannot share state)
//   3. Persists dismissals (24h scope)
//   4. Sends FP reports to the backend ONLY when the user has
//      explicitly opted in (via "Submit & dismiss")
//   5. Is 100% local by default (Tier 0)
//
// The SW is NOT a module (per the architecture doc and the threat
// model F-02). No "type": "module" in the manifest.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  // --- Tiny logger (the SW has its own console; logger.js is
  // for the content script because it doesn't have a global
  // __lensLogger when it boots) ---
  var log = {
    info: function (m) { try { console.log('[AegisGate Lens SW] ' + m); } catch (e) {} },
    warn: function (m) { try { console.warn('[AegisGate Lens SW] ' + m); } catch (e) {} },
    error: function (m, e) {
      try { console.error('[AegisGate Lens SW] ' + m, e); } catch (e2) {}
    }
  };

  log.info('background.js loaded; service worker ready');
  // Constants from src/util/constants.js (loaded via globalThis)
  var C = (typeof self !== 'undefined' && self.__lensConstants) ||
           (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
           null;


  // Load the messages module. In the SW context, scripts are
  // loaded via importScripts() OR by being in the same JS file
  // (we chose the latter for transparency). To avoid duplicating
  // the messages module, we use a minimal inline copy below.
  // The content script uses src/api/messages.js; the SW uses
  // the same shape but inlined here.
  //
  // We DO NOT use importScripts() because that would require
  // the file to be web-accessible (which would leak it to
  // page content) OR bundled into the SW. For 1 file we
  // inline; if the module grows, we'll revisit.
  var M = {
    TYPE: {
      PING: 'PING',
      DETECTION: 'DETECTION',
      USER_ACTION: 'USER_ACTION',
      FP_REPORTS: 'FP_REPORTS',
      GET_OPT_IN_STATE: 'GET_OPT_IN_STATE',
      OPEN_LENS_POPUP: 'OPEN_LENS_POPUP',
      PONG: 'PONG',
      ACK: 'ACK',
      ERROR: 'ERROR',
      OPT_IN_STATE: 'OPT_IN_STATE'
    },
    isValidEnvelope: function (msg) {
      if (msg === null || typeof msg !== 'object') return false;
      if (typeof msg.type !== 'string') return false;
      if (typeof msg.version !== 'string') return false;
      if (!msg.payload || typeof msg.payload !== 'object') return false;
      return true;
    },
    isValidDetection: function (msg) {
      if (!this.isValidEnvelope(msg)) return false;
      if (msg.type !== 'DETECTION') return false;
      var p = msg.payload;
      return typeof p.timestamp === 'number' && p.timestamp > 0 &&
             typeof p.domain_hash === 'string' && /^[0-9a-f]{16}$/.test(p.domain_hash) &&
             typeof p.facet === 'string' &&
             typeof p.category === 'string' &&
             ['low', 'medium', 'high', 'critical'].indexOf(p.severity) !== -1 &&
             typeof p.count === 'number' && p.count > 0;
    },
    isValidFPReports: function (msg) {
      if (!this.isValidEnvelope(msg)) return false;
      if (msg.type !== 'FP_REPORTS') return false;
      var p = msg.payload;
      if (!Array.isArray(p.reports)) return false;
      var forbidden = ['text', 'prompt', 'url', 'page_content',
                       'page', 'input', 'output', 'value', 'matches',
                       'cookies', 'keystrokes', 'mouse', 'fingerprint'];
      for (var i = 0; i < p.reports.length; i++) {
        var r = p.reports[i];
        if (typeof r !== 'object' || r === null) return false;
        for (var j = 0; j < forbidden.length; j++) {
          if (r[forbidden[j]] !== undefined) return false;
        }
        if (typeof r.domain_hash !== 'string' || !/^[0-9a-f]{16}$/.test(r.domain_hash)) return false;
        if (typeof r.category !== 'string') return false;
        if (typeof r.facet !== 'string') return false;
        if (typeof r.severity !== 'string') return false;
      }
      return true;
    }
  };

  // --- Storage helpers ---

  // Get a value from chrome.storage.local. Returns Promise.
  function storageGet(key) {
    return new Promise(function (resolve) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
          resolve(null);
          return;
        }
        chrome.storage.local.get([key], function (result) {
          if (chrome.runtime && chrome.runtime.lastError) {
            log.warn('storage get failed: ' + chrome.runtime.lastError.message);
            resolve(null);
            return;
          }
          resolve(result[key] || null);
        });
      } catch (e) {
        log.error('storageGet threw', e);
        resolve(null);
      }
    });
  }

  function storageSet(key, value) {
    return new Promise(function (resolve) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
          resolve(false);
          return;
        }
        var obj = {};
        obj[key] = value;
        chrome.storage.local.set(obj, function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            log.warn('storage set failed: ' + chrome.runtime.lastError.message);
            resolve(false);
            return;
          }
          resolve(true);
        });
      } catch (e) {
        log.error('storageSet threw', e);
        resolve(false);
      }
    });
  }

  // --- The FP report queue ---
  // When the user opts in, we send the reports. If the network
  // is down, we persist them in chrome.storage.local and
  // retry on the next SW startup (or when a new FP_REPORTS
  // message arrives).

  var FP_QUEUE_KEY = 'aegisgate_lens_fp_queue';
  // v0.1.2 F-2: OPT_IN_KEY now matches constants.js STORAGE_KEYS.OPT_IN
  // (aegisgate_lens_opt_in). Previously the SW and the welcome page used
  // different keys; the two opt-in states never synced. The fix unifies
  // on a single nested-object shape { enabled, last_changed_at, lens_version }.
  // The key is centralized in constants.js; this string literal is a
  // defensive fallback for the case where constants.js fails to load.
  var OPT_IN_KEY = (C && C.STORAGE_KEYS && C.STORAGE_KEYS.OPT_IN) || 'aegisgate_lens_opt_in';
  var LENS_VERSION = (C && C.STORAGE_SCHEMA_VERSION) || '0.1.1';
  var LAST_SEND_KEY = 'aegisgate_lens_last_fp_send';

  // The backend endpoint. Default: the Cloudflare Worker endpoint.
  // Configurable via storage for self-hosted users who point their
  // Lens extension at their own Platform instance.
  var DEFAULT_BACKEND = 'https://lens.aegisgatesecurity.io';

  // H-5 fix: Validate backend URL to prevent SSRF. Must be HTTPS.
  function isValidBackendUrl(url) {
    if (typeof url !== 'string' || url.length === 0) return false;
    if (url.indexOf('https://') !== 0) return false; // Must be HTTPS
    try {
      var parsed = new URL(url);
      if (parsed.protocol !== 'https:') return false;
      // Block loopback/private IPs (SSRF protection)
      var host = parsed.hostname;
      if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' ||
          host === '::1' || host.indexOf('127.') === 0 ||
          host.indexOf('10.') === 0 || host.indexOf('192.168.') === 0 ||
          host.indexOf('169.254.') === 0) {
        // Allow loopback for self-hosted Platform on localhost (local tool)
        // but log a warning
        log.warn('backend URL points to loopback/private IP: ' + host + ' (acceptable for self-hosted Platform)');
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  function getBackend() {
    return storageGet('aegisgate_lens_backend_url').then(function (url) {
      if (url && isValidBackendUrl(url)) return url;
      if (url && !isValidBackendUrl(url)) {
        log.warn('stored backend URL is invalid (must be HTTPS); using default');
      }
      return DEFAULT_BACKEND;
    });
  }

  // Bearer token for Platform self-hosted users. The Cloudflare Worker
  // (DEFAULT_BACKEND) does not require a bearer token; it uses
  // Cloudflare-native rate limiting. But when the backend is a
  // self-hosted Platform instance, the /api/v1/lens/* and /lens/*
  // endpoints require Authorization: Bearer <token>.
  // M-8 (accepted risk): Token stored in chrome.storage.local as plaintext.
  // This is the same model as AWS CLI (~/.aws/credentials) and kubectl
  // (~/.kube/config). chrome.storage.local is scoped to the extension and
  // not accessible to web pages. Future: OS keychain integration.
  var BEARER_TOKEN_KEY = 'aegisgate_lens_bearer_token';

  function getBearerToken() {
    return storageGet(BEARER_TOKEN_KEY).then(function (token) {
      return token || '';
    });
  }

  // v0.1.2 F-2: getOptIn now reads the unified nested-object shape
  // { enabled, last_changed_at, lens_version } written by welcome.js
  // and setOptIn (below). Returns { enabled: bool, lastChangedAt: number|null,
  // lensVersion: string|null } so callers can show the user when they
  // last changed their opt-in state.
  function getOptIn() {
    return storageGet(OPT_IN_KEY).then(function (v) {
      if (!v) return { enabled: false, lastChangedAt: null, lensVersion: null };
      if (typeof v === 'boolean') {
        // Backwards-compat: v0.1.0-beta wrote a bare boolean. Treat as enabled
        // with a synthetic last_changed_at = null (we don't know when).
        return { enabled: v === true, lastChangedAt: null, lensVersion: null };
      }
      if (typeof v === 'object') {
        return {
          enabled: v.enabled === true,
          lastChangedAt: typeof v.last_changed_at === 'number' ? v.last_changed_at : null,
          lensVersion: typeof v.lens_version === 'string' ? v.lens_version : null
        };
      }
      return { enabled: false, lastChangedAt: null, lensVersion: null };
    });
  }

  // v0.1.2 F-2: setOptIn now writes the unified nested-object shape.
  // Preserves the previous lens_version if there is one (in case the
  // user opted in on an older version and is upgrading).
  function setOptIn(optedIn) {
    return storageGet(OPT_IN_KEY).then(function (prev) {
      var prevVersion = (prev && typeof prev === 'object' && typeof prev.lens_version === 'string')
        ? prev.lens_version
        : LENS_VERSION;
      var payload = {
        enabled: !!optedIn,
        last_changed_at: Math.floor(Date.now() / 1000),
        lens_version: prevVersion
      };
      return storageSet(OPT_IN_KEY, payload);
    });
  }

  // Add a report (or array of reports) to the queue
  function enqueueFP(reports) {
    return storageGet(FP_QUEUE_KEY).then(function (queue) {
      queue = queue || [];
      if (!Array.isArray(reports)) reports = [reports];
      for (var i = 0; i < reports.length; i++) {
        // Tag with a client-generated UUID so we can dedup
        // (also useful for the backend to ignore duplicates)
        if (!reports[i].client_id) {
          reports[i].client_id = generateUUID();
        }
        queue.push(reports[i]);
      }
      return storageSet(FP_QUEUE_KEY, queue);
    });
  }

  // Drain the queue: send all queued reports in one batch
  function drainQueue() {
    return Promise.all([
      storageGet(FP_QUEUE_KEY),
      getBackend(),
      getOptIn(),
      getBearerToken()
    ]).then(function (results) {
      var queue = results[0] || [];
      var backend = results[1];
      // v0.1.2 F-2: getOptIn now returns { enabled, lastChangedAt, lensVersion }.
      var optInState = results[2] || { enabled: false, lastChangedAt: null, lensVersion: null };
      var bearerToken = results[3] || '';
      var optedIn = optInState.enabled === true;
      if (queue.length === 0) return { sent: 0, failed: 0 };
      if (!optedIn) {
        // The user revoked opt-in between sending and now.
        // Drop the queue. The privacy guarantee is paramount.
        log.info('queue drained but user is not opted in; dropping ' + queue.length + ' reports');
        return storageSet(FP_QUEUE_KEY, []).then(function () {
          return { sent: 0, failed: 0, dropped: queue.length };
        });
      }
      return sendToBackend(backend, queue, bearerToken).then(function (result) {
        if (result.success) {
          return storageSet(FP_QUEUE_KEY, []).then(function () {
            return storageSet(LAST_SEND_KEY, Date.now()).then(function () {
              return { sent: queue.length, failed: 0 };
            });
          });
        } else {
          // Keep the queue; we'll retry on next send or SW startup
          log.warn('queue send failed; will retry. reason: ' + result.reason);
          return { sent: 0, failed: queue.length, reason: result.reason };
        }
      });
    });
  }

  // Send a batch of reports to the backend. If bearerToken is
  // non-empty, include it as an Authorization header (Platform
  // self-hosted). The Cloudflare Worker (default backend) does
  // not require a bearer token.
  function sendToBackend(backend, reports, bearerToken) {
    return new Promise(function (resolve) {
      try {
        if (typeof fetch === 'undefined') {
          resolve({ success: false, reason: 'fetch not available' });
          return;
        }
        var url = backend.replace(/\/+$/, '') + '/lens/telemetry/fp-report';
        var headers = { 'Content-Type': 'application/json' };
        if (bearerToken) {
          headers['Authorization'] = 'Bearer ' + bearerToken;
        }
        fetch(url, {
          method: 'POST',
          headers: headers,
          body: JSON.stringify({
            lens_event_version: '0.3.0',
            timestamp: Math.floor(Date.now() / 1000),
            reports: reports
          }),
          // F-25 (v0.1.4 polish): wire up a real 10-second timeout via
          // AbortController. Previously the signal was a no-op (a
          // placeholder controller whose .abort() was never called), so
          // a hung backend could keep the SW alive until Chrome's 30s
          // SW kill timer fired. The fix: create a controller, schedule
          // abort() in 10s, pass the controller's signal. On abort,
          // fetch rejects and the catch handler resolves with reason
          // 'aborted (10s timeout)'.
          signal: (function () {
            if (typeof AbortController === 'undefined') return undefined;
            var c = new AbortController();
            setTimeout(function () { try { c.abort(); } catch (e) {} }, 10000);
            return c.signal;
          })()
        }).then(function (resp) {
          if (resp.ok) {
            log.info('sent ' + reports.length + ' FP reports to backend');
            resolve({ success: true });
          } else {
            resolve({ success: false, reason: 'HTTP ' + resp.status });
          }
        }).catch(function (err) {
          // If the fetch was aborted by our 10s timeout, surface a clear
          // reason. DOMException with name 'AbortError' is the standard
          // signal; some Chrome versions use err.code === 20.
          var reason = (err && (err.name === 'AbortError' || err.code === 20))
            ? 'aborted (10s timeout)'
            : (err && err.message) || String(err);
          resolve({ success: false, reason: reason });
        });
      } catch (e) {
        log.error('sendToBackend threw', e);
        resolve({ success: false, reason: (e && e.message) || String(e) });
      }
    });
  }

  // Simple UUID v4 generator (RFC 4122). No external deps.
  function generateUUID() {
    var b = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(b);
    } else {
      for (var i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
    }
    // RFC 4122 v4
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var s = '';
    for (var j = 0; j < 16; j++) {
      var hex = b[j].toString(16);
      if (hex.length === 1) hex = '0' + hex;
      s += hex;
      if (j === 3 || j === 5 || j === 7 || j === 9) s += '-';
    }
    return s;
  }

  // --- Message handlers ---

  // PING: respond with PONG (used to verify SW is alive)
  function handlePing(msg, sender, sendResponse) {
    sendResponse({ type: M.TYPE.PONG, version: msg.version, payload: { ok: true } });
  }

  // DETECTION: log the detection (local-only for now; future
  // versions may aggregate detection counts for the popup)
  function handleDetection(msg, sender, sendResponse) {
    if (!M.isValidDetection(msg)) {
      sendResponse({ type: M.TYPE.ERROR, version: msg.version,
                     payload: { error: 'invalid detection message' } });
      return;
    }
    log.info('detection: ' + msg.payload.facet + '/' + msg.payload.category +
             ' severity=' + msg.payload.severity + ' count=' + msg.payload.count);
    // Increment a local counter (for the popup badge in 3j)
    storageGet('aegisgate_lens_detection_count').then(function (count) {
      count = (count || 0) + 1;
      return storageSet('aegisgate_lens_detection_count', count);
    });
    sendResponse({ type: M.TYPE.ACK, version: msg.version, payload: { ok: true } });
  }

  // USER_ACTION: log what the user did (send/cancel/dismiss).
  // Local-only; the privacy doc says we may store "user_action"
  // in the schema but for v1.0 we just log it.
  function handleUserAction(msg, sender, sendResponse) {
    if (!M.isValidEnvelope(msg)) {
      sendResponse({ type: M.TYPE.ERROR, version: msg.version,
                     payload: { error: 'invalid user_action message' } });
      return;
    }
    var p = msg.payload;
    log.info('user_action: ' + p.action + ' domain=' + p.domain_hash);
    // Persist user actions for the popup / opt-in flow (3i)
    storageGet('aegisgate_lens_user_actions').then(function (actions) {
      actions = actions || [];
      actions.push({
        action: p.action,
        domain_hash: p.domain_hash,
        timestamp: p.timestamp
      });
      // Cap at last 100 actions to keep storage small
      if (actions.length > ((C && C.MAX_USER_ACTIONS) || 100)) actions = actions.slice(-((C && C.MAX_USER_ACTIONS) || 100));
      return storageSet('aegisgate_lens_user_actions', actions);
    });
    sendResponse({ type: M.TYPE.ACK, version: msg.version, payload: { ok: true } });
  }

  // FP_REPORTS: the user explicitly opted in to send. Queue
  // the reports, then attempt to drain. If opt-in is FALSE
  // (the user revoked after the banner fired but before this
  // message was sent), we drop the reports.
  function handleFPReports(msg, sender, sendResponse) {
    if (!M.isValidFPReports(msg)) {
      sendResponse({ type: M.TYPE.ERROR, version: msg.version,
                     payload: { error: 'invalid FP_REPORTS message (privacy check failed)' } });
      return;
    }
    // Mark the user as opted in (they clicked Submit & dismiss)
    setOptIn(true).then(function () {
      // Enqueue all reports
      return enqueueFP(msg.payload.reports);
    }).then(function () {
      // Attempt to drain immediately
      return drainQueue();
    }).then(function (result) {
      log.info('FP reports: ' + JSON.stringify(result));
      sendResponse({ type: M.TYPE.ACK, version: msg.version, payload: result });
    }).catch(function (err) {
      log.error('FP_REPORTS handler failed', err);
      sendResponse({ type: M.TYPE.ERROR, version: msg.version,
                     payload: { error: (err && err.message) || String(err) } });
    });
  }

  // GET_OPT_IN_STATE: the popup (3j) asks whether the user
  // has opted in. v0.1.2 F-2: the response now includes the full
  // { enabled, last_changed_at, lens_version } state so the popup
  // can show the user when they last changed their opt-in.
  // Backwards-compat: still includes a flat `opted_in` boolean for
  // any older popup that reads only the boolean.
  function handleGetOptInState(msg, sender, sendResponse) {
    getOptIn().then(function (optInState) {
      sendResponse({
        type: M.TYPE.OPT_IN_STATE,
        version: msg.version,
        payload: {
          opted_in: optInState.enabled === true,
          enabled: optInState.enabled === true,
          last_changed_at: optInState.lastChangedAt,
          lens_version: optInState.lensVersion
        }
      });
    });
  }

  // v0.1.4 Bug #4 fix: open the extension popup when the user
  // clicks the "🛡️ Lens active" indicator on a content page. The
  // popup has the 3 v0.1.4 features (hide indicator, pause 1h/1d,
  // "Not PII" dismiss). This handler is a no-op for the popup
  // itself — the openPopup() call opens the UI; we don't need to
  // send a response back. We log to the SW log on success/failure
  // so the user can see in the SW console if it broke.
  function handleOpenLensPopup(msg, sender, sendResponse) {
    try {
      if (typeof chrome !== 'undefined' && chrome.action && chrome.action.openPopup) {
        chrome.action.openPopup().catch(function (e) {
          // openPopup() may fail in some contexts (Chrome 99-101
          // restricted it to user-gesture toolbar actions; in those
          // cases we log a warning and the user can still click
          // the toolbar icon to open the popup). The catch on
          // openPopup() catches the promise rejection; we ALSO
          // wrap in try/catch in case openPopup is synchronous-throws.
          try { log.warn('openPopup failed: ' + (e && e.message)); } catch (e2) {}
        });
      } else {
        log.warn('chrome.action.openPopup unavailable; user can still use toolbar icon');
      }
    } catch (e) {
      try { log.warn('handleOpenLensPopup threw: ' + (e && e.message)); } catch (e2) {}
    }
    // We MUST return false (synchronous response) because we are
    // not keeping the channel open — the popup will appear as a
    // side-effect, not as a message response.
    if (typeof sendResponse === 'function') {
      try { sendResponse({ type: M.TYPE.ACK, version: msg.version, payload: { ok: true } }); } catch (e) {}
    }
  }

  // The message router. The SW validates sender.id (must be
  // chrome.runtime.id; i.e., our own extension) and dispatches.
  // This is F-01 from the threat model: defend against messages
  // from other extensions or page content.
  function onMessage(msg, sender, sendResponse) {
    try {
      // F-01: validate sender. In MV3, sender.id is the extension
      // id for extension-to-extension messages. For content
      // scripts, sender.id is also chrome.runtime.id.
      if (sender && sender.id && chrome.runtime && chrome.runtime.id) {
        if (sender.id !== chrome.runtime.id) {
          log.warn('rejecting message from foreign sender: ' + sender.id);
          sendResponse({ type: M.TYPE.ERROR, payload: { error: 'foreign sender' } });
          return false;  // do not keep the channel open
        }
      }
      // Validate envelope
      if (!M.isValidEnvelope(msg)) {
        log.warn('rejecting message with invalid envelope');
        sendResponse({ type: M.TYPE.ERROR, payload: { error: 'invalid envelope' } });
        return false;
      }
      // Dispatch
      switch (msg.type) {
        case M.TYPE.PING:            handlePing(msg, sender, sendResponse); return false;
        case M.TYPE.DETECTION:       handleDetection(msg, sender, sendResponse); return false;
        case M.TYPE.USER_ACTION:     handleUserAction(msg, sender, sendResponse); return false;
        case M.TYPE.FP_REPORTS:      handleFPReports(msg, sender, sendResponse); return true;  // async
        case M.TYPE.GET_OPT_IN_STATE: handleGetOptInState(msg, sender, sendResponse); return true;  // async
        case M.TYPE.OPEN_LENS_POPUP:  handleOpenLensPopup(msg, sender, sendResponse); return false;  // sync (popup is side-effect)
        default:
          log.warn('unknown message type: ' + msg.type);
          sendResponse({ type: M.TYPE.ERROR, payload: { error: 'unknown type' } });
          return false;
      }
    } catch (err) {
      log.error('onMessage threw', err);
      try { sendResponse({ type: M.TYPE.ERROR, payload: { error: 'internal error' } }); } catch (e) {}
      return false;
    }
  }

  // --- Lifecycle ---

  // On install: open the welcome page (3a behavior)
  chrome.runtime.onInstalled.addListener(function (details) {
    try {
      log.info('installed: ' + details.reason);
      if (details.reason === 'install') {
        chrome.tabs.create({ url: chrome.runtime.getURL('src/welcome/welcome.html') });
      }
    } catch (e) {
      log.error('onInstalled handler threw', e);
    }
    // Try to drain the FP queue on every install/startup
    drainQueue().catch(function (err) { log.warn('startup drain failed', err); });
  });

  // On tab update: dynamically inject content script for providers
  // This handles sites with Cloudflare access controls (like perplexity.ai)
  // that block static content_scripts injection
  chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    try {
      // Only inject on successful navigation (not on background loads)
      if (changeInfo.status !== 'complete') return;
      
      // Get the hostname from the URL
      var url = tab.url || '';
      var hostname = '';
      try {
        var urlObj = new URL(url);
        hostname = urlObj.hostname;
      } catch (e) {
        return; // Invalid URL
      }
      
      // Check if this is one of our provider domains
      // Provider domains. Mirrors src/util/selectors.js PROVIDERS +
      // src/manifest.json content_scripts.matches. The three sets MUST
      // stay in sync; the test/unit/manifest-hosts.test.mjs test asserts
      // this on every CI run.
      //
      // x.com, twitter.com, and duckduckgo.com were removed in v0.1.2:
      //   - x.com / twitter.com: the Grok tab lives at grok.com (not x.com);
      //     posting to x.com is a different surface and not in v0.1.x scope.
      //   - duckduckgo.com: Duck.ai lives at duck.ai; duckduckgo.com is the
      //     search engine, not the AI chat.
      var providerDomains = [
        'chat.openai.com', 'chatgpt.com',
        'claude.ai',
        'gemini.google.com',
        'copilot.microsoft.com', 'copilot.cloud.microsoft',
        'duck.ai',
        'perplexity.ai', 'www.perplexity.ai',
        'grok.com', 'www.grok.com',
        'chat.mistral.ai', 'le-chat.mistral.ai',
        'chat.deepseek.com',
        'meta.ai', 'www.meta.ai'
      ];
      
      var isProviderDomain = false;
      for (var i = 0; i < providerDomains.length; i++) {
        var domain = providerDomains[i];
        if (hostname === domain || hostname.endsWith('.' + domain)) {
          isProviderDomain = true;
          break;
        }
      }
      
      if (!isProviderDomain) return;
      
      // Check if already injected (to avoid duplicate injections)
      storageGet('aegisgate_lens_injected_tabs').then(function (injectedTabs) {
        injectedTabs = injectedTabs || {};
        if (injectedTabs[tabId]) return; // Already injected
        
        // Mark as injected
        injectedTabs[tabId] = Date.now();
        storageSet('aegisgate_lens_injected_tabs', injectedTabs).then(function () {
          // Dynamically inject the content script.
          // The file list MUST match manifest.json content_scripts[0].js
          // exactly (including the src/ prefix and all sub-modules).
          // The test/e2e/manifest-validation.test.mjs test guards against
          // drift between this list and the manifest.
          chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: [
              'src/browser-compat.js',
              'src/util/logger.js',
              'src/util/constants.js',
              'src/util/typedefs.js',
              'src/detectors/luhn.js',
              'src/detectors/regex/pii-us-core.js',
              'src/detectors/regex/pii-us-extended.js',
              'src/detectors/regex/pii-international-id.js',
              'src/detectors/regex/pii-financial.js',
              'src/detectors/regex/pii.js',
              'src/detectors/regex/ot-protocols.js',
              'src/detectors/regex/secrets.js',
              'src/detectors/regex/source_xss.js',
              'src/detectors/regex/compliance.js',
              'src/privacy/schema.js',
              'src/privacy/domain_hash.js',
              'src/detectors/ml/char-normalizer.js',
              'src/detectors/ml/threat-detector-js.js',
              'src/detectors/index.js',
              'src/util/selectors.js',
              'src/util/prompt-detect-dom.js',
              'src/util/prompt-detect-lifecycle.js',
              'src/util/prompt-detect.js',
              'src/util/banner-icons.js',
              'src/util/dismiss.js',
              'src/util/banner-ui-formatters.js',
              'src/util/banner-ui-html.js',
              'src/util/banner-ui-lifecycle.js',
              'src/util/banner-ui.js',
              'src/content.js'
            ]
          }).then(function () {
            log.info('dynamically injected content script into tab ' + tabId + ' (' + hostname + ')');
          }).catch(function (err) {
            log.warn('dynamic injection failed for tab ' + tabId + ': ' + err.message);
          });
        });
      });
    } catch (e) {
      log.error('onTabUpdate handler threw', e);
    }
  });

  // On startup (SW reactivated): drain the queue
  chrome.runtime.onStartup.addListener(function () {
    try {
      log.info('startup');
      drainQueue().catch(function (err) { log.warn('startup drain failed', err); });
    } catch (e) {
      log.error('onStartup handler threw', e);
    }
  });

  // The message listener. The `chrome.runtime.onMessage` event
  // fires when any content script or extension sends a message.
  // Defensive: handle both `chrome.runtime.onMessage` (MV3)
  // and `chrome.onMessage` (some test environments expose it
  // at the chrome level).
  var onMessageEvent = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) ||
                       (typeof chrome !== 'undefined' && chrome.onMessage) ||
                       null;
  if (onMessageEvent && typeof onMessageEvent.addListener === 'function') {
    onMessageEvent.addListener(onMessage);
  } else {
    log.warn('no onMessage event found; SW will not receive messages');
  }

  // Keep the SW alive briefly after a message is processed
  // (MV3 SWs can be killed within 30s of inactivity, but our
  // async handlers may take longer for FP report sending)
  // Note: we don't actually need this for short operations,
  // but it makes the SW more reliable for the queue drain.

  log.info('SW message handlers registered');

  // Expose for tests (when loaded outside the SW context).
  // We check both self and globalThis because:
  //   - In the SW: self is the WorkletGlobalScope (not standard)
  //     but globalThis is always the worker's global
  //   - In tests: self is undefined (strict mode in eval), but
  //     globalThis is always available
  var _exposeTarget = (typeof self !== 'undefined' && self) ||
                      (typeof globalThis !== 'undefined' && globalThis) ||
                      null;
  if (_exposeTarget) {
    _exposeTarget.__lensSW = {
      handlePing: handlePing,
      handleDetection: handleDetection,
      handleUserAction: handleUserAction,
      handleFPReports: handleFPReports,
      handleGetOptInState: handleGetOptInState,
      // v0.1.2 F-2: exposed for unit tests that round-trip the opt-in
      // state through the canonical STORAGE_KEYS.OPT_IN key.
      getOptIn: getOptIn,
      setOptIn: setOptIn,
      isValidEnvelope: M.isValidEnvelope,
      isValidDetection: M.isValidDetection,
      isValidFPReports: M.isValidFPReports,
      sendToBackend: sendToBackend,
      drainQueue: drainQueue,
      enqueueFP: enqueueFP,
      generateUUID: generateUUID,
      M: M
    };
  }
})();

