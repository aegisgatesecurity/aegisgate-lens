// AegisGate Lens — background.js (service worker)
//
// Step 3a: minimum viable service worker. It exists so the manifest
// reference is valid and the extension loads cleanly. The full
// implementation comes in 3g (api/messages.js + the message handler)
// and 3h (ML bundle caching + lazy-load).
//
// What this file DOES today (3a):
//   1. Logs on install + on startup
//   2. Opens the welcome page on first install
//   3. Validates sender.id on every message (per F-01: foreign senders
//      are rejected even though no message handlers exist yet)
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

// self here is the service worker global. In MV3, this is an isolated
// context with no DOM access.
var log = (typeof self !== 'undefined' && self.__lensLogger) ||
          (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
          { info: function(m){ console.log('[AegisGate Lens SW] ' + m); },
            warn: function(m){ console.warn('[AegisGate Lens SW] ' + m); },
            error: function(m,e){ console.error('[AegisGate Lens SW] ' + m, e); } };

// In an MV3 service worker, the content scripts we load via
// content_scripts.js share a separate global context. They can't
// directly set self.__lensLogger; we set it here from our own
// bundle. Logger is duplicated in SW (not shared) for simplicity.

self.__lensLogger = log;

// F-01: validate sender.id on every message. Even though no message
// handlers exist yet, we set up the listener so the security boundary
// is in place from day one.
function isOwnSender(sender) {
  if (!sender) return false;
  if (typeof sender.id !== 'string' || sender.id.length === 0) return false;
  // chrome.runtime.id is our own extension's ID; foreign extensions
  // send a different sender.id.
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.id) return false;
  // Case-sensitive comparison (no toLowerCase bypass)
  return sender.id === chrome.runtime.id;
}

// Service worker lifecycle hooks
self.addEventListener('install', function (event) {
  log.info('service worker installed');
  // Skip waiting so the SW activates immediately on update.
  if (typeof self.skipWaiting === 'function') {
    self.skipWaiting();
  }
});

self.addEventListener('activate', function (event) {
  log.info('service worker activated');
  // Claim existing clients so content scripts on already-open pages
  // start working immediately on SW update.
  if (event && typeof event.waitUntil === 'function' && typeof self.clients === 'object') {
    event.waitUntil(self.clients.claim());
  }
});

// chrome.runtime.onMessage: validate sender, then route.
// Step 3a: only the F-01 validation exists. Message routing comes in 3g.
if (typeof chrome !== 'undefined' && chrome.runtime && typeof chrome.runtime.onMessage === 'object') {
  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    try {
      if (!isOwnSender(sender)) {
        log.warn('rejecting message from foreign sender: ' + (sender && sender.id ? sender.id : '<no-id>'));
        try { sendResponse({ error: 'foreign sender rejected' }); } catch (e) { /* ignore */ }
        return false;
      }
      // No handlers yet. In 3g we route by message.type.
      log.info('received message (no handler yet in 3a): type=' + (message && message.type ? message.type : '<no-type>'));
      try { sendResponse({ ok: true, status: 'received' }); } catch (e) { /* ignore */ }
      return false; // synchronous response
    } catch (err) {
      log.error('onMessage handler threw', err);
      return false;
    }
  });
}

// On install: open the welcome page. Per the architecture doc, the
// welcome page is the user's first contact with the privacy posture.
if (typeof chrome !== 'undefined' && chrome.runtime && typeof chrome.runtime.onInstalled === 'object') {
  chrome.runtime.onInstalled.addListener(function (details) {
    try {
      log.info('runtime.onInstalled: ' + (details && details.reason ? details.reason : '<unknown>'));
      if (details && details.reason === 'install' && chrome.tabs && typeof chrome.tabs.create === 'function') {
        chrome.tabs.create({ url: chrome.runtime.getURL('src/welcome/welcome.html') });
      }
    } catch (err) {
      log.error('onInstalled handler threw', err);
    }
  });
}

log.info('background.js loaded; service worker ready');
