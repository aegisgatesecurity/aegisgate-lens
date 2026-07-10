// AegisGate Lens — test/helpers/mock-chrome.js
//
// A comprehensive mock of the Chrome extension APIs (chrome.*)
// used by the SW (background.js) and content scripts.
//
// This mock covers the surface area actually used by AegisGate
// Lens: chrome.storage, chrome.runtime, chrome.tabs.
//
// Why this helper exists (v0.1.1 item 8):
// - The previous MockChrome was inline in sw-messages.test.mjs
//   and had a corrupted construction history (the assistant
//   had to clean it up during an earlier session). Extracting
//   it to a helper makes the mock testable, reusable, and
//   harder to accidentally break.
// - Other tests (dispatcher, banner-ui-dismiss, etc.) need
//   similar mocking and previously had to duplicate the
//   class definitions.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

// ============================================================
// MockStorage: chrome.storage.local in-memory shim
// ============================================================
export class MockStorage {
  constructor() { this._data = {}; }
  get(keys, cb) {
    var result = {};
    if (Array.isArray(keys)) {
      for (var i = 0; i < keys.length; i++) {
        if (this._data[keys[i]] !== undefined) result[keys[i]] = this._data[keys[i]];
      }
    } else if (typeof keys === 'string') {
      if (this._data[keys] !== undefined) result[keys] = this._data[keys[i]];
    } else {
      // Object (defaults)
      Object.assign(result, this._data);
    }
    if (cb) setTimeout(function () { cb(result); }, 0);
    return Promise.resolve(result);
  }
  set(obj, cb) {
    Object.assign(this._data, obj);
    if (cb) setTimeout(function () { cb(); }, 0);
    return Promise.resolve();
  }
  remove(keys, cb) {
    if (Array.isArray(keys)) {
      for (var i = 0; i < keys.length; i++) delete this._data[keys[i]];
    }
    if (cb) setTimeout(function () { cb(); }, 0);
    return Promise.resolve();
  }
  clear() { this._data = {}; }
}

// ============================================================
// MockRuntime: chrome.runtime shim with sender-id capture
// ============================================================
export class MockRuntime {
  constructor() {
    this.id = 'test-extension-id';
    this.lastError = null;
    this.listeners = {};
  }
  getURL(path) { return 'chrome-extension://' + this.id + '/' + path; }
  // v0.1.2 F-10: sendMessage now dispatches to the registered
  // __onMessageHandler (the SW's onMessage listener). The
  // handler is expected to call the response callback
  // synchronously or asynchronously. If no handler is
  // registered, the callback is invoked with a "no
  // receiver" error. This mirrors Chrome's actual behavior
  // when chrome.runtime.sendMessage has no listener.
  sendMessage(msg, responseCallback) {
    var cr = this;
    var respond = function (response) {
      if (typeof responseCallback === 'function') {
        // chrome.runtime.lastError is set when there's no
        // receiver; tests can set it before calling
        // sendMessage to simulate the error path.
        responseCallback(response || undefined);
      }
    };
    if (globalThis.__onMessageHandler) {
      try {
        // Chrome sends a fake sender; we use {} since the
        // SW validates sender.id which we don't have here.
        var result = globalThis.__onMessageHandler(msg, { id: cr.id }, respond);
        // If the handler returned true, it will call respond
        // asynchronously. If false, it already called respond
        // synchronously. If undefined, it called respond
        // synchronously too. Either way, our job is done.
        if (result === true) {
          // async response expected; the handler will call respond
        }
        return;
      } catch (e) {
        // Fall through to error path
        cr.lastError = { message: (e && e.message) || String(e) };
        respond();
        return;
      }
    }
    // No receiver: Chrome sets lastError and calls back with
    // no response. (See F-10 popup.js readOptInViaMessage.)
    cr.lastError = { message: 'Could not establish connection. Receiving end does not exist.' };
    respond();
  }
  onMessage_addListener(fn) { this.listeners.message = fn; }
  onInstalled_addListener(fn) { this.listeners.installed = fn; }
  onStartup_addListener(fn) { this.listeners.startup = fn; }
}

// Use prototype for the event-handler objects (avoids the
// "Cannot set property onMessage of #<MockRuntime> which has
// only a getter" error that bites us when we try to assign
// these on the instance).
MockRuntime.prototype.onMessage = {
  addListener: function (fn) { globalThis.__onMessageHandler = fn; }
};
MockRuntime.prototype.onInstalled = {
  addListener: function (fn) { globalThis.__onInstalledHandler = fn; }
};
MockRuntime.prototype.onStartup = {
  addListener: function (fn) { globalThis.__onStartupHandler = fn; }
};

// ============================================================
// MockTabs: chrome.tabs shim with tab event listeners
// ============================================================
export class MockTabs {
  constructor() { this.tabs = []; }
  create(opts) {
    this.tabs.push(opts);
    return Promise.resolve({ id: this.tabs.length });
  }
  onUpdated = {
    _listeners: [],
    addListener(fn) { this._listeners.push(fn); }
  };
  onRemoved = {
    _listeners: [],
    addListener(fn) { this._listeners.push(fn); }
  };
  onActivated = {
    _listeners: [],
    addListener(fn) { this._listeners.push(fn); }
  };
  query() { return Promise.resolve(this.tabs); }
  get() { return Promise.resolve(this.tabs[0]); }
  update() { return Promise.resolve(); }
  remove() { return Promise.resolve(); }
}

// ============================================================
// MockChrome: the top-level chrome.* shim
// ============================================================
export class MockChrome {
  constructor() {
    this.storage = { local: new MockStorage() };
    this.runtime = new MockRuntime();
    this.tabs = new MockTabs();
  }
}

// ============================================================
// installMockChrome(): helper to install the mock on globalThis
// so that the production src/ code's references to `chrome.*`
// resolve to our mock instead of `undefined`.
// ============================================================
export function installMockChrome() {
  globalThis.chrome = new MockChrome();
  return globalThis.chrome;
}

// ============================================================
// resetMockChrome(): helper to reset state between tests.
// Clears storage, recreates the chrome mock, and clears any
// global event handlers that previous tests set.
// ============================================================
export function resetMockChrome() {
  if (globalThis.__onMessageHandler) delete globalThis.__onMessageHandler;
  if (globalThis.__onInstalledHandler) delete globalThis.__onInstalledHandler;
  if (globalThis.__onStartupHandler) delete globalThis.__onStartupHandler;
  return installMockChrome();
}
