// AegisGate Lens — logger.js
// Tiny console wrapper that NEVER silently swallows errors.
// Per the architecture doc and standing rules: every .catch() must log
// the actual err with a contextual prefix.
//
// Loaded as the FIRST content_script (per manifest.json content_scripts
// order) so all subsequent content-script modules can use this logger.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // The single shared logger object. Exposed on `self.__lensLogger` so
  // other content-script modules can grab it without coupling to the
  // global `aegisgateLens` namespace (which may not be initialized yet
  // when this file first runs).
  var logger = {
    tag: '[AegisGate Lens]',

    info: function (msg, extra) {
      try {
        if (extra === undefined) {
          console.info(this.tag + ' ' + msg);
        } else {
          console.info(this.tag + ' ' + msg, extra);
        }
      } catch (e) {
        // Last-resort fallback: the logging itself failed (e.g. console
        // is not available in some sandboxed context). Do NOT swallow
        // silently — re-throw so the caller knows logging is broken.
        throw new Error('logger.info failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    warn: function (msg, extra) {
      try {
        if (extra === undefined) {
          console.warn(this.tag + ' ' + msg);
        } else {
          console.warn(this.tag + ' ' + msg, extra);
        }
      } catch (e) {
        throw new Error('logger.warn failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    error: function (msg, err) {
      // The KEY rule: always log the actual err object. Never use a
      // useless "init failed" string. If err is undefined, log that
      // we have no err object — don't pretend we do.
      try {
        if (err === undefined || err === null) {
          console.error(this.tag + ' ' + msg + ' (no err object provided)');
        } else if (err instanceof Error) {
          console.error(this.tag + ' ' + msg + ':', err.message, err.stack || '');
        } else {
          // err might be a string, a plain object, anything
          console.error(this.tag + ' ' + msg + ':', err);
        }
      } catch (e) {
        // Logging failed. We can't log the failure, so we re-throw
        // with a meaningful message.
        throw new Error('logger.error failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    // Convenience: wrap a promise so any rejection is logged with context.
    // Use: `logger.guard('analytics.flush', analytics.flush())`
    guard: function (context, promise) {
      if (!promise || typeof promise.then !== 'function') {
        this.error('logger.guard called with non-promise', { context: context, value: promise });
        return Promise.reject(new Error('logger.guard: not a promise'));
      }
      return promise.catch(function (err) {
        this.error(context, err);
        // Re-throw so the caller's .then chain still sees the rejection
        throw err;
      }.bind(this));
    }
  };

  // Expose on multiple globals for compatibility:
  //   - `self.__lensLogger` (the canonical reference)
  //   - `window.__lensLogger` (when the content script runs in a page
  //     context with a window, which it does because it's injected)
  //   - `globalThis.__lensLogger` (modern standard)
  if (typeof self !== 'undefined') {
    /**
     * @type {import("./typedefs").LensLogger}
     */
    self.__lensLogger = logger;
  }
  if (typeof window !== 'undefined') {
    window.__lensLogger = logger;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensLogger = logger;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
