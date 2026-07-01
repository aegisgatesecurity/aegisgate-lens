/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Logger
   =========================================================================

   Minimal logger used by every Lens module. Writes to console with
   the "[AegisGate Lens]" prefix so support engineers can filter logs
   in DevTools. The Lens never logs prompt content, URLs, or page
   content — only structural events (banner shown, telemetry sent,
   etc.). See legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md
   §4, non-negotiable #1–3.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * @typedef {'debug'|'info'|'warn'|'error'} LogLevel
   */

  /**
   * Minimum level that will be emitted. "warn" means debug/info are
   * suppressed; "error" means only errors are emitted. Default is
   * "info" so end-user DevTools sessions are not flooded.
   *
   * @type {LogLevel}
   */
  let minLevel = 'info';

  /**
   * Numeric rank of each level for cheap comparison.
   * @type {Readonly<Record<LogLevel, number>>}
   */
  const RANK = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40 });

  /**
   * @param {LogLevel} level
   * @returns {number}
   */
  function rank(level) {
    return RANK[level] || RANK.info;
  }

  /**
   * Set the minimum log level. Persisted for the lifetime of the
   * page (i.e., one content script injection). The Lens never
   * persists this — debug-level logs are opt-in for development.
   *
   * @param {LogLevel} level
   */
  function setLevel(level) {
    if (Object.prototype.hasOwnProperty.call(RANK, level)) {
      minLevel = level;
    }
  }

  /**
   * @param {LogLevel} level
   * @param {string} msg
   * @param {...unknown} rest
   */
  function emit(level, msg, ...rest) {
    if (rank(level) < rank(minLevel)) return;
    const line = '[AegisGate Lens] ' + msg;
    // The first arg is the level-specific logger; map by name.
    const fn =
      level === 'error'
        ? console.error
        : level === 'warn'
        ? console.warn
        : level === 'debug'
        ? console.debug
        : console.info;
    if (rest.length === 0) {
      fn(line);
    } else {
      fn(line, ...rest);
    }
  }

  /**
   * @param {string} msg
   * @param {...unknown} rest
   */
  function debug(msg, ...rest) {
    emit('debug', msg, ...rest);
  }

  /**
   * @param {string} msg
   * @param {...unknown} rest
   */
  function info(msg, ...rest) {
    emit('info', msg, ...rest);
  }

  /**
   * @param {string} msg
   * @param {...unknown} rest
   */
  function warn(msg, ...rest) {
    emit('warn', msg, ...rest);
  }

  /**
   * @param {string} msg
   * @param {...unknown} rest
   */
  function error(msg, ...rest) {
    emit('error', msg, ...rest);
  }

  NS.logger = Object.freeze({ debug, info, warn, error, setLevel });
})();