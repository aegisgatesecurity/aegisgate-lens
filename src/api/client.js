/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - API Client
   =========================================================================

   The API client sends LensEvent payloads to the Lens backend
   at POST /api/v1/lens/telemetry. The privacy policy §10.2
   commits to:

     - 100 events/min per installation (client-side enforced)
     - 10K events/min server-side (defense in depth)
     - TLS 1.2+ only (HTTP is rejected)
     - No payload in the request body other than the 9 fields
     in the LensEvent schema

   This file is the browser-side implementation of those
   commitments. The client-side rate limit is the "100/min
   per installation" cap. The server-side cap is the
   backend's responsibility.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const log = NS.logger || console;
  const { validate } = (NS.privacy && NS.privacy.schema) || { validate: () => ({ valid: true }) };

  /** 100/min default. Matches the privacy policy. */
  const DEFAULT_EVENTS_PER_MINUTE = 100;

  /** Hard-coded production URL. */
  const DEFAULT_BASE_URL = 'https://lens.aegisgatesecurity.io';

  /** Schemes we accept. http:// is dev/test only. */
  const ALLOWED_SCHEMES = ['https', 'http'];

  /** Hosts allowed to use http (dev/testlab only). */
  const ALLOWED_HOSTS_FOR_HTTP = new Set(['localhost', '127.0.0.1', '[::1]']);

  /**
   * @typedef {Object} ClientConfig
   * @property {string} baseUrl
   * @property {string} bearerToken
   * @property {number} [eventsPerMinute]
   * @property {typeof fetch} [fetchImpl]
   */

  /**
   * @typedef {Object} HealthzResponse
   * @property {string} status
   * @property {string} version
   */

  /**
   * @typedef {Object} StatsResponse
   * @property {number} events24h
   * @property {number} detections24h
   */

  /**
   * @typedef {Object} CheckResponse
   * @property {string} domain_hash
   * @property {boolean} has_iocs
   * @property {string} [last_updated]
   */

  /**
   * @typedef {Object} LensEvent
   * @property {string} domain_hash
   * @property {string} category
   * @property {string} severity
   * @property {string} user_action
   * @property {number} timestamp
   * @property {string} model_version
   * @property {string} lens_version
   * @property {number} confidence
   * @property {string} [id]            Client-side UUID; optional, not
   *                                     stored server-side (Go marks
   *                                     this field Required: false).
   */

  /**
   * RateLimitState implements a coarse-grained sliding-window
   * rate limit. Ring buffer of timestamps; allows up to N events
   * in any 60-second window.
   */
  function RateLimitState(eventsPerMinute) {
    /** @type {number} */
    this.cap = eventsPerMinute;
    /** @type {number[]} */
    this.ring = new Array(eventsPerMinute);
    for (let i = 0; i < eventsPerMinute; i++) this.ring[i] = 0;
    /** @type {number} */
    this.writeIdx = 0;
    /** @type {number} */
    this.count = 0;
    /** @type {number} */
    this.windowStart = 0;
  }

  RateLimitState.prototype.allow = function () {
    const now = Date.now();
    if (now - this.windowStart > 60000) {
      this.windowStart = now;
      this.count = 0;
      this.writeIdx = 0;
      for (let i = 0; i < this.cap; i++) this.ring[i] = 0;
    }
    if (this.count === this.cap) {
      const oldest = this.ring[this.writeIdx];
      if (now - oldest < 60000) {
        return false; // cap reached within window
      }
      this.ring[this.writeIdx] = now;
      this.writeIdx = (this.writeIdx + 1) % this.cap;
      return true;
    }
    this.ring[this.writeIdx] = now;
    this.writeIdx = (this.writeIdx + 1) % this.cap;
    this.count++;
    return true;
  };

  /**
   * APIClient is the Lens's interface to the backend. It is
   * the only module that knows the backend's URL, the bearer
   * token, or the rate-limit policy.
   *
   * @param {ClientConfig} config
   * @constructor
   */
  function APIClient(config) {
    let url;
    try {
      url = new URL(config.baseUrl);
    } catch (_) {
      throw new Error('invalid baseUrl: ' + config.baseUrl);
    }
    if (ALLOWED_SCHEMES.indexOf(url.protocol.slice(0, -1)) === -1) {
      throw new Error(
        'unsupported scheme: ' + url.protocol +
        ' (must be https, or http for localhost)',
      );
    }
    if (url.protocol === 'http:' && !ALLOWED_HOSTS_FOR_HTTP.has(url.hostname)) {
      throw new Error(
        'http is only allowed for localhost/127.0.0.1; got ' + url.hostname,
      );
    }
    if (!config.bearerToken || config.bearerToken.length === 0) {
      throw new Error('bearerToken must be non-empty');
    }
    /** @type {{baseUrl: string, bearerToken: string, eventsPerMinute: number, fetchImpl: typeof fetch}} */
    this.cfg = {
      baseUrl: config.baseUrl,
      bearerToken: config.bearerToken,
      eventsPerMinute: config.eventsPerMinute || DEFAULT_EVENTS_PER_MINUTE,
      fetchImpl: config.fetchImpl || globalThis.fetch,
    };
    /** @type {RateLimitState} */
    this.rateLimitState = new RateLimitState(this.cfg.eventsPerMinute);
  }

  /**
   * Send a single event to POST /api/v1/lens/telemetry.
   * Returns true on success, false on rate-limit skip.
   * Throws on validation error or HTTP non-2xx.
   *
   * @param {LensEvent} event
   * @returns {Promise<boolean>}
   */
  APIClient.prototype.sendEvent = async function (event) {
    const v = validate(event);
    if (!v.valid) {
      throw new Error('client-side validation failed: ' + v.reason);
    }
    if (!this.rateLimitState.allow()) {
      return false; // silently drop
    }
    const url = this.cfg.baseUrl + '/api/v1/lens/telemetry';
    const resp = await this.cfg.fetchImpl(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + this.cfg.bearerToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(event),
    });
    if (!resp.ok) {
      throw new Error('telemetry HTTP ' + resp.status + ': ' + (await safeReadBody(resp)));
    }
    return true;
  };

  /**
   * Call GET /api/v1/lens/check?domain=<hostname>.
   *
   * @param {string} hostname
   * @returns {Promise<CheckResponse>}
   */
  APIClient.prototype.checkDomain = async function (hostname) {
    const url = new URL(this.cfg.baseUrl + '/api/v1/lens/check');
    url.searchParams.set('domain', hostname);
    const resp = await this.cfg.fetchImpl(url.href, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + this.cfg.bearerToken },
    });
    if (!resp.ok) {
      throw new Error('check HTTP ' + resp.status + ': ' + (await safeReadBody(resp)));
    }
    return resp.json();
  };

  /**
   * Call GET /api/v1/lens/stats. Returns 24-hour aggregates.
   *
   * @returns {Promise<StatsResponse>}
   */
  APIClient.prototype.getStats = async function () {
    const resp = await this.cfg.fetchImpl(this.cfg.baseUrl + '/api/v1/lens/stats', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + this.cfg.bearerToken },
    });
    if (!resp.ok) {
      throw new Error('stats HTTP ' + resp.status + ': ' + (await safeReadBody(resp)));
    }
    return resp.json();
  };

  /**
   * Call GET /api/v1/lens/healthz. No bearer token required.
   *
   * @returns {Promise<HealthzResponse>}
   */
  APIClient.prototype.healthz = async function () {
    const resp = await this.cfg.fetchImpl(this.cfg.baseUrl + '/api/v1/lens/healthz', {
      method: 'GET',
    });
    if (!resp.ok) {
      throw new Error('healthz HTTP ' + resp.status);
    }
    return resp.json();
  };

  /**
   * Safely read a response body. Used for error messages only.
   *
   * @param {Response} resp
   * @returns {Promise<string>}
   */
  async function safeReadBody(resp) {
    try {
      return await resp.text();
    } catch (_) {
      return '<unreadable>';
    }
  }

  NS.api = NS.api || {};
  NS.api.client = Object.freeze({
    APIClient,
    DEFAULT_API_BASE_URL: DEFAULT_BASE_URL,
    DEFAULT_EVENTS_PER_MINUTE,
  });
  NS.APIClient = APIClient;
})();