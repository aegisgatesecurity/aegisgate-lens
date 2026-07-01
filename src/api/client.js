/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - API Client (v0.2.0)
   =========================================================================

   Browser-side HTTP client for the AegisGate Lens backend.
   Implements the wire protocol defined in plans/AEGISGATE-LENS-WIRE-PROTOCOL.md.

   Responsibilities:
     - Send LensEvents (validated by privacy/schema.js) to /v1/events
     - Send anonymous checkDomain requests (for threat-intel feed)
     - Apply client-side rate limiting (100 events/min)
     - TLS 1.2+ enforcement (HTTPS only; HTTP only for localhost)

   v0.2 changes from v0.1:
     - Adds checkDomain() method (already partially in v0.1; wired through)
     - Adds bearer-token auth (per Lens opt-in flow)
     - Same wire-protocol shape as v0.1; schema version 2
   ========================================================================= */

  /**
   * @typedef {Object} LensEvent
   * @property {number} lens_event_version  Schema version. The extension
   *                                       emits 2 (v0.2.0+). The backend
   *                                       accepts ONLY version 2.
   * @property {string} domain_hash       SHA-256 prefix of the AI provider
   *                                       hostname (16 hex chars, k-anonymous)
   * @property {string} category          Enum: pii_email, secret_api_key,
   *                                       xss_payload, etc. (65 categories)
   * @property {string} severity          Enum: low, medium, high, critical
   * @property {string} user_action       Enum: send_anyway, edit, cancel,
   *                                       dismiss
   * @property {number} timestamp         ISO 8601 epoch (seconds since 1970)
   * @property {string} model_version     e.g. "modernbert-v1", "regex-v1"
   * @property {string} lens_version      e.g. "0.3.0"
   * @property {number} confidence       0-1 float
   * @property {string} [id]             Client-side UUID; optional, not
   *                                       stored server-side
   *
   * The cross-language schema contract: this JSDoc @typedef must agree
   * field-for-field with the Go struct in pkg/lensbackend/validation.go
   * (which is enforced by CI via the Platform's tools/build-lens-extension/
   * build tool's validate-schema stage).
   */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const SCHEMA_VERSION = 2;

  function mapCategoryToFacet(category) {
    if (!category) return 1;
    if (category.startsWith('pii_')) return 1;
    if (category.startsWith('secret_')) return 2;
    if (category === 'source_code' || category === 'xss_payload') return 3;
    if (category.startsWith('owasp_') || category.startsWith('atlas_') ||
        category.startsWith('eu_ai_act_') || category.startsWith('anp_') ||
        category.startsWith('computeruse_')) return 4;
    if (category === 'toxicity_custom' || category === 'violence' ||
        category === 'weapons' || category === 'illegal' ||
        category === 'harassment' || category === 'self_harm') return 5;
    if (category === 'prompt_injection_ml' || category === 'prompt_injection_ml_long') return 6;
    return 1;
  }
  const DEFAULT_BASE_URL = 'https://lens.aegisgatesecurity.io';
  const RATE_LIMIT_EVENTS_PER_MIN = 100;
  const HTTP_ONLY_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

  /**
   * APIClient sends telemetry to the Lens backend over HTTPS.
   * @param {Object} opts
   * @param {string} [opts.baseUrl='https://lens.aegisgatesecurity.io']
   * @param {string} [opts.bearerToken] - opt-in bearer token (per Lens opt-in flow)
   * @param {Function} [opts.fetchFn] - injectable fetch (v0.2 name)
   * @param {Function} [opts.fetchImpl] - injectable fetch (v0.1/test name; alias for fetchFn)
   * @param {number} [opts.eventsPerMinute] - rate limit (default 100)
   */
  function APIClient(opts) {
    opts = opts || {};
    this.baseUrl = opts.baseUrl || DEFAULT_BASE_URL;
    this.bearerToken = opts.bearerToken || null;
    this.eventTimestamps = [];  // rolling window for client-side rate limiting
    // v0.2 uses fetchFn; v0.1/test code uses fetchImpl — accept both
    this.fetchFn = opts.fetchFn || opts.fetchImpl || ((typeof fetch !== 'undefined') ? fetch.bind(globalThis) : null);
    // Allow overriding rate limit (for tests)
    this.eventsPerMinute = opts.eventsPerMinute || RATE_LIMIT_EVENTS_PER_MIN;
  }

  APIClient.prototype._enforceTls = function () {
    const url = this.baseUrl;
    if (!url) throw new Error('APIClient: baseUrl is required');
    if (url.startsWith('https://')) return;
    if (url.startsWith('http://')) {
      try {
        const u = new URL(url);
        if (HTTP_ONLY_HOSTS.has(u.hostname)) return;  // OK for tests on localhost
      } catch (_) {}
      throw new Error(`APIClient: non-TLS baseUrl rejected (Privacy Policy): ${url}`);
    }
    throw new Error(`APIClient: baseUrl must use https:// (got ${url})`);
  };

  APIClient.prototype._checkRateLimit = function () {
    const now = Date.now();
    const cutoff = now - 60_000;
    this.eventTimestamps = this.eventTimestamps.filter((t) => t > cutoff);
    if (this.eventTimestamps.length >= this.eventsPerMinute) {
      throw new Error('rate_limited: client-side rate limit hit (' + this.eventsPerMinute + '/min)');
    }
    this.eventTimestamps.push(now);
  };

  /**
   * Test-only diagnostic: print current state to console.
   */
  APIClient.prototype._diagnostic = function () {
    return JSON.stringify({
      eventsPerMinute: this.eventsPerMinute,
      timestampCount: this.eventTimestamps.length,
      baseUrl: this.baseUrl,
    });
  };

  /**
   * Send a single LensEvent to the backend.
   * @param {Object} event - The LensEvent (already validated)
   * @returns {Promise<{status: number, body?: object}>}
   * @throws on 4xx/5xx with status code attached
   */
  APIClient.prototype.sendEvent = async function (event) {
    // v0.1 compat: rate limit returns false (no throw)
    // HTTP errors (4xx/5xx) still throw (with status code in message)
    const now = Date.now();
    const cutoff = now - 60_000;
    this.eventTimestamps = this.eventTimestamps.filter((t) => t > cutoff);
    if (this.eventTimestamps.length >= this.eventsPerMinute) {
      return false;  // rate-limited, silent drop
    }
    this.eventTimestamps.push(now);

    this._enforceTls();

    // v1 backward compat: default facet field for legacy events
    if (event && event.lens_event_version === 1 && !('facet' in event)) {
      event = Object.assign({}, event, { facet: mapCategoryToFacet(event.category) });
    }

    const url = `${this.baseUrl}/api/v1/lens/telemetry`;
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    if (this.bearerToken) headers['Authorization'] = `Bearer ${this.bearerToken}`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(event),
    });

    const status = response.status;
    let body = null;
    const text = await response.text();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch (_) {
        body = { raw: text };
      }
    }

    if (status >= 400) {
      // Format includes "HTTP <code>" for v0.1 test compatibility
      const err = new Error(`HTTP ${status}: ${body && body.error ? body.error : JSON.stringify(body)}`);
      err.status = status;
      err.body = body;
      throw err;
    }
    // v0.1 compat: return true on success
    return true;
  };

  /**
   * v0.2 strict: same as sendEvent but throws on rate limit (instead of
   * returning false). Used when the caller wants to distinguish a rate
   * drop from a successful send.
   */
  APIClient.prototype.sendEventStrict = async function (event) {
    this._checkRateLimit();  // throws on rate limit
    return this.sendEvent(event);
  };

  /**
   * v0.2: Check domain for threat-intel feed (per architecture §4).
   * Returns aggregated network counts; no user-identifying data.
   * @param {string} hostname
   * @returns {Promise<{has_iocs: boolean, ioc_count: number, top_categories: Array}>}
   */
  APIClient.prototype.checkDomain = async function (hostname) {
    this._enforceTls();
    const url = `${this.baseUrl}/api/v1/lens/check?domain=${encodeURIComponent(hostname)}`;
    const headers = { 'Accept': 'application/json' };
    if (this.bearerToken) headers['Authorization'] = `Bearer ${this.bearerToken}`;

    const response = await this.fetchFn(url, { method: 'GET', headers });
    if (response.status >= 400) {
      const err = new Error(`checkDomain ${response.status}`);
      err.status = response.status;
      throw err;
    }
    return await response.json();
  };

  /**
   * v0.2: Get user stats (only when telemetry is opt-in).
   */
  APIClient.prototype.getStats = async function () {
    this._enforceTls();
    if (!this.bearerToken) throw new Error('getStats requires bearerToken (opt-in)');
    const url = `${this.baseUrl}/api/v1/lens/stats`;
    const response = await this.fetchFn(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${this.bearerToken}` },
    });
    if (response.status >= 400) {
      const err = new Error(`getStats ${response.status}`);
      err.status = response.status;
      throw err;
    }
    return await response.json();
  };

  /**
   * v0.2: Health check.
   */
  APIClient.prototype.healthz = async function () {
    this._enforceTls();
    const url = `${this.baseUrl}/api/v1/lens/healthz`;
    const response = await this.fetchFn(url, { method: 'GET' });
    return response.status === 200;
  };

  /**
   * v0.1-compatible: get the current rate-limit state.
   */
  APIClient.prototype.rateLimitState = function () {
    const now = Date.now();
    const cutoff = now - 60_000;
    this.eventTimestamps = this.eventTimestamps.filter((t) => t > cutoff);
    return {
      used: this.eventTimestamps.length,
      max: this.eventsPerMinute,
      window_seconds: 60,
    };
  };

  NS.api = NS.api || {};
  NS.api.APIClient = APIClient;        // v0.2 namespaced
  NS.APIClient = APIClient;             // v0.1 compat (top-level)
  NS.api.SCHEMA_VERSION = SCHEMA_VERSION;
  NS.api.RATE_LIMIT_EVENTS_PER_MIN = RATE_LIMIT_EVENTS_PER_MIN;
})();
