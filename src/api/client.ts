// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - API Client
// =========================================================================
//
// The API client sends LensEvent payloads to the Lens backend
// at POST /api/v1/lens/telemetry. The privacy policy §10.2
// commits to:
//
//   - 100 events/min per installation (client-side enforced)
//   - 10K events/min server-side (defense in depth)
//   - TLS 1.2+ only (HTTP is rejected)
//   - No payload in the request body other than the 9 fields
//     in the LensEvent schema
//
// This file is the browser-side implementation of those
// commitments. The client-side rate limit is the "100/min
// per installation" cap. The server-side cap is the
// backend's responsibility.
//
// v0.1 pre-release.
// =========================================================================

import { validate } from "../privacy/schema.js";
import type {
  HealthzResponse,
  LensEvent,
  StatsResponse,
  CheckResponse,
} from "../types.js";

/** Configuration for the API client. */
export interface ClientConfig {
  /**
   * The base URL of the Lens backend, including the scheme
   * (e.g., "https://lens.aegisgatesecurity.io"). The client
   * REJECTS http:// URLs in production builds; the allowlist
   * for development/testing is "http://localhost" and
   * "http://127.0.0.1" only.
   */
  baseUrl: string;

  /**
   * The bearer token used in the Authorization header.
   * This is the extension's installation secret, derived
   * from the user's opt-in flow. It is stored in
   * chrome.storage.sync.
   */
  bearerToken: string;

  /**
   * Per-installation rate limit, in events/min. Default 100.
   * Configurable for testing; production uses the privacy
   * policy's locked value.
   */
  eventsPerMinute?: number;

  /**
   * Optional fetch implementation. Defaults to the global
   * fetch. Tests inject a mock.
   */
  fetchImpl?: typeof fetch;
}

/**
 * The 100/min default. Matches the privacy policy.
 */
const DEFAULT_EVENTS_PER_MINUTE = 100;

/**
 * Hard-coded production URL. The dev/test override is
 * chrome.storage.local["__lens_base_url_override"].
 */
const DEFAULT_BASE_URL = "https://lens.aegisgatesecurity.io";

/**
 * The allowed schemes. We reject http:// in production
 * (TLS-only). Localhost/127.0.0.1 are exempted for the
 * testlab integration tests.
 */
const ALLOWED_SCHEMES: ReadonlyArray<"https" | "http"> = ["https", "http"];
const ALLOWED_HOSTS_FOR_HTTP: ReadonlySet<string> = new Set([
  "localhost",
  "127.0.0.1",
  "[::1]",
]);

/**
 * APIClient is the Lens's interface to the backend. It is
 * the only module that knows the backend's URL, the
 * bearer token, or the rate-limit policy.
 */
export class APIClient {
  // Simplified from a TS intersection type (`Required<Omit<...>> & {...}`)
  // to a plain class field so the stripper can handle it.
  private readonly cfg;
  private readonly rateLimitState: RateLimitState;

  constructor(config: ClientConfig) {
    // Validate the base URL.
    let url: URL;
    try {
      url = new URL(config.baseUrl);
    } catch {
      throw new Error(`invalid baseUrl: ${config.baseUrl}`);
    }
    if (!ALLOWED_SCHEMES.includes(url.protocol.slice(0, -1) | "http")) {
      throw new Error(
        `unsupported scheme: ${url.protocol} (must be https, or http for localhost)`,
      );
    }
    if (url.protocol === "http:" && !ALLOWED_HOSTS_FOR_HTTP.has(url.hostname)) {
      throw new Error(
        `http is only allowed for localhost/127.0.0.1; got ${url.hostname}`,
      );
    }
    if (!config.bearerToken || config.bearerToken.length === 0) {
      throw new Error("bearerToken must be non-empty");
    }
    this.cfg = {
      baseUrl: config.baseUrl,
      bearerToken: config.bearerToken,
      eventsPerMinute: config.eventsPerMinute ?? DEFAULT_EVENTS_PER_MINUTE,
      // globalThis.fetch does not use `this`, so no .bind
      // is needed. The previous code used
      // `globalThis.fetch.bind(globalThis)` which created a
      // new function on every constructor call.
      fetchImpl: config.fetchImpl ?? globalThis.fetch,
    };
    this.rateLimitState = new RateLimitState(this.cfg.eventsPerMinute);
  }

  /**
   * Send a single event to POST /api/v1/lens/telemetry.
   *
   * Returns true on success, false on rate-limit skip.
   * Throws on validation error or HTTP non-2xx (caller's
   * job to log; the client does not retain a payload).
   */
  async sendEvent(event: LensEvent): Promise<boolean> {
    // Validate the event one more time on the client side.
    const v = validate(event);
    if (!v.valid) {
      throw new Error(`client-side validation failed: ${v.reason}`);
    }
    // Check the per-installation rate limit.
    if (!this.rateLimitState.allow()) {
      return false; // silently drop; the rate-limit job
                    // is a backpressure mechanism, not a
                    // security boundary.
    }
    // Send. The Authorization header is the bearer token;
    // the body is the JSON-encoded event. No other fields.
    const url = `${this.cfg.baseUrl}/api/v1/lens/telemetry`;
    const resp = await this.cfg.fetchImpl(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.cfg.bearerToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(event),
    });
    if (!resp.ok) {
      throw new Error(
        `telemetry HTTP ${resp.status}: ${await safeReadBody(resp)}`,
      );
    }
    return true;
  }

  /**
   * Call GET /api/v1/lens/check?domain=<hostname>.
   * Used by the popup UI to show the user whether a given
   * AI provider has any known IOCs.
   */
  async checkDomain(hostname: string): Promise<CheckResponse> {
    const url = new URL(`${this.cfg.baseUrl}/api/v1/lens/check`);
    url.searchParams.set("domain", hostname);
    const resp = await this.cfg.fetchImpl(url.href, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${this.cfg.bearerToken}`,
      },
    });
    if (!resp.ok) {
      throw new Error(`check HTTP ${resp.status}: ${await safeReadBody(resp)}`);
    }
    return (await resp.json());
  }

  /**
   * Call GET /api/v1/lens/stats. Returns the 24-hour
   * aggregate counts. Used by the popup UI to show the
   * user their contribution to the network.
   */
  async getStats(): Promise<StatsResponse> {
    const resp = await this.cfg.fetchImpl(
      `${this.cfg.baseUrl}/api/v1/lens/stats`,
      {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${this.cfg.bearerToken}`,
        },
      },
    );
    if (!resp.ok) {
      throw new Error(`stats HTTP ${resp.status}: ${await safeReadBody(resp)}`);
    }
    return (await resp.json());
  }

  /**
   * Call GET /api/v1/lens/healthz. No bearer token required.
   * Used by the extension's startup health check.
   */
  async healthz(): Promise<HealthzResponse> {
    const resp = await this.cfg.fetchImpl(
      `${this.cfg.baseUrl}/api/v1/lens/healthz`,
      { method: "GET" },
    );
    if (!resp.ok) {
      throw new Error(`healthz HTTP ${resp.status}`);
    }
    return (await resp.json());
  }
}

/**
 * RateLimitState implements a coarse-grained sliding-window
 * rate limit. It tracks the timestamps of the last N events
 * in a ring buffer of length eventsPerMinute. An event is
 * allowed if there are fewer than N events in the last 60
 * seconds.
 *
 * The window advances by one slot per event, not
 * continuously. For 100 events/min, this is a 1-second
 * resolution approximation of a true sliding window, which
 * is sufficient for the privacy policy's 100/min cap.
 *
 * The implementation is intentionally minimal: a 100-element
 * array, a write index, a count. O(1) per check.
 */
class RateLimitState {
  private readonly cap: number;
  private readonly ring: number[];
  private writeIdx = 0;
  private count = 0;
  private windowStart = 0;

  constructor(eventsPerMinute: number) {
    this.cap = eventsPerMinute;
    this.ring = new Array<number>(eventsPerMinute);
    for (let i = 0; i < eventsPerMinute; i++) {
      this.ring[i] = 0;
    }
  }

  /**
   * Returns true if an event is allowed under the
   * per-installation rate limit, false otherwise.
   */
  allow(): boolean {
    const now = Date.now();
    // If the last window start is more than 60s ago,
    // reset the ring.
    if (now - this.windowStart > 60_000) {
      this.windowStart = now;
      this.count = 0;
      this.writeIdx = 0;
      for (let i = 0; i < this.cap; i++) {
        this.ring[i] = 0;
      }
    }
    // The ring contains the last `count` event timestamps,
    // in insertion order (oldest at writeIdx-count, newest
    // at writeIdx-1). If the oldest is more than 60s old,
    // it's outside the window and the slot is free.
    if (this.count === this.cap) {
      const oldest = this.ring[this.writeIdx];
      if (now - oldest < 60_000) {
        return false; // cap reached within window
      }
      // Oldest event is outside the window; overwrite it.
      this.ring[this.writeIdx] = now;
      this.writeIdx = (this.writeIdx + 1) % this.cap;
      return true;
    }
    // Cap not reached; record the event.
    this.ring[this.writeIdx] = now;
    this.writeIdx = (this.writeIdx + 1) % this.cap;
    this.count++;
    return true;
  }
}

/**
 * Safely read a response body, swallowing JSON-decode
 * errors. Used for error messages only.
 */
async function safeReadBody(resp: Response): Promise<string> {
  try {
    return await resp.text();
  } catch {
    return "<unreadable>";
  }
}

/** The default base URL. */
export const DEFAULT_API_BASE_URL = DEFAULT_BASE_URL;
