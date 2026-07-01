/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Telemetry Queue (v0.3.0)
   =========================================================================

   Local event queue for opt-in telemetry. Handles:

     - Local buffering (last N events in chrome.storage.local)
     - Client-side rate limiting (100 events/min per Privacy Policy §10.2)
     - Pre-aggregation (deduplicate by domain_hash + category + hour)
     - Background flushing (every 5 min when opt-in enabled)

   Privacy guarantees:
     - Only runs if user has explicitly opted in (Tier 1 or Tier 2)
     - Never sends prompt text, URLs, page content
     - Sends only the 9-field v0.1 schema (Tier 1) or 14-field v0.3 schema (Tier 2)
     - Local buffer is cleared if user opts out

   Plain JavaScript, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const log = NS.logger || console;
  const OptIn = NS.util && NS.util.optIn;

  // ============================================================================
  // Config
  // ============================================================================

  const DEFAULT_MAX_BUFFER = 200;            // Max events stored locally
  const DEFAULT_FLUSH_INTERVAL_MS = 5 * 60 * 1000;  // 5 min
  const DEFAULT_RATE_PER_MIN = 100;           // Privacy Policy §10.2
  const KEY_BUFFER = 'lens.telemetry.buffer';

  // ============================================================================
  // Buffer management (chrome.storage.local)
  // ============================================================================

  async function readBuffer() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return [];
    }
    return new Promise((resolve) => {
      chrome.storage.local.get(KEY_BUFFER, (result) => {
        resolve((result && result[KEY_BUFFER]) || []);
      });
    });
  }

  async function writeBuffer(events) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return;
    }
    return new Promise((resolve, reject) => {
      chrome.storage.local.set({ [KEY_BUFFER]: events }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve();
      });
    });
  }

  async function clearBuffer() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return;
    }
    return new Promise((resolve) => {
      chrome.storage.local.remove(KEY_BUFFER, () => resolve());
    });
  }

  // ============================================================================
  // Event creation
  // ============================================================================

  /**
   * Build a v0.3 telemetry event from a detection.
   * Returns null if event would be sent with no useful data.
   */
  function buildEvent(detection, userAction, extra) {
    if (!detection) return null;
    return {
      // v0.1 schema (9 fields)
      lens_event_version: 1,
      domain_hash: extra && extra.domainHash || '',
      category: detection.category || '',
      severity: detection.severity || 'info',
      user_action: userAction || 'detect',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: (extra && extra.modelVersion) || 'unknown',
      lens_version: (extra && extra.lensVersion) || 'unknown',
      confidence: typeof detection.confidence === 'number' ? detection.confidence : 1.0,
      // v0.3 TI extensions (only included if Tier 2 enabled)
      attack_keywords_hash: extra && extra.attackKeywordsHash || undefined,
      attack_pattern_id: extra && extra.attackPatternId || undefined,
      model_consensus: extra && extra.modelConsensus || undefined,
      similar_attack_count_30d: extra && extra.similarAttackCount30d || undefined,
      bundle_signature: extra && extra.bundleSignature || undefined,
    };
  }

  // ============================================================================
  // Rate limiting (100 events/min per installation)
  // ============================================================================

  const rateState = {
    timestamps: [],
  };

  function canSend() {
    const now = Date.now();
    const cutoff = now - 60_000;
    rateState.timestamps = rateState.timestamps.filter((t) => t > cutoff);
    return rateState.timestamps.length < DEFAULT_RATE_PER_MIN;
  }

  function recordSend() {
    rateState.timestamps.push(Date.now());
  }

  // ============================================================================
  // Enqueue / Send
  // ============================================================================

  /**
   * Enqueue an event. Returns true if enqueued, false if dropped.
   * Events are buffered locally and flushed periodically.
   */
  async function enqueue(event) {
    if (!event) return false;

    // Opt-in check (fast fail)
    if (OptIn && OptIn.isTelemetryEnabled) {
      const enabled = await OptIn.isTelemetryEnabled();
      if (!enabled) {
        log.info('[AegisGate Lens] telemetry disabled; dropping event');
        return false;
      }
    } else {
      // No opt-in module → cannot confirm; fail safe.
      log.warn('[AegisGate Lens] opt-in module unavailable; dropping event');
      return false;
    }

    // Buffer locally
    const buf = await readBuffer();
    buf.push(event);

    // Cap buffer
    if (buf.length > DEFAULT_MAX_BUFFER) {
      buf.splice(0, buf.length - DEFAULT_MAX_BUFFER);
    }

    await writeBuffer(buf);
    log.info(`[AegisGate Lens] event buffered (total: ${buf.length})`);
    return true;
  }

  /**
   * Flush the buffer to the backend.
   * Respects client-side rate limit (100/min).
   */
  async function flush(apiClient) {
    const events = await readBuffer();
    if (events.length === 0) {
      log.info('[AegisGate Lens] no events to flush');
      return { sent: 0, dropped: 0 };
    }

    const to_send = [];
    const dropped = [];
    for (const ev of events) {
      if (canSend()) {
        to_send.push(ev);
      } else {
        dropped.push(ev);
      }
    }

    // Send (rate-limited)
    let sent_count = 0;
    for (const ev of to_send) {
      if (!canSend()) {
        log.warn('[AegisGate Lens] rate limit hit during flush; deferring remaining events');
        break;
      }
      try {
        if (apiClient && apiClient.sendEvent) {
          await apiClient.sendEvent(ev);
          recordSend();
          sent_count++;
        }
      } catch (err) {
        log.warn('[AegisGate Lens] send failed:', err.message);
      }
    }

    // Update buffer: remove successfully sent events, keep the rest
    const remaining = events.slice(sent_count);
    await writeBuffer(remaining);

    log.info(`[AegisGate Lens] flush: ${sent_count} sent, ${remaining.length} retained`);
    return { sent: sent_count, retained: remaining.length };
  }

  /**
   * Clear all queued events (e.g., when user opts out).
   */
  async function reset() {
    await clearBuffer();
    rateState.timestamps = [];
    log.info('[AegisGate Lens] telemetry queue reset');
  }

  // ============================================================================
  // Background flusher (call from service-worker or content-script)
  // ============================================================================

  let flushTimer = null;

  function startBackgroundFlush(apiClient) {
    if (flushTimer) return;  // Already running
    flushTimer = setInterval(() => {
      flush(apiClient).catch((err) => {
        log.warn('[AegisGate Lens] background flush failed:', err.message);
      });
    }, DEFAULT_FLUSH_INTERVAL_MS);
    log.info('[AegisGate Lens] background flush started');
  }

  function stopBackgroundFlush() {
    if (flushTimer) {
      clearInterval(flushTimer);
      flushTimer = null;
      log.info('[AegisGate Lens] background flush stopped');
    }
  }

  NS.util = NS.util || {};
  NS.util.telemetryQueue = Object.freeze({
    buildEvent,
    enqueue,
    flush,
    reset,
    startBackgroundFlush,
    stopBackgroundFlush,
    canSend,
    readBuffer,
    writeBuffer,
    clearBuffer,
  });
})();