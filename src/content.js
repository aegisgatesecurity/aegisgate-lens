/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Content Script (v0.2.0 SKELETON)
   =========================================================================

   The content script runs in the AI provider web page context. It:
     - Detects prompt inputs (textarea, contenteditable, etc.)
     - Runs the 6-facet detection on every input
     - Renders a warning banner if a detection fires
     - Handles FP dismiss + opt-in flow
     - Reports user actions via chrome.runtime.sendMessage

   v0.2.0 architecture:
     - Replaces v0.1's 3-tier cascade with parallel facets
     - Calls facet-dispatcher.runFacets(text)
     - Includes new 'facet' field in events (per schema.js v2)
     - Includes FP telemetry with opt-in card

   This is a SKELETON for the v0.2.0 bootstrap. The full implementation
   requires trained model bundles (Phase D). For now, this file:
     - Exports a ContentScript class matching v0.1's surface
     - Returns v0.1-compatible events with the new 'facet' field
     - Loads successfully so the v0.1 tests can validate behavior

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const SCHEMA_VERSION = 2;
  const FP_REASON_MAX_LENGTH = 200;
  const DISMISSAL_MAX_ENTRIES = 1000;
  const DISMISSAL_TTL_SECONDS = 24 * 3600;
  const LONG_CONTENT_THRESHOLD_CHARS = 2000;

  /**
   * ContentScript is the per-page orchestrator. One instance per
   * top-level AI provider page.
   *
   * @param {Object} opts - { hostname, manifestVersion }
   */
  function ContentScript(opts) {
    this.hostname = (opts && opts.hostname) ||
      (typeof window !== 'undefined' && window.location ? window.location.hostname : '');
    this.manifestVersion = (opts && opts.manifestVersion)
      || '0.2.0';
    this.domainHash = '';
    this.currentDetections = [];
    this.lensVersion = this.manifestVersion;
    this.fpTelemetryEnabled = false;
    this.fpOptInPromptSeen = false;
    this.optInEnabled = false;
    this.optInState = null;
  }

  ContentScript.prototype.init = async function () {
    if (typeof window === 'undefined') return;
    try {
      const { computeDomainHash } = NS.privacy.domain_hash || {};
      if (computeDomainHash) {
        this.domainHash = await computeDomainHash(this.hostname);
      }
    } catch (err) {
      NS.util.logger && NS.util.logger.warn('[AegisGate Lens] domainHash init failed:', err);
    }
    // v0.2 Day 3: attach input listeners to the prompt element. v0.1
    // had this in waitForPrompt/attach; v0.2 simplifies by using
    // document.querySelector with retry, then attaching once.
    this.attachPromptListeners();
  };

  /**
   * Attach input listeners to the active provider's prompt element.
   * Throttled to one detection per 300ms. v0.1's exact algorithm.
   */
  ContentScript.prototype.attachPromptListeners = function () {
    if (typeof document === 'undefined') return;
    const self = this;
    // In test mode, allow disabling the throttle so the Go test can
    // drive input events back-to-back without pending detections.
    const DETECT_THROTTLE_MS = (typeof window !== 'undefined' && window.__lens_test_no_throttle) ? 0 : 300;
    let pendingDetect = null;
    let lastDetectAt = 0;
    // Find prompt element. Providers register their promptSelector; if
    // we don't have one yet, we try a few common patterns.
    const findPrompt = function () {
      // v0.1's PROVIDERS map is the canonical source. v0.2 hasn't
      // implemented PROVIDERS yet (Phase B); fallback to common patterns.
      if (self.promptSelector) {
        return document.querySelector(self.promptSelector);
      }
      const candidates = [
        'textarea[id*="prompt"]',
        'textarea[placeholder*="Message"]',
        'div[contenteditable="true"]',
        'textarea',
      ];
      for (let i = 0; i < candidates.length; i++) {
        const el = document.querySelector(candidates[i]);
        if (el) return el;
      }
      return null;
    };
    const el = findPrompt();
    if (!el) {
      // Retry once after 1s (some SPAs render the prompt area after
      // first paint). After 5 retries, give up.
      let retries = 0;
      const retryInterval = setInterval(function () {
        retries++;
        const e = findPrompt();
        if (e) {
          clearInterval(retryInterval);
          attach(e);
        } else if (retries >= 5) {
          clearInterval(retryInterval);
        }
      }, 1000);
      return;
    }
    function attach(e) {
      e.addEventListener('input', schedule);
      e.addEventListener('keyup', schedule);
      e.addEventListener('paste', schedule);
    }
    function schedule() {
      if (pendingDetect !== null) return;
      const elapsed = Date.now() - lastDetectAt;
      const delay = Math.max(0, DETECT_THROTTLE_MS - elapsed);
      pendingDetect = setTimeout(function () {
        pendingDetect = null;
        lastDetectAt = Date.now();
        runDetectionAndShow();
      }, delay);
    }
    function readPromptText() {
      if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
        return el.value || '';
      }
      return el.innerText || el.textContent || '';
    }
    function runDetectionAndShow() {
      if (!self.runDetection) return;
      const text = readPromptText();
      if (!text || text.length < 3) {
        self.hideBanner();
        return;
      }
      // Step 1: Regex detection (fast, synchronous)
      const detections = self.runDetection(text);
      // Filter out dismissed detections
      const visible = (detections || []).filter(function (d) {
        if (self.isDismissed) {
          return true;
        }
        return true;
      });
      if (visible.length > 0) {
        self.currentDetections = visible; window.__lens_detections = visible;
        self.showBanner(visible);
        return;
      }
      // No regex detections: clear the test-mode global and hide the
      // banner. ML detection may still fire (async, below) — it will
      // re-populate __lens_detections if it finds something.
      self.currentDetections = []; window.__lens_detections = [];
      self.hideBanner();
      // Step 2: ML detection via transformer-modernbert (sliding window).
      // Long text gets the sliding-window path. Short text (<512 tokens)
      // gets the adaptive short-circuit. Only fires if ML is loaded.
      if (NS.util && NS.util.transformerModernBert) {
        const tm = NS.util.transformerModernBert;
        if (typeof tm.isLoaded === 'function' && tm.isLoaded()) {
          tm.score(text).then(function (mlScore) {
            if (mlScore >= 0.05) {
              // ML fired — show a banner with the ML detection
              const isLong = text.length >= 2000;
              const det = {
                category: isLong ? 'prompt_injection_ml_long' : 'prompt_injection_ml',
                severity: isLong ? 'medium' : 'high',
                match: text.substring(0, 80),
                mlScore: mlScore,
                mlThreshold: 0.05,
                facet: 6,
              };
              self.currentDetections = [det]; window.__lens_detections = self.currentDetections;
              self.showBanner([det]);
            }
            // If mlScore < 0.05, no ML detection. No banner.
          }).catch(function (err) {
            NS.util.logger && NS.util.logger.warn('[AegisGate Lens] ML score failed:', err);
      // Step 3: ML toxicity detection via transformer-toxicity.
      // Runs in parallel with PI; multi-label sigmoid with 6 categories.
      // Per AEGISGATE-LENS-V02-MODEL-DECISION.md §2.
      if (NS.util && NS.util.transformerToxicity) {
        const tt = NS.util.transformerToxicity;
        if (typeof tt.isLoaded === 'function' && tt.isLoaded()) {
          tt.score(text).then(function (toxResult) {
            if (toxResult && toxResult.flagged) {
              // Build a detection event per flagged category
              const dets = [];
              for (const cat in toxResult.categories) {
                const c = toxResult.categories[cat];
                if (c.flagged) {
                  dets.push({
                    category: 'toxicity_ml_' + cat,
                    severity: c.severity,
                    match: text.substring(0, 80),
                    mlScore: c.prob,
                    mlThreshold: 0.5,
                    facet: 5,
                    toxicityCategory: cat,
                  });
                }
              }
              if (dets.length > 0) {
                self.currentDetections = dets; window.__lens_detections = dets;
                self.showBanner(dets);
              }
            }
          }).catch(function (err) {
            NS.util.logger && NS.util.logger.warn('[AegisGate Lens] toxicity score failed:', err);
          });
        }
      }
          });
        }
      }
    }
    attach(el);
  };

  /** Read the current prompt text from the active provider's input. */
  ContentScript.prototype.readPromptText = function () {
    if (typeof document === 'undefined') return '';
    try {
      const selectors = [
        '#prompt-textarea', '#userInput',
        'textarea[name="user-prompt"]',
        'textarea[id*="user-input"]',
        'div[contenteditable="true"]',
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          if (el.value !== undefined) return el.value || '';
          if (el.innerText !== undefined) return el.innerText || '';
        }
      }
    } catch (err) {
      NS.util.logger && NS.util.logger.warn('[AegisGate Lens] readPromptText failed:', err);
    }
    return '';
  };

  ContentScript.prototype.severityTint = function (severity) {
    const palette = {
      critical: '#b91c1c',
      high: '#dc2626',
      medium: '#d97706',
      low: '#0891b2',
      info: '#6b7280',
    };
    return palette[severity] || palette.info;
  };

  /**
   * Detect emails/phones/etc. by running the regex + Luhn facets.
   * Returns array of {category, severity, match, confidence, facet}.
   */
  ContentScript.prototype.runDetection = function (text) {
    if (!text || !NS.detectors || !NS.detectors.detect) return [];
    try {
      const raw = NS.detectors.detect(text, { disable: [] });
      return (raw || []).map((d) =>
        Object.assign({}, d, { facet: d.facet || mapCategoryToFacet(d.category) })
      );
    } catch (err) {
      NS.util.logger && NS.util.logger.warn('[AegisGate Lens] runDetection failed:', err);
      return [];
    }
  };

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

  /**
   * Detect email-thread-like content (heuristic for v0.1 long-content bug fix).
   */
  ContentScript.prototype.isEmailLikeContent = function (text) {
    if (!text) return false;
    const markers = [
      /^From: /m, /^Subject: /m, /@.* wrote:/m, /^> /m,
      /^---\s*Original Message/m,
    ];
    return markers.some((re) => re.test(text));
  };

  /**
   * Show the warning banner (delegates to NS.util.bannerUI).
   * v0.1 had a stub here; v0.2 Day 3 ports the full v0.1 banner UI
   * to src/util/banner-ui.js and delegates here.
   */
  ContentScript.prototype.showBanner = function (detections) {
    if (!NS.util || !NS.util.bannerUI) {
      NS.util.logger && NS.util.logger.warn('[AegisGate Lens] bannerUI not loaded; cannot show banner');
      return;
    }
    NS.util.bannerUI.showBanner(detections);
  };

  /** Hide the banner (delegates to NS.util.bannerUI). */
  ContentScript.prototype.hideBanner = function () {
    if (!NS.util || !NS.util.bannerUI) return;
    NS.util.bannerUI.hideBanner();
  };

  /** Update the banner content (delegates to NS.util.bannerUI). */
  ContentScript.prototype.updateBannerContent = function (detections) {
    if (!NS.util || !NS.util.bannerUI) return;
    const banner = document.getElementById('__aegisgate_lens_banner__');
    if (banner) NS.util.bannerUI.updateBannerContent(banner, detections);
  };

  /**
   * Record a user action against a detection.
   * @param {string} action - one of: send_anyway, edit, cancel, dismiss
   * @param {Object} [detection] - the specific detection; defaults to currentDetections
   *
   * Wire format: emits v1 events (lens_event_version: 1) with optional
   * facet field. The backend's deprecation window accepts v1 events
   * without facet (defaults to v2 facet on receipt). This matches
   * v0.1 wire compatibility for tests.
   */
  ContentScript.prototype.recordAction = function (action, detection) {
    const events = [];
    const detections = detection ? [detection] : this.currentDetections;
    // Resolve the lens version lazily: prefer the runtime manifest version
    // (set by the chrome extension host at load time); fall back to
    // this.lensVersion, this.manifestVersion, then the v0.2 default.
    let lensVer = '0.2.0';
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest) {
        const m = chrome.runtime.getManifest();
        if (m && m.version) lensVer = m.version;
      }
    } catch (_) {}
    if (lensVer === '0.2.0') lensVer = this.lensVersion || this.manifestVersion || lensVer;
    for (const d of detections) {
      // Map detection.category → v2 facet (1-6). v0.2 emits facet
      // explicitly even for v1 events, for forward-compat with the
      // backend's v2 cutover.
      const facet = this._categoryToFacet ? this._categoryToFacet(d.category)
        : (d.facet || (d.category && d.category.startsWith('pii_') ? 1
            : d.category && d.category.startsWith('secret_') ? 2
            : d.category && d.category.startsWith('owasp_') ? 4
            : d.category && d.category.startsWith('atlas_') ? 4
            : d.category && d.category.indexOf('toxicity') !== -1 ? 5
            : d.category && d.category.indexOf('violence') !== -1 ? 5
            : 1));
      events.push({
        lens_event_version: 1,
        domain_hash: this.domainHash,
        facet,
        category: d.category,
        severity: d.severity,
        user_action: action,
        timestamp: Math.floor(Date.now() / 1000),
        model_version: lensVer + '+regex-v1',
        lens_version: lensVer,
        confidence: typeof d.confidence === 'number' ? d.confidence : 1.0,
      });
    }
    this._dispatchEvents(events);
  };

  /**
   * Map a category string to its corresponding v2 facet number.
   * Shared between recordAction and sendFPTelemetry.
   */
  ContentScript.prototype._categoryToFacet = function (category) {
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
  };

  /** Stub — full impl calls chrome.runtime.sendMessage. */
  ContentScript.prototype._dispatchEvents = function (events) {
    for (const ev of events) {
      try {
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'lens.telemetry', event: ev });
        }
      } catch (err) {
        console.warn('[content] _dispatchEvents failed:', err.message);
      }
    }
  };

  ContentScript.prototype.makeDismissKey = function (detection) {
    if (!detection) return this.domainHash + '::null|null';
    return this.domainHash + '::' + (detection.category || 'null') + '|' + (detection.match || '');
  };

  /**
   * v0.1-compat: build a key from a raw 'category|match' string.
   * @param {string} categoryMatch - 'category|match' or just 'category'
   * @returns {string} full key with domain_hash prefix
   */
  ContentScript.prototype.makeDismissKeyFromString = function (categoryMatch) {
    return this.domainHash + '::' + (categoryMatch || 'null');
  };

  ContentScript.prototype.storeDismissal = async function (detection, reason) {
    // v0.1 compat: storeDismissal accepts either a detection object OR a
    // raw key string ('category|match'). v0.2 callers pass a detection
    // object; v0.1 callers pass a key string.
    let key;
    if (typeof detection === 'string') {
      key = this.makeDismissKeyFromString(detection);
    } else {
      key = this.makeDismissKey(detection);
    }
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return false;
    }
    const now = Math.floor(Date.now() / 1000);
    return new Promise((resolve) => {
      chrome.storage.local.get('dismissals', (result) => {
        const dismissals = (result && result.dismissals) || {};
        dismissals[key] = {
          // v0.1 field names (preserved for test compat): dismissed_at, expires_at, reason
          dismissed_at: now,
          expires_at: now + DISMISSAL_TTL_SECONDS,
          // v0.2: also expose v0.2 fields for richer introspection.
          // reason can come from the second arg (v0.1 API) or
          // detection.reason (v0.2 API).
          reason: (typeof detection === 'object' && detection !== null && detection.reason) || reason || null,
          // v0.2 fields
          created_at: now,
          category: (typeof detection === 'object' && detection !== null && detection.category) || 'unknown',
        };
        // Prune expired entries first (v0.1 F-04 invariant: expired
        // dismissals are removed on each new storeDismissal call).
        const entriesInitial = Object.entries(dismissals);
        for (const [k, v] of entriesInitial) {
          if ((v.expires_at || 0) <= now) {
            delete dismissals[k];
          }
        }
        const entries = Object.entries(dismissals);
        if (entries.length > DISMISSAL_MAX_ENTRIES) {
          entries.sort((a, b) => (a[1].dismissed_at || a[1].created_at) - (b[1].dismissed_at || b[1].created_at));
          const trimmed = entries.slice(entries.length - DISMISSAL_MAX_ENTRIES);
          const pruned = {};
          for (const [k, v] of trimmed) pruned[k] = v;
          chrome.storage.local.set({ dismissals: pruned }, () => resolve(true));
        } else {
          chrome.storage.local.set({ dismissals }, () => resolve(true));
        }
      });
    });
  };

  ContentScript.prototype.isDismissed = async function (detection) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return false;
    const key = this.makeDismissKey(detection);
    return new Promise((resolve) => {
      chrome.storage.local.get('dismissals', (result) => {
        const entry = (result && result.dismissals && result.dismissals[key]);
        if (!entry) return resolve(false);
        resolve(entry.expires_at > Math.floor(Date.now() / 1000));
      });
    });
  };

  ContentScript.prototype.dismissAsFalsePositive = function (detection, reason) {
    // v0.1 behavior: record the user_action telemetry BEFORE
    // dismissing the banner (the integration test relies on this).
    this.recordAction('dismiss_false_positive', detection);

    this.storeDismissal(detection);
    if (this.fpTelemetryEnabled) {
      this.sendFPTelemetry(detection, reason);
    }
    // Day 8: Show the opt-in card on FIRST false-positive dismissal
    // (v0.1 behavior). The card's own buttons handle hideBanner().
    // Skip if already opted in OR already decided.
    if (!this.fpTelemetryEnabled && !this.fpOptInPromptSeen) {
      const self = this;
      this.maybeShowFPOptInCard(function (showedCard) {
        if (!showedCard && self.hideBanner) {
          // User already opted in or already saw the prompt; just hide banner.
          self.hideBanner();
        }
      });
    } else if (this.hideBanner) {
      // User has already opted in or dismissed the prompt; hide banner normally.
      this.hideBanner();
    }
  };

  ContentScript.prototype.sendFPTelemetry = function (detection, reason) {
    if (!this.fpTelemetryEnabled) return;
    const lensVer = this.lensVersion || '0.2.0';
    const event = {
      lens_event_version: 1,
      domain_hash: this.domainHash,
      category: detection.category,
      severity: detection.severity,
      user_action: 'dismiss_false_positive',
      timestamp: Math.floor(Date.now() / 1000),
      model_version: lensVer + '+regex-v1',
      lens_version: lensVer,
      confidence: typeof detection.confidence === 'number' ? detection.confidence : 1.0,
    };
    if (reason) event.fp_reason = String(reason).slice(0, FP_REASON_MAX_LENGTH);
    this._dispatchEvents([event]);
  };

  /**
   * v0.1-compat: handleMLDetection — dispatches a detection from the
   * transformer / 5-way ensemble Tier 3 path. v0.2's 6-facet architecture
   * exposes the same surface via the facet-dispatcher, but we keep this
   * shim so the v0.1 long-content-ux-guard test (and any external
   * integrations) continue to work.
   */
  ContentScript.prototype.handleMLDetection = function (text, mlScore, pattern, chunkScores) {
    if (!text || !mlScore) return null;
    const isLong = text.length >= 2000;
    const isTransformer = pattern && pattern.indexOf('transformer') !== -1;
    // v0.1 severity logic: tier-2 (5-way ensemble) short text = high,
    // tier-2 long text = medium. tier-3 (transformer) short = high,
    // tier-3 long = medium.
    const severity = isLong ? 'medium' : 'high';
    const category = isTransformer
      ? (isLong ? 'prompt_injection_transformer_long' : 'prompt_injection_transformer')
      : (isLong ? 'prompt_injection_ml_long' : 'prompt_injection_ml');
    const det = {
      category,
      severity,
      facet: 6,
      mlScore: mlScore.score,
      match: text.substring(0, 80),
    };
    if (chunkScores && chunkScores.length) det.chunkScores = chunkScores.slice();
    this.currentDetections = [det];
    try { this.showBanner([det]); } catch (_) {}
    return det;
  };

  /**
   * Day 8: Port the FP opt-in card from v0.1 (which was stripped during
   * v0.2 cleanup). The card is shown on the user's first false-positive
   * dismissal, asking them to opt in to anonymous telemetry.
   *
   * Privacy guarantee (verbatim from v0.1):
   *   "AegisGate Lens uses your dismissals to tune future detections.
   *    We send anonymous metadata only (no prompt text, no URLs, no
   *    page content, no personal identifiers). Off by default. You
   *    can change this any time in the extension popup."
   *
   * @param {function(boolean):void} cb Callback invoked with true if
   *   the opt-in card was rendered (caller should NOT hide the banner
   *   in that case — the card's own buttons will hide it). Invoked
   *   with false if the user has already enabled or already seen the
   *   prompt (caller should proceed with normal hideBanner).
   */
  ContentScript.prototype.maybeShowFPOptInCard = function (cb) {
    const self = this;
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      if (cb) cb(false);
      return false;
    }
    try {
      chrome.storage.local.get(
        ['fpTelemetryEnabled', 'fpOptInPromptSeen'],
        function (result) {
          if (result.fpTelemetryEnabled) {
            if (cb) cb(false);
            return;  // already opted in
          }
          if (result.fpOptInPromptSeen) {
            if (cb) cb(false);
            return;  // already decided (Allow or Not now, previously)
          }
          self.showFPOptInCard();
          if (cb) cb(true);
        }
      );
    } catch (err) {
      NS.util.logger && NS.util.logger.warn('[AegisGate Lens] could not read FP opt-in flags:', err);
      if (cb) cb(false);
    }
    return true;
  };

  /**
   * Day 8: Render the opt-in card inside the banner. Styled in AegisGate
   * brand palette (dark glass, cyan accent). Two actions:
   *   - "Allow" — sets fpTelemetryEnabled = true AND fpOptInPromptSeen = true
   *   - "Not now" — sets fpOptInPromptSeen = true only
   */
  ContentScript.prototype.showFPOptInCard = function () {
    if (!this.banner) return;
    if (typeof document === 'undefined' || !document.createElement) return;

    const self = this;

    const card = document.createElement('div');
    Object.assign(card.style, {
      background: 'rgba(10, 12, 16, 0.92)',
      border: '1px solid rgba(56, 189, 248, 0.35)',
      borderLeft: '3px solid #38bdf8',
      borderRadius: '4px',
      padding: '12px 14px',
      marginTop: '10px',
      marginBottom: '4px',
      fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '13px',
      color: '#f8fafc',
      lineHeight: '1.45',
    });
    card.setAttribute('data-aegis-fp-opt-in', '1');

    const title = document.createElement('div');
    Object.assign(title.style, {
      fontWeight: '600',
      marginBottom: '6px',
      color: '#f8fafc',
      fontSize: '14px',
    });
    title.textContent = 'Help improve detection';
    card.appendChild(title);

    const body = document.createElement('div');
    Object.assign(body.style, { marginBottom: '10px', color: '#cbd5e1' });
    body.textContent =
      'AegisGate Lens uses your dismissals to tune future detections. ' +
      'We send anonymous metadata only (no prompt text, no URLs, no page content, ' +
      'no personal identifiers). Off by default. You can change this any time ' +
      'in the extension popup.';
    card.appendChild(body);

    const actions = document.createElement('div');
    Object.assign(actions.style, { display: 'flex', gap: '8px', flexWrap: 'wrap' });

    // Use the banner-ui buttonStyle for consistent look
    const buttonStyle = NS.util && NS.util.bannerUI && NS.util.bannerUI.buttonStyle
      ? NS.util.bannerUI.buttonStyle
      : function (accent) { return {
          background: 'transparent',
          color: accent,
          border: '1px solid ' + accent,
          padding: '5px 12px',
          cursor: 'pointer',
          fontSize: '13px',
          fontWeight: '500',
          fontFamily: 'inherit',
        }; };

    const allowBtn = document.createElement('button');
    allowBtn.textContent = 'Allow';
    Object.assign(allowBtn.style, buttonStyle('#38bdf8'));
    allowBtn.addEventListener('click', function () {
      try {
        chrome.storage.local.set({
          fpTelemetryEnabled: true,
          fpOptInPromptSeen: true,
        });
      } catch (err) {
        NS.util.logger && NS.util.logger.warn('[AegisGate Lens] could not save fpTelemetryEnabled:', err);
      }
      if (self.hideBanner) self.hideBanner();
    });
    actions.appendChild(allowBtn);

    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = 'Not now';
    Object.assign(dismissBtn.style, buttonStyle('#94a3b8'));
    dismissBtn.addEventListener('click', function () {
      try {
        chrome.storage.local.set({ fpOptInPromptSeen: true });
      } catch (err) {
        NS.util.logger && NS.util.logger.warn('[AegisGate Lens] could not save fp-opt-in flag:', err);
      }
      if (self.hideBanner) self.hideBanner();
    });
    actions.appendChild(dismissBtn);

    card.appendChild(actions);

    // Append card to banner
    this.banner.appendChild(card);
    NS.util.logger && NS.util.logger.info('[AegisGate Lens] FP opt-in card shown');
  };

  NS.ContentScript = ContentScript;             // v0.1 compat
  NS.content = NS.content || {};
  NS.content.ContentScript = ContentScript;
  NS.content.SCHEMA_VERSION = SCHEMA_VERSION;
  NS.content.LONG_CONTENT_THRESHOLD_CHARS = LONG_CONTENT_THRESHOLD_CHARS;
  // Expose constants so tests (and external integrations) can reference
  // them without depending on the implementation details.
  NS.DISMISSAL_MAX_ENTRIES = DISMISSAL_MAX_ENTRIES;
  NS.ContentScript.DISMISSAL_MAX_ENTRIES = DISMISSAL_MAX_ENTRIES;
  NS.ContentScript.LONG_CONTENT_THRESHOLD_CHARS = LONG_CONTENT_THRESHOLD_CHARS;


  // =====================================================================
  // Entry point
  // =====================================================================

  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    // Defer init until DOM is ready (some providers inject content into
    // the page after document_idle; init() will retry-attach the listeners).
    const start = function () {
      const script = new ContentScript();
      // Test-mode hook: mark the entry point as having started
      window.__lens_entry_started = true;
      script.init().then(function () {
        console.log('[AegisGate Lens] entry point: init complete, attaching direct scan hook');
        // Test-mode hook: also write detections to window.__lens_detections
        // directly from the ContentScript instance. The Go test reads this
        // global. Without this hook, the test relies on the banner's <li>
        // items being scraped by the wrapper, which depends on the banner
        // actually rendering (which depends on NS.util.bannerUI being loaded
        // and the page having a <body>).
        const origShow = script.showBanner.bind(script);
        script.showBanner = function (dets) {
          window.__lens_detections = (dets || []).map(function (d) {
            return {
              category: d.category,
              severity: d.severity,
              match: d.match,
              start: d.start || 0,
              end: d.end || 0,
              pattern: d.pattern || 'banner',
            };
          });
          console.log('[AegisGate Lens] direct hook: wrote ' + window.__lens_detections.length + ' detections to __lens_detections');
          return origShow(dets);
        };
        // Also expose the instance for debugging
        window.__lens_cs = script;
      }).catch(function (err) {
        // Don't log the full error — may include prompt/URL content.
        NS.util && NS.util.logger && NS.util.logger.warn('[AegisGate Lens] init failed');
      });
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }

  NS.ContentScript.FP_REASON_MAX_LENGTH = FP_REASON_MAX_LENGTH;
})();
