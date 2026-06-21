/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Content Script
   =========================================================================

   The content script runs in the context of the AI provider's
   web page (e.g., chat.openai.com). It is the ONLY place in
   the extension that sees the user's prompt text. It:

     1. Looks up the current hostname in the PROVIDERS map.
     2. If supported, waits for the prompt area to appear.
     3. Observes DOM mutations on the prompt input area.
     4. Calls detectors/detect() on the prompt text.
     5. Renders the warning UI inline (a banner at the top
        of the prompt area) when sensitive data is detected.
     6. Sends a LensEvent to the service worker (NOT to the
        backend directly) when the user takes an action
        (send_anyway, edit, cancel, dismiss).

   Privacy boundary: the content script never makes a network
   request directly. All outbound traffic is via the service
   worker, which applies the rate limit and the auth header.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const log = NS.logger || console;
  const { detect, describeCategory } = (NS.detectors) || {};
  const { computeDomainHash } = (NS.privacy && NS.privacy.domainHash) || {};
  const mlEngine = NS.mlEngine || null;
  const transformerEngine = NS.transformerEngine || null;
  const TRANSFORMER_UNCERTAIN_LOW = 0.3;
  const TRANSFORMER_UNCERTAIN_HIGH = 0.7;

  /**
   * The current Lens version.
   * Kept in sync by tools/build-lens-extension in the Platform
   * monorepo. DO NOT EDIT THIS LINE; the build tool templates
   * it from version.txt at the Platform monorepo root.
   */
  const LENS_VERSION = '0.1.0';

  /** Throttle interval for re-running detect() on input. */
  const DETECT_THROTTLE_MS = 250;

  /**
   * @typedef {Object} ProviderInfo
   * @property {string} name             Canonical provider name.
   * @property {string} promptSelector   CSS selector for the prompt input.
   * @property {string} sendSelector     CSS selector for the send button.
   */

  /**
   * The supported AI providers, mapped by hostname.
   * @type {ReadonlyMap<string, ProviderInfo>}
   */
  const PROVIDERS = new Map([
    ['chat.openai.com', {
      name: 'chatgpt',
      promptSelector: '#prompt-textarea',
      sendSelector: 'button[data-testid="send-button"]',
    }],
    ['chatgpt.com', {
      name: 'chatgpt',
      promptSelector: '#prompt-textarea',
      sendSelector: 'button[data-testid="send-button"]',
    }],
    ['claude.ai', {
      name: 'claude',
      promptSelector: 'div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send"]',
    }],
    ['gemini.google.com', {
      name: 'gemini',
      promptSelector: 'div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send"]',
    }],
    ['copilot.microsoft.com', {
      name: 'copilot',
      promptSelector: '#userInput',
      sendSelector: 'button[type="submit"]',
    }],
    ['duck.ai', {
      name: 'duck',
      // Updated 2026-06-19: duck.ai uses name="user-prompt" on the
      // textarea (no id, no aria-label). The previous selector
      // textarea[id*="user-input"] was for an older version of
      // duck.ai and didn't match the current DOM.
      promptSelector: 'textarea[name="user-prompt"], textarea[id*="user-input"], div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send"]',
    }],
  ]);

  /**
   * Read the prompt text from a textarea or contenteditable.
   * @param {Element} el
   * @returns {string}
   */
  function readPromptText(el) {
    if (el instanceof HTMLTextAreaElement) return el.value;
    if (el instanceof HTMLElement && el.isContentEditable) {
      return el.textContent || '';
    }
    return '';
  }

  /**
   * Tint for a button by severity.
   * @param {string} s
   * @returns {{bg: string, fg: string}}
   */
  function severityTint(s) {
    switch (s) {
      case 'critical': return { bg: '#dc2626', fg: '#ffffff' };
      case 'high':     return { bg: '#f59e0b', fg: '#1f2937' };
      case 'medium':   return { bg: '#fbbf24', fg: '#1f2937' };
      case 'low':      return { bg: '#e5e7eb', fg: '#1f2937' };
      case 'info':     return { bg: '#e5e7eb', fg: '#1f2937' };
      default:         return { bg: '#e5e7eb', fg: '#1f2937' };
    }
  }

  /** Sleep helper. */
  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * ContentScript is the entry point. One instance per page.
   * @constructor
   */
  function ContentScript() {
    this.hostname = '';
    this.provider = null;
    this.domainHash = '';
    this.banner = null;
    this.currentDetections = [];
    this.lastDetectAt = 0;
    this.pendingDetect = null;
  }

  /** Initialize the content script for the current page. */
  ContentScript.prototype.init = async function () {
    this.hostname = window.location.hostname.toLowerCase();
    const info = PROVIDERS.get(this.hostname);
    if (!info) {
      // Not a supported provider; do nothing.
      return;
    }
    this.provider = info;
    this.domainHash = await computeDomainHash(this.hostname);
    await this.waitForPrompt();
    this.attach();
  };

  /**
   * Wait for the prompt input to appear in the DOM. AI providers
   * are SPAs, so the prompt area is rendered after the initial
   * JS loads.
   */
  ContentScript.prototype.waitForPrompt = async function () {
    const sel = this.provider.promptSelector;
    for (let i = 0; i < 60; i++) {
      if (document.querySelector(sel)) return;
      await sleep(500);
    }
  };

  /** Attach input listeners to the prompt element. */
  ContentScript.prototype.attach = function () {
    const el = document.querySelector(this.provider.promptSelector);
    if (!el) return;
    el.addEventListener('input', () => this.scheduleDetect());
    el.addEventListener('keyup', () => this.scheduleDetect());
    el.addEventListener('paste', () => this.scheduleDetect());
  };

  /** Schedule a detect run. Throttled to DETECT_THROTTLE_MS. */
  ContentScript.prototype.scheduleDetect = function () {
    if (this.pendingDetect !== null) return;
    const elapsed = Date.now() - this.lastDetectAt;
    const delay = Math.max(0, DETECT_THROTTLE_MS - elapsed);
    const self = this;
    this.pendingDetect = window.setTimeout(function () {
      self.pendingDetect = null;
      self.lastDetectAt = Date.now();
      self.runDetect();
    }, delay);
  };

  /**
   * Run the detector on the current prompt text.
   * Uses regex (fast, deterministic) + ML ensemble (deeper).
   * If ML fires, adds a prompt_injection_ml detection.
   */
  ContentScript.prototype.runDetect = function () {
    const el = document.querySelector(this.provider.promptSelector);
    if (!el) return;
    const text = readPromptText(el);

    // Sync: regex detection (fast)
    const regexDetections = detect(text);

    // If regex already found something, skip ML (regex is faster and
    // already caught this). If regex found nothing but text is long
    // enough to potentially be an attack, run ML.
    const self = this;

    // Helper: filter out dismissed detections
    function filterDismissed(detections) {
      return detections.filter(function (d) { return !self.isDismissed(d); });
    }

    if (regexDetections.length > 0) {
      const visible = filterDismissed(regexDetections);
      if (visible.length > 0) {
        self.currentDetections = visible;
        self.showBanner(visible);
      } else {
        self.currentDetections = [];
        self.hideBanner();
      }
    } else if (text.length >= 20 && mlEngine) {
      // Async: ML detection
      mlEngine.scoreText(text).then(function (mlResult) {
        if (!mlResult) return;
        // Tier 2 (TF-IDF 5-way) fired - show banner
        if (mlResult.isAttack) {
          self.handleMLDetection(text, mlResult, 'ml_5way_ensemble', mlResult.scores);
          return;
        }
        // Tier 2 said no. If score is UNCERTAIN (0.3-0.7), invoke Tier 3 (transformer)
        if (mlResult.loaded && transformerEngine &&
            mlResult.score >= TRANSFORMER_UNCERTAIN_LOW &&
            mlResult.score <= TRANSFORMER_UNCERTAIN_HIGH) {
          transformerEngine.scoreTransformer(text).then(function (transResult) {
            if (transResult && transResult.isAttack) {
              self.handleMLDetection(text, {
                score: transResult.score,
                threshold: transResult.threshold,
              }, 'transformer_minilm', null);
            }
          }).catch(function (err) {
            log.warn('[AegisGate Lens] Tier 3 (transformer) failed:', err);
          });
        }
      }).catch(function (err) {
        log.warn('[AegisGate Lens] ML score failed:', err);
      });
    } else {
      // No detections from regex, text too short for ML, or ML not loaded
      self.currentDetections = [];
      self.hideBanner();
    }
  };

  /**
   * Show the warning banner.
   * @param {Array<{category: string, severity: string, match: string, name: string}>} detections
   */
  /**
   * Handle an ML detection (either from Tier 2 or Tier 3).
   * @param {string} text - the original text that was scored
   * @param {Object} mlResult - { score, threshold, scores }
   * @param {string} pattern - which model fired ('ml_5way_ensemble' or 'transformer_minilm')
   * @param {Array<number>|null} allScores - per-model scores (null for transformer)
   */
  ContentScript.prototype.handleMLDetection = function (text, mlResult, pattern, allScores) {
    // Re-check the prompt in case it changed between calls.
    const currentEl = document.querySelector(this.provider.promptSelector);
    if (!currentEl) return;
    const currentText = readPromptText(currentEl);
    if (currentText !== text) return;  // prompt changed, skip stale result

    const category = pattern === 'transformer_minilm' ?
      'prompt_injection_transformer' : 'prompt_injection_ml';

    const mlDetection = {
      category: category,
      severity: 'high',
      match: currentText.substring(0, Math.min(80, currentText.length)),
      start: 0,
      end: currentText.length,
      pattern: pattern,
      mlScore: mlResult.score,
      mlThreshold: mlResult.threshold,
      mlScores: allScores,
    };

    // Check if dismissed
    if (this.isDismissed(mlDetection)) {
      this.currentDetections = [];
      this.hideBanner();
      return;
    }
    this.currentDetections = [mlDetection];
    this.showBanner([mlDetection]);
  };

  ContentScript.prototype.showBanner = function (detections) {
    if (this.banner && document.body.contains(this.banner)) {
      this.updateBannerContent(detections);
      return;
    }
    const banner = document.createElement('div');
    banner.id = '__aegisgate_lens_banner__';
    banner.setAttribute('role', 'alert');
    banner.setAttribute('aria-live', 'polite');
    Object.assign(banner.style, {
      position: 'fixed',
      top: '0', left: '0', right: '0',
      zIndex: '2147483647',
      background: '#fef3c7',
      borderBottom: '2px solid #f59e0b',
      padding: '12px 16px',
      paddingRight: '40px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '14px',
      color: '#1f2937',
      boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
    });
    document.body.appendChild(banner);
    this.banner = banner;
    this.updateBannerContent(detections);
  };

  /**
   * Update the banner's content. Replaces children; does not
   * recreate the banner element.
   */
  ContentScript.prototype.updateBannerContent = function (detections) {
    if (!this.banner) return;
    while (this.banner.firstChild) {
      this.banner.removeChild(this.banner.firstChild);
    }
    const header = document.createElement('div');
    Object.assign(header.style, { fontWeight: '600', marginBottom: '6px' });
    const count = detections.length;
    header.textContent =
      '\uD83D\uDEE1\uFE0F AegisGate Lens: ' + count + ' sensitive item' +
      (count === 1 ? '' : 's') + ' detected in your prompt.';
    this.banner.appendChild(header);

    const list = document.createElement('ul');
    Object.assign(list.style, { margin: '0 0 8px 0', paddingLeft: '20px' });
    for (let i = 0; i < detections.length; i++) {
      const d = detections[i];
      const li = document.createElement('li');
      const masked = (d.match || '').length > 8
        ? (d.match || '').slice(0, 4) + '\u2026' + (d.match || '').slice(-4)
        : (d.match || '');
      let label = describeCategory(d.category) + ' (' + d.severity + ') \u2014 match: "' + masked + '"';
      // For ML detections, show the score and per-model breakdown
      if (d.category === 'prompt_injection_ml' && d.mlScore !== undefined) {
        label += ' [ML score: ' + d.mlScore.toFixed(3) +
                 ', threshold: ' + d.mlThreshold.toFixed(2) + ']';
      }
      li.textContent = label;
      list.appendChild(li);
    }
    this.banner.appendChild(list);

    // False positive link (expandable)
    const fpRow = document.createElement('div');
    Object.assign(fpRow.style, { marginBottom: '8px' });
    const fpLink = document.createElement('button');
    fpLink.textContent = 'This is a false positive';
    Object.assign(fpLink.style, {
      background: 'transparent',
      border: 'none',
      color: '#1d4ed8',
      textDecoration: 'underline',
      cursor: 'pointer',
      fontSize: '13px',
      padding: '0',
    });
    fpLink.setAttribute('aria-expanded', 'false');
    fpRow.appendChild(fpLink);
    this.banner.appendChild(fpRow);

    // FP form (hidden by default)
    const fpForm = document.createElement('div');
    Object.assign(fpForm.style, {
      display: 'none',
      background: '#fffbeb',
      border: '1px solid #fbbf24',
      borderRadius: '4px',
      padding: '8px 12px',
      marginBottom: '8px',
    });
    const fpLabel = document.createElement('div');
    Object.assign(fpLabel.style, { fontWeight: '500', marginBottom: '4px', fontSize: '13px' });
    fpLabel.textContent = 'Why is this a false positive? (optional)';
    fpForm.appendChild(fpLabel);

    const reasons = [
      { value: 'test_data', label: 'This is test/fake data' },
      { value: 'own_data', label: 'This is my own data (I know what I\'m doing)' },
      { value: 'legitimate', label: 'This is for a legitimate use case I trust' },
      { value: 'other', label: 'Other' },
    ];
    const fpCheckboxes = [];
    for (let r = 0; r < reasons.length; r++) {
      const row = document.createElement('label');
      Object.assign(row.style, { display: 'block', fontSize: '13px', marginBottom: '2px', cursor: 'pointer' });
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = reasons[r].value;
      cb.style.marginRight = '4px';
      fpCheckboxes.push(cb);
      row.appendChild(cb);
      const span = document.createElement('span');
      span.textContent = reasons[r].label;
      row.appendChild(span);
      fpForm.appendChild(row);
    }
    const fpActions = document.createElement('div');
    Object.assign(fpActions.style, { marginTop: '6px', display: 'flex', gap: '6px' });

    const fpSubmitBtn = document.createElement('button');
    fpSubmitBtn.textContent = 'Submit & dismiss (24h)';
    Object.assign(fpSubmitBtn.style, buttonStyle('#0891b2'));
    fpSubmitBtn.addEventListener('click', () => {
      // Collect selected reasons
      const selected = [];
      for (let i = 0; i < fpCheckboxes.length; i++) {
        if (fpCheckboxes[i].checked) selected.push(fpCheckboxes[i].value);
      }
      this.dismissAsFalsePositive(selected.join(','));
    });
    fpActions.appendChild(fpSubmitBtn);

    const fpJustDismissBtn = document.createElement('button');
    fpJustDismissBtn.textContent = 'Just dismiss (24h)';
    Object.assign(fpJustDismissBtn.style, buttonStyle('#6b7280'));
    fpJustDismissBtn.addEventListener('click', () => {
      this.dismissAsFalsePositive(null);
    });
    fpActions.appendChild(fpJustDismissBtn);

    fpForm.appendChild(fpActions);
    this.banner.appendChild(fpForm);

    // Toggle FP form
    const self = this;
    fpLink.addEventListener('click', function () {
      const visible = fpForm.style.display === 'block';
      fpForm.style.display = visible ? 'none' : 'block';
      fpLink.setAttribute('aria-expanded', String(!visible));
    });

    // Actions row.
    const actions = document.createElement('div');
    Object.assign(actions.style, { display: 'flex', gap: '8px' });

    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'Cancel';
    Object.assign(cancelBtn.style, buttonStyle('#6b7280'));
    cancelBtn.addEventListener('click', () => {
      this.recordAction('cancel');
      this.hideBanner();
    });
    actions.appendChild(cancelBtn);

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    Object.assign(editBtn.style, buttonStyle('#3b82f6'));
    editBtn.addEventListener('click', () => {
      this.recordAction('edit');
      this.hideBanner();
    });
    actions.appendChild(editBtn);

    const sendBtn = document.createElement('button');
    sendBtn.textContent = 'Send anyway';
    Object.assign(sendBtn.style, buttonStyle('#dc2626'));
    sendBtn.addEventListener('click', () => {
      this.recordAction('send_anyway');
      this.hideBanner();
    });
    actions.appendChild(sendBtn);

    this.banner.appendChild(actions);

    // Dismiss (×) in the corner.
    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = '\u00D7';
    dismissBtn.setAttribute('aria-label', 'Dismiss this warning');
    Object.assign(dismissBtn.style, {
      position: 'absolute', top: '8px', right: '12px',
      background: 'transparent', border: 'none',
      fontSize: '20px', lineHeight: '1', cursor: 'pointer',
      color: '#1f2937', padding: '0 4px',
    });
    dismissBtn.addEventListener('click', () => {
      this.recordAction('dismiss');
      this.hideBanner();
    });
    this.banner.appendChild(dismissBtn);
  };

  /** Hide the banner if it exists. */
  ContentScript.prototype.hideBanner = function () {
    if (this.banner && this.banner.parentNode) {
      this.banner.parentNode.removeChild(this.banner);
    }
    this.banner = null;
  };

  /**
   * Record a user action by sending one LensEvent per detection
   * to the service worker (NOT to the backend directly).
   * @param {string} userAction One of: send_anyway, edit, cancel, dismiss.
   */
  /**
   * Dismiss a detection as a false positive. Stores the dismissal
   * locally (24h expiration) and sends opt-in telemetry.
   * @param {string|null} reason Comma-separated reasons, or null.
   */
  ContentScript.prototype.dismissAsFalsePositive = function (reason) {
    // Record action
    this.recordAction('dismiss_false_positive');

    // For each detection, store a local dismissal
    for (let i = 0; i < this.currentDetections.length; i++) {
      const d = this.currentDetections[i];
      const key = this.makeDismissKey(d);
      this.storeDismissal(key, reason);
    }
    this.hideBanner();
  };

  /**
   * Create a stable key for dismissal storage. Includes category
   * and the first 50 chars of the match (for pattern similarity).
   */
  ContentScript.prototype.makeDismissKey = function (detection) {
    const match = (detection.match || '').substring(0, 50);
    return detection.category + '|' + match;
  };

  /**
   * Store a dismissal in chrome.storage.local with 24h expiration.
   */
  ContentScript.prototype.storeDismissal = function (key, reason) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      log.warn('[AegisGate Lens] chrome.storage.local unavailable');
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const expires = now + 24 * 60 * 60;  // 24 hours
    const dismissKey = this.domainHash + '::' + key;
    const entry = {
      dismissed_at: now,
      expires_at: expires,
      reason: reason || null,
    };
    try {
      chrome.storage.local.get('dismissals', function (result) {
        const dismissals = result.dismissals || {};
        dismissals[dismissKey] = entry;
        chrome.storage.local.set({ dismissals: dismissals });
      });
    } catch (err) {
      log.warn('[AegisGate Lens] storage failed:', err);
    }

    // Send opt-in telemetry (if user enabled it)
    this.sendFPTelemetry(key, reason);
  };

  /**
   * Check if a detection has been dismissed for this domain.
   * @returns {boolean} true if a recent dismissal exists.
   */
  ContentScript.prototype.isDismissed = function (detection) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return false;
    }
    const key = this.domainHash + '::' + this.makeDismissKey(detection);
    let isDismissed = false;
    try {
      chrome.storage.local.get('dismissals', function (result) {
        const dismissals = result.dismissals || {};
        const entry = dismissals[key];
        if (entry && entry.expires_at > Math.floor(Date.now() / 1000)) {
          isDismissed = true;
        }
      });
    } catch (err) {
      // ignore
    }
    return isDismissed;
  };

  /**
   * Send an anonymous FP telemetry event (if enabled in storage).
   * NO prompt content is sent - only category, score, domain hash.
   */
  ContentScript.prototype.sendFPTelemetry = function (key, reason) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return;
    }
    const self = this;
    try {
      chrome.storage.local.get('fpTelemetryEnabled', function (result) {
        if (!result.fpTelemetryEnabled) return;
        // User opted in - send via service worker
        if (chrome.runtime && chrome.runtime.sendMessage) {
          for (let i = 0; i < self.currentDetections.length; i++) {
            const d = self.currentDetections[i];
            const event = {
              domain_hash: self.domainHash,
              category: d.category,
              severity: d.severity,
              user_action: 'dismiss_false_positive',
              timestamp: Math.floor(Date.now() / 1000),
              model_version: LENS_VERSION + '+regex-v1+ml-5way-v1',
              lens_version: LENS_VERSION,
              confidence: d.mlScore || 1.0,
              fp_reason: reason || null,
            };
            try {
              chrome.runtime.sendMessage({ type: 'lens.telemetry', event: event });
            } catch (err) {
              // ignore
            }
          }
        }
      });
    } catch (err) {
      // ignore
    }
  };

  /**
   * Record a user action by sending one LensEvent per detection
   * to the service worker (NOT to the backend directly).
   * @param {string} userAction One of: send_anyway, edit, cancel, dismiss.
   */
  ContentScript.prototype.recordAction = function (userAction) {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
      log.warn('[AegisGate Lens] chrome.runtime.sendMessage unavailable; skipping telemetry');
      return;
    }
    for (let i = 0; i < this.currentDetections.length; i++) {
      const d = this.currentDetections[i];
      const event = {
        domain_hash: this.domainHash,
        category: d.category,
        severity: d.severity,
        user_action: userAction,
        timestamp: Math.floor(Date.now() / 1000),
        model_version: LENS_VERSION + '+regex-v1+ml-5way-v1',
        lens_version: LENS_VERSION,
        confidence: 1.0,
      };
      try {
        chrome.runtime.sendMessage({ type: 'lens.telemetry', event: event });
      } catch (err) {
        log.warn('[AegisGate Lens] sendMessage failed:', err);
      }
    }
  };

  /**
   * Shared button style.
   * @param {string} bg
   * @returns {Object}
   */
  function buttonStyle(bg) {
    return {
      background: bg,
      color: '#ffffff',
      border: 'none',
      padding: '6px 12px',
      borderRadius: '4px',
      cursor: 'pointer',
      fontSize: '14px',
      fontWeight: '500',
    };
  }

  // =====================================================================
  // Entry point
  // =====================================================================

  NS.ContentScript = ContentScript;

  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    const script = new ContentScript();
    script.init().catch(function (err) {
      log.warn('[AegisGate Lens] init failed:', err);
    });
  }
})();