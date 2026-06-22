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
  // Schema reference for current-event-version constant. Day 3 cut-over:
  // every event we construct below sets lens_event_version to this value.
  // If the version is undefined (e.g. running without privacy/schema.js
  // loaded), we fall back to undefined which means client-side validate()
  // will reject the event — fail loud, never silently send unversioned
  // events. See plans/AEGISGATE-LENS-DAY-2-SCHEMA-V1.md.
  const SCHEMA_VERSION = (NS.privacy && NS.privacy.schema && NS.privacy.schema.SCHEMA_VERSION) || undefined;
  // LENS_VERSION: read from the manifest at IIFE time. Day 4 caught a
  // bug where this was hardcoded to '0.1.0' as a string literal; the
  // service worker reads from chrome.runtime.getManifest().version, so
  // this file should too. Fall back to '0.0.0' (not '0.1.0') so a
  // missed-update is detectable in the backend as a clear signal.
  const LENS_VERSION =
    (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest &&
      chrome.runtime.getManifest().version) || '0.0.0';
  const mlEngine = NS.mlEngine || null;
  const transformerEngine = NS.transformerEngine || null;
  const TRANSFORMER_UNCERTAIN_LOW = 0.3;
  const TRANSFORMER_UNCERTAIN_HIGH = 0.7;

  /**
   * The current Lens version is read at IIFE time from
   * chrome.runtime.getManifest().version (see top of this IIFE).
   * Day 4: previously hardcoded as '0.1.0' here as a build-tool
   * placeholder, but content.js never ran through the build tool
   * in this repo, so the value was stale. The runtime read above
   * is the single source of truth for both this file and
   * service-worker.js. See commit history for the Day-4 fix.
   */

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
  /**
   * AegisGate brand palette (matches https://aegisgatesecurity.io):
   *   critical: #f43f5e (rose)
   *   high:     #f59e0b (amber)
   *   medium:   #38bdf8 (sophisticated cyan)
   *   low:      #10b981 (emerald)
   *   safe:     #94a3b8 (slate)
   *
   * Returns the accent color + a readable foreground for that accent
   * on a dark glass background.
   */
  function severityTint(s) {
    switch (s) {
      case 'critical': return { accent: '#f43f5e', fg: '#ffffff', label: 'CRITICAL' };
      case 'high':     return { accent: '#f59e0b', fg: '#0a0c10', label: 'HIGH' };
      case 'medium':   return { accent: '#38bdf8', fg: '#0a0c10', label: 'MEDIUM' };
      case 'low':      return { accent: '#10b981', fg: '#0a0c10', label: 'LOW' };
      case 'info':     return { accent: '#94a3b8', fg: '#0a0c10', label: 'INFO' };
      default:         return { accent: '#94a3b8', fg: '#0a0c10', label: 'INFO' };
    }
  }

  /**
   * Banner background - shared glass panel in deep midnight.
   * Severity color is applied as a left accent border + a thin
   * top hairline, not a full-color fill (better readability on
   * dark themes, less page takeover).
   */
  const BANNER_BG = 'rgba(10, 12, 16, 0.92)';
  const BANNER_FONT_FAMILY = 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

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
      background: BANNER_BG,
      // Severity accent border applied in updateBannerContent.
      borderBottom: '1px solid rgba(56, 189, 248, 0.18)',
      borderLeft: '3px solid #38bdf8', // default; overwritten by severity
      padding: '14px 44px 14px 18px',
      fontFamily: BANNER_FONT_FAMILY,
      fontSize: '14px',
      lineHeight: '1.5',
      color: '#f8fafc',
      backdropFilter: 'blur(12px)',
      WebkitBackdropFilter: 'blur(12px)',
      boxShadow: '0 4px 24px rgba(0, 0, 0, 0.45)',
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
    // Header: AegisGate icon + title + severity badge.
    const header = document.createElement('div');
    Object.assign(header.style, {
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      marginBottom: '8px',
      flexWrap: 'wrap',
    });

    // Resolve a representative severity from the detection set
    // (critical > high > medium > low > info).
    const sevRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    let topSev = detections[0] && detections[0].severity || 'info';
    for (let i = 1; i < detections.length; i++) {
      const s = detections[i].severity || 'info';
      if ((sevRank[s] || 0) > (sevRank[topSev] || 0)) topSev = s;
    }
    const tint = severityTint(topSev);

    // Apply severity accent to the banner's left border + bottom hairline.
    this.banner.style.borderLeft = '3px solid ' + tint.accent;
    this.banner.style.borderBottom = '1px solid ' + tint.accent;

    // Small AegisGate shield icon (chrome-extension:// icon URL).
    const icon = document.createElement('img');
    icon.src = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
      ? chrome.runtime.getURL('icons/icon-32.png')
      : 'icons/icon-32.png';
    icon.alt = '';
    icon.width = 20;
    icon.height = 20;
    Object.assign(icon.style, {
      width: '20px',
      height: '20px',
      flexShrink: '0',
      display: 'block',
    });
    header.appendChild(icon);

    // Title text
    const title = document.createElement('span');
    Object.assign(title.style, {
      fontWeight: '600',
      color: '#f8fafc',
      letterSpacing: '-0.01em',
    });
    const count = detections.length;
    title.textContent =
      'AegisGate Lens: ' + count + ' sensitive item' +
      (count === 1 ? '' : 's') + ' detected in your prompt.';
    header.appendChild(title);

    // Severity badge - terminal-style code, not a colored pill.
    const badge = document.createElement('span');
    Object.assign(badge.style, {
      fontFamily: 'ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace',
      fontSize: '10px',
      fontWeight: '500',
      letterSpacing: '0.12em',
      padding: '2px 6px',
      border: '1px solid ' + tint.accent,
      color: tint.accent,
      background: 'transparent',
      textTransform: 'uppercase',
    });
    badge.textContent = '[' + tint.label + ']';
    header.appendChild(badge);

    this.banner.appendChild(header);

    const list = document.createElement('ul');
    Object.assign(list.style, {
      margin: '0 0 10px 0',
      paddingLeft: '20px',
      color: '#94a3b8',
    });
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
      color: '#38bdf8',
      textDecoration: 'underline',
      textUnderlineOffset: '2px',
      cursor: 'pointer',
      fontSize: '13px',
      fontFamily: 'inherit',
      padding: '0',
    });
    fpLink.setAttribute('aria-expanded', 'false');
    fpRow.appendChild(fpLink);
    this.banner.appendChild(fpRow);

    // FP form (hidden by default)
    const fpForm = document.createElement('div');
    Object.assign(fpForm.style, {
      display: 'none',
      background: 'rgba(17, 20, 29, 0.7)',
      border: '1px solid rgba(56, 189, 248, 0.25)',
      padding: '10px 12px',
      marginBottom: '10px',
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
    Object.assign(fpSubmitBtn.style, buttonStyle('#38bdf8'));
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
    Object.assign(fpJustDismissBtn.style, buttonStyle('#94a3b8'));
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
    Object.assign(cancelBtn.style, buttonStyle('#94a3b8'));
    cancelBtn.addEventListener('click', () => {
      this.recordAction('cancel');
      this.hideBanner();
    });
    actions.appendChild(cancelBtn);

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    Object.assign(editBtn.style, buttonStyle('#38bdf8'));
    editBtn.addEventListener('click', () => {
      this.recordAction('edit');
      this.hideBanner();
    });
    actions.appendChild(editBtn);

    const sendBtn = document.createElement('button');
    sendBtn.textContent = 'Send anyway';
    Object.assign(sendBtn.style, buttonStyle('#f43f5e'));
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
      position: 'absolute', top: '10px', right: '14px',
      background: 'transparent', border: 'none',
      fontSize: '22px', lineHeight: '1', cursor: 'pointer',
      color: '#94a3b8', padding: '0 6px',
      fontFamily: 'inherit',
      transition: 'color 120ms ease',
    });
    dismissBtn.addEventListener('mouseenter', () => { dismissBtn.style.color = '#f8fafc'; });
    dismissBtn.addEventListener('mouseleave', () => { dismissBtn.style.color = '#94a3b8'; });
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

    // Day 5: surface the opt-in prompt for FP telemetry, but only if
    // the user has not yet seen it AND has not already enabled it.
    // The prompt is keyed on chrome.storage.local; both flags persist
    // across sessions so the user is asked at most once.
    //
    // The banner stays visible while we read the flags asynchronously;
    // if the user has not yet decided, we render the opt-in card and
    // let its own buttons handle hiding the banner. Otherwise we hide
    // the banner immediately (pre-Day-5 behavior).
    this.maybeShowFPOptInCard(function (showCard) {
      if (!showCard) {
        this.hideBanner();
      }
    }.bind(this));
  };

  /**
   * Show the opt-in prompt for false-positive telemetry, unless the
   * user has already enabled FP telemetry OR has already seen and
   * dismissed the prompt.
   *
   * Day 5: this is the only call site. The card appears once per
   * installation, on the first false-positive dismiss. The privacy
   * guarantee is explicit: anonymous metadata, never prompt content,
   * no URLs, no per-user identifiers. See
   * plans/AEGISGATE-LENS-DAY-2-SCHEMA-V1.md for the wire format.
   *
   * Reads two flags from chrome.storage.local:
   *   - fpTelemetryEnabled (boolean): set when the user clicks
   *     "Help improve detection". When true, sendFPTelemetry will
   *     actually send events.
   *   - fpOptInPromptSeen (boolean): set when the user clicks EITHER
   *     button. Prevents the card from reappearing on every FP
   *     dismiss.
   */
  /**
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
      return;
    }
    try {
      chrome.storage.local.get(
        ['fpTelemetryEnabled', 'fpOptInPromptSeen'],
        function (result) {
          if (result.fpTelemetryEnabled) {
            if (cb) cb(false);
            return; // already opted in
          }
          if (result.fpOptInPromptSeen) {
            if (cb) cb(false);
            return; // already decided (Allow or Not now, previously)
          }
          self.showFPOptInCard();
          if (cb) cb(true);
        },
      );
    } catch (err) {
      log.warn('[AegisGate Lens] could not read FP opt-in flags:', err);
      if (cb) cb(false);
    }
  };

  /**
   * Render the opt-in card inside the banner. The card is styled in
   * the AegisGate brand palette (dark glass, cyan accent) and contains:
   *   - Title: "Help improve detection"
   *   - Privacy guarantee: short, plain-language statement
   *   - Two actions: "Help improve detection" (enable) and
   *     "Not now" (dismiss for this installation).
   *
   * Both actions set fpOptInPromptSeen = true so the card does not
   * reappear. Only the "Help improve detection" action also sets
   * fpTelemetryEnabled = true.
   */
  ContentScript.prototype.showFPOptInCard = function () {
    if (!this.banner) return;
    if (typeof document === 'undefined' || !document.createElement) return;

    // Day 5: capture this so the card's button click handlers (which
    // are regular functions, not arrow functions, so 'this' would be
    // the button) can call back into the content script.
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
      fontFamily: 'Inter, system-ui, sans-serif',
      fontSize: '13px',
      color: '#f8fafc',
      lineHeight: '1.45',
    });
    card.setAttribute('data-aegis-fp-opt-in', '1');

    // Title.
    const title = document.createElement('div');
    Object.assign(title.style, {
      fontWeight: '600',
      marginBottom: '6px',
      color: '#f8fafc',
      fontSize: '14px',
    });
    title.textContent = 'Help improve detection';
    card.appendChild(title);

    // Privacy guarantee.
    const body = document.createElement('div');
    Object.assign(body.style, { marginBottom: '10px', color: '#cbd5e1' });
    body.textContent =
      'AegisGate Lens uses your dismissals to tune future detections. ' +
      'We send anonymous metadata only (no prompt text, no URLs, no page content, ' +
      'no personal identifiers). Off by default. You can change this any time ' +
      'in the extension popup.';
    card.appendChild(body);

    // Actions row.
    const actions = document.createElement('div');
    Object.assign(actions.style, { display: 'flex', gap: '8px', flexWrap: 'wrap' });

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
        log.warn('[AegisGate Lens] could not save fpTelemetryEnabled:', err);
      }
      // Day 5: the card's actions own the banner lifecycle. dismissAsFalsePositive
      // deferred hideBanner() so the user can read the privacy guarantee; we
      // hide now that they've decided.
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
        log.warn('[AegisGate Lens] could not save fpOptInPromptSeen:', err);
      }
      if (self.hideBanner) self.hideBanner();
    });
    actions.appendChild(dismissBtn);

    card.appendChild(actions);

    // Insert at the END of the banner so it appears below the FP form
    // and the main action buttons (Cancel / Edit / Send anyway). The
    // banner will be hidden by hideBanner() right after this method
    // returns, so the card is only visible if the user re-opens the
    // banner via the detection list, OR if the content script is
    // re-displayed on a new detection with stale state.
    this.banner.appendChild(card);
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
              lens_event_version: SCHEMA_VERSION,
              domain_hash: self.domainHash,
              category: d.category,
              severity: d.severity,
              user_action: 'dismiss_false_positive',
              timestamp: Math.floor(Date.now() / 1000),
              model_version: LENS_VERSION + '+regex-v1+ml-5way-v1',
              lens_version: LENS_VERSION,
              confidence: d.mlScore || 1.0,
            };
            // fp_reason is optional; only attach when the user typed
            // something. Empty string or null would be rejected by
            // schema.validate() (must be non-empty when present).
            if (typeof reason === 'string' && reason.length > 0) {
              event.fp_reason = reason;
            }
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
        lens_event_version: SCHEMA_VERSION,
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
  /**
   * Dark-theme button style. Renders as an outlined button on
   * the banner's glass background, with the given accent color.
   *
   * @param {string} accent Border + text color.
   * @returns {Object} Style object suitable for Object.assign.
   */
  function buttonStyle(accent) {
    return {
      background: 'transparent',
      color: accent,
      border: '1px solid ' + accent,
      padding: '5px 12px',
      borderRadius: '0',
      cursor: 'pointer',
      fontSize: '13px',
      fontWeight: '500',
      fontFamily: 'inherit',
      letterSpacing: '0.01em',
      transition: 'background 120ms ease, color 120ms ease',
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