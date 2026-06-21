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

  /** Run the detector on the current prompt text. */
  ContentScript.prototype.runDetect = function () {
    const el = document.querySelector(this.provider.promptSelector);
    if (!el) return;
    const text = readPromptText(el);
    const detections = detect(text);
    this.currentDetections = detections;
    if (detections.length > 0) {
      this.showBanner(detections);
    } else {
      this.hideBanner();
    }
  };

  /**
   * Show the warning banner.
   * @param {Array<{category: string, severity: string, match: string, name: string}>} detections
   */
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
      li.textContent = describeCategory(d.category) + ' (' + d.severity +
        ') \u2014 match: "' + masked + '"';
      list.appendChild(li);
    }
    this.banner.appendChild(list);

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
        model_version: LENS_VERSION + '+regex-v1',
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