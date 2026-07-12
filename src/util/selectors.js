// AegisGate Lens — util/selectors.js
// Selector table for the 10 supported AI providers.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Logger. Per the architecture doc and standing rules: every module
  // must NEVER silently swallow errors. Use __lensLogger (set by
  // logger.js, which loads before this file). Fall back to console
  // if the logger isn't available (e.g., when running under node:test
  // or in the headless smoke test before all modules load).
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // Each entry: { hosts, inputSelector, sendSelector, containerSelector,
  //               submitMethod, isContentEditable, version }
  //
  // IMPORTANT: These selectors are based on the AI providers public
  // DOM structures as of July 2026. AI providers change their DOM
  // frequently. When a selector fails, the MutationObserver in
  // prompt-detect.js logs a warning and re-queries. A long-term
  // fix would be a per-provider plugin, but for v0.1.0-beta we
  // ship a curated list and rely on the observer for resilience.
  var PROVIDERS = [
    {
      id: 'chatgpt',
      name: 'ChatGPT',
      hosts: ['chat.openai.com', 'chatgpt.com'],
      // ChatGPT: contenteditable ProseMirror element or textarea
      inputSelector: 'div#prompt-textarea[contenteditable="true"], div.ProseMirror[contenteditable="true"], textarea#prompt-textarea, textarea[name="userInput"]',
      // Send button (the up-arrow)
      sendSelector: 'button[data-testid="send-button"], button[aria-label*="Send" i]',
      // The bottom composer area
      containerSelector: 'form.w-full, div[role="presentation"]',
      // Submit by Enter (Shift+Enter is newline)
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'claude',
      name: 'Claude',
      hosts: ['claude.ai'],
      // Claude: a ProseMirror-style editor
      inputSelector: 'div.ProseMirror[contenteditable="true"], [data-testid="chat-input"] [contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button[data-testid="send-message"]',
      containerSelector: 'div[data-testid="chat-input"], fieldset',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'gemini',
      name: 'Gemini',
      hosts: ['gemini.google.com'],
      // Gemini: a rich-text editor div
      inputSelector: 'div.ql-editor[contenteditable="true"], rich-textarea div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button.send-button',
      containerSelector: 'rich-textarea, input-area',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'copilot',
      name: 'Microsoft Copilot',
      hosts: ['copilot.microsoft.com', 'copilot.cloud.microsoft'],
      // Copilot: textarea in the composer area
      inputSelector: 'textarea#userInput, textarea[name="userInput"], textarea[placeholder*="message" i], textarea[placeholder*="Ask" i], div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button[aria-label*="Submit" i], button[type="submit"]',
      containerSelector: 'form, div.input-container, div[role="main"]',
      submitMethod: 'click',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'perplexity',
      name: 'Perplexity',
      hosts: ['perplexity.ai', 'www.perplexity.ai'],
      // Perplexity: textarea in the search/composer area
      inputSelector: 'textarea[placeholder*="message" i], textarea[placeholder*="Ask" i], textarea[placeholder*="search" i], textarea[name="q"], textarea[name="prompt"], div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Submit" i], button[type="submit"], button[aria-label*="Search" i]',
      containerSelector: 'div[role="search"], form, div[role="main"]',
      submitMethod: 'click',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'duck_ai',
      name: 'Duck.ai',
      hosts: ['duck.ai'],
      // Duck.ai: new chat interface - updated selectors based on actual DOM
      inputSelector: 'textarea[placeholder*="message" i], textarea[placeholder*="Ask" i], div[contenteditable="true"]',
      sendSelector: 'button[type="submit"], button[aria-label*="Send" i], button[aria-label*="Submit" i]',
      containerSelector: 'main, form, div[role="main"]',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'grok',
      name: 'Grok',
      hosts: ['grok.com', 'www.grok.com'],
      // Grok: textarea in the Grok composer area
      // Note: x.com and twitter.com are NOT supported. The Grok tab on
      // x.com lives at grok.com (and www.grok.com). Posting to x.com
      // itself is a different surface; the v0.1.0-beta scope is
      // limited to the dedicated Grok chat.
      inputSelector: 'textarea[placeholder*="message" i], textarea[placeholder*="Ask" i], div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send" i], button[aria-label*="Post" i], button[type="submit"]',
      containerSelector: 'form, div[role="group"], div[role="textbox"]',
      submitMethod: 'enter',
      isContentEditable: true,
      version: '2026-07'
    },
    {
      id: 'mistral',
      name: 'Mistral Le Chat',
      hosts: ['chat.mistral.ai', 'le-chat.mistral.ai'],
      // Mistral: textarea
      inputSelector: 'textarea[name="text"], textarea[placeholder*="Ask" i]',
      sendSelector: 'button[type="submit"], button[aria-label*="Send" i]',
      containerSelector: 'form',
      submitMethod: 'enter',
      isContentEditable: false,
      version: '2026-07'
    },
  ];

  // Identify which provider matches the current page.
  // Returns the provider config object, or null if no match.
  function identifyProvider() {
    // Test-only: window.__lensMockHost is a shim set by the mini smoke
    // mock HTML (tools/headless-smoke/mini/mock.go) so per-host mock
    // pages can be identified as their respective providers even
    // though the URL is always https://localhost:PORT/. This is a
    // no-op in production (no mock page sets this global).
    var hostname = (window.__lensMockHost) ||
                   (window.location && window.location.hostname) || '';
    if (!hostname) return null;
    var host = hostname.toLowerCase();
    for (var i = 0; i < PROVIDERS.length; i++) {
      var p = PROVIDERS[i];
      for (var j = 0; j < p.hosts.length; j++) {
        // Exact match or subdomain match
        var h = p.hosts[j].toLowerCase();
        if (host === h || host.endsWith('.' + h)) {
          return p;
        }
      }
    }
    // Test-only: localhost matches the first provider (chatgpt).
    // This enables the headless smoke test (test/headless-smoke/)
    // to fire the content script on a localhost HTTPS mock. In
    // production, this only matches on localhost (which Chrome
    // treats as a secure context but the user would have to
    // intentionally navigate to). See test/headless-smoke/STATUS.md.
    if (host === 'localhost' || host === '127.0.0.1') {
      log.info('selectors: localhost hostname detected, using chatgpt provider for smoke test');
      return PROVIDERS[0];
    }
    return null;
  }

  // Get the input element (textarea or contenteditable div).
  // Returns null if not found.
  function findInput(provider) {
    if (!provider) return null;
    var candidates = document.querySelectorAll(provider.inputSelector);
    if (candidates.length > 0) return candidates[0];
    // Fallback: try to find any visible contenteditable or textarea
    // in the page (this is the DOM changed case)
    var fallbacks = document.querySelectorAll(
      'textarea[placeholder*="Ask" i], ' +
      'textarea[placeholder*="message" i], ' +
      'textarea[placeholder*="prompt" i], ' +
      'div[contenteditable="true"]'
    );
    for (var i = 0; i < fallbacks.length; i++) {
      var el = fallbacks[i];
      var rect = el.getBoundingClientRect();
      // Only visible elements (positive width/height)
      if (rect.width > 100 && rect.height > 20) return el;
    }
    return null;
  }

  // Get the current text from the input element.
  // Works for both textarea and contenteditable.
  function getInputValue(input) {
    if (!input) return '';
    if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
      return input.value || '';
    }
    if (input.isContentEditable || input.getAttribute('contenteditable') === 'true') {
      return input.innerText || input.textContent || '';
    }
    return input.value || input.innerText || '';
  }

  // Set the text in the input element.
  function setInputValue(input, value) {
    if (!input) return;
    if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
      var nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
      ).set;
      nativeSetter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      input.innerText = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  // Find the send button (may not exist on every page)
  function findSendButton(provider) {
    if (!provider || !provider.sendSelector) return null;
    var candidates = document.querySelectorAll(provider.sendSelector);
    if (candidates.length > 0) return candidates[0];
    return null;
  }

  // Find the container to attach the banner to
  function findContainer(provider) {
    if (!provider) return document.body;
    var candidates = document.querySelectorAll(provider.containerSelector);
    if (candidates.length > 0) return candidates[0];
    return document.body;
  }

  var module = {
    PROVIDERS: PROVIDERS,
    identifyProvider: identifyProvider,
    findInput: findInput,
    getInputValue: getInputValue,
    setInputValue: setInputValue,
    findSendButton: findSendButton,
    findContainer: findContainer
  };

  if (typeof self !== 'undefined') self.__lensSelectors = module;
  if (typeof window !== 'undefined') window.__lensSelectors = module;
  /**
   * @type {import("./typedefs").LensSelectors}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensSelectors = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
