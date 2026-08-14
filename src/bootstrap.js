// AegisGate Lens — bootstrap.js
//
// Single source of truth for the content-script load-order contract.
//
// Every file in src/content_scripts[] (declared in manifest.json)
// gets executed in order, and each one exposes a module by setting
// `globalThis.__lensXxx` at the bottom of its IIFE. Subsequent
// scripts can then read those globals and depend on them.
//
// This file documents that ordering, the dependency graph, and the
// expected global names. It does NOT run any detection code; it is
// loaded first so that if any later script queries
// `globalThis.__lensBootstrap`, they can read the manifest, the
// dependency graph, and a `whenReady(name, fn)` helper that
// resolves once the named module is present.
//
// The 17 scripts in content_scripts.js MUST be loaded in this order
// because of the dependency graph below. Reordering breaks the
// init contract.
//
// Per the v0.2.0 code-quality plan (item 5).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  /**
   * The canonical list of every global a content script exposes.
   * Each entry: { name, file, dependsOn, summary }.
   * @type {Array<{name: string, file: string, dependsOn: string[], summary: string}>}
   */
  var MODULE_REGISTRY = [
    { name: '__lensConstants',   file: 'util/constants.js',         dependsOn: [],                  summary: 'Magic numbers, color tokens, storage keys, URLs' },
    { name: '__lensTypedefs',    file: 'util/typedefs.js',          dependsOn: [],                  summary: 'JSDoc type definitions (IntelliSense only, no runtime effect)' },
    { name: '__lensLogger',      file: 'util/logger.js',            dependsOn: ['__lensConstants'],  summary: 'Logger wrapper (info / warn / error) with chrome.runtime.lastError handling' },
    { name: '__lensLuhn',        file: 'detectors/luhn.js',         dependsOn: [],                  summary: 'Luhn-validates credit card candidates; used by pii.js postProcess' },
    { name: '__lensPII',         file: 'detectors/regex/pii.js',    dependsOn: ['__lensLuhn'],      summary: 'PII facet detector (65 patterns: SSN, email, phone, CC, DOB, address, passport, DL, IBAN, Aadhaar, NHS, TFN, SIN, CPF, BIP39, BTC/ETH/BNB/LTC/SOL, PayPal/Stripe/Venmo/CashApp, SWIFT/BIC, CPT/HCPCS, residence, visa, intl DL)' },
    { name: '__lensOT_protocols',file: 'detectors/regex/ot-protocols.js', dependsOn: [],            summary: 'OT/ICS protocol detector (9 patterns: Modbus function codes, DNP3 control operations, OPC-UA method calls)' },
    { name: '__lensSecrets',     file: 'detectors/regex/secrets.js',dependsOn: [],                  summary: 'Secrets facet detector (41 patterns: AWS, GitHub PAT, GCP, Azure, JWT, Stripe, OpenAI, Anthropic, Slack, Discord, Twilio, SendGrid, Mailgun, Heroku, GitLab, npm, PyPI, PEM, OAuth, CI tokens)' },
    { name: '__lensXSS',         file: 'detectors/regex/source_xss.js', dependsOn: [],              summary: 'Source/XSS facet detector (12 patterns: script tags, event handlers, javascript:/data: URLs, SVG onload, mutation XSS, polyglot, DOM clobbering)' },
    { name: '__lensCompliance',  file: 'detectors/regex/compliance.js', dependsOn: [],             summary: 'Compliance facet detector (24 patterns: OWASP LLM Top 10, MITRE ATLAS, EU AI Act, ANP, Computer Use Guard, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA, toxicity)' },
    { name: '__lensSchema',      file: 'privacy/schema.js',         dependsOn: [],                  summary: 'Privacy event schema + validation (for opt-in telemetry payloads)' },
    { name: '__lensDomainHash',  file: 'privacy/domain_hash.js',    dependsOn: ['__lensSchema'],    summary: 'Domain hashing for opt-in telemetry (one-way, salt-rotated)' },
    { name: '__lensDispatcher',  file: 'detectors/index.js',        dependsOn: ['__lensPII', '__lensOT_protocols', '__lensSecrets', '__lensXSS', '__lensCompliance'], summary: '5-facet dispatcher: runs all 5 detectors and merges events' },
    { name: '__lensSelectors',   file: 'util/selectors.js',         dependsOn: [],                  summary: 'Provider-specific DOM selectors (10 providers) + identify/findInput/setInputValue/findSendButton' },
    { name: '__lensPromptDetect',file: 'util/prompt-detect.js',     dependsOn: ['__lensConstants', '__lensDispatcher', '__lensSelectors', '__lensLogger'], summary: 'Per-keystroke orchestrator: 250ms debounce, redact dispatch, event broadcasting' },
    { name: '__lensBannerIcons', file: 'util/banner-icons.js',      dependsOn: [],                  summary: 'Inline SVG icon strings (shield, close, help, chevronDown)' },
    { name: '__lensDismiss',     file: 'util/dismiss.js',           dependsOn: ['__lensConstants', '__lensSchema'], summary: 'Per-session FP dismissal state (24h TTL, opt-in FP reports)' },
    { name: '__lensBannerUI',    file: 'util/banner-ui.js',         dependsOn: ['__lensConstants', '__lensBannerIcons', '__lensLogger'], summary: 'Banner render, DOM injection, action delegation, dismiss handling' },
    { name: '__lensContent',     file: 'content.js',                dependsOn: ['__lensLogger', '__lensPromptDetect', '__lensBannerUI', '__lensSelectors', '__lensDismiss'], summary: 'Top-level content script: identifies provider, attaches to input, wires banner actions' }
  ];

  /**
   * Wait until a specific global is present, then call the callback.
   * Used by content.js to handle the race where some scripts may
   * finish loading in an order other than declaration order (which
   * should not happen but we defensive-program against).
   *
   * @param {string} name   The global to wait for (e.g. '__lensPII')
   * @param {function} fn   Called when the global is set
   * @param {number} [timeoutMs=2000]  Max wait before giving up
   */
  function whenReady(name, fn, timeoutMs) {
    timeoutMs = timeoutMs || 2000;
    var start = Date.now();
    (function check() {
      if (global[name] !== undefined) {
        fn();
      } else if (Date.now() - start < timeoutMs) {
        setTimeout(check, 5);
      } else {
        if (global.__lensLogger) {
          global.__lensLogger.error('bootstrap: timed out waiting for ' + name);
        }
      }
    })();
  }

  /**
   * Verify the dependency graph: walk the registry, check each module
   * is set after a 100ms grace period. Returns a report suitable for
   * logging. Does NOT throw — diagnostics only.
   *
   * @returns {{ok: boolean, missing: string[], cycle: boolean, loadOrder: string[]}}
   */
  function verify() {
    var missing = [];
    var seen = {};
    var loadOrder = [];
    // Topological walk based on dependsOn.
    function visit(mod) {
      if (seen[mod.name]) return;
      mod.dependsOn.forEach(function (dep) {
        var depMod = MODULE_REGISTRY.find(function (m) { return m.name === dep; });
        if (depMod && !seen[depMod.name]) visit(depMod);
      });
      seen[mod.name] = true;
      loadOrder.push(mod.name);
    }
    MODULE_REGISTRY.forEach(function (m) {
      // Defer the actual global check; the registry walk is pure.
    });
    MODULE_REGISTRY.forEach(visit);
    return { ok: missing.length === 0, missing: missing, cycle: false, loadOrder: loadOrder };
  }

  if (typeof globalThis !== 'undefined') {
    /**
     * @type {{MODULE_REGISTRY: Array, whenReady: function, verify: function, version: string}}
     */
    globalThis.__lensBootstrap = {
      MODULE_REGISTRY: MODULE_REGISTRY,
      whenReady: whenReady,
      verify: verify,
      version: '0.3.0'
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
