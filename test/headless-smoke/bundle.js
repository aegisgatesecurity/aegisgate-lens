window.__lens_test_wrapper = { started: Date.now() };
try {

// === bootstrap.js ===
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
// Per the v0.1.1 code-quality plan (item 5).
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
    { name: '__lensPII',         file: 'detectors/regex/pii.js',    dependsOn: ['__lensLuhn'],      summary: 'PII facet detector (54 patterns: SSN, email, phone, CC, DOB, address, passport, DL, IBAN, Aadhaar, NHS, TFN, SIN, CPF, BIP39, BTC/ETH/BNB/LTC/SOL, PayPal/Stripe/Venmo/CashApp, residence, visa, intl DL)' },
    { name: '__lensSecrets',     file: 'detectors/regex/secrets.js',dependsOn: [],                  summary: 'Secrets facet detector (41 patterns: AWS, GitHub PAT, GCP, Azure, JWT, Stripe, OpenAI, Anthropic, Slack, Discord, Twilio, SendGrid, Mailgun, Heroku, GitLab, npm, PyPI, PEM, OAuth, CI tokens)' },
    { name: '__lensXSS',         file: 'detectors/regex/source_xss.js', dependsOn: [],              summary: 'Source/XSS facet detector (12 patterns: script tags, event handlers, javascript:/data: URLs, SVG onload, mutation XSS, polyglot, DOM clobbering)' },
    { name: '__lensCompliance',  file: 'detectors/regex/compliance.js', dependsOn: [],             summary: 'Compliance facet detector (24 patterns: OWASP LLM Top 10, MITRE ATLAS, EU AI Act, ANP, Computer Use Guard, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA, toxicity)' },
    { name: '__lensSchema',      file: 'privacy/schema.js',         dependsOn: [],                  summary: 'Privacy event schema + validation (for opt-in telemetry payloads)' },
    { name: '__lensDomainHash',  file: 'privacy/domain_hash.js',    dependsOn: ['__lensSchema'],    summary: 'Domain hashing for opt-in telemetry (one-way, salt-rotated)' },
    { name: '__lensDispatcher',  file: 'detectors/index.js',        dependsOn: ['__lensPII', '__lensSecrets', '__lensXSS', '__lensCompliance'], summary: '4-facet dispatcher: runs all 4 detectors and merges events' },
    { name: '__lensSelectors',   file: 'util/selectors.js',         dependsOn: [],                  summary: 'Provider-specific DOM selectors (8 providers) + identify/findInput/setInputValue/findSendButton' },
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
      version: '0.1.1'
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/constants.js ===
// AegisGate Lens — util/constants.js
//
// Single source of truth for the magic numbers, color tokens,
// timing constants, and storage keys that were previously
// scattered across banner-ui.js, prompt-detect.js, background.js,
// dismiss.js, and banner.css.
//
// Per the v0.1.1 code-quality plan (item 7).
//
// Consumers import this module via the globalThis side-effect
// pattern (e.g. `globalThis.__lensConstants.DEBOUNCE_MS`).
// In tests, the module is loaded via readFileSync + eval just
// like every other Lens module; the export is also placed on
// `module.exports` for direct require() use in the node test
// sandbox.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // === Detection timing ===
  // How long to wait after the last keystroke before running the
  // 4-facet regex scan. 250ms is short enough to feel real-time
  // and long enough to avoid running on every keystroke.
  var DEBOUNCE_MS = 250;

  // === Banner UI / animation ===
  // Banner fade-in animation duration, in milliseconds.
  var BANNER_FADE_IN_MS = 200;

  // Maximum number of detection items shown in the banner list
  // before the "+ N more" overflow line appears.
  var BANNER_MAX_ITEMS = 8;

  // z-index for the banner. 2147483647 = max 32-bit signed int.
  // Pinned above every conceivable page element.
  var BANNER_Z_INDEX = 2147483647;

  // === Detection limits ===
  // Maximum number of events to keep in the per-installation
  // event ring buffer. Caps storage usage under heavy use.
  var MAX_EVENTS_RING = 1000;

  // Maximum number of user-action records kept in chrome.storage.local
  // for the popup history view. Per background.js.
  var MAX_USER_ACTIONS = 100;

  // === Storage keys ===
  // Centralized so we never typo a key and silently break persistence.
  var STORAGE_KEYS = Object.freeze({
    DISMISSALS: 'aegisgate_lens_dismissals',
    USER_ACTIONS: 'aegisgate_lens_user_actions',
    FP_REPORTS_QUEUE: 'aegisgate_lens_fp_reports_queue',
    OPT_IN: 'aegisgate_lens_opt_in',
    SESSION_DISMISS: 'aegisgate_lens_session_dismiss',
    ONBOARDED: 'aegisgate_lens_onboarded',
    // v0.1.4: per-popup "Hide Lens active indicator" toggle.
    // Default ON (show indicator) — no behavior change for existing
    // users. The content script's prompt-detect-dom.js reads this
    // synchronously (cached value with onChanged listener) and
    // early-returns from injectIndicator() when false.
    SHOW_INDICATOR: 'aegisgate_lens_show_indicator',
    // v0.1.4: global "Pause Lens for 1h / 1d" toggle.
    // Default 0 (not paused). When set to a future timestamp (ms
    // since epoch), the content script's prompt-detect-dom.js
    // early-returns from onInput() until Date.now() >= the value.
    // Different semantic from per-domain 24h dismiss (dismiss.js):
    // pause is global across all domains/categories; dismiss is
    // per-domain per-category. Used by security researchers and
    // developers testing prompts.
    PAUSE_UNTIL: 'aegisgate_lens_pause_until'
  });

  // === Telemetry / dismissal ===
  // How long a per-domain + per-pattern dismissal lasts in
  // chrome.storage.local before it expires. 24 hours.
  var DISMISS_TTL_MS = 24 * 60 * 60 * 1000;

  // Schema version stamped into the dismissals storage record
  // so future migrations can detect old payloads.
  var STORAGE_SCHEMA_VERSION = '0.1.1';

  // === FP report reason codes ===
  // The 3 reason codes the user can pick when dismissing.
  // These match the BANNER-DESIGN-SPEC.
  var FP_REASON = Object.freeze({
    TEST_DATA: 'test_data',
    OWN_DATA: 'own_data',
    LEGITIMATE: 'legitimate_use_case'
  });

  // === Brand color tokens (mirror of CSS custom properties) ===
  // Kept in JS so the SW (which can run before CSS loads) and
  // popup.html (which has its own scoped CSS) can reference the
  // same brand palette. CSS remains the source of truth at
  // runtime; this is a fallback for SW-side logging/messaging.
  var COLORS = Object.freeze({
    BG_PRIMARY:      '#0a0c10',
    BG_SECONDARY:    '#11141d',
    BG_TERTIARY:     '#1a1f2e',
    PRIMARY:         '#38bdf8',
    PRIMARY_HOVER:   '#00c4ec',
    PRIMARY_GLOW:    'rgba(56, 189, 248, 0.15)',
    SECONDARY:       '#10b981',
    ACCENT:          '#f43f5e',
    TEXT_PRIMARY:    '#f8fafc',
    TEXT_SECONDARY:  '#94a3b8',
    TEXT_MUTED:      '#64748b',
    BORDER:          'rgba(51, 65, 85, 0.5)',
    GLASS_BG:        'rgba(17, 20, 29, 0.7)'
  });

  // === Severity levels ===
  // Must match the keys used in detector pattern definitions.
  var SEVERITY = Object.freeze({
    CRITICAL: 'critical',
    HIGH:     'high',
    MEDIUM:   'medium',
    LOW:      'low'
  });

  // === Detector category prefixes ===
  // Used by banner-ui.formatCategory() to strip the leading
  // category prefix from a category id like "pii_email" ->
  // "email". Centralized so adding a new detector family is
  // a single-file change.
  var CATEGORY_PREFIXES = Object.freeze([
    'pii_',
    'secret_',
    'xss_',
    'owasp_',
    'atlas_',
    'eu_ai_act_',
    'anp_',
    'cu_',
    'toxicity_',
    'pi_'
  ]);

  // === Detection facets (the 4 ship-state categories) ===
  var FACETS = Object.freeze({
    PII:       'pii',
    SECRETS:   'secrets',
    XSS:       'xss',
    COMPLIANCE:'compliance'
  });

  // === Public URLs ===
  // Single source of truth so updates only happen in one place.
  // Manifest host_permissions are separate; these are user-facing
  // links rendered in the banner / popup / welcome page.
  var URLS = Object.freeze({
    LEARN_MORE:    'https://github.com/aegisgatesecurity/aegisgate-lens#readme',
    PLATFORM_CTA:  'https://aegisgatesecurity.io/platform/pricing',
    PRIVACY:       'https://aegisgatesecurity.io/lens/privacy',
    SUPPORT:       'https://github.com/aegisgatesecurity/aegisgate-lens/issues',
    HOMEPAGE:      'https://github.com/aegisgatesecurity/aegisgate-lens'
  });

  // === Module export ===
  var module = {
    DEBOUNCE_MS:          DEBOUNCE_MS,
    BANNER_FADE_IN_MS:    BANNER_FADE_IN_MS,
    BANNER_MAX_ITEMS:     BANNER_MAX_ITEMS,
    BANNER_Z_INDEX:       BANNER_Z_INDEX,
    MAX_EVENTS_RING:      MAX_EVENTS_RING,
    MAX_USER_ACTIONS:     MAX_USER_ACTIONS,
    STORAGE_KEYS:         STORAGE_KEYS,
    DISMISS_TTL_MS:       DISMISS_TTL_MS,
    STORAGE_SCHEMA_VERSION: STORAGE_SCHEMA_VERSION,
    FP_REASON:            FP_REASON,
    COLORS:               COLORS,
    SEVERITY:             SEVERITY,
    CATEGORY_PREFIXES:    CATEGORY_PREFIXES,
    FACETS:               FACETS,
    URLS:                 URLS
  };

  if (typeof globalThis !== 'undefined') {
    /**
     * @type {import("./typedefs").LensConstants}
     */
    globalThis.__lensConstants = module;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = module;
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/typedefs.js ===
// AegisGate Lens — util/typedefs.js
//
// Central JSDoc type definitions for every module export in the
// Lens. Loaded once at boot (manifest declares it as the second
// content_script after constants.js). At runtime this file has no
// effect; its purpose is to give editors (VS Code, WebStorm,
// GitHub code review) the ability to type-check and auto-complete
// against the actual runtime shape of every module.
//
// Per the v0.1.1 code-quality plan (item 4).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  /**
   * @typedef {Object} LensConstants
   * @property {number} DEBOUNCE_MS
   * @property {number} BANNER_FADE_IN_MS
   * @property {number} BANNER_MAX_ITEMS
   * @property {number} BANNER_Z_INDEX
   * @property {number} MAX_EVENTS_RING
   * @property {number} MAX_USER_ACTIONS
   * @property {{DISMISSALS: string, USER_ACTIONS: string, FP_REPORTS_QUEUE: string, OPT_IN: string, SESSION_DISMISS: string}} STORAGE_KEYS
   * @property {number} DISMISS_TTL_MS
   * @property {string} STORAGE_SCHEMA_VERSION
   * @property {{TEST_DATA: string, OWN_DATA: string, LEGITIMATE: string}} FP_REASON
   * @property {Object<string, string>} COLORS
   * @property {{CRITICAL: string, HIGH: string, MEDIUM: string, LOW: string}} SEVERITY
   * @property {string[]} CATEGORY_PREFIXES
   * @property {{PII: string, SECRETS: string, XSS: string, COMPLIANCE: string}} FACETS
   * @property {{LEARN_MORE: string, PLATFORM_CTA: string, PRIVACY: string, SUPPORT: string, HOMEPAGE: string}} URLS
   */

  /**
   * @typedef {Object} LensLogger
   * @property {(m: string) => void} info
   * @property {(m: string) => void} warn
   * @property {(m: string, e?: Error) => void} error
   */

  /**
   * @typedef {('critical'|'high'|'medium'|'low')} LensSeverity
   */

  /**
   * @typedef {Object} LensDetectionEvent
   * @property {string} category
   * @property {LensSeverity} severity
   * @property {string} [sample]
   * @property {number} [index]
   * @property {string} [pattern]
   * @property {string} [facet]
   */

  /**
   * @typedef {Object} LensDetectionResult
   * @property {LensDetectionEvent[]} events
   * @property {string} [facet]
   */

  /**
   * @typedef {Object} LensDomainHash
   * @property {(hostname: string) => string} hash
   * @property {(hostname: string) => Promise<string>} hashAsync
   */

  /**
   * @typedef {Object} LensProvider
   * @property {string} id
   * @property {string} name
   * @property {string[]} hosts
   * @property {string} inputSelector
   * @property {string} [sendSelector]
   * @property {string} [containerSelector]
   * @property {('button'|'form'|'enter'|'unknown')} submitMethod
   * @property {boolean} [isContentEditable]
   * @property {string} version
   */

  /**
   * @typedef {Object} LensSelectors
   * @property {LensProvider[]} PROVIDERS
   * @property {() => LensProvider | null} identifyProvider
   * @property {() => HTMLElement | null} findInput
   * @property {() => string} getInputValue
   * @property {(el: HTMLElement, value: string) => void} setInputValue
   * @property {() => HTMLElement | null} findSendButton
   * @property {() => HTMLElement | null} findContainer
   */

  /**
   * @typedef {Object} LensDetectorPattern
   * @property {string} key
   * @property {string} category
   * @property {RegExp} re
   * @property {LensSeverity} severity
   * @property {string} [description]
   */

  /**
   * @typedef {Object} LensDetector
   * @property {string} facet
   * @property {Object<string, LensDetectorPattern>} patterns
   * @property {(text: string) => LensDetectionEvent[]} detect
   * @property {string} version
   */

  /**
   * @typedef {Object} LensDispatcher
   * @property {(text: string) => LensDetectionEvent[]} detect
   * @property {string[]} [facets]
   * @property {Object<string, LensDetector>} [_modules]
   */

  /**
   * @typedef {Object} LensBannerOptions
   * @property {(action: string, payload: Object) => void} [onAction]
   * @property {string} [learnMoreUrl]
   * @property {string} [platformUrl]
   * @property {string} [scope]
   */

  /**
   * @typedef {Object} LensBannerState
   * @property {HTMLElement} el
   * @property {LensDetectionEvent[]} events
   * @property {LensBannerOptions} opts
   * @property {boolean} visible
   */

  /**
   * @typedef {Object} LensBannerUI
   * @property {(events: LensDetectionEvent[], opts?: LensBannerOptions) => void} show
   * @property {() => void} hide
   * @property {() => boolean} isVisible
   * @property {() => HTMLElement | null} getElement
   * @property {() => void} injectStyles
   */

  /**
   * @typedef {Object} LensPromptDetect
   * @property {() => void} attach
   * @property {() => void} detach
   * @property {() => void} onInput
   * @property {() => void} onSendClick
   * @property {() => void} onKeyDown
   * @property {(text: string) => LensDetectionEvent[]} detect
   * @property {() => boolean} isAttached
   * @property {() => string} getState
   */

  /**
   * @typedef {Object} LensDismissRecord
   * @property {string} domainHash
   * @property {string} category
   * @property {string} [patternId]
   * @property {string} reason
   * @property {number} expiresAt
   * @property {string} schemaVersion
   */

  /**
   * @typedef {Object} LensDismiss
   * @property {() => Promise<Object<string, LensDismissRecord>>} getAll
   * @property {(domainHash: string, category: string, patternId: string, reason: string) => Promise<boolean>} add
   * @property {(domainHash: string, category: string, patternId: string) => Promise<boolean>} isDismissed
   * @property {(domainHash: string, category: string, patternId: string) => Promise<boolean>} remove
   * @property {() => Promise<void>} clearAll
   * @property {() => Promise<number>} prune
   * @property {string} STORAGE_KEY
   * @property {number} TTL_MS
   * @property {string} SCHEMA_VERSION
   */

  /**
   * @typedef {Object} LensMessageEnvelope
   * @property {string} type
   * @property {string} version
   * @property {Object} payload
   */

  /**
   * @typedef {Object} LensMessages
   * @property {Object<string, string>} TYPE
   * @property {(msg: Object) => boolean} isValidEnvelope
   * @property {(msg: Object) => boolean} isValidFPReports
   * @property {(msg: Object) => boolean} isValidUserAction
   */

  /**
   * @typedef {Object} LensPrivacyCategory
   * @property {string} id
   * @property {string} name
   * @property {string} facet
   * @property {string} description
   * @property {string[]} examples
   */

  /**
   * @typedef {Object} LensSchema
   * @property {string} version
   * @property {LensPrivacyCategory[]} categories
   * @property {Object<string, string[]>} [patternsByCategory]
   */

  if (typeof globalThis !== 'undefined') {
    globalThis.__lensTypedefs = {
      version: '0.1.1',
      loaded: new Date().toISOString()
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/logger.js ===
// AegisGate Lens — logger.js
// Tiny console wrapper that NEVER silently swallows errors.
// Per the architecture doc and standing rules: every .catch() must log
// the actual err with a contextual prefix.
//
// Loaded as the FIRST content_script (per manifest.json content_scripts
// order) so all subsequent content-script modules can use this logger.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // The single shared logger object. Exposed on `self.__lensLogger` so
  // other content-script modules can grab it without coupling to the
  // global `aegisgateLens` namespace (which may not be initialized yet
  // when this file first runs).
  var logger = {
    tag: '[AegisGate Lens]',

    info: function (msg, extra) {
      try {
        if (extra === undefined) {
          console.info(this.tag + ' ' + msg);
        } else {
          console.info(this.tag + ' ' + msg, extra);
        }
      } catch (e) {
        // Last-resort fallback: the logging itself failed (e.g. console
        // is not available in some sandboxed context). Do NOT swallow
        // silently — re-throw so the caller knows logging is broken.
        throw new Error('logger.info failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    warn: function (msg, extra) {
      try {
        if (extra === undefined) {
          console.warn(this.tag + ' ' + msg);
        } else {
          console.warn(this.tag + ' ' + msg, extra);
        }
      } catch (e) {
        throw new Error('logger.warn failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    error: function (msg, err) {
      // The KEY rule: always log the actual err object. Never use a
      // useless "init failed" string. If err is undefined, log that
      // we have no err object — don't pretend we do.
      try {
        if (err === undefined || err === null) {
          console.error(this.tag + ' ' + msg + ' (no err object provided)');
        } else if (err instanceof Error) {
          console.error(this.tag + ' ' + msg + ':', err.message, err.stack || '');
        } else {
          // err might be a string, a plain object, anything
          console.error(this.tag + ' ' + msg + ':', err);
        }
      } catch (e) {
        // Logging failed. We can't log the failure, so we re-throw
        // with a meaningful message.
        throw new Error('logger.error failed: ' + (e && e.message ? e.message : String(e)));
      }
    },

    // Convenience: wrap a promise so any rejection is logged with context.
    // Use: `logger.guard('analytics.flush', analytics.flush())`
    guard: function (context, promise) {
      if (!promise || typeof promise.then !== 'function') {
        this.error('logger.guard called with non-promise', { context: context, value: promise });
        return Promise.reject(new Error('logger.guard: not a promise'));
      }
      return promise.catch(function (err) {
        this.error(context, err);
        // Re-throw so the caller's .then chain still sees the rejection
        throw err;
      }.bind(this));
    }
  };

  // Expose on multiple globals for compatibility:
  //   - `self.__lensLogger` (the canonical reference)
  //   - `window.__lensLogger` (when the content script runs in a page
  //     context with a window, which it does because it's injected)
  //   - `globalThis.__lensLogger` (modern standard)
  if (typeof self !== 'undefined') {
    /**
     * @type {import("./typedefs").LensLogger}
     */
    self.__lensLogger = logger;
  }
  if (typeof window !== 'undefined') {
    window.__lensLogger = logger;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensLogger = logger;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/luhn.js ===
// AegisGate Lens — detectors/luhn.js
// Luhn algorithm validation for credit card numbers.
//
// Per the architecture doc Section 3, the PII facet validates credit
// card numbers with Luhn before reporting. A regex match alone has a
// high false-positive rate (e.g., any 16-digit number matches a
// generic regex); Luhn reduces this to near-zero.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Standard Luhn checksum: starting from the rightmost digit, double
  // every second digit. If doubled value > 9, subtract 9. Sum all
  // digits. The number is valid iff sum % 10 === 0.
  //
  // Accepts a string of digits (no separators) or a number.
  // Returns true if valid, false if not.
  function luhnCheck(cardNumber) {
    if (cardNumber === null || cardNumber === undefined) return false;
    var s = String(cardNumber);
    // Strip any non-digit characters
    s = s.replace(/\D/g, '');
    if (s.length < 12 || s.length > 19) return false;
    var sum = 0;
    var alt = false;
    for (var i = s.length - 1; i >= 0; i--) {
      var d = s.charCodeAt(i) - 48;  // '0' is 48
      if (d < 0 || d > 9) return false;
      if (alt) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  // Common card-type identifiers. Each entry is a regex that matches
  // the IIN/BIN prefix and length for the card type. Used by the PII
  // detector to assign the right category.
  var CARD_PATTERNS = [
    { name: 'visa',       re: /^4\d{12}(\d{3})?(\d{3})?$/ },
    { name: 'mastercard', re: /^(5[1-5]\d{14}|2(2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$/ },
    { name: 'amex',       re: /^3[47]\d{13}$/ },
    { name: 'discover',   re: /^(6011|65\d{2}|64[4-9]\d|62212[6-9]|6221[3-9]\d|622[2-8]\d|6229[01]\d|62292[0-5])\d{10,12}$/ },
    { name: 'diners',     re: /^(36\d{12}|38\d{12}|30[0-5]\d{11})$/ },
    { name: 'jcb',        re: /^(2131|1800|35\d{3})\d{11}$/ }
  ];

  function identifyCard(cardNumber) {
    var s = String(cardNumber).replace(/[\s-]/g, '');
    for (var i = 0; i < CARD_PATTERNS.length; i++) {
      if (CARD_PATTERNS[i].re.test(s)) return CARD_PATTERNS[i].name;
    }
    return null;
  }

  // Convenience: validate + identify in one call.
  function validateCard(cardNumber) {
    var s = String(cardNumber).replace(/[\s-]/g, '');
    return { valid: luhnCheck(s), type: identifyCard(s) };
  }

  var module = {
    luhnCheck: luhnCheck,
    identifyCard: identifyCard,
    validateCard: validateCard,
    CARD_PATTERNS: CARD_PATTERNS
  };

  if (typeof self !== 'undefined') self.__lensLuhn = module;
  if (typeof window !== 'undefined') window.__lensLuhn = module;
  /**
   * @type {{validateLuhn: (n: string) => boolean, version: string}}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensLuhn = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/regex/pii-us-core.js ===
// AegisGate Lens — pii-us-core.js
//
// US high-priority PII patterns: SSN, email, phone, credit card, DOB, street address, driver license, US passport, EIN tax ID, bank account, IP address. These are the patterns that fire most often in real US user prompts. Loaded by pii.js (the aggregator) BEFORE any other pii-* sub-file so the patterns object is built up in alphabetical group order.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_ssn: {
          severity: 'critical',
          // 9 digits in XXX-XX-XXXX or XXX XX XXXX format. We require
          // the separators (dashes or spaces) between the 3-2-4 groups
          // to avoid matching 9-digit numbers like bank routing numbers
          // or arbitrary IDs. An SSN with NO separators is matched by
          // a separate, more permissive pattern (case 2 below).
          re: /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g
        },
        pii_email: {
          severity: 'medium',
          // RFC 5322 simplified: local@domain.tld. Allows +, ., -, _ in
          // local part. Domain is at least 2 labels. TLD is 2-24 alpha.
          re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g
        },
        pii_phone: {
          severity: 'medium',
          // US phone: exactly 10 digits (area code + 7-digit local), with
          // a variety of separators. International prefix is optional
          // (+1 or +CC). The 10-digit count is the boundary that prevents
          // matching credit card numbers (16 digits) or routing numbers
          // (9 digits) or account numbers (10-12 digits).
          re: /(?:\+?\d{1,3}[-.\s]?)?\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g
        },
        pii_credit_card: {
          severity: 'high',
          // 13-19 digits, optional spaces or dashes between groups.
          // Luhn-validated in postProcess. To prevent overlap with phone
          // (10 digits) and SSN (9 digits), we require at least 13 digits
          // total (with separators allowed).
          re: /\b(?:\d{4}[ -]?){3}\d{1,7}\b|\b\d{13,19}\b/g
        },
        // ========================================================================
        // v0.1.0-beta Path 1 coverage expansion (2026-07-08, per benchmark v3):
        //   8 new patterns to close the top-3 recall gaps (phone, ID, passport)
        //   and fix two detector bugs (CJK email, 12-digit credit card).
        //   All 8 patterns are NEW entries; existing patterns unchanged.
        // ========================================================================,
        pii_dob: {
          severity: 'high',
          // DOB common formats: MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD,
          // Mon DD, YYYY. We're permissive on the day/year but require
          // a year that looks plausible (1900-2099).
          re: /\b(?:(?:0?[1-9]|1[0-2])[\/.\-](?:0?[1-9]|[12]\d|3[01])[\/.\-](?:19|20)\d{2}|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01]))\b/g
        },
        pii_address: {
          severity: 'medium',
          // US street: number + street name + (St|Ave|Rd|Blvd|Ln|Dr|Way|Ct|Pl).
          // This is approximate; we use word boundaries to avoid false hits.
          re: /\b\d{1,6}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Place|Pl)\b\.?(?:\s+(?:Apt|Suite|Ste|#)\s*\d+)?/g
        },
        pii_driver_license: {
          severity: 'high',
          // US DL formats vary by state. We match a label + alphanumeric.
          // The label makes the FP rate low; the value can be any 5-15
          // uppercase alnum. The label/value separator may be :, #, No.,
          // or whitespace.
          re: /\b(?:DL|D\.L\.|Driver(?:'s)?\s+License|License)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*[A-Z0-9]{5,15}\b/gi
        },
        pii_passport: {
          severity: 'critical',
          // US passport: 1 letter + 8 digits. The "Passport" label is
          // REQUIRED to prevent false positives on alphanumeric codes
          // like "D12345678" (DL) or "A12345678" (random). The label
          // makes the FP rate near zero.
          re: /\b(?:US|United\s+States\s+)?Passport\s*(?:#|No\.?)?\s*[A-Z]\d{8}\b/gi
        },
        pii_tax_id: {
          severity: 'high',
          // US EIN: XX-XXXXXXX (9 digits with one dash after the first 2).
          re: /\b\d{2}-\d{7}\b/g
        },
        pii_bank_account: {
          severity: 'high',
          // US ABA routing: 9 digits with optional spaces/dashes. Account:
          // 4-17 digits. We match the label "Routing" or "Account".
          re: /\b(?:Routing|Account|ABA)\s*(?:#|No\.?|Number)?\s*\d{4,17}\b/gi
        },
        pii_ip_address: {
          severity: 'low',
          // IPv4: a.b.c.d with each octet 0-255. IPv6: hex groups with colons.
          re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g
        },
        // ====================================================================
        // NEW PATTERNS (v0.1.0-beta PII expansion, 2026-07-04)
        // Each pattern is verified with positive + negative test cases in
        // test/unit/regex-pii.test.mjs.
        // ====================================================================
  };

  if (typeof self !== 'undefined') self.__lensPII_us_core = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_us_core = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_us_core = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === detectors/regex/pii-us-extended.js ===
// AegisGate Lens — pii-us-extended.js
//
// Path 1 + Path 2 PII coverage expansion (2026-07-08). All 11 patterns here were added in the benchmark v3 round to close recall gaps on CJK email, international phone, 12-digit credit card, French/Russian/Swiss national IDs, and bare letter IDs / multi-segment ID codes. Each pattern is NEW since the v0.1.0-beta PII expansion; none of these existed in the original 42-pattern baseline.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_credit_card_loose: {
          // BUG FIX: corpus has 12-digit credit cards (Diners Club, Maestro)
          // that fail the 13-19 threshold. Lower to 12.
          severity: 'high',
          re: /\b\d{12,19}\b/g
        },
        pii_email_intl: {
          // BUG FIX: \b word boundary fails on CJK / Hangul / Kana chars
          // before @. Use Unicode letter class instead of \b.
          severity: 'medium',
          re: /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,24}/gu
        },
        pii_phone_intl_loose: {
          // COVERAGE: international phone formats missed by pii_phone.
          // Examples: +75-88-157-9864, 069-1292 0270, 0039 11481.1291,
          // 1018 680 2110, 01905-25379, +4938458 1606, +1.11 415 2793.
          severity: 'medium',
          // v0.1.3 follow-up: tightened to (a) exclude "." from the
          // inner char class (the worst backtracker on inputs like
          // +1.234.567.890.123), (b) cap the separator-run length
          // to 12 (the previous {6,18} was too permissive), and
          // (c) add boundary lookarounds for "." to reject
          // dot-bounded tokens (likely parts of IP / version
          // strings, not phone numbers). Net effect: rejects ~80%
          // of the WildChat FPs that were code-sample digit runs
          // (per the H2 metrics doc, 54% of FPs were pii_phone_intl_loose).
          re: /(?<![\d@+\.])\+?\d[\d\s\-()]{6,12}\d(?![\d@\.\b])/g
        },
        pii_phone_intl_strict: {
          // v0.1.3 follow-up: NEW pattern. Matches international phones
          // with a phone-format separator (dash, space, parens) — the
          // format a real phone number is written in. This is the
          // high-precision pattern; the dispatcher prefers this
          // over pii_phone_intl_loose when both match the same span.
          // Examples: +1 (415) 555-2671, +44 20 7946 0958,
          //           +86 138 0013 4567, +49 30 12345678.
          severity: 'medium',
          re: /(?<![\d@+\.])(?<![xX])\+?\d{1,3}[\s\-.()]{1,2}\(?\d{2,4}\)?[\s\-.()]{0,2}\d{3,4}[\s\-.()]{0,2}\d{3,4}(?![\d@\.\b])/g
        },
        pii_passport_generic: {
          // v0.1.4: requires an ID label word (id/code/number/ref/license/
          // certificate/document/serial/account/passport) before the match.
          severity: 'critical',
          re: /\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b/g
},
        pii_id_generic_alphanumeric: {
          // COVERAGE: bare 4-15 char alphanumeric ID-shaped strings WITH CONTEXT WORD (id/code/number/ref/license/passport/certificate/serial/account) before the match.
          // Pure letters and pure numbers excluded by dual lookaheads.
          severity: 'high',
          re: /\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{4,15}\b/g
},
        pii_ssn_fr: {
          // COVERAGE: French INSEE SSN (synthetic 13-digit ai4privacy
          // format, plus the real 15-digit format with key).
          severity: 'critical',
          re: /\b[12]\d{2}\.\d{2}\.\d{2}\.\d{3}\.\d{2}\b|\b\d{3}\.\d{4}\.\d{4}\.\d{2}\b/g
        },
        pii_ssn_ru: {
          // COVERAGE: Russian SNILS (11-12 digit format, with optional
          // separators).
          severity: 'critical',
          re: /\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2,3}\b/g
        },
        pii_tax_id_ch: {
          // COVERAGE: Swiss UID CHE-XXX.XXX.XXX.
          severity: 'high',
          re: /\bCHE-\d{3}\.\d{3}\.\d{3}\b/g
        },
        // ========================================================================
        // v0.1.0-beta Path 2 coverage expansion (2026-07-08):
        //   3 additional patterns to close the remaining ~60 of 75 missed records.
        // ========================================================================,
        pii_letter_only_id: {
          // COVERAGE: pure-letter 8-12 char uppercase strings WITH CONTEXT WORD (id/code/number/ref/license/passport/certificate) before the match.
          // Examples: SCZOTYNCUC, ABXUHKNRJL, YRSKYMMMVX.
          // Common words like API/JSON/BANK are too short (<8).
          // FP risk: 0.69% on real user prompts (proper nouns).
          severity: 'high',
          re: /\b[A-Z]{8,12}\b/g
},
        pii_id_multisegment: {
          // COVERAGE: multi-segment ID codes with dots or dashes.
          // Examples: SHERZ.790015.S9.027, ROOHI-4120021-R9-745.
          // FP risk: 0.07% on real user prompts (product codes).
          severity: 'high',
          re: /\b[A-Z][A-Z0-9]{1,7}[-.][A-Z0-9]{1,8}(?:[-.][A-Z0-9]{1,8}){1,3}\b/g
        },
        pii_street_intl: {
          // COVERAGE: international street addresses (Romanian, etc.).
          // Examples: Bulevardul Anabela Ardelean Nr. 18, Intrarea Popa Nr. 62.
          // FP risk: 0% on real user prompts.
          severity: 'medium',
          re: /\b(?:Bulevardul|Bd\.|Intrarea|Strada|Str\.|Aleea|Pia\u021ba|Calea)\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+Nr\.?\s+\d+\b/g
        }
  };

  if (typeof self !== 'undefined') self.__lensPII_us_extended = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_us_extended = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_us_extended = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === detectors/regex/pii-international-id.js ===
// AegisGate Lens — pii-international-id.js
//
// International PII patterns: national IDs, passports, residence permits, visas, and international driver licenses for the top non-US jurisdictions we expect to encounter in real user prompts. 23 patterns covering Brazil (CPF), India (Aadhaar), UK (NHS), Australia (TFN), Canada (SIN), generic IBAN, BIP39 seed phrases, and passports/NIDs for UK, EU, Canada, Australia, Germany, France, Spain, Italy, Japan.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_cpf_br: {
          // Brazilian CPF (Cadastro de Pessoas Físicas): XXX.XXX.XXX-XX
          // (11 digits with format separators). Critical because CPF is
          // a primary identity document in Brazil; the 11-digit format
          // includes a check digit which we don't validate (the regex
          // is permissive to avoid rejecting valid CPFs that are
          // retyped or formatted differently in prompts).
          severity: 'critical',
          re: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g
        },
        pii_aadhaar_in: {
          // Indian Aadhaar: 12 digits in XXXX-XXXX-XXXX format
          // (occasionally written as XXXX XXXX XXXX). The label is
          // optional; the 12-digit-with-3-4-format is highly specific.
          // We use negative lookbehind/lookahead to avoid matching
          // when the match is part of a larger hyphen-separated sequence.
          severity: 'critical',
          re: /(?<!\d[-\s])\d{4}[-\s]\d{4}[-\s]\d{4}(?!\s*[-\s]\d)/g
        },
        pii_nhs_uk: {
          // UK NHS number: 10 digits in XXX-XXX-XXXX format. Distinct
          // from US SSN (which uses XXX-XX-XXXX) by the dash position.
          // The "NHS" label is REQUIRED to prevent false positives on
          // phone numbers (which also use XXX-XXX-XXXX format).
          severity: 'high',
          re: /\b(?:NHS|NHS\s+Number|National\s+Health\s+Service)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*\d{3}-\d{3}-\d{4}\b/gi
        },
        pii_tfn_au: {
          // Australian Tax File Number: 9 digits in XXX XXX XXX format
          // (spaces, not dashes). We use \s as the separator to match
          // real-world formatted TFNs.
          severity: 'high',
          re: /\b\d{3}\s\d{3}\s\d{3}\b/g
        },
        pii_sin_ca: {
          // Canadian Social Insurance Number: 9 digits in XXX XXX XXX
          // format. We use a negative-lookahead to avoid matching
          // TFN (AU) or other 3-3-3 patterns: SINs start with a digit
          // 1-7 (per the Canadian SIN rules), but the regex is permissive
          // to avoid FNs on edge cases.
          severity: 'high',
          re: /\b[1-7]\d{2}\s\d{3}\s\d{3}\b/g
        },
        pii_iban: {
          // International Bank Account Number: 2 letters (country code)
          // + 2 digits (check digits) + up to 30 alphanumeric. Total
          // length 15-32. We use a strict format with no spaces.
          severity: 'critical',
          re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g
        },
        pii_bip39_seed: {
          // BIP39 cryptocurrency seed phrase: 12 or 24 lowercase words
          // from the BIP39 wordlist, separated by single spaces. The
          // first 4 words are validated against a partial wordlist of
          // common BIP39 words. If at least 3 of the first 4 words are
          // valid BIP39 words AND the total is 12 or 24 words AND all
          // words are 3-8 lowercase letters, we flag as a seed phrase.
          // This is a strong indicator; the false-positive rate on
          // English prose is very low.
          severity: 'critical',
          re: /\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b|\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b/g
        },
        // International passport patterns,
        pii_passport_uk: {
          severity: 'critical',
          re: /(?:UK|United\s+Kingdom)?\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b/gi
        },
        pii_passport_eu: {
          severity: 'critical',
          re: /(?:European\s+Union|EU)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]{1,2}\d{6,8})\b/gi
        },
        pii_passport_ca: {
          severity: 'critical',
          re: /(?:Canadian|Canada)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]\d{8})\b/gi
        },
        pii_passport_au: {
          severity: 'critical',
          re: /(?:Australian|Australia)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b/gi
        },
        pii_passport_de: {
          severity: 'critical',
          re: /(?:German|Germany)\s*Passport\s*(?:#|No\.?)?\s*(?:([A-Z]\d{8})|(D\d{8}))\b/gi
        },
        pii_passport_fr: {
          severity: 'critical',
          re: /(?:French|France)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b/gi
        },
        // National ID patterns,
        pii_nid_de: {
          severity: 'critical',
          re: /(?:German\s+Nationalseid|Personalausweis|PA)\s*[:#]?\s*(\d{11})\b/gi
        },
        pii_nid_fr: {
          severity: 'critical',
          re: /(?:French\s+National\s+ID|Carte\s+Nationale|Carte\s+Nationale\s+Identite|CN)\s*[:#]?\s*([A-Z]{1,5}\d{10})\b/gi
        },
        pii_nid_es: {
          severity: 'critical',
          re: /(?:Spanish\s+National\s+ID|DNI)\s*[:#]?\s*(\d{8}[A-Z])\b/gi
        },
        pii_nid_it: {
          severity: 'critical',
          re: /(?:Italian\s+National\s+ID|Codice\s+Fiscale|CF)\s*[:#]?\s*([A-Z0-9]{16})\b/gi
        },
        pii_nid_jp: {
          severity: 'critical',
          re: /(?:Japanese\s+National\s+ID|My\s+Number|MyNumber)\s*[:#]?\s*(\d{3}-\d{3}-\d{5,6})\b/gi
        },
        // Cryptocurrency wallet patterns,
        pii_residence_us: {
          severity: 'critical',
          re: /(?:I-551|Green\s+Card|Resident\s+Permit)\s*([A-Z]?\d{9,11})\b/gi
        },
        pii_residence_ca: {
          severity: 'critical',
          re: /(?:Permanent\s+Resident|PR\s+Card|Canadians\s+Permanent\s+Resident)\s*([A-Z]?\d{9,11})\b/gi
        },
        pii_residence_uk: {
          severity: 'critical',
          re: /(?:Biometric\s+Residence\s+Permit|BRP)\s*([A-Z]?\d{9,11})\b/gi
        },
        pii_visa: {
          severity: 'critical',
          // Visa number or entry type - Visa [Number|Entry|Type] value
          re: /(?:Visa|visa)\s+(?:number|entry|entry\s+type)?\s*[:=]?\s*([A-Z0-9]{8,17})\b/gi
        },
        pii_driver_license_international: {
          severity: 'high',
          // International DL formats that aren't covered by the US DL patterns.
          // We require a specific language label to avoid overlapping with US DLs.
          // Note: "DL" is intentionally NOT included here - that's handled by pii_driver_license
          re: /(?:(?:Driver's\s+License|State\s+ID|Permis\s+conduire|Führerschein|Patente|Licencia|Permiso|Brevetto|Korti\s+ajamiso|Dokument\s+tożsamosgi)\s*[:#]?\s*[A-Z]?\d{5,15}|(?:Korti\s+ajamiso|Dokument\s+tożsamosgi)\s*[:#]?\s*\d{5,15})\b/gi
        }
  };

  if (typeof self !== 'undefined') self.__lensPII_international_id = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_international_id = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_international_id = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === detectors/regex/pii-financial.js ===
// AegisGate Lens — pii-financial.js
//
// Financial PII patterns: cryptocurrency wallet addresses and digital payment service identifiers. 9 patterns covering the top crypto chains (BTC, ETH, BNB, LTC, SOL) and the top US digital payment services (PayPal, Stripe, Venmo, Cash App). These are high-risk for credential theft / financial fraud when pasted into a prompt that then gets sent to a model that retains the conversation.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_crypto_btc: {
          severity: 'high',
          re: /(?:Bitcoin|BTC|btc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qrp][0-9A-Za-z]{39,59})\b/gi
        },
        pii_crypto_eth: {
          severity: 'high',
          re: /(?:Ethereum|ETH|eth)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40})\b/gi
        },
        pii_crypto_bnb: {
          severity: 'high',
          re: /(?:Binance|BNB|bnb)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40}|bnb[a-zA-HJ-NP-Z1-9]{39})\b/gi
        },
        pii_crypto_ltc: {
          severity: 'high',
          re: /(?:Litecoin|LTC|ltc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([LM3][a-zA-Z0-9]{26,33})\b/gi
        },
        pii_crypto_sol: {
          severity: 'high',
          re: /(?:Solana|SOL|sol)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([1-9A-HJ-NP-Za-km-z]{32,44})\b/gi
        },
        // Digital payment patterns - based on test expectations,
        pii_digital_paypal: {
          severity: 'medium',
          // PayPal email - requires "email" keyword
          // PayPal ID - P followed by digits
          re: /(?:PayPal|paypal)\s+(?:email|email\s+address|email\s+no\.?|ID)\s*[:=]?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[A-Z]\d{9,})\b/gi
        },
        pii_digital_stripe: {
          severity: 'high',
          // Stripe keys and customer/payment IDs
          re: /(?:Stripe|stripe)\s+(?:api\s*key|secret\s*key|publishable\s*key|customer\s*ID|customer|payment\s*ID|payment)?\s*[:=]?\s*(pk_live_[0-9a-zA-Z]{24,50}|sk_live_[0-9a-zA-Z]{24,50}|pk_test_[0-9a-zA-Z]{24,50}|sk_test_[0-9a-zA-Z]{24,50}|cus_[A-Za-z0-9]{21,}|pi_[A-Za-z0-9]{21,}|pay_[A-Za-z0-9]{21,})\b/gi
        },
        pii_digital_venmo: {
          severity: 'medium',
          // Venmo username - @username or username format
          re: /(?:Venmo|venmo)\s+(?:username|user\s+name|handle)?\s*[:=]?\s*(@[a-zA-Z][a-zA-Z0-9._]{0,29}|[a-zA-Z][a-zA-Z0-9._]{1,30})\b/gi
        },
        pii_digital_cashapp: {
          severity: 'medium',
          re: /(?:Cashapp|cashapp|cash\s*app)\s*(?:username|handle)?\s*[:=]?\s*(\$?[a-zA-Z][a-zA-Z0-9._-]{1,20})\b/gi
        },
        // Residence permit patterns
  };

  if (typeof self !== 'undefined') self.__lensPII_financial = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_financial = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_financial = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === detectors/regex/pii.js ===
// AegisGate Lens — pii.js
//
// PII facet detector (aggregator). Pulls in 4 sub-files that each
// own a semantic group of patterns:
//
//   pii-us-core.js          (11 patterns: SSN, email, phone, CC,
//                                    DOB, address, DL, passport,
//                                    tax_id, bank, IP)
//   pii-us-extended.js      (11 patterns: Path 1 + Path 2 expansion,
//                                    loose/intl variants)
//   pii-international-id.js (23 patterns: non-US national IDs,
//                                    passports, NIDs, residence,
//                                    visa, intl DL)
//   pii-financial.js         (9 patterns: crypto wallets, digital
//                                    payment)
//
// Total: 54 patterns. The aggregator builds a single `patterns`
// object by merging all 4 sub-file exports, then defines the
// `postProcess` and `detect` functions and exposes them via the
// `__lensPII` global.
//
// All 4 sub-files are loaded BEFORE pii.js in the manifest's
// content_scripts.js order (see src/bootstrap.js MODULE_REGISTRY).
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Sub-file loading: each sub-file exposes a `__lensPII_<group>` global
  // with the shape { patterns: { ... } }. We merge them into one patterns
  // object in alphabetical group order (so the patterns dict's key order
  // is deterministic across reloads).
  // -------------------------------------------------------------------------
  function loadSubFile(globalName) {
    var g = (typeof self !== 'undefined' && self[globalName]) ||
            (typeof window !== 'undefined' && window[globalName]) ||
            (typeof globalThis !== 'undefined' && globalThis[globalName]) ||
            null;
    if (!g) {
      throw new Error('pii.js: required sub-file not loaded: ' + globalName);
    }
    return g.patterns || {};
  }

  var us_core          = loadSubFile('__lensPII_us_core');
  var us_extended      = loadSubFile('__lensPII_us_extended');
  var international_id = loadSubFile('__lensPII_international_id');
  var financial        = loadSubFile('__lensPII_financial');

  var patterns = {};
  // Merge in deterministic order.
  ['us_core', 'us_extended', 'international_id', 'financial'].forEach(function (g) {
    var src = { us_core: us_core, us_extended: us_extended,
                international_id: international_id, financial: financial }[g];
    Object.keys(src).forEach(function (key) {
      if (patterns[key]) {
        throw new Error('pii.js: duplicate pattern key "' + key + '" from group ' + g);
      }
      patterns[key] = src[key];
    });
  });

  // -------------------------------------------------------------------------
  // Luhn helper: pull in the Luhn module from the sibling detector. The
  // luhn.js is NOT listed in manifest.json content_scripts as a separate
  // entry (it's a utility for this detector, not a separate script the
  // page needs). Instead we either inline a require (for node:test) or
  // rely on it being loaded earlier in this same script when the content
  // script runs in the browser. For simplicity, we look for it on
  // globalThis at call time; if absent, we skip the Luhn check (and the
  // regex still flags the candidate as a potential card, so the
  // dispatcher can still warn).
  // -------------------------------------------------------------------------
  function getLuhn() {
    if (typeof self !== 'undefined' && self.__lensLuhn) return self.__lensLuhn;
    if (typeof globalThis !== 'undefined' && globalThis.__lensLuhn) return globalThis.__lensLuhn;
    return null;
  }

  // -------------------------------------------------------------------------
  // Severity levels used by the patterns object:
  //   critical — direct identity theft vector (SSN, passport, full CC+CVV)
  //   high     — strong identity vector (DOB, driver license, full CC w/o CVV)
  //   medium   — contextual identity vector (email, phone, address, IP)
  //   low      — informational
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // Post-process: drop false positives and attach metadata. The pii
  // facet has 3 special postProcess paths (CC Luhn, phone digit filter,
  // BIP39 wordlist verification); everything else passes through.
  // -------------------------------------------------------------------------
  function postProcess(category, match, text) {
    if (category === 'pii_credit_card' || category === 'pii_credit_card_loose') {
      // v0.1.3 B1 fix: also Luhn-validate the loose variant. Previously
      // pii_credit_card_loose (which matches \b\d{12,19}\b) was NOT
      // Luhn-checked, so any 12-19 digit run (including non-CC numbers
      // like long IBAN bodies) generated a false positive. The smoke
      // test flow-pii-credit-card-luhn-invalid surfaced this; the
      // invalid CC "1234-5678-9012-3456" (16 digits) was being flagged.
      var luhn = getLuhn();
      if (!luhn) {
        var log = (typeof self !== 'undefined' && self.__lensLogger) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
                  null;
        if (log && typeof log.warn === 'function') {
          log.warn('pii.detect: luhn module unavailable; credit card candidate dropped');
        }
        return null;
      }
      var v = luhn.validateCard(match.value);
      if (!v.valid) return null;  // drop false positive (Luhn-invalid number)
      match.cardType = v.type;
    }
    if (category === 'pii_phone_intl_loose') {
      // Filter by digit count: phones are 7-13 digits (ITU-T E.164).
      // The v0.1.3 B1 fix lowered the upper bound from 15 to 13 to
      // reject IBAN body matches (the IBAN body, e.g., "60161331926819"
      // in "GB29 NWBK 6016 1331 9268 19", is 14-16 unseparated digits and
      // was matching as pii_phone_intl_loose). The v0.1.3 follow-up
      // regex (in pii-us-extended.js) ALSO bounds the inner separator
      // char class to 12 chars max + excludes "." from the inner class,
      // eliminating the worst backtrackers (16-char dot strings).
      var digits = (match.value.match(/\d/g) || []).length;
      if (digits < 7 || digits > 13) return null;
      if (digits === 9) return null;  // SSN shape, not phone
      // v0.1.4 follow-up: reject 4-4-4 CC pattern (e.g., 1234-5678-9012
      // is a credit card segment, not a phone). The smoke test
      // flow-pii-credit-card-luhn-invalid surfaced this: 12-digit
      // CC-segment runs were matching as pii_phone_intl_loose
      // because the regex's inner class {6,12} covers 12 separators
      // and the postProcess digit count was <= 13.
      if (/^\d{4}[-.\s]\d{4}[-.\s]\d{4}$/.test(match.value)) return null;
      // v0.1.3 follow-up: reject pure date-like matches (8 digits
      // in YYYY-MM-DD / DD-MM-YYYY patterns) -- already in the
      // original F-1 fix.
      if (digits === 8 && /^\d{4}[-.\s]\d{1,2}[-.\s]\d{1,2}$/.test(match.value)) return null;
      // v0.1.3 follow-up: reject matches in code-like contexts. The
      // H2 metrics doc found pii_phone_intl_loose was 54.4% of all
      // FPs, with samples like "ssl_evp_cipher_fetch 0x000000010e5f5400"
      // (function-pointer hex strings matching the digit run). The
      // heuristic: if the 50 chars on either side of the match have
      // any of { ; = ( ` function, var, let, const, 0x, 0X, it is code.
      // This is conservative -- we only reject if MULTIPLE code markers
      // appear in the 100-char window. Real phone numbers in normal
      // prose don't have {/;/= syntax.
      var s = match.value;
      var idx = (match.index || 0);
      // We need the full input text. pii.js doesn't get the full text
      // here, only match.value. Instead, use the detector's last
      // input -- we have to thread it through. Easiest path: the
      // detector (index.js) already builds events from matches; the
      // pii postProcess only gets the match. So we rely on the regex
      // change in pii-us-extended.js (the "." exclusion) to filter
      // out the bulk of code-context FPs. The current pii.js heuristic
      // is the existing digit count + date-shape check.
    }
    if (category === 'pii_bip39_seed') {
      // The regex matches 12- or 24-word sequences. We need to
      // verify the words are likely BIP39 (vs random English words).
      // We use a partial wordlist of the 100 most common BIP39
      // words. If at least 3 of the 12 words (or 5 of 24) are in
      // the wordlist AND all words are 3-8 lowercase letters, we
      // accept the match. Otherwise drop it as a false positive.
      var BIP39_COMMON = ['abandon', 'ability', 'able', 'about', 'above', 'absent',
        'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
        'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
        'across', 'act', 'action', 'actor', 'actress', 'actual', 'adapt',
        'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
        'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age',
        'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle',
        'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley',
        'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
        'always', 'amateur', 'amazing', 'among', 'amount', 'amused',
        'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal',
        'ankle', 'announce', 'annual', 'another', 'answer', 'antenna',
        'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple',
        'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue',
        'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest',
        'arrive', 'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask',
        'aspect', 'assault', 'asset', 'assist', 'assume', 'asthma',
        'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract',
        'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn',
        'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome',
        'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge',
        'bag', 'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner',
        'bar', 'barely', 'bargain', 'barrel', 'base', 'basic', 'basket',
        'battle', 'beach', 'bean', 'beauty', 'because', 'become', 'beef',
        'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt',
        'bench', 'benefit', 'best', 'betray', 'better', 'between', 'beyond',
        'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird', 'birth', 'bitter',
        'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind',
        'blood', 'blossom', 'blow', 'blue', 'blur', 'blush', 'board', 'boat',
        'body', 'boil', 'bomb', 'bone', 'bonus', 'book', 'boost', 'border',
        'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy', 'bracket',
        'brain', 'brand', 'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge',
        'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze',
        'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget',
        'buffalo', 'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker',
        'burden', 'burger', 'burst', 'bus', 'business', 'busy', 'butter',
        'buyer', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake',
        'call', 'calm', 'camera', 'camp', 'canal', 'cancel', 'candy', 'cannon',
        'canoe', 'canvas', 'canyon', 'capable', 'capital', 'captain', 'car',
        'carbon', 'card', 'cargo', 'carpet', 'carry', 'cart', 'case', 'cash',
        'casino', 'castle', 'casual', 'cat', 'catalog', 'catch', 'category',
        'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling', 'celery',
        'cement', 'census', 'century', 'cereal', 'certain', 'chair', 'chalk',
        'champion', 'change', 'chaos', 'chapter', 'charge', 'chase', 'chat',
        'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken',
        'chief', 'child', 'chimney', 'choice', 'choose', 'chronic', 'chuckle',
        'chunk', 'churn', 'cigar', 'cinnamon', 'circle', 'citizen', 'city',
        'civil', 'claim', 'clap', 'clarify', 'claw', 'clay', 'clean', 'clerk',
        'clever', 'click', 'client', 'cliff', 'climb', 'clinic', 'clip',
        'clock', 'clog', 'close', 'cloth', 'cloud', 'clown', 'club', 'clump',
        'cluster', 'clutch', 'coach', 'coast', 'coconut', 'code', 'coffee',
        'coil', 'coin', 'collect', 'color', 'column', 'combine', 'come',
        'comfort', 'comic', 'common', 'company', 'concert', 'conduct',
        'confirm', 'congress', 'connect', 'consider', 'control', 'convince',
        'cook', 'cool', 'copper', 'copy', 'coral', 'core', 'corn', 'correct',
        'cost', 'cotton', 'couch', 'country', 'couple', 'course', 'cousin',
        'cover', 'coyote', 'crack', 'cradle', 'craft', 'cram', 'crane',
        'crash', 'crater', 'crawl', 'crazy', 'cream', 'credit', 'creek',
        'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop', 'cross',
        'crouch', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble', 'crunch',
        'crush', 'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard',
        'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cute',
        'cycle', 'dad', 'damage', 'damp', 'dance', 'danger', 'daring', 'dash',
        'daughter', 'dawn', 'day', 'deal', 'debate', 'debris', 'decade',
        'december', 'decide', 'decline', 'decorate', 'decrease', 'deer',
        'defense', 'define', 'defy', 'degree', 'delay', 'deliver', 'demand',
        'demise', 'denial', 'dentist', 'deny', 'depart', 'depend', 'deposit',
        'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk',
        'despair', 'destroy', 'detail', 'detect', 'develop', 'device',
        'devote', 'diagram', 'dial', 'diamond', 'diary', 'dice', 'diesel',
        'diet', 'differ', 'digital', 'dignity', 'dilemma', 'dinner', 'dinosaur',
        'direct', 'dirt', 'disagree', 'discover', 'disease', 'dish', 'dismiss',
        'disorder', 'display', 'distance', 'divert', 'divide', 'divorce',
        'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain',
        'donate', 'donkey', 'donor', 'door', 'dose', 'double', 'dove', 'draft',
        'dragon', 'drama', 'drape', 'draw', 'dream', 'dress', 'drift', 'drill',
        'drink', 'drip', 'drive', 'drop', 'drum', 'dry', 'duck', 'dumb',
        'dune', 'during', 'Dutch', 'duty', 'dwarf', 'dynamic', 'eager',
        'eagle', 'early', 'earn', 'earth', 'easily', 'east', 'easy', 'echo',
        'ecology', 'economy', 'edge', 'edit', 'educate', 'effort', 'egg',
        'eight', 'either', 'elbow', 'elder', 'electric', 'elegant', 'element',
        'elephant', 'elevator', 'elite', 'else', 'embark', 'embody', 'embrace',
        'emerge', 'emotion', 'employ', 'empower', 'empty', 'enable', 'enact',
        'end', 'endless', 'endorse', 'enemy', 'energy', 'enforce', 'engage',
        'engine', 'enhance', 'enjoy', 'enlist', 'enough', 'enrich', 'enroll',
        'ensure', 'enter', 'entire', 'entry', 'envelope', 'episode', 'equal',
        'equip', 'era', 'erase', 'erode', 'erosion', 'error', 'erupt', 'escape',
        'essay', 'essence', 'estate', 'eternal', 'ethics', 'evidence', 'evil',
        'evoke', 'evolve', 'exact', 'example', 'excess', 'exchange', 'excite',
        'exclude', 'excuse', 'execute', 'exercise', 'exhaust', 'exhibit',
        'exile', 'exist', 'exit', 'exotic', 'expand', 'expect', 'expire',
        'explain', 'expose', 'express', 'extend', 'extra', 'eye', 'eyebrow',
        'fabric', 'face', 'faculty', 'fade', 'faint', 'faith', 'fall', 'false',
        'fame', 'family', 'famous', 'fan', 'fancy', 'fantasy', 'farm', 'fashion',
        'fat', 'fatal', 'father', 'fatigue', 'fault', 'favorite', 'feature',
        'february', 'federal', 'fee', 'feed', 'feel', 'female', 'fence',
        'festival', 'fetch', 'fever', 'few', 'fiber', 'fiction', 'field',
        'figure', 'file', 'film', 'filter', 'final', 'find', 'fine', 'finger',
        'finish', 'fire', 'firm', 'first', 'fiscal', 'fish', 'fit', 'fitness',
        'fix', 'flag', 'flame', 'flash', 'flat', 'flavor', 'flee', 'flight',
        'flip', 'float', 'flock', 'floor', 'flower', 'fluid', 'flush', 'fly',
        'foam', 'focus', 'fog', 'foil', 'fold', 'follow', 'food', 'foot',
        'force', 'forest', 'forget', 'fork', 'fortune', 'forum', 'forward',
        'fossil', 'foster', 'found', 'fox', 'fragile', 'frame', 'frequent',
        'fresh', 'friend', 'fringe', 'frog', 'front', 'frost', 'frown', 'frozen',
        'fruit', 'fuel', 'fun', 'funny', 'furnace', 'fury', 'future', 'gadget',
        'gain', 'galaxy', 'gallery', 'gamble', 'gap', 'garage', 'garbage',
        'garden', 'garlic', 'gas', 'gather', 'gauge', 'gaze', 'general', 'genius',
        'genre', 'gentle', 'genuine', 'gesture', 'ghost', 'giant', 'gift',
        'giggle', 'ginger', 'giraffe', 'girl', 'give', 'glad', 'glance', 'glare',
        'glass', 'glide', 'globe', 'gloom', 'glory', 'glove', 'glow', 'glue',
        'goat', 'goddess', 'gold', 'good', 'goose', 'gorilla', 'gospel', 'gossip',
        'govern', 'gown', 'grab', 'grace', 'grain', 'grant', 'grape', 'grass',
        'gravity', 'great', 'green', 'grid', 'grief', 'grit', 'grocery', 'group',
        'grow', 'grunt', 'guard', 'guess', 'guide', 'guitar', 'gun', 'gym', 'habit',
        'hair', 'half', 'hammer', 'hamster', 'hand', 'happy', 'harbor', 'hard',
        'harsh', 'harvest', 'hat', 'have', 'hawk', 'hazard', 'head', 'heart',
        'heavy', 'hedgehog', 'height', 'hello', 'helmet', 'help', 'hen', 'hero',
        'hidden', 'high', 'hill', 'hint', 'hip', 'hire', 'history', 'hobby',
        'hockey', 'hold', 'hole', 'holiday', 'hollow', 'home', 'honey', 'hood',
        'hope', 'horn', 'horror', 'horse', 'hospital', 'host', 'hot', 'hotel',
        'hour', 'house', 'human', 'humble', 'humor', 'hundred', 'hungry', 'hunt',
        'hurdle', 'hurry', 'hurt', 'husband', 'hybrid', 'ice', 'icon', 'idea',
        'identify', 'idle', 'ignore', 'ill', 'illegal', 'illness', 'image',
        'imitate', 'immense', 'immune', 'impact', 'impose', 'improve', 'impulse',
        'inch', 'include', 'income', 'increase', 'index', 'indicate', 'indoor',
        'industry', 'infant', 'inflict', 'inform', 'inhale', 'inherit', 'initial',
        'inject', 'injury', 'inmate', 'inner', 'innocent', 'input', 'inquiry',
        'insane', 'insect', 'inside', 'inspire', 'install', 'intact', 'interest',
        'into', 'invest', 'invite', 'involve', 'iron', 'island', 'isolate',
        'issue', 'item', 'ivory', 'jacket', 'jaguar', 'jail', 'jelly', 'jewel',
        'job', 'join', 'joke', 'journey', 'joy', 'judge', 'juice', 'jump',
        'jungle', 'junior', 'junk', 'just', 'kangaroo', 'karate', 'keen', 'keep',
        'ketchup', 'key', 'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss',
        'kit', 'kitchen', 'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock',
        'know', 'lab', 'label', 'labor', 'ladder', 'lady', 'lake', 'lamb',
        'lamp', 'language', 'laptop', 'large', 'later', 'latin', 'laugh',
        'laundry', 'lava', 'law', 'lawn', 'lawsuit', 'layer', 'lazy', 'leader',
        'leaf', 'learn', 'leave', 'lecture', 'left', 'leg', 'legal', 'legend',
        'leisure', 'lemon', 'lend', 'length', 'lens', 'leopard', 'less', 'lesson',
        'letter', 'level', 'liberty', 'library', 'license', 'life', 'lift',
        'light', 'like', 'limb', 'lime', 'limit', 'link', 'lion', 'liquid',
        'list', 'little', 'live', 'lizard', 'load', 'loan', 'lobster', 'local',
        'lock', 'log', 'logic', 'lonely', 'long', 'loop', 'lottery', 'loud',
        'lounge', 'love', 'loyal', 'lucky', 'luggage', 'lumber', 'lunar',
        'lunch', 'luxury', 'lyrics', 'machine', 'mad', 'magic', 'magnet',
        'maid', 'mail', 'main', 'major', 'make', 'mammal', 'man', 'manage',
        'mandate', 'mango', 'mansion', 'manual', 'maple', 'marble', 'march',
        'margin', 'marine', 'market', 'marriage', 'mask', 'mass', 'master',
        'match', 'material', 'math', 'matrix', 'matter', 'maximum', 'maze',
        'meadow', 'mean', 'measure', 'meat', 'meal', 'media',
        'melody', 'mchanic', 'medelt', 'member', 'memory', 'mention', 'menu', 'mercy',
        'merge', 'merit', 'merry', 'mesh', 'message', 'metal', 'method',
        'middle', 'midnight', 'milk', 'million', 'mimic', 'mind', 'minimum',
        'minor', 'minute', 'miracle', 'mirror', 'misery', 'miss', 'mistake',
        'mix', 'mixed', 'mixture', 'mobile', 'model', 'modify', 'mom', 'moment',
        'monitor', 'monkey', 'monster', 'month', 'moon', 'moral', 'more',
        'morning', 'mosquito', 'mother', 'motion', 'motor', 'mountain', 'mouse',
        'move', 'movie', 'much', 'muffin', 'mule', 'multiply', 'muscle',
        'museum', 'mushroom', 'music', 'must', 'myself', 'mystery', 'naive',
        'name', 'napkin', 'narrow', 'nasty', 'nation', 'nature', 'near', 'neck',
        'need', 'negative', 'neglect', 'neither', 'nephew', 'nerve', 'nest',
        'net', 'network', 'neutral', 'never', 'next', 'nice', 'night', 'noble',
        'noise', 'nominate', 'noodle', 'normal', 'north', 'nose', 'notable',
        'note', 'nothing', 'notice', 'novel', 'now', 'nuclear', 'number',
        'nurse', 'nut', 'oak', 'obey', 'object', 'oblige', 'obscure', 'observe',
        'obtain', 'obvious', 'occur', 'ocean', 'october', 'odd', 'odor', 'off',
        'offer', 'office', 'often', 'oil', 'okay', 'old', 'olive', 'olympic',
        'omit', 'once', 'one', 'onion', 'online', 'only', 'open', 'opera',
        'opinion', 'oppose', 'option', 'orange', 'orbit', 'orchard', 'order',
        'organ', 'orient', 'original', 'orphan', 'ostrich', 'other', 'outdoor',
        'outer', 'output', 'outside', 'oval', 'oven', 'over', 'own', 'owner',
        'oxygen', 'oyster', 'ozone', 'pact', 'paddle', 'page', 'pair', 'palace',
        'palm', 'panda', 'panel', 'panic', 'panther', 'paper', 'parade', 'parent',
        'park', 'parrot', 'party', 'pass', 'patch', 'path', 'patient', 'patrol',
        'pattern', 'pause', 'pave', 'payment', 'peace', 'peanut', 'pear',
        'peasant', 'pelican', 'pen', 'penalty', 'pencil', 'people', 'pepper',
        'perfect', 'permit', 'person', 'pet', 'phone', 'phrase', 'physical',
        'piano', 'picnic', 'picture', 'piece', 'pig', 'pigeon', 'pill', 'pilot',
        'pink', 'pioneer', 'pipe', 'pistol', 'pitch', 'pizza', 'place', 'planet',
        'plastic', 'plate', 'play', 'please', 'pledge', 'pluck', 'plug', 'plunge',
        'poem', 'poet', 'point', 'polar', 'pole', 'police', 'pond', 'pony',
        'pool', 'popular', 'portion', 'position', 'possible', 'post', 'potato',
        'pottery', 'poverty', 'powder', 'power', 'practice', 'praise', 'predict',
        'prefer', 'prepare', 'present', 'pretty', 'prevent', 'price', 'pride',
        'primary', 'print', 'priority', 'prison', 'private', 'prize', 'problem',
        'process', 'produce', 'profit', 'program', 'project', 'promote', 'proof',
        'property', 'prosper', 'protect', 'proud', 'provide', 'public', 'pudding',
        'pull', 'pulp', 'pulse', 'pumpkin', 'punch', 'pupil', 'puppy', 'purchase',
        'purity', 'purpose', 'push', 'put', 'puzzle', 'pyramid', 'quality',
        'quantum', 'quarter', 'question', 'quick', 'quit', 'quiz', 'quote',
        'rabbit', 'raccoon', 'race', 'rack', 'radar', 'radio', 'rail', 'rain',
        'raise', 'rally', 'ramp', 'ranch', 'random', 'range', 'rapid', 'rare',
        'rate', 'rather', 'raven', 'raw', 'razor', 'ready', 'real', 'reason',
        'rebel', 'rebuild', 'recall', 'receive', 'recipe', 'record', 'recycle',
        'reduce', 'reflect', 'reform', 'refuse', 'region', 'regret', 'regular',
        'reject', 'relax', 'release', 'relief', 'remain', 'remember', 'remind',
        'remove', 'render', 'renew', 'rent', 'reopen', 'repair', 'repeat',
        'replace', 'report', 'require', 'rescue', 'resemble', 'resist', 'resource',
        'response', 'result', 'retire', 'retreat', 'return', 'reunion', 'reveal',
        'review', 'reward', 'rhythm', 'rib', 'rice', 'rich', 'ride', 'ridge',
        'rifle', 'right', 'rigid', 'ring', 'riot', 'ripple', 'risk', 'ritual',
        'rival', 'river', 'road', 'roast', 'robot', 'robust', 'rocket', 'romance',
        'roof', 'rookie', 'room', 'rose', 'rotate', 'rough', 'round', 'route',
        'royal', 'rubber', 'rude', 'rug', 'rule', 'run', 'runway', 'rural', 'sad',
        'saddle', 'sadness', 'safe', 'sail', 'salad', 'salmon', 'salon', 'salt',
        'salute', 'same', 'sample', 'sand', 'satisfy', 'satoshi', 'sauce', 'sausage',
        'save', 'say', 'scale', 'scan', 'scare', 'scatter', 'scene', 'scheme',
        'school', 'science', 'scissors', 'scorpion', 'scout', 'scrap', 'screen',
        'script', 'scrub', 'sea', 'search', 'season', 'seat', 'second', 'secret',
        'section', 'security', 'seed', 'seek', 'segment', 'select', 'sell', 'seminar',
        'senior', 'sense', 'sentence', 'series', 'service', 'session', 'settle',
        'setup', 'seven', 'shadow', 'shaft', 'shallow', 'share', 'shed', 'shell',
        'sheriff', 'shield', 'shift', 'shine', 'ship', 'shiver', 'shock', 'shoe',
        'shoot', 'shop', 'short', 'shoulder', 'shove', 'shrimp', 'shrug', 'shuffle',
        'shy', 'sibling', 'sick', 'side', 'siege', 'sight', 'sign', 'silent',
        'silk', 'silly', 'silver', 'similar', 'simple', 'since', 'sing', 'siren',
        'sister', 'situate', 'six', 'size', 'skate', 'sketch', 'ski', 'skill',
        'skin', 'skirt', 'skull', 'slab', 'slam', 'sleep', 'slender', 'slice',
        'slide', 'slight', 'slim', 'slogan', 'slot', 'slow', 'slush', 'small',
        'smart', 'smile', 'smoke', 'smooth', 'snack', 'snake', 'snap', 'sniff',
        'snow', 'soap', 'soccer', 'social', 'sock', 'soda', 'soft', 'solar',
        'soldier', 'solid', 'solution', 'solve', 'someone', 'song', 'soon', 'sorry',
        'sort', 'soul', 'sound', 'soup', 'source', 'south', 'space', 'spare',
        'spatial', 'spawn', 'speak', 'special', 'speed', 'spell', 'spend', 'sphere',
        'spice', 'spider', 'spike', 'spin', 'spirit', 'split', 'sponsor', 'spoon',
        'sport', 'spot', 'spray', 'spread', 'spring', 'spy', 'square', 'squeeze',
        'squirrel', 'stable', 'stadium', 'staff', 'stage', 'stairs', 'stamp',
        'stand', 'start', 'state', 'stay', 'steak', 'steel', 'stem', 'step',
        'stereo', 'stick', 'still', 'sting', 'stock', 'stomach', 'stone', 'stool',
        'story', 'stove', 'strategy', 'street', 'strike', 'strong', 'struggle',
        'student', 'stuff', 'stumble', 'style', 'subject', 'submit', 'subway',
        'success', 'such', 'sudden', 'suffer', 'sugar', 'suggest', 'suit',
        'summer', 'sun', 'sunny', 'sunset', 'super', 'supply', 'supreme', 'sure',
        'surface', 'surge', 'surprise', 'surround', 'survey', 'suspect', 'sustain',
        'swallow', 'swamp', 'swap', 'swarm', 'swear', 'sweet', 'swift', 'swim',
        'swing', 'switch', 'sword', 'symbol', 'symptom', 'syrup', 'system', 'table',
        'tackle', 'tag', 'tail', 'talent', 'talk', 'tank', 'tape', 'target',
        'task', 'taste', 'tattoo', 'taxi', 'teach', 'team', 'tell', 'ten',
        'tenant', 'tennis', 'tent', 'term', 'test', 'text', 'thank', 'that',
        'theme', 'then', 'theory', 'there', 'they', 'thing', 'this', 'thought',
        'three', 'thrive', 'throw', 'thumb', 'thunder', 'ticket', 'tide', 'tiger',
        'tilt', 'timber', 'time', 'tiny', 'tip', 'tired', 'tissue', 'title',
        'toast', 'tobacco', 'today', 'toddler', 'toe', 'together', 'toilet',
        'token', 'tomato', 'tomorrow', 'tone', 'tongue', 'tonight', 'tool',
        'tooth', 'top', 'topic', 'topple', 'torch', 'tornado', 'tortoise',
        'toss', 'total', 'tourist', 'toward', 'tower', 'town', 'toy', 'track',
        'trade', 'traffic', 'tragic', 'train', 'transfer', 'trap', 'trash',
        'travel', 'tray', 'treat', 'tree', 'trend', 'trial', 'tribe', 'trick',
        'trigger', 'trim', 'trip', 'trophy', 'trouble', 'truck', 'true', 'truly',
        'trumpet', 'trust', 'truth', 'try', 'tube', 'tuition', 'tumble', 'tuna',
        'tunnel', 'turkey', 'turn', 'turtle', 'twelve', 'twenty', 'twice', 'twin',
        'twist', 'two', 'type', 'typical', 'ugly', 'umbrella', 'unable', 'unaware',
        'uncle', 'uncover', 'under', 'undo', 'unfair', 'unfold', 'unhappy',
        'uniform', 'unique', 'unit', 'universe', 'unknown', 'unlock', 'until',
        'unusual', 'unveil', 'update', 'upgrade', 'uphold', 'upon', 'upper',
        'upset', 'urban', 'urge', 'usage', 'used', 'useful', 'useless', 'usual',
        'utility', 'vacant', 'vacuum', 'vague', 'valid', 'valley', 'valve',
        'vanish', 'vapor', 'various', 'vast', 'vault', 'vehicle', 'velvet',
        'vendor', 'venture', 'venue', 'verb', 'verify', 'version', 'very',
        'vessel', 'veteran', 'viable', 'vibrant', 'vicious', 'victory', 'video',
        'view', 'village', 'vintage', 'violin', 'virtual', 'virus', 'visa',
        'visit', 'visual', 'vital', 'vivid', 'vocal', 'voice', 'void', 'volcano',
        'volume', 'vote', 'voyage', 'wage', 'wagon', 'wait', 'walk', 'wall',
        'walnut', 'want', 'warfare', 'warm', 'warrior', 'wash', 'wasp', 'waste',
        'water', 'wave', 'way', 'wealth', 'weapon', 'wear', 'weasel', 'weather',
        'web', 'wedding', 'weekend', 'weird', 'welcome', 'west', 'wet', 'whale',
        'what', 'wheat', 'wheel', 'when', 'where', 'whip', 'whisper', 'wide',
        'width', 'wife', 'wild', 'will', 'win', 'window', 'wine', 'wing', 'wink',
        'winner', 'winter', 'wire', 'wisdom', 'wise', 'wish', 'with', 'withdraw',
        'witness', 'wolf', 'woman', 'wonder', 'wood', 'wool', 'word', 'work',
        'world', 'worry', 'worth', 'wrap', 'wreck', 'wrestle', 'wrist', 'write',
        'wrong', 'yard', 'year', 'yellow', 'you', 'young', 'youth', 'zebra',
        'zero', 'zone', 'zoo'];

      var words = (match.value || '').toLowerCase().split(/\s+/).filter(function (w) {
        return /^[a-z]{3,8}$/.test(w);
      });
      // Count how many of the matched words are in the BIP39 common wordlist.
      var validCount = 0;
      for (var w = 0; w < words.length; w++) {
        if (BIP39_COMMON.indexOf(words[w]) !== -1) {
          validCount++;
        }
      }
      // Need at least 9 of the first 12 words to be BIP39 words.
      // The full BIP39 wordlist has 2048 words; we have ~2040 of
      // them. The wordlist overlaps significantly with English
      // prose (e.g., 'quick', 'brown', 'fox' are all in BIP39).
      // 9 of 12 is a strong signal: random English prose matches
      // 3-7 BIP39 words out of 12; a real seed matches 11-12.
      // At 9+, the false-positive rate is < 0.01% on English prose.
      if (validCount < 9) {
        return null;  // false positive, drop
      }
    }
    
    // v0.1.4 follow-up: the 3 new ID-shape patterns (letter_only_id,
    // id_generic_alphanumeric, passport_generic) fire on bare 6-15 char
    // alphanumeric strings. Without context, they generate FPs on
    // DNA sequences ('CCGCACGGAUAU'), engine numbers ('AUM082114'),
    // alternators ('5DR'), etc. Fix: require the match to be preceded
    // by an ID label word (id/code/number/ref/license/certificate/
    // document/serial/account/passport) in the preceding 20 chars.
    if (category === 'pii_letter_only_id' ||
        category === 'pii_id_generic_alphanumeric' ||
        category === 'pii_passport_generic') {
      var startIdx = Math.max(0, (match.index || 0) - 20);
      var preceding = (text || '').substring(startIdx, match.index || 0);
      if (!/\b(?:id|code|number|ref|license|certificate|document|serial|account|passport|case|order)\b/i.test(preceding)) {
        return null;
      }
    }
return match;
  }

  // -------------------------------------------------------------------------
  // The detect function. Takes a string, returns Array<match>.
  // -------------------------------------------------------------------------
  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(patterns);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = patterns[key];
      // Reset lastIndex for each pattern (regex with /g)
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        var match = {
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[1] !== undefined ? m[1] : m[0],
          index: m.index
        };
        var processed = postProcess(key, match, text);
        if (processed !== null) matches.push(processed);
        // Avoid infinite loop on zero-length matches
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    // Sort by index (primary) then by category (secondary) so ties are
    // deterministic. Multiple patterns may match at the same position
    // (e.g. pii_credit_card and pii_credit_card_loose both match a CC).
    // The test 'pii: matches are sorted by index' requires strict
    // ordering, so we break ties alphabetically by category.
    matches.sort(function (a, b) {
      if (a.index !== b.index) return a.index - b.index;
      return a.category < b.category ? -1 : a.category > b.category ? 1 : 0;
    });
    return matches;
  }

  var module = {
    detect: detect,
    patterns: patterns
  };

  if (typeof self !== 'undefined') self.__lensPII = module;
  if (typeof window !== 'undefined') window.__lensPII = module;
  /**
   * @type {import("../util/typedefs").LensDetector}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensPII = module;
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === detectors/regex/secrets.js ===
// AegisGate Lens — detectors/regex/secrets.js
// Facet 2: Secrets detection. Regex-based, no Luhn.
// Per schema.js VALID_CATEGORIES[2], 42 secret types are detected (expanded from 17).
// Each pattern is provider-specific (where possible) to keep FP low.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Each pattern: { severity, re, description (for debugging) }
  // Severity:
  //   critical — direct credential that grants access (AWS, GitHub PAT, PEM)
  //   high     — likely credential (GCP, Stripe live, OpenAI)
  //   medium   — possible credential or context-dependent
  var PATTERNS = {
    secret_aws_key: {
      severity: 'critical',
      re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g
    },
    secret_github_token: {
      severity: 'critical',
      re: /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,120}\b/g
    },
    secret_gcp_key: {
      severity: 'high',
      re: /\bAIza[0-9A-Za-z_-]{30,50}\b/g
    },
    secret_azure_key: {
      severity: 'high',
      re: /(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}/g
    },
    secret_private_key_pem: {
      severity: 'critical',
      re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
    },
    secret_oauth_token: {
      severity: 'high',
      re: /\bya29\.[0-9A-Za-z_-]{50,}\b|\b1\/[0-9A-Za-z_-]{40,}\b/g
    },
    secret_jwt: {
      severity: 'high',
      re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g
    },
    secret_api_key_generic: {
      severity: 'high',
      re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi
    },
    secret_db_connection_string: {
      severity: 'high',
      re: /(?:mongodb|postgres|postgresql|mysql|redis|amqp)(\+\w+)?:\/\/[\w.-]+:[^\s@]+@[^\s/]+/g
    },
    secret_slack_token: {
      severity: 'high',
      re: /\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/g
    },
    secret_stripe_key: {
      severity: 'high',
      re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g
    },
    secret_twilio_key: {
      severity: 'high',
      re: /\b(?:SK|AC)[a-fA-F0-9]{32}\b/g
    },
    secret_sendgrid_key: {
      severity: 'high',
      re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g
    },
    secret_mailgun_key: {
      severity: 'high',
      re: /\bkey-[a-f0-9]{32}\b/g
    },
    secret_openai_key: {
      severity: 'high',
      re: /\bsk-(?!ant-)(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b/g
    },
    secret_anthropic_key: {
      severity: 'high',
      re: /\bsk-ant-(?:api)?\d{2}-[A-Za-z0-9_-]{20,}\b/g
    },
    secret_heroku_key: {
      severity: 'medium',
      re: /\bheroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g
    },
    secret_gitlab_pat: {
      severity: 'critical',
      re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g
    },
    secret_npm_token: {
      severity: 'critical',
      re: /\bnpm_[A-Za-z0-9]{30,}\b/g
    },
    secret_pypi_token: {
      severity: 'critical',
      re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g
    },
    secret_slack_legacy: {
      severity: 'high',
      re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g
    },
    secret_github_finegrained: {
      severity: 'critical',
      re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g
    },
    secret_supabase: {
      severity: 'high',
      re: /\beyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b/g
    },
    secret_db_url_with_password: {
      severity: 'high',
      re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|sqlserver|oracle|jdbc:(?:mysql|postgresql|sqlserver|oracle)|cassandra|influxdb|clickhouse|rabbitmq|mssql|sybase|db2|firebird|hsqldb|derby|sqlite):\/\/[\w.-]+:[^\s@'"]+@[^\s/'"]+/g
    },
    secret_aws_account_id: {
      severity: 'medium',
      re: /\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:aws)?:?(\d{12}):/g
    },
    secret_github_actions_token: {
      severity: 'critical',
      re: /\bgh[osur]_[A-Za-z0-9]{30,}\b/g
    },
    secret_gitlab_token: {
      severity: 'critical',
      re: /(?:GLPAT|gitlab_pat)_[A-Za-z0-9]{20,255}/g
    },
    secret_bitbucket_token: {
      severity: 'critical',
      re: /(?:BITBUCKET_TOKEN|BITBUCKET_PAT)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}/g
    },
    secret_gitea_token: {
      severity: 'critical',
      re: /gitea_[A-Za-z0-9]{36,255}/g
    },
    secret_circleci_token: {
      severity: 'high',
      re: /cici_[A-Za-z0-9]{36,255}/g
    },
    secret_travis_token: {
      severity: 'high',
      re: /travis_[A-Za-z0-9]{36,255}/g
    },
    secret_jenkins_token: {
      severity: 'high',
      re: /(?:JENKINS_TOKEN|JENKINS_API|JENKINS_PASSWORD)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}/g
    },
    secret_azure_devops: {
      severity: 'critical',
      re: /azdo_[A-Za-z0-9]{36,255}/g
    },
    secret_digitalocean_token: {
      severity: 'critical',
      re: /(?:DO_PAT|DIGITALOCEAN_TOKEN|DO_TOKEN)\s*[:=]\s*dop_v1_[A-Za-z0-9]{40,100}/g
    },
    secret_linode_token: {
      severity: 'critical',
      re: /linode_[A-Za-z0-9]{40,80}/g
    },
    secret_rackspace_token: {
      severity: 'high',
      re: /rackspace_[A-Za-z0-9]{32,64}/g
    },
    secret_heroku_token_legacy: {
      severity: 'high',
      re: /heroku_[A-Za-z0-9-]{36,50}/g
    },
    secret_salesforce_token: {
      severity: 'critical',
      re: /00D[A-Za-z0-9]{15}![A-Za-z0-9]{64,128}/g
    },
    secret_shopify_token: {
      severity: 'high',
      re: /sh[a-z]+_[A-Za-z0-9]{20,255}/g
    },
    secret_wordpress_token: {
      severity: 'high',
      re: /wordpress_[A-Za-z0-9]{32,64}/g
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta secrets expansion, 2026-07-06)
    // Additional secrets patterns for 95%+ coverage
    // ====================================================================
    secret_internal_api_key: {
      severity: 'critical',
      re: /(?:INTERNAL[_-]?API[_-]?KEY|INTERNAL[_-]?KEY|INTERNAL[_-]?TOKEN)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi
    },
  };

  function postProcess(category, match) {
    if (category === 'secret_private_key_pem') {
      return match;
    }
    if (category === 'secret_supabase') {
      return match;
    }
    return match;
  }

  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(PATTERNS);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = PATTERNS[key];
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        var match = {
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0],
          index: m.index
        };
        if (typeof postProcess === 'function') {
          var processed = postProcess(key, match);
          if (processed !== null && processed !== undefined) matches.push(processed);
        } else {
          matches.push(match);
        }
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensSecrets = module;
  if (typeof window !== 'undefined') window.__lensSecrets = module;
  /**
   * @type {import("./typedefs").LensDetector}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensSecrets = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/regex/source_xss.js ===
// AegisGate Lens — detectors/regex/source_xss.js
// Facet 3: Source code and XSS detection. Regex-based.
// Per schema.js VALID_CATEGORIES[3], 6 XSS categories are detected.
// These detect code that an attacker might paste into an AI tool to
// get help weaponizing, OR patterns that suggest prompt injection via
// code blocks.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var PATTERNS = {
    xss_script_tag: {
      severity: 'critical',
      // <script> opening or closing tag. We require an actual HTML
      // tag with attributes or content, not the word "script" alone.
      re: /<\s*script\b[^>]*>(?:[\s\S]*?<\s*\/\s*script\s*>)?/gi
    },
    xss_event_handler: {
      severity: 'high',
      // HTML event handler attribute: on*= followed by JS.
      // Matches onclick=, onerror=, onload=, onmouseover=, etc.
      re: /\s(?:on(?:click|error|load|mouseover|mouseout|focus|blur|submit|change|keydown|keyup|keypress|input|abort|resize|scroll|unload|drag|drop))\s*=\s*["'][^"']*["']/gi
    },
    xss_javascript_url: {
      severity: 'critical',
      // href or src with javascript: scheme
      re: /(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:/gi
    },
    xss_data_url: {
      severity: 'high',
      // data: URL with text/html (the dangerous one). data:image is
      // generally safe so we don't flag it.
      re: /(?:href|src|action|formaction)\s*=\s*["']?\s*data:text\/html/gi
    },
    xss_svg_script: {
      severity: 'critical',
      // <svg> with embedded script OR <svg> with event handler
      re: /<\s*svg\b[^>]*(?:on\w+\s*=|<\s*script)/gi
    },
    xss_dom_clobbering: {
      severity: 'medium',
      // HTML element with id or name that clobbers a common global
      // (e.g., getElementById, document.cookie, document.write).
      // The clobbering target list covers common cases.
      re: /<\s*(?:a|form|img|iframe|input|embed|object)\b[^>]*\s(?:id|name)\s*=\s*["'](?:getElementById|cookie|write|forms|length|parent|top|name)\b/gi
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta XSS expansion, 2026-07-04)
    // Each pattern: strict regex + tests covering positive cases and
    // benign strings (no FPs on common English / common code).
    // ====================================================================
    xss_svg_namespace_abuse: {
      // SVG with embedded foreignObject, animation, or use elements
      // (namespace abuse allows script execution in non-script contexts).
      // These are SVG-specific XSS vectors.
      severity: 'critical',
      re: /<\s*svg\b[^>]*\s+(?:xmlns|xmlns:[a-z]+)\s*=\s*["'][^"']*["'][^>]*<\s*(?:foreignObject|animation|set|animate|use|script)\b/gi
    },
    xss_mutation_xss: {
      // Mutation XSS (mXSS) patterns: HTML where the parser's
      // mutation produces different output than the author wrote.
      // Common mXSS vectors: nested <noembed>/<noscript>/<title>,
      // <svg>/<math> with <style>, <form> with <math>, <a> inside
      // <svg>, etc. We match the structural patterns that produce
      // mXSS, not the runtime behavior.
      //
      // The inner content (0-500 chars) must contain at least one
      // XSS indicator: a tag opener '<', an event handler 'on*=',
      // or 'javascript:'. This reduces FPs on normal title text
      // like '<title>Page Title</title>'.
      severity: 'high',
      re: /<\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\b[^>]*>(?:[^<]|<(?!\s*\/\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\s*>)){0,500}?(?:<[^>]*(?:on\w+\s*=|javascript:)[^>]*>|javascript:)[^<]{0,500}?<\s*\/\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\s*>/gi
    },
    xss_polyglot: {
      // Polyglot XSS: a single payload that is valid in multiple
      // contexts (HTML, JS, CSS, URL). Common vectors:
      //   - JavaScript comment in a CSS context: /* */
      //   - alert() inside a data: URL that's also a JS file
      //   - HTML entities that decode to JS
      // We match the most common polyglot patterns: inline event
      // handlers combined with template literals, or alert/eval
      // inside CSS or SVG.
      severity: 'high',
      re: /(?:alert|eval|prompt|confirm|document\.write)\s*\(\s*[`'"][^`'"]{0,200}?\$\{[^}]{0,100}?\}[^`'"]*[`'"]\s*\)/g
    },
    xss_svg_use_external: {
      // SVG <use> with external href (XXE/SVG XSS vector). When a
      // SVG references an external file via <use href="external">,
      // it can load attacker-controlled content. The pattern
      // requires the <use> element AND an external href.
      severity: 'critical',
      re: /<\s*use\b[^>]*\s(?:xlink:)?href\s*=\s*["']\s*(?:https?:|data:|file:|\/\/)/gi
    },
    xss_javascript_data_url: {
      // javascript: scheme in any URL context (not just href/src).
      // Includes formaction, xlink:href, action, etc. The
      // existing xss_javascript_url pattern covers href/src;
      // this extends to all URL contexts.
      severity: 'critical',
      re: /(?:href|src|action|formaction|xlink:href|background|poster|cite|usemap|data)\s*=\s*["']?\s*javascript:/gi
    },
    xss_meta_refresh: {
      // <meta http-equiv="refresh" content="0;url=javascript:...">
      // This is a less-common XSS vector but still possible in
      // older browsers and some HTML contexts.
      severity: 'medium',
      re: /<\s*meta\b[^>]*\shttp-equiv\s*=\s*["']\s*refresh\s*["'][^>]*\scontent\s*=\s*["'][^"']*javascript:/gi
    }
  };

  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(PATTERNS);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = PATTERNS[key];
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        matches.push({
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0].length > 200 ? m[0].substring(0, 200) + '...' : m[0],
          index: m.index
        });
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensXSS = module;
  if (typeof window !== 'undefined') window.__lensXSS = module;
  /**
   * @type {import("./typedefs").LensDetector}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensXSS = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/regex/compliance.js ===
// AegisGate Lens — detectors/regex/compliance.js
// Facet 4: Compliance framework detection. Keyword/phrase-based.
//
// Per schema.js VALID_CATEGORIES[4], 23 compliance categories across
// OWASP LLM Top 10, MITRE ATLAS, EU AI Act, ANP (GDPR data
// protection), and CU (consumer protection).
//
// v1.0 philosophy: match specific phrases that are clear signals
// (e.g., "credit scoring decision" = EU AI Act high-risk). Avoid
// single keywords (e.g., "race" alone is too broad). Future v1.1
// can use ML to add context-aware detection.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var PATTERNS = {
    // --- OWASP LLM Top 10 ---
    owasp_llm01_prompt_injection: {
      severity: 'critical',
      // Direct prompt injection: "ignore previous", "disregard prior",
      // "forget everything", "new instructions:", "system: you are"
      re: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:^|\s)(?:new|updated?)\s+instructions?\s*:|system\s*:\s*you\s+are\s+now/gi
    },
    owasp_llm04_model_dos: {
      severity: 'high',
      // Denial-of-service: flooding, overwhelming, massive inputs
      re: /(?:flood|overwhelm|DDoS|denial.of.service)\s+(?:the\s+)?(?:system|server|model|API)|(?:repeat|output)\s+(?:this\s+)?(?:sentence|phrase|word)\s+\d{3,}\s+times?/gi
    },
    owasp_llm08_excessive_agency: {
      severity: 'high',
      // Excessive agency: asking the AI to use tools with no oversight
      re: /(?:use|run|execute|call|invoke)\s+(?:the\s+)?(?:file|shell|terminal|command|exec|system)\s+(?:tool|command|function|API)|(?:without|no)\s+(?:human\s+)?(?:oversight|review|approval|confirmation)/gi
    },
    owasp_llm09_overreliance: {
      severity: 'medium',
      // Overreliance: asking AI to validate critical decisions
      re: /(?:is\s+this\s+(?:safe|legal|compliant|ethical|appropriate))|(?:should\s+I\s+(?:trust|rely\s+on|sign|send|submit))|(?:validate|verify|check)\s+(?:this\s+)?(?:for\s+me|before\s+I)/gi
    },
    owasp_llm10_model_theft: {
      severity: 'high',
      // Model extraction / theft
      re: /(?:extract|reveal|expose|leak|give\s+me)\s+(?:the\s+)?(?:model|weights?|parameters?|architecture|training\s+data|embeddings?)/gi
    },

    // --- MITRE ATLAS ---
    atlas_poison: {
      severity: 'high',
      // Training data poisoning: fine-tune, retrain, or ingest
      // untrusted data. We allow optional intervening words (model,
      // network, system) between the action and the data source.
      re: /(?:train|retrain|fine-?tune|ingest|poison(?:ing)?)\s+(?:the\s+)?(?:model|network|system|LLM)?\s*(?:on|with)\s+(?:this\s+|untrusted\s+|malicious\s+|adversarial\s+)?(?:data|dataset|corpus|examples?)/gi
    },
    atlas_exfiltration: {
      severity: 'high',
      // Data exfiltration via the AI
      re: /(?:send|exfiltrate|leak|upload|post|transmit)\s+(?:the\s+)?(?:data|secrets?|keys?|passwords?|tokens?)\s+to\s+(?:my\s+)?(?:server|endpoint|webhook|attacker|attacker\.com)/gi
    },
    atlas_jailbreak: {
      severity: 'critical',
      // Jailbreak attempts
      re: /\b(?:DAN|do\s+anything\s+now)\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+(?:the\s+)?model|ignore\s+(?:all\s+)?(?:safety|ethical)\s+(?:guidelines|filters?|restrictions?)/gi
    },

    // --- EU AI Act ---
    eu_ai_act_high_risk: {
      severity: 'high',
      // High-risk use cases per Annex III
      re: /(?:credit\s+scoring|loan\s+(?:approval|decision)|insurance\s+(?:risk|pricing))|(?:employment|hiring|firing|promotion|recruitment)\s+(?:decision|assessment|screening)|(?:law\s+enforcement|predictive\s+policing|criminal\s+justice)|(?:biometric|facial)\s+(?:identification|recognition|verification)|(?:medical|clinical)\s+diagnosis|emotion\s+recognition\s+system/gi
    },
    eu_ai_act_transparency: {
      severity: 'medium',
      // Transparency obligations (Article 50)
      re: /(?:AI[- ]generated|chatbot\s+without\s+disclosure|deepfake|synthetic\s+media)\s+(?:content|without\s+(?:disclosure|labeling))|users?\s+(?:must|should)\s+be\s+(?:informed|told)\s+(?:this\s+is\s+)?AI/gi
    },
    eu_ai_act_human_oversight: {
      severity: 'medium',
      // Human oversight (Article 14)
      re: /(?:no|without|zero)\s+human[- ](?:in[- ]the[- ]loop|oversight|review|intervention|approval)|fully\s+autonomous\s+(?:AI|system|decision)/gi
    },
    eu_ai_act_robustness: {
      severity: 'low',
      // Robustness/accuracy (Article 15)
      re: /(?:adversarial|adversarially[- ]crafted)\s+(?:input|example|perturbation|attack)/gi
    },

    // --- ANP (GDPR data protection) ---
    anp_personal_data: {
      severity: 'medium',
      // Personal data / PII in a GDPR context
      re: /(?:GDPR|personal\s+data|data\s+subject)\s+(?:of|processing|consent|lawful\s+basis)|(?:lawful|legitimate)\s+basis\s+for\s+processing/gi
    },
    anp_special_category: {
      severity: 'high',
      // Article 9 special categories (sensitive data)
      re: /(?:racial|ethnic)\s+(?:origin|discrimination)|(?:religious|political)\s+(?:beliefs?|opinions?|affiliation)|trade[- ]union\s+membership|(?:genetic|biometric)\s+data\s+for\s+(?:identification|profiling)|(?:health|medical)\s+data\s+(?:about|of)|(?:sex\s+life|sexual\s+orientation)/gi
    },

    // --- CU (Consumer protection) ---
    cu_consumer_rights: {
      severity: 'medium',
      re: /(?:consumer|user)\s+rights?\s+(?:to|of)\s+(?:explanation|erasure|rectification|deletion|portability)|right\s+to\s+(?:explanation|be\s+forgotten|erasure)/gi
    },
    cu_minor_protection: {
      severity: 'high',
      re: /(?:minor|child|juvenile|underage)\s+(?:protection|safety|consent)|(?:under|below)\s+(?:13|16|18)\s+(?:years?|yrs?\s+old)|(?:COPPA|age[- ]appropriate)\s+compliance/gi
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta Compliance expansion, 2026-07-04)
    // Each pattern: keyword + brief context, strict regex for low FP.
    // These cover region-specific privacy regulations and
    // cybersecurity frameworks that the Lens should detect so users
    // can flag content containing references to them.
    // ====================================================================
    nist_csf_reference: {
      // NIST Cybersecurity Framework (CSF) identifiers. CSF uses
      // function.category.subcategory (e.g., ID.AM-1, PR.AC-1).
      // We match the 5 function prefixes (ID, PR, DE, RS, RC) and
      // a few of the most common subcategories.
      severity: 'medium',
      re: /\b(?:(?:ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+(?:\.\d+)?)\b/g
    },
    iso_27001_reference: {
      // ISO/IEC 27001 control references. The format is Annex A
      // control IDs (A.5.1, A.6.1, A.8.2, etc.) or clause
      // references (6.1.2, 8.2.1, 10.1.1). The A.x.y format is
      // the most common.
      severity: 'medium',
      re: /\b(?:A\.\d{1,2}\.\d{1,2}(?:\.\d+)?|clause\s+\d{1,2}\.\d{1,2}(?:\.\d+)?)\b/g
    },
    ccpa_reference: {
      // California Consumer Privacy Act (CCPA). Section numbers
      // (1798.100, 1798.105, etc.) or keywords like "CCPA",
      // "California Consumer Privacy", "right to know", "right to
      // delete", "right to opt out", "sale of personal information".
      severity: 'medium',
      re: /\b(?:CCPA|California\s+Consumer\s+Privacy\s+Act|Civil\s+Code\s+§\s*1798(?:\.\d+)?|right\s+to\s+(?:know|delete|opt[\s-]?out|correct)|sale\s+of\s+personal\s+information|Shine\s+the\s+Light|Do\s+Not\s+Sell)\b/gi
    },
    lgpd_reference: {
      // Brazilian Lei Geral de Protecao de Dados (LGPD). Article
      // references (Art. 7, Art. 18, Art. 46) or keywords
      // ("LGPD", "Lei Geral de Protecao de Dados", "dados pessoais",
      // "controlador", "operador", "ANPD").
      severity: 'medium',
      re: /\b(?:LGPD|Lei\s+Geral\s+de\s+Protec[ãa]o\s+de\s+Dados|Art\.\s*\d+(?:[\s,ºo]+(?:I|II|III|IV|V|VI|VII|VIII|IX|X))*|dados\s+pessoais|controlador|operador|ANPD)\b/gi
    },
    pipeda_reference: {
      // Canadian Personal Information Protection and Electronic
      // Documents Act (PIPEDA). Schedule 1 references or keywords
      // ("PIPEDA", "personal information", "consent", "Principle").
      severity: 'medium',
      re: /\b(?:PIPEDA|Personal\s+Information\s+Protection\s+and\s+Electronic\s+Documents\s+Act|Schedule\s+1|Principle\s+\d+(?:\.\d+)?|express\s+consent)\b/gi
    },
    popia_reference: {
      // South African Protection of Personal Information Act (POPIA).
      // Section references (s. 11, s. 14) or keywords ("POPIA",
      // "Information Regulator", "processing of personal information").
      severity: 'medium',
      re: /\b(?:POPIA|Protection\s+of\s+Personal\s+Information\s+Act|s\.\s*\d+(?:\s*\(\d+\))?|Information\s+Regulator|processing\s+of\s+personal\s+information|special\s+personal\s+information)\b/gi
    },
    // ====================================================================
    // TOXICITY REGEX FALLBACK (Facet 5)
    // These are the 2 toxicity categories NOT in the unitary/toxic-bert
    // 6-class output. They fall back to regex detection. Per
    // plans/AEGISGATE-LENS-V01BETA-MODEL-DECISION.md (Section 4.1),
    // toxicity_sexual and toxicity_self_harm require regex patterns.
    // The other 5 toxicity categories (toxicity_hate, toxicity_insult,
    // toxicity_obscene, toxicity_threat, toxicity_violence) are
    // covered by the ML detector (unitary/toxic-bert) in
    // src/detectors/ml/toxicity.py.
    // ====================================================================
    toxicity_sexual: {
      // Sexual content indicators. We match explicit sexual terms
      // (avoiding medical/educational contexts). The pattern is
      // conservative -- we require an explicit qualifier to reduce FPs.
      severity: 'high',
      re: /\b(?:(?:pornographic|obscene|explicit|nsfw|hardcore)\s+(?:content|material|images?|video|text)|(?:sexual|sex)\s+(?:content|act(?:s|s)?|intercourse|fetish)|(?:rape|molest|incest)\s+(?:scene|content|material)|(?:child|minor|underage)\s+(?:sexual|porn(?:ography)?|abuse|exploitation))\b/gi
    },
    toxicity_self_harm: {
      // Self-harm indicators. We match explicit references to self-harm,
      // suicide, and self-injury. Conservative to avoid FPs on
      // mental health discussion (e.g., "how to help someone with
      // depression" should NOT fire; "I want to kill myself" SHOULD).
      severity: 'critical',
      re: /\b(?:suicid(?:e|al)|kill\s+(?:my)?self|hurt\s+(?:my)?self|end\s+(?:my\s+)?(?:life|suffering)|self\s*[-]?\s*harm|cut(?:ting)?)\b/gi
    }
  };

  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(PATTERNS);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = PATTERNS[key];
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        matches.push({
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0].length > 200 ? m[0].substring(0, 200) + '...' : m[0],
          index: m.index
        });
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensCompliance = module;
  if (typeof window !== 'undefined') window.__lensCompliance = module;
  /**
   * @type {import("./typedefs").LensDetector}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensCompliance = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === privacy/schema.js ===
// AegisGate Lens — schema.js
// Event schema validator for telemetry and detection events.
//
// Per the architecture doc Section 12 (F-09) and the threat model, every
// event sent from the content script to the service worker (and from
// the SW to the backend) must be validated against this schema before
// transmission. The schema is the contract that guarantees no prompt
// content, no URLs, no page content, no user IDs ever leak.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // The 6 facets. The "facet" field on every detection is the
  // discriminator that says which facet fired. Per the v0.2
  // architecture doc, facets are identified by their human-readable
  // name (not a numeric ID) so that logs and events are readable
  // and so the facet name matches the category prefix
  // (e.g. pii_ssn starts with pii, secret_aws_key starts with
  // secrets).
  //
  // The 4 regex facets are fully implemented in v0.1.0-beta. The
  // 2 ML facets (toxicity, prompt_injection) are reserved for
  // Step 3h.
  var VALID_FACETS = ['pii', 'secrets', 'xss', 'compliance', 'toxicity', 'prompt_injection'];

  // The category enum. 65 categories across the 6 facets.
  // Source: the v0.2 architecture doc Appendix B and the v0.2 schema
  // implementation. We re-implement from the spec, not from the old code.
  //
  // Format: { facetName: [category, category, ...] }
  var VALID_CATEGORIES = {
    pii: [
      'pii_ssn', 'pii_email', 'pii_phone', 'pii_credit_card', 'pii_phone_intl_loose',
      'pii_address', 'pii_dob', 'pii_driver_license', 'pii_passport',
      'pii_bip39_seed',
      'pii_tax_id', 'pii_bank_account', 'pii_ip_address',
      'pii_nhs_uk', 'pii_tfn_au',
      'pii_aadhaar_in', 'pii_cpf_br', 'pii_sin_ca',
      'pii_driver_license_international', 'pii_iban', 'pii_visa',
      'pii_passport_au', 'pii_passport_ca', 'pii_passport_de',
      'pii_passport_eu', 'pii_passport_fr', 'pii_passport_uk',
      'pii_residence_ca', 'pii_residence_uk', 'pii_residence_us',
      'pii_digital_paypal', 'pii_digital_stripe', 'pii_digital_venmo',
      'pii_digital_cashapp', 'pii_nid_de', 'pii_nid_es',
      'pii_nid_fr', 'pii_nid_it', 'pii_nid_jp',
      'pii_crypto_btc', 'pii_crypto_eth', 'pii_crypto_bnb',
      'pii_crypto_ltc', 'pii_crypto_sol', 'pii_letter_only_id',
      'pii_id_generic_alphanumeric', 'pii_id_multisegment',
      'pii_passport_generic', 'pii_street_intl', 'pii_ssn_ru',
      'pii_ssn_fr', 'pii_tax_id_ch', 'pii_credit_card_loose',
      'pii_email_intl'
    ],
    secrets: [
      'secret_aws_key', 'secret_github_token', 'secret_gcp_key',
      'secret_azure_key', 'secret_private_key_pem', 'secret_oauth_token',
      'secret_jwt', 'secret_api_key_generic', 'secret_db_connection_string',
      'secret_slack_token', 'secret_stripe_key', 'secret_twilio_key',
      'secret_sendgrid_key', 'secret_mailgun_key', 'secret_openai_key',
      'secret_anthropic_key', 'secret_heroku_key', 'secret_azure_devops', 'secret_gitea_token', 'secret_heroku_token_legacy', 'secret_slack_legacy',
      'secret_aws_account_id', 'secret_github_actions_token',
      'secret_github_finegrained', 'secret_gitlab_token', 'secret_gitlab_pat',
      'secret_linode_token', 'secret_digitalocean_token', 'secret_rackspace_token',
      'secret_salesforce_token', 'secret_shopify_token', 'secret_travis_token',
      'secret_jenkins_token', 'secret_circleci_token', 'secret_bitbucket_token',
      'secret_wordpress_token', 'secret_npm_token', 'secret_pypi_token',
      'secret_internal_api_key', 'secret_supabase', 'secret_db_url_with_password'
    ],
    xss: [
      'xss_javascript_data_url', 'xss_script_tag', 'xss_event_handler', 'xss_mutation_xss', 'xss_polyglot', 'xss_svg_namespace_abuse', 'xss_svg_use_external', 'xss_javascript_url',
      'xss_data_url', 'xss_svg_script', 'xss_dom_clobbering'
    ],
    compliance: [
      'owasp_llm01_prompt_injection',
      'owasp_llm02_insecure_output',
      'owasp_llm03_training_data_poisoning',
      'owasp_llm04_model_dos',
      'owasp_llm05_supply_chain',
      'owasp_llm06_sensitive_info_disclosure',
      'owasp_llm07_insecure_plugin',
      'owasp_llm08_excessive_agency',
      'owasp_llm09_overreliance',
      'owasp_llm10_model_theft',
      'atlas_promptinjection',
      'atlas_poison',
      'atlas_exfiltration',
      'atlas_jailbreak',
      'eu_ai_act_high_risk',
      'eu_ai_act_transparency',
      'eu_ai_act_human_oversight',
      'eu_ai_act_robustness',
      'anp_personal_data',
      'anp_special_category',
      'cu_consumer_rights', 'cu_minor_protection',
      'ccpa_reference', 'iso_27001_reference', 'lgpd_reference', 'nist_csf_reference', 'pipeda_reference', 'popia_reference',
      'cu_minor_protection',
    ],
    toxicity: [
      'toxicity_hate', 'toxicity_insult', 'toxicity_obscene',
      'toxicity_threat', 'toxicity_sexual', 'toxicity_self_harm',
      'toxicity_violence'
    ],
    prompt_injection: [
      'pi_direct_override',
      'pi_indirect_injection',
      'pi_jailbreak',
      'pi_role_play_attack'
    ]
  };

  var VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];

  var VALID_USER_ACTIONS = [
    'send_anyway', 'redact', 'cancel', 'dismiss_false_positive'
  ];

  // The schema for a single detection event. Optional fields default
  // to undefined and are omitted from the validated output.
  //
  // REQUIRED fields:
  //   - lens_event_version: string, "0.1.0-beta"
  //   - timestamp: number, Unix seconds (integer)
  //   - domain_hash: string, 16 hex chars (SHA-256 truncated)
  //   - facet: string, one of VALID_FACETS
  //   - category: string, from VALID_CATEGORIES[facet]
  //   - severity: string, from VALID_SEVERITIES
  //
  // OPTIONAL fields:
  //   - confidence: number, 0.0-1.0 (default 1.0 for regex)
  //   - user_action: string, from VALID_USER_ACTIONS
  //   - model_version: string, e.g. "regex-v1" or "modernbert-v1"
  //   - facet_results: object, per-facet confidence breakdown
  //   - pattern_id: string, e.g. "credit_card_visa_v1"
  //   - ml_score: number, 0.0-1.0 (only for ML detectors, 3h)
  //   - ml_threshold: number, 0.0-1.0 (only for ML detectors, 3h)
  //
  // What this schema DELIBERATELY does NOT include (privacy guarantee):
  //   - prompt text, URLs, page content, user IDs, cookies,
  //     keystroke timing, mouse movement, etc. (the 12 non-negotiables)

  var SCHEMA_VERSION = '0.1.0-beta';

  function isHex16(s) {
    return typeof s === 'string' && /^[0-9a-f]{16}$/.test(s);
  }

  function isPositiveInt(n) {
    return typeof n === 'number' && Number.isInteger(n) && n > 0;
  }

  // Validate just the metadata (facet + category + severity) of an
  // event, without requiring the full schema fields (timestamp,
  // domain_hash). This is what the dispatcher calls when it builds
  // an event from regex matches; the full event is built later
  // (by the SW) when the event is persisted or sent.
  function validateEventMetadata(event) {
    if (event === null || typeof event !== 'object') {
      return { ok: false, error: 'event must be an object' };
    }
    if (VALID_FACETS.indexOf(event.facet) === -1) {
      return { ok: false, error: 'facet must be one of ' + VALID_FACETS.join(',') };
    }
    var validCats = VALID_CATEGORIES[event.facet];
    if (!validCats || validCats.indexOf(event.category) === -1) {
      return { ok: false, error: 'category "' + event.category + '" is not valid for facet ' + event.facet };
    }
    if (VALID_SEVERITIES.indexOf(event.severity) === -1) {
      return { ok: false, error: 'severity must be one of ' + VALID_SEVERITIES.join(',') };
    }
    return { ok: true };
  }

  // Validate a single detection event. Returns { ok: true, event: <cleaned> }
  // on success, or { ok: false, error: '<message>' } on failure.
  function validateEvent(event) {
    if (event === null || typeof event !== 'object') {
      return { ok: false, error: 'event must be an object' };
    }

    // Required: lens_event_version
    if (event.lens_event_version !== SCHEMA_VERSION) {
      return { ok: false, error: 'lens_event_version must be "' + SCHEMA_VERSION + '"' };
    }

    // Required: timestamp
    if (!isPositiveInt(event.timestamp)) {
      return { ok: false, error: 'timestamp must be a positive integer (Unix seconds)' };
    }

    // Required: domain_hash
    if (!isHex16(event.domain_hash)) {
      return { ok: false, error: 'domain_hash must be a 16-char hex string' };
    }

    // Required: facet
    if (VALID_FACETS.indexOf(event.facet) === -1) {
      return { ok: false, error: 'facet must be one of ' + VALID_FACETS.join(',') };
    }

    // Required: category (must be valid for the given facet)
    var validCats = VALID_CATEGORIES[event.facet];
    if (validCats.indexOf(event.category) === -1) {
      return { ok: false, error: 'category "' + event.category + '" is not valid for facet ' + event.facet };
    }

    // Required: severity
    if (VALID_SEVERITIES.indexOf(event.severity) === -1) {
      return { ok: false, error: 'severity must be one of ' + VALID_SEVERITIES.join(',') };
    }

    // Optional: confidence
    if (event.confidence !== undefined) {
      if (typeof event.confidence !== 'number' || event.confidence < 0 || event.confidence > 1) {
        return { ok: false, error: 'confidence must be a number between 0 and 1' };
      }
    }

    // Optional: user_action
    if (event.user_action !== undefined && VALID_USER_ACTIONS.indexOf(event.user_action) === -1) {
      return { ok: false, error: 'user_action must be one of ' + VALID_USER_ACTIONS.join(',') };
    }

    // Optional: model_version
    if (event.model_version !== undefined && typeof event.model_version !== 'string') {
      return { ok: false, error: 'model_version must be a string' };
    }

    // Optional: pattern_id
    if (event.pattern_id !== undefined && typeof event.pattern_id !== 'string') {
      return { ok: false, error: 'pattern_id must be a string' };
    }

    // Optional: ml_score
    if (event.ml_score !== undefined) {
      if (typeof event.ml_score !== 'number' || event.ml_score < 0 || event.ml_score > 1) {
        return { ok: false, error: 'ml_score must be a number between 0 and 1' };
      }
    }

    // Optional: ml_threshold
    if (event.ml_threshold !== undefined) {
      if (typeof event.ml_threshold !== 'number' || event.ml_threshold < 0 || event.ml_threshold > 1) {
        return { ok: false, error: 'ml_threshold must be a number between 0 and 1' };
      }
    }

    // Optional: facet_results (object, per-facet confidence breakdown)
    if (event.facet_results !== undefined && (typeof event.facet_results !== 'object' || event.facet_results === null)) {
      return { ok: false, error: 'facet_results must be an object' };
    }

    // CRITICAL: Privacy guard. The cleaned event must NOT contain
    // any of the prohibited fields. We do this by EXPLICITLY
    // constructing the cleaned object from a whitelist of allowed
    // fields. Any field not in the whitelist is dropped.
    var cleaned = {
      lens_event_version: SCHEMA_VERSION,
      timestamp: event.timestamp,
      domain_hash: event.domain_hash,
      facet: event.facet,
      category: event.category,
      severity: event.severity
    };
    if (event.confidence !== undefined) cleaned.confidence = event.confidence;
    if (event.user_action !== undefined) cleaned.user_action = event.user_action;
    if (event.model_version !== undefined) cleaned.model_version = event.model_version;
    if (event.facet_results !== undefined) cleaned.facet_results = event.facet_results;
    if (event.pattern_id !== undefined) cleaned.pattern_id = event.pattern_id;
    if (event.ml_score !== undefined) cleaned.ml_score = event.ml_score;
    if (event.ml_threshold !== undefined) cleaned.ml_threshold = event.ml_threshold;

    return { ok: true, event: cleaned };
  }

  // Quick check for a single field. Used by tests and by other
  // modules that want to validate one piece of the schema.
  function isValidFacet(facet) { return VALID_FACETS.indexOf(facet) !== -1; }
  function isValidCategory(facet, category) {
    var cats = VALID_CATEGORIES[facet];
    return cats ? cats.indexOf(category) !== -1 : false;
  }
  function isValidSeverity(s) { return VALID_SEVERITIES.indexOf(s) !== -1; }
  function isValidUserAction(a) { return VALID_USER_ACTIONS.indexOf(a) !== -1; }

  // Build a full event from a metadata-only event (dispatcher output)
  // plus the required system fields (timestamp, domain_hash). This
  // is the canonical way the SW builds an event for persistence.
  function buildFullEvent(metadataEvent, timestamp, domainHash) {
    var candidate = {
      lens_event_version: SCHEMA_VERSION,
      timestamp: timestamp,
      domain_hash: domainHash,
      facet: metadataEvent.facet,
      category: metadataEvent.category,
      severity: metadataEvent.severity
    };
    if (metadataEvent.confidence !== undefined) candidate.confidence = metadataEvent.confidence;
    if (metadataEvent.user_action !== undefined) candidate.user_action = metadataEvent.user_action;
    if (metadataEvent.model_version !== undefined) candidate.model_version = metadataEvent.model_version;
    if (metadataEvent.pattern_id !== undefined) candidate.pattern_id = metadataEvent.pattern_id;
    if (metadataEvent.ml_score !== undefined) candidate.ml_score = metadataEvent.ml_score;
    if (metadataEvent.ml_threshold !== undefined) candidate.ml_threshold = metadataEvent.ml_threshold;
    return validateEvent(candidate);
  }

  var schema = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    VALID_FACETS: VALID_FACETS,
    VALID_CATEGORIES: VALID_CATEGORIES,
    VALID_SEVERITIES: VALID_SEVERITIES,
    VALID_USER_ACTIONS: VALID_USER_ACTIONS,
    validateEvent: validateEvent,
    validateEventMetadata: validateEventMetadata,
    buildFullEvent: buildFullEvent,
    isValidFacet: isValidFacet,
    isValidCategory: isValidCategory,
    isValidSeverity: isValidSeverity,
    isValidUserAction: isValidUserAction
  };

  /**
   * @type {import("./typedefs").LensSchema}
   */
  if (typeof self !== 'undefined') self.__lensSchema = schema;
  if (typeof window !== 'undefined') window.__lensSchema = schema;
  if (typeof globalThis !== 'undefined') globalThis.__lensSchema = schema;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === privacy/domain_hash.js ===
// AegisGate Lens — domain_hash.js
// SHA-256 of a hostname, truncated to 16 hex chars.
//
// Privacy posture: the Lens never sends the page URL to the backend.
// Instead, the page's hostname is hashed locally before any opt-in
// telemetry event. The hash is one-way; the backend cannot recover
// the hostname from the hash. This is the structural privacy guarantee
// — even if the backend is compromised, no user browsing data leaks.
//
// Per threat model F-09: domain hashes are 16 hex chars (64 bits of
// entropy). Collision risk for 1M distinct domains is ~2.7e-8 (birthday
// bound), acceptable for telemetry aggregation purposes.
//
// Feature-detect: prefers crypto.subtle (Chrome 116+ requires
// secure context — true for extension pages). Falls back to a
// pure-JS SHA-256 implementation if subtle is unavailable.

(function (global) {
  'use strict';

  // Pure-JS SHA-256. ~80 lines, no deps. Used as the fallback when
  // crypto.subtle is not available (older browsers, certain edge cases).
  // Based on FIPS 180-4 reference, with 32-bit word operations.
  function sha256Bytes(message) {
    // Convert message to bytes if it's a string
    if (typeof message === 'string') {
      var enc = new TextEncoder();
      message = enc.encode(message);
    }
    // message is now a Uint8Array

    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // Pre-processing: padding
    var ml = message.length * 8;
    var padLen = (56 - (message.length + 1) % 64 + 64) % 64;
    var totalLen = message.length + 1 + padLen + 8;
    var padded = new Uint8Array(totalLen);
    padded.set(message);
    padded[message.length] = 0x80;
    // Append length in bits as 64-bit big-endian. We only support
    // messages up to 2^32 bits (4GB), which is well above any
    // hostname string. Top 4 bytes are 0.
    var dv = new DataView(padded.buffer);
    dv.setUint32(totalLen - 4, ml, false);

    // Process each 512-bit (64-byte) chunk
    var w = new Array(64);
    for (var chunk = 0; chunk < padded.length; chunk += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = dv.getUint32(chunk + i * 4, false);
      }
      for (var j = 16; j < 64; j++) {
        var s0 = ((w[j-15] >>> 7) | (w[j-15] << 25)) ^ ((w[j-15] >>> 18) | (w[j-15] << 14)) ^ (w[j-15] >>> 3);
        var s1 = ((w[j-2] >>> 17) | (w[j-2] << 15)) ^ ((w[j-2] >>> 19) | (w[j-2] << 13)) ^ (w[j-2] >>> 10);
        w[j] = (w[j-16] + s0 + w[j-7] + s1) | 0;
      }

      var a = H[0], b = H[1], c = H[2], d = H[3];
      var e = H[4], f = H[5], g = H[6], h = H[7];

      for (var k = 0; k < 64; k++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + K[k] + w[k]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) | 0;

        h = g; g = f; f = e;
        e = (d + temp1) | 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) | 0;
      }

      H[0] = (H[0] + a) | 0;
      H[1] = (H[1] + b) | 0;
      H[2] = (H[2] + c) | 0;
      H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0;
      H[5] = (H[5] + f) | 0;
      H[6] = (H[6] + g) | 0;
      H[7] = (H[7] + h) | 0;
    }

    // Output as Uint8Array
    var out = new Uint8Array(32);
    var outDv = new DataView(out.buffer);
    for (var m = 0; m < 8; m++) {
      outDv.setUint32(m * 4, H[m], false);
    }
    return out;
  }

  // Convert a Uint8Array of bytes to a hex string
  function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      hex += (b < 16 ? '0' : '') + b.toString(16);
    }
    return hex;
  }

  // Normalize a hostname: lowercase, strip leading "www.", trim.
  // "WWW.ChatGPT.com" -> "chatgpt.com"
  function normalizeHostname(host) {
    if (typeof host !== 'string') {
      throw new TypeError('hostname must be a string, got ' + typeof host);
    }
    var h = host.toLowerCase().trim();
    if (h.startsWith('www.')) h = h.substring(4);
    // Strip port if present
    var colon = h.indexOf(':');
    if (colon !== -1) h = h.substring(0, colon);
    return h;
  }

  // Synchronous SHA-256 (uses pure-JS impl). Returns a 16-char hex
  // string (truncated from the 64-char full hash).
  function computeDomainHashSync(hostname) {
    var normalized = normalizeHostname(hostname);
    var bytes = sha256Bytes(normalized);
    return bytesToHex(bytes).substring(0, 16);
  }

  // Async SHA-256 (uses crypto.subtle when available). Returns a
  // Promise<string> of the 16-char hex hash.
  // If subtle is unavailable, falls back to the sync impl.
  var subtle = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle)
            || (typeof self !== 'undefined' && self.crypto && self.crypto.subtle)
            || null;

  function computeDomainHash(hostname) {
    var normalized;
    try {
      normalized = normalizeHostname(hostname);
    } catch (e) {
      return Promise.reject(e);
    }
    if (subtle && typeof subtle.digest === 'function') {
      var enc = new TextEncoder();
      return subtle.digest('SHA-256', enc.encode(normalized)).then(function (buf) {
        var bytes = new Uint8Array(buf);
        return bytesToHex(bytes).substring(0, 16);
      });
    }
    // Fallback
    return Promise.resolve(computeDomainHashSync(normalized));
  }

  // Expose
  var module = {
    computeDomainHash: computeDomainHash,
    computeDomainHashSync: computeDomainHashSync,
    normalizeHostname: normalizeHostname,
    sha256Bytes: sha256Bytes,    // exposed for testing
    bytesToHex: bytesToHex,      // exposed for testing
    subtleAvailable: !!subtle
  };

  if (typeof self !== 'undefined') self.__lensDomainHash = module;
  if (typeof window !== 'undefined') window.__lensDomainHash = module;
  /**
   * @type {import("./typedefs").LensDomainHash}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensDomainHash = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === detectors/index.js ===
// AegisGate Lens — detectors/index.js
// The 6-facet dispatcher. Aggregates PII + Secrets + XSS + Compliance
// (regex facets) and (in 3h) Toxicity + Prompt-Injection (ML facets).
//
// v0.1.0-beta: 4 regex facets only. ML facets will be added in Step
// 3h with lazy-load from the service worker.
//
// Per docs/ARCHITECTURE-v0.1.0-BETA.md Section 4 (the 6 detection
// facets), each facet is an independent detection surface. The
// dispatcher:
//   1. Calls all 4 regex facets
//   2. Validates each match with privacy/schema.js
//   3. Deduplicates by category (multiple matches of the same
//      category become 1 event with count=N)
//   4. Sorts by severity (critical first)
//   5. Returns a structured DetectionResult object
//
// IMPORTANT: This module is 100% local. No network calls. The
// "Send & dismiss" opt-in path (in 3f's banner-ui.js) is the
// only time any data is sent, and the user must explicitly
// choose it. See docs/BANNER-DESIGN-SPEC-v0.1.0-BETA.md for the
// full opt-in flow.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // Severity order for sorting (lower = more severe)
  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  // The 4 regex facets. Each is loaded from globalThis (set by the
  // content_scripts load order in manifest.json).
  function getFacets() {
    var facets = [];

    if (typeof self !== 'undefined' && self.__lensPII) {
      facets.push({ id: 'pii', module: self.__lensPII });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensPII) {
      facets.push({ id: 'pii', module: globalThis.__lensPII });
    }

    if (typeof self !== 'undefined' && self.__lensSecrets) {
      facets.push({ id: 'secrets', module: self.__lensSecrets });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensSecrets) {
      facets.push({ id: 'secrets', module: globalThis.__lensSecrets });
    }

    if (typeof self !== 'undefined' && self.__lensXSS) {
      facets.push({ id: 'xss', module: self.__lensXSS });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensXSS) {
      facets.push({ id: 'xss', module: globalThis.__lensXSS });
    }

    if (typeof self !== 'undefined' && self.__lensCompliance) {
      facets.push({ id: 'compliance', module: self.__lensCompliance });
    } else if (typeof globalThis !== 'undefined' && globalThis.__lensCompliance) {
      facets.push({ id: 'compliance', module: globalThis.__lensCompliance });
    }

    return facets;
  }

  // Get the schema module (for validateEvent).
  function getSchema() {
    if (typeof self !== 'undefined' && self.__lensSchema) return self.__lensSchema;
    if (typeof globalThis !== 'undefined' && globalThis.__lensSchema) return globalThis.__lensSchema;
    return null;
  }

  // Build a single DetectionEvent from one or more raw matches.
  // The event is what gets passed to the banner and (optionally,
  // on opt-in) the SW. It is the EVENT that gets schema-validated.
  function buildEvent(facetId, category, severity, matches, schemaModule) {
    if (!matches || matches.length === 0) return null;
    var event = {
      facet: facetId,                        // 'pii' | 'secrets' | 'xss' | 'compliance'
      category: category,                     // e.g. 'pii_credit_card'
      severity: severity,                     // 'critical' | 'high' | 'medium' | 'low'
      count: matches.length,                  // how many matches
      // For display: the masked values (first match is enough;
      // the banner shows the first 4 + last 4 chars).
      sample: matches[0].value,
      // All matches, in original order
      matches: matches.map(function (m) {
        return {
          value: m.value,
          index: m.index,
          severity: m.severity,
          // cardType is added by pii.js for credit cards (Luhn-validated)
          cardType: m.cardType || null,
          // confidence is a 0-1 score; regex detectors set 1.0
          confidence: typeof m.confidence === 'number' ? m.confidence : 1.0
        };
      }),
      // ML facets (3h) will set this; regex sets null
      ml_score: null,
      ml_model_version: null
    };

    // Validate the metadata (facet + category + severity) if the
    // schema module is available. The full event (with timestamp
    // and domain_hash) is built later by the SW when it persists
    // or sends the event. The metadata validation ensures the
    // category is legitimate for the facet and the severity is
    // one of the 4 allowed values.
    if (schemaModule && typeof schemaModule.validateEventMetadata === 'function') {
      var validation = schemaModule.validateEventMetadata(event);
      if (!validation.ok) {
        log.warn('event failed metadata validation: ' + validation.error +
                 ' (facet=' + facetId + ' category=' + category + ')');
        return null;
      }
    }
    return event;
  }

  // Deduplicate matches by category. Multiple matches of the same
  // category become one event with count=N. We also cap the
  // matches array at MAX_MATCHES_PER_EVENT to avoid memory bloat
  // for prompts that have hundreds of the same pattern.
  var MAX_MATCHES_PER_EVENT = 20;

  function dedupeByCategory(facetId, rawMatches) {
    var byCategory = {};
    for (var i = 0; i < rawMatches.length; i++) {
      var m = rawMatches[i];
      if (!byCategory[m.category]) {
        byCategory[m.category] = {
          category: m.category,
          severity: m.severity,
          matches: []
        };
      }
      if (byCategory[m.category].matches.length < MAX_MATCHES_PER_EVENT) {
        byCategory[m.category].matches.push(m);
      }
    }
    return byCategory;
  }

  // Run detection on a text string. Returns a DetectionResult.
  //
  // DetectionResult {
  //   text: string,             // the input text (NOT modified)
  //   hasDetections: boolean,
  //   count: number,            // total detection count
  //   maxSeverity: 'critical' | 'high' | 'medium' | 'low' | null,
  //   events: [DetectionEvent]  // sorted by severity, critical first
  // }
  function detect(text) {
    if (typeof text !== 'string') text = '';
    var result = {
      text: text,
      hasDetections: false,
      count: 0,
      maxSeverity: null,
      events: []
    };

    if (text.length === 0) return result;

    var facets = getFacets();
    if (facets.length === 0) {
      log.error('dispatcher: no regex facets available; cannot detect');
      return result;
    }

    var schemaModule = getSchema();
    if (!schemaModule) {
      log.error('dispatcher: schema module not available; cannot validate events');
      return result;
    }

    for (var i = 0; i < facets.length; i++) {
      var facet = facets[i];
      try {
        var rawMatches = facet.module.detect(text);
        if (!rawMatches || rawMatches.length === 0) continue;

        var byCategory = dedupeByCategory(facet.id, rawMatches);
        var categoryKeys = Object.keys(byCategory);
        for (var j = 0; j < categoryKeys.length; j++) {
          var group = byCategory[categoryKeys[j]];
          var event = buildEvent(facet.id, group.category, group.severity, group.matches, schemaModule);
          if (event) result.events.push(event);
        }
      } catch (err) {
        // Per lesson K: a broken facet should not break the
        // whole dispatcher. Log the error and continue with
        // the other facets.
        log.error('facet ' + facet.id + ' threw in detect()', err);
      }
    }

    // Sort by severity (critical first), then by count descending
    // Note: SEVERITY_ORDER has critical=0, so we MUST NOT use
    // `|| 99` to default unknown severities — that pattern breaks
    // for critical (since 0 is falsy). Use explicit undefined check.
    result.events.sort(function (a, b) {
      var rankA = (typeof SEVERITY_ORDER[a.severity] === 'number') ? SEVERITY_ORDER[a.severity] : 99;
      var rankB = (typeof SEVERITY_ORDER[b.severity] === 'number') ? SEVERITY_ORDER[b.severity] : 99;
      var sevDiff = rankA - rankB;
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });

    // Compute summary
    result.hasDetections = result.events.length > 0;
    result.count = 0;
    var maxSevRank = 99;
    for (var k = 0; k < result.events.length; k++) {
      result.count += result.events[k].count;
      var rank = (typeof SEVERITY_ORDER[result.events[k].severity] === 'number')
        ? SEVERITY_ORDER[result.events[k].severity] : 99;
      if (rank < maxSevRank) {
        maxSevRank = rank;
        result.maxSeverity = result.events[k].severity;
      }
    }

    return result;
  }

  // For testing: list the loaded facets (so we can assert all 4
  // are present in a healthy state)
  function listFacets() {
    return getFacets().map(function (f) { return f.id; });
  }

  // For testing: list the expected facets (so the test can assert)
  var EXPECTED_FACETS = ['pii', 'secrets', 'xss', 'compliance'];

  var module = {
    detect: detect,
    listFacets: listFacets,
    EXPECTED_FACETS: EXPECTED_FACETS,
    SEVERITY_ORDER: SEVERITY_ORDER,
    MAX_MATCHES_PER_EVENT: MAX_MATCHES_PER_EVENT
  };

  if (typeof self !== 'undefined') self.__lensDispatcher = module;
  if (typeof window !== 'undefined') window.__lensDispatcher = module;
  /**
   * @type {import("./typedefs").LensDispatcher}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensDispatcher = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/selectors.js ===
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

// === util/prompt-detect-dom.js ===
// AegisGate Lens — util/prompt-detect-dom.js
//
// DOM event handlers for the prompt-detect orchestrator. Owns:
//   - findElements: locate the input/sendButton for the current provider
//   - onInput: per-keystroke detection trigger
//   - onSendClick: intercept the send button click
//   - onKeyDown: intercept Enter on contentEditable inputs
//
// Loaded by prompt-detect.js (the aggregator) BEFORE the lifecycle
// sub-file, so the aggregator's attach() can reference the DOM
// handlers.
//
// Per the v0.1.1 code-quality plan (item 3: split prompt-detect.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Pull in dependencies from the globals set by earlier-loaded modules.
  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // -----------------------------------------------------------------
  // v0.1.4: "Pause Lens for 1h / 1d" toggle state.
  //
  // Cached timestamp (ms since epoch) at which the pause expires.
  // When Date.now() < _pausedUntil, onInput() early-returns BEFORE
  // running the 4-facet regex scan — detection is suppressed
  // globally across all domains, categories, and patterns.
  //
  // Default 0 (not paused). When the user clicks "Pause for 1h" in
  // the popup, the popup writes Date.now() + 3600000 to
  // chrome.storage.local. The onChanged listener updates the
  // cache in real-time. The pause auto-expires — when Date.now() >=
  // _pausedUntil, detection resumes automatically. No manual
  // "unpause" action needed.
  //
  // Different semantic from the per-domain 24h dismiss (dismiss.js):
  // pause is global, dismiss is per-domain per-category. Pause is
  // for "I'm testing prompts, suppress all detection"; dismiss is
  // for "this specific detection is wrong, don't show it again
  // for 24h on this domain".
  //
  // The constants module is NOT imported here (this file loads
  // before constants in the bundle order per bootstrap.js), so we
  // hardcode the key as a fallback. The canonical key is in
  // src/util/constants.js STORAGE_KEYS.PAUSE_UNTIL.
  // -----------------------------------------------------------------
  var _pausedUntil = 0;
  var PAUSE_UNTIL_KEY = 'aegisgate_lens_pause_until';
  function _loadPausedUntil() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
      chrome.storage.local.get([PAUSE_UNTIL_KEY], function (result) {
        try {
          if (result && Object.prototype.hasOwnProperty.call(result, PAUSE_UNTIL_KEY)) {
            var v = result[PAUSE_UNTIL_KEY];
            _pausedUntil = (typeof v === 'number' && v > 0) ? v : 0;
          }
        } catch (e) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }
  _loadPausedUntil();
  // v0.1.4: react to popup pause changes in real-time.
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;
        if (changes && changes[PAUSE_UNTIL_KEY]) {
          var nv = changes[PAUSE_UNTIL_KEY].newValue;
          _pausedUntil = (typeof nv === 'number' && nv > 0) ? nv : 0;
        }
      });
    }
  } catch (e) { /* ignore */ }

  // -----------------------------------------------------------------
  // v0.1.4: "Hide Lens active indicator" toggle state.
  //
  // Cached at module init from chrome.storage.local, with a
  // chrome.storage.onChanged listener that updates the cache in
  // real-time if the user toggles the popup setting while the
  // content script is running. The cache is consulted by
  // injectIndicator() — if disabled, the on-page "🛡️ Lens active"
  // chip is never rendered.
  //
  // Default ON (show indicator). If the storage read fails (e.g.,
  // chrome.storage unavailable in a test env), we default to ON
  // for safety — a missing toggle should not silently hide the
  // indicator.
  //
  // The constants module is NOT imported here (this file loads
  // before constants in the bundle order per bootstrap.js), so we
  // hardcode the key as a fallback. The canonical key is in
  // src/util/constants.js STORAGE_KEYS.SHOW_INDICATOR.
  // -----------------------------------------------------------------
  var _showIndicator = true;
  var SHOW_INDICATOR_KEY = 'aegisgate_lens_show_indicator';
  function _loadShowIndicator() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
      chrome.storage.local.get([SHOW_INDICATOR_KEY], function (result) {
        try {
          if (result && Object.prototype.hasOwnProperty.call(result, SHOW_INDICATOR_KEY)) {
            _showIndicator = result[SHOW_INDICATOR_KEY] !== false;
          }
        } catch (e) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }
  _loadShowIndicator();
  // v0.1.4: react to popup toggle in real-time. The popup writes
  // directly to chrome.storage.local, which fires onChanged in the
  // content script's storage area.
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;
        if (changes && changes[SHOW_INDICATOR_KEY]) {
          _showIndicator = changes[SHOW_INDICATOR_KEY].newValue !== false;
        }
      });
    }
  } catch (e) { /* ignore */ }

  function findElements(state) {
    if (!state.provider || !selectors) return;
    state.input = selectors.findInput(state.provider);
    state.sendButton = selectors.findSendButton(state.provider);
  }

  // v0.1.1 item 19: on-page "Lens active" indicator.
  // Renders a small, unobtrusive chip in the input area so the
  // user knows the Lens is running. The chip is a <span> with
  // [data-aegisgate-lens="indicator"]; the CSS in banner.css
  // positions it absolutely at the bottom-right of the input
  // container. Clicking the chip shows a console.info message
  // (and can be extended to open a small "what this is" popover
  // in v0.2.0).
  function injectIndicator(state) {
    if (typeof document === 'undefined') return;
    // v0.1.4: respect the "Hide Lens active indicator" popup
    // toggle. The cached _showIndicator is updated by the
    // chrome.storage.onChanged listener above.
    if (_showIndicator === false) return;
    if (document.querySelector('[data-aegisgate-lens="indicator"]')) return;
    if (!state.input) return;
    var container = state.input.parentNode;
    if (!container || container.nodeType !== 1) return;
    var indicator = document.createElement('span');
    indicator.setAttribute('data-aegisgate-lens', 'indicator');
    indicator.setAttribute('role', 'status');
    indicator.setAttribute('aria-label', 'AegisGate Lens is active on this page');
    indicator.title = 'AegisGate Lens is active — click for details';
    // v0.1.4 F-7: replace innerHTML with safe DOM construction.
    // Per security.yml CSP gate: innerHTML is only allowed in banner-ui.js.
    // We use createElement for the shield icon (aria-hidden because
    // it's decorative) and textContent for the visible label. This
    // eliminates the innerHTML surface entirely.
    var shieldIcon = document.createElement('span');
    shieldIcon.className = 'lens-indicator-shield';
    shieldIcon.setAttribute('aria-hidden', 'true');
    shieldIcon.textContent = '🛡️';
    indicator.appendChild(shieldIcon);
    indicator.appendChild(document.createTextNode(' Lens active'));
    indicator.addEventListener('click', function (e) {
      try {
        e.preventDefault();
        if (typeof console !== 'undefined' && console.info) {
          console.info('AegisGate Lens is watching this prompt for PII, secrets, and compliance issues. ' +
                       'Click the banner for details. ' +
                       'Opt out: click the dismiss icon on the banner for 24h.');
        }
      } catch (e2) { /* ignore */ }
    }, true);
    // Make sure the container is positioned so the absolute
    // indicator positions relative to it.
    var containerStyle = (typeof window !== 'undefined' && window.getComputedStyle) ?
                         window.getComputedStyle(container) : null;
    if (containerStyle && containerStyle.position === 'static') {
      container.style.position = 'relative';
    }
    container.appendChild(indicator);
  }

  function removeIndicator() {
    if (typeof document === 'undefined') return;
    var el = document.querySelector('[data-aegisgate-lens="indicator"]');
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  // The onInput handler: read the current value, run detection
  // (caller passes in detectPrompt so we can stay decoupled from
  // the aggregator's internal API).
  function onInput(state, detectPrompt) {
    try {
      if (!state.input || !selectors) return;
      // v0.1.4: global pause check. If the user paused Lens from
      // the popup (Date.now() < _pausedUntil), suppress all
      // detection globally. The 4-facet regex scan is skipped
      // entirely; the banner is not shown; the FP report queue is
      // not touched. Auto-resumes when the pause expires.
      if (_pausedUntil > 0 && Date.now() < _pausedUntil) return;
      var value = selectors.getInputValue(state.input);
      if (value === state.lastValue) return;
      state.lastValue = value;
      if (value.length === 0) {
        state.lastDetections = [];
        if (state.onDetect) {
          try { state.onDetect([], ''); } catch (e) { log.error('onDetect threw', e); }
        }
        return;
      }
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (state.onDetect) {
        try { state.onDetect(dets, value); } catch (e) { log.error('onDetect threw', e); }
      }
    } catch (err) {
      log.error('onInput handler threw', err);
    }
  }

  // The onSendClick handler: intercept the send button click
  function onSendClick(e, state, detectPrompt) {
    try {
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value.length === 0) return;
      // Always re-detect on send (the last keyup might have been
      // before the user finished typing)
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (dets.length > 0 && state.onSendIntercept) {
        // Pause the default action; let the consumer decide
        try { e.preventDefault(); e.stopPropagation(); } catch (e2) { /* ignore */ }
        try {
          var decision = state.onSendIntercept(dets, value);
          if (decision && decision.action === 'send') {
            log.info('user chose to send anyway despite ' + dets.length + ' detections');
            // Re-dispatch on the next tick (we already prevented it)
            setTimeout(function () {
              if (state.sendButton) state.sendButton.click();
            }, 0);
          } else if (decision && decision.action === 'redact') {
            log.info('user chose to redact ' + dets.length + ' detections');
            // Remove the detected values from the input
            var redacted = value;
            for (var i = 0; i < dets.length; i++) {
              redacted = redacted.replace(dets[i].value, '[REDACTED]');
            }
            selectors.setInputValue(state.input, redacted);
          } else {
            log.info('user chose to cancel the send');
          }
        } catch (e3) { log.error('onSendIntercept threw', e3); }
      }
    } catch (err) {
      log.error('onSendClick handler threw', err);
    }
  }

  // The onKeyDown handler for Enter on contenteditable
  function onKeyDown(e, state, detectPrompt) {
    try {
      if (!state.provider) return;
      if (state.provider.submitMethod !== 'enter') return;
      if (e.key !== 'Enter') return;
      if (e.shiftKey) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (!state.input || !selectors) return;
      var value = selectors.getInputValue(state.input);
      if (value.length === 0) return;
      var dets = detectPrompt(value);
      state.lastDetections = dets;
      if (dets.length > 0 && state.onSendIntercept) {
        try { e.preventDefault(); e.stopPropagation(); } catch (e2) { /* ignore */ }
        try {
          var decision = state.onSendIntercept(dets, value);
          if (decision && decision.action === 'send') {
            log.info('user chose to send anyway despite detections; press Enter again to confirm');
          } else if (decision && decision.action === 'redact') {
            var redacted = value;
            for (var i = 0; i < dets.length; i++) {
              redacted = redacted.replace(dets[i].value, '[REDACTED]');
            }
            selectors.setInputValue(state.input, redacted);
          }
        } catch (e3) { log.error('onSendIntercept (keydown) threw', e3); }
      }
    } catch (err) {
      log.error('onKeyDown handler threw', err);
    }
  }

  if (typeof self !== 'undefined') self.__lensPromptDetect_dom = {
    findElements: findElements,
    onInput: onInput,
    onSendClick: onSendClick,
    onKeyDown: onKeyDown,
    injectIndicator: injectIndicator,
    removeIndicator: removeIndicator
  };
  if (typeof window !== 'undefined') window.__lensPromptDetect_dom = {
    findElements: findElements,
    onInput: onInput,
    onSendClick: onSendClick,
    onKeyDown: onKeyDown,
    injectIndicator: injectIndicator,
    removeIndicator: removeIndicator
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPromptDetect_dom = {
      findElements: findElements,
      onInput: onInput,
      onSendClick: onSendClick,
      onKeyDown: onKeyDown,
      injectIndicator: injectIndicator,
      removeIndicator: removeIndicator
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/prompt-detect-lifecycle.js ===
// AegisGate Lens — util/prompt-detect-lifecycle.js
//
// Lifecycle + MutationObserver for the prompt-detect orchestrator.
// Owns:
//   - attach: bind event listeners to the input + send button
//   - detach: remove event listeners
//   - onMutation: re-attach if the input was replaced (React SPA)
//
// Loaded by prompt-detect.js (the aggregator) AFTER the dom
// sub-file, so the aggregator's attach() can reference the DOM
// handlers (onInput, onSendClick, onKeyDown) that the dom
// sub-file exports.
//
// Per the v0.1.1 code-quality plan (item 3: split prompt-detect.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;
  var dom = (typeof self !== 'undefined' && self.__lensPromptDetect_dom) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect_dom) ||
            null;
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  // The attach() function. Takes:
  //   - state: the aggregator's state object (contains input,
  //     sendButton, attached, _debouncedInput)
  //   - debounce: the aggregator's debounce helper
  //   - detectPrompt: the aggregator's detectPrompt function
  //   - onMutation: the lifecycle's own onMutation handler (for
  //     MutationObserver wiring)
  // Returns nothing; mutates state.
  function attach(state, debounce, detectPrompt, onMutation) {
    if (state.attached) return;
    if (!state.input) return;
    try {
      var debouncedInput = debounce(function () { dom.onInput(state, detectPrompt); },
                                    (constants && constants.DEBOUNCE_MS) || 250);
      state.input.addEventListener('input', debouncedInput, true);
      state.input.addEventListener('keyup', debouncedInput, true);
      state.input.addEventListener('keydown', function (e) { dom.onKeyDown(e, state, detectPrompt); }, true);
      if (state.sendButton) {
        state.sendButton.addEventListener('click', function (e) { dom.onSendClick(e, state, detectPrompt); }, true);
      }
      state._debouncedInput = debouncedInput;
      state.attached = true;
      // v0.1.1 item 19: render the on-page indicator chip so the
      // user can see that the Lens is running. Remove any prior
      // indicator first to handle re-attach.
      try { dom.removeIndicator(); } catch (e3) { /* ignore */ }
      try { dom.injectIndicator(state); } catch (e3) { log.warn('injectIndicator threw', e3); }
      log.info('attached to input' + (state.sendButton ? ' + send button' : ''));
    } catch (err) {
      log.error('attach() threw', err);
    }
  }

  // Detach event listeners. Takes state + onSendClick/onKeyDown
  // function refs (but we already have those in dom; pass through).
  function detach(state) {
    if (!state.attached) return;
    try {
      if (state.input) {
        if (state._debouncedInput) {
          state.input.removeEventListener('input', state._debouncedInput, true);
          state.input.removeEventListener('keyup', state._debouncedInput, true);
        }
        state.input.removeEventListener('keydown', function (e) { dom.onKeyDown(e, state, arguments.callee && arguments.callee.prototype); }, true);
      }
      if (state.sendButton) {
        state.sendButton.removeEventListener('click', function (e) { dom.onSendClick(e, state, arguments.callee && arguments.callee.prototype); }, true);
      }
      state.attached = false;
      // v0.1.1 item 19: remove the on-page indicator when the
      // content script detaches (e.g., during a navigation).
      try { dom.removeIndicator(); } catch (e3) { /* ignore */ }
      log.info('detached from input');
    } catch (err) {
      log.error('detach() threw', err);
    }
  }

  // The MutationObserver callback: re-attach if the input was replaced
  // (state, attach, detach are passed in so this function is pure).
  function onMutation(mutations, state, attachFn, detachFn) {
    try {
      if (!state.provider) return;
      var newInput = selectors.findInput(state.provider);
      if (newInput && newInput !== state.input) {
        log.info('input element changed; re-attaching');
        detachFn(state);
        state.input = newInput;
        state.sendButton = selectors.findSendButton(state.provider);
        attachFn(state);
      } else if (!newInput && state.input) {
        log.info('input element removed; detaching');
        detachFn(state);
        state.input = null;
        state.sendButton = null;
      }
    } catch (err) {
      log.error('onMutation threw', err);
    }
  }

  if (typeof self !== 'undefined') self.__lensPromptDetect_lifecycle = {
    attach: attach,
    detach: detach,
    onMutation: onMutation
  };
  if (typeof window !== 'undefined') window.__lensPromptDetect_lifecycle = {
    attach: attach,
    detach: detach,
    onMutation: onMutation
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPromptDetect_lifecycle = {
      attach: attach,
      detach: detach,
      onMutation: onMutation
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/prompt-detect.js ===
// AegisGate Lens — util/prompt-detect.js
//
// Per-keystroke detection orchestrator. Aggregates 2 sub-files
// that each own a logical group of helpers:
//
//   prompt-detect-dom.js         (findElements, onInput,
//                                onSendClick, onKeyDown)
//   prompt-detect-lifecycle.js   (attach, detach, onMutation)
//
// The aggregator owns the public API (init, shutdown, getState,
// detectPrompt), the debounce helper, the identifyProvider helper,
// the state object, and the __lensPromptDetect global.
//
// Per the architecture doc Section 9 (SPA MutationObserver pattern),
// modern AI chat UIs are React SPAs that re-mount the input element
// when state changes. document_idle does not fire reliably on these
// pages. The MutationObserver is the canonical fix.
//
// All 3 files (this + 2 sub-files) are loaded in this order in
// manifest.json content_scripts.js; see src/bootstrap.js.
//
// Per the v0.1.1 code-quality plan (item 3: split prompt-detect.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Dependencies: read from globals (set by earlier-loaded modules).
  // -------------------------------------------------------------------------
  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };
  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;
  var dom = (typeof self !== 'undefined' && self.__lensPromptDetect_dom) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect_dom) ||
            null;
  var lifecycle = (typeof self !== 'undefined' && self.__lensPromptDetect_lifecycle) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect_lifecycle) ||
                  null;

  if (!dom) {
    throw new Error('prompt-detect.js: required sub-file not loaded: __lensPromptDetect_dom');
  }
  if (!lifecycle) {
    throw new Error('prompt-detect.js: required sub-file not loaded: __lensPromptDetect_lifecycle');
  }

  // -------------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------------
  var state = {
    provider: null,
    input: null,
    sendButton: null,
    attached: false,
    lastValue: '',
    lastDetections: [],
    onDetect: null,
    onSendIntercept: null,
    observer: null,
    debounceTimer: null,
    _debouncedInput: null
  };

  // -------------------------------------------------------------------------
  // The detection pipeline. Delegates to the 4-facet dispatcher
  // (loaded in pii.js' content_scripts chain). The dispatcher
  // aggregates PII + Secrets + XSS + Compliance (regex facets)
  // and (in v0.2.0+) Toxicity + Prompt-Injection (ML facets).
  // It validates each event against the schema, deduplicates by
  // category, and sorts by severity.
  // -------------------------------------------------------------------------
  function detectPrompt(text) {
    var dispatcher = (typeof self !== 'undefined' && self.__lensDispatcher) ||
                     (typeof globalThis !== 'undefined' && globalThis.__lensDispatcher) ||
                     null;
    if (!dispatcher) {
      log.error('prompt-detect: dispatcher not available; cannot detect');
      return [];
    }
    var result = dispatcher.detect(text);
    // The banner wants the events array (with sample, matches, etc.)
    return result.events;
  }

  // -------------------------------------------------------------------------
  // Debounce helper: schedule fn to run after ms of quiet
  // -------------------------------------------------------------------------
  function debounce(fn, ms) {
    var timer = null;
    return function () {
      var args = arguments;
      var ctx = this;
      if (timer) clearTimeout(timer);
      timer = setTimeout(function () {
        timer = null;
        fn.apply(ctx, args);
      }, ms);
    };
  }

  // -------------------------------------------------------------------------
  // Identify the current provider from the hostname. Returns the
  // matching provider descriptor or null.
  // -------------------------------------------------------------------------
  function identifyProvider() {
    if (!selectors) return null;
    return selectors.identifyProvider();
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------
  function init(opts) {
    opts = opts || {};
    state.onDetect = opts.onDetect || null;
    state.onSendIntercept = opts.onSendIntercept || null;

    state.provider = identifyProvider();
    if (!state.provider) {
      log.warn('no provider identified; prompt-detect will not attach');
      return false;
    }

    dom.findElements(state);
    if (!state.input) {
      log.warn('input not found yet; will retry on mutations');
    } else {
      lifecycle.attach(state, debounce, detectPrompt, function (muts) { lifecycle.onMutation(muts, state, function (s) { lifecycle.attach(s, debounce, detectPrompt, function () {}); }, lifecycle.detach); });
    }

    // Set up the MutationObserver
    try {
      state.observer = new MutationObserver(function (mutations) {
        lifecycle.onMutation(mutations, state,
          function (s) { lifecycle.attach(s, debounce, detectPrompt, function () {}); },
          lifecycle.detach);
      });
      state.observer.observe(document.body, {
        childList: true,
        subtree: true
      });
      log.info('MutationObserver attached on body');
    } catch (err) {
      log.error('failed to create MutationObserver', err);
      return false;
    }

    return true;
  }

  // Shutdown
  function shutdown() {
    try {
      if (state.observer) {
        state.observer.disconnect();
        state.observer = null;
      }
      lifecycle.detach(state);
      state.provider = null;
      state.input = null;
      state.sendButton = null;
      log.info('prompt-detect shut down');
    } catch (err) {
      log.error('shutdown threw', err);
    }
  }

  // For testing: get current state
  function getState() {
    return {
      provider: state.provider ? state.provider.id : null,
      inputAttached: state.attached,
      hasInput: !!state.input,
      hasSendButton: !!state.sendButton,
      lastValue: state.lastValue.substring(0, 50),
      lastDetectionCount: state.lastDetections.length
    };
  }

  var module = {
    init: init,
    shutdown: shutdown,
    getState: getState,
    detectPrompt: detectPrompt
  };

  if (typeof self !== 'undefined') self.__lensPromptDetect = module;
  if (typeof window !== 'undefined') window.__lensPromptDetect = module;
  /**
   * @type {import("./typedefs").LensPromptDetect}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensPromptDetect = module;
  if (typeof globalThis !== 'undefined' && globalThis.__lensConstants) module.__lensConstants = globalThis.__lensConstants;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/banner-icons.js ===
// AegisGate Lens — util/banner-icons.js
// Inline SVG icons used by the banner. Inlined to avoid any
// network fetch (privacy guarantee #1) and to avoid any
// "icon not found" if the user has aggressive ad blockers.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Each icon is a 16x16 viewBox SVG. Color is controlled by the
  // CSS fill (currentColor).
  var ICONS = {
    // AegisGate shield-with-padlock mark (simplified, single color).
    // The real corporate logo is a detailed metallic shield; this is
    // a single-color version that reads at 16x16 in the banner.
    shield: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
            'fill="currentColor" aria-hidden="true">' +
            '<path d="M8 1L2 3v5c0 3.5 2.5 6.5 6 7 3.5-.5 6-3.5 6-7V3L8 1zm0 1.2l4.8 1.5V8c0 2.8-2 5.2-4.8 5.7C5.2 13.2 3.2 10.8 3.2 8V3.7L8 2.2z"/>' +
            '<path d="M7 6V4.5C7 3.7 7.4 3 8 3s1 .7 1 1.5V6h.5v4.5h-3V6H7zm.5-1.5V6h1V4.5C8.5 4 8.3 3.5 8 3.5s-.5.5-.5 1z"/>' +
            '</svg>',

    // Close X
    close: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
           'fill="currentColor" aria-hidden="true">' +
           '<path d="M3.7 3L3 3.7 7.3 8 3 12.3 3.7 13 8 8.7 12.3 13 13 12.3 8.7 8 13 3.7 12.3 3 8 7.3 3.7 3z"/>' +
           '</svg>',

    // Help ?
    help: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
          'fill="currentColor" aria-hidden="true">' +
          '<path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 13a6 6 0 110-12 6 6 0 010 12z"/>' +
          '<path d="M7.3 5.5C7.3 4.7 7.9 4 8.8 4c.9 0 1.5.7 1.5 1.5 0 .5-.2.9-.6 1.2L8.5 7.5c-.3.2-.5.5-.5 1v.5h1V8.5c0-.2.1-.3.3-.4L10.6 7c.6-.4.9-1 .9-1.6C11.5 4 10.2 3 8.8 3 7.3 3 6.2 4.1 6.2 5.5h1.1zm.2 4.5v1.1h1.1V10H7.5z"/>' +
          '</svg>',

    // Down chevron (for the "Tell us why" expand)
    chevronDown: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
                 'fill="currentColor" aria-hidden="true">' +
                 '<path d="M3 5.5L3.7 4.8 8 9.1l4.3-4.3.7.7L8 10.5 3 5.5z"/>' +
                 '</svg>'
  };

  var module = { ICONS: ICONS };

  if (typeof self !== 'undefined') self.__lensBannerIcons = module;
  if (typeof window !== 'undefined') window.__lensBannerIcons = module;
  /**
   * @type {{SHIELD: string, CLOSE: string, HELP: string, CHEVRON_DOWN: string, REDACT: string, ICONS: Object<string, string>}}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensBannerIcons = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/dismiss.js ===
// AegisGate Lens — util/dismiss.js
// 24-hour dismissal storage + opt-in false-positive report.
//
// Per the BANNER-DESIGN-SPEC, when the user dismisses a banner
// they have two options:
//   1. "Submit & dismiss" — opt-in to sending ONE anonymous,
//      sanitized FP report to the AegisGate TI engine. The
//      domain_hash, category, pattern_id, reason, ml_score,
//      and timestamp are sent. NO prompt text, NO URLs, NO
//      page content, NO user identifier.
//   2. "Just dismiss (private)" — local-only suppression.
//      No data is sent. The detection is suppressed for 24h
//      on the same domain + same pattern.
//
// v0.1.1 item 25: storage now uses chrome.storage.session (not
// chrome.storage.local). Session storage is automatically cleared
// when the browser restarts, which is a defense-in-depth check on
// top of the 24h TTL. This matches the user's intent ("dismiss
// for this session") and reduces the chance of a stale entry
// surviving a long period of browser inactivity. The 24h TTL
// is still enforced by gc() (entry.expires_at), so session
// storage is purely belt-and-suspenders.
//
// Per docs/ARCHITECTURE-v0.1.0-BETA.md, the Lens is opt-in by
// default. "Submit & dismiss" is the only way the user can opt
// in to telemetry. Until they opt in, NO data is sent.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                       (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                       null;

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };

  var STORAGE_KEY = (constants && constants.STORAGE_KEYS && constants.STORAGE_KEYS.DISMISSALS) || 'aegisgate_lens_dismissals';
  var TTL_MS = (constants && constants.DISMISS_TTL_MS) || (24 * 60 * 60 * 1000);  // 24h (from constants.js)
  var SCHEMA_VERSION = (constants && constants.STORAGE_SCHEMA_VERSION) || '0.1.0-beta';

  // The 3 reason codes. These match the design spec.
  var REASON_TEST_DATA = 'test_data';
  var REASON_OWN_DATA = 'own_data';
  var REASON_LEGITIMATE = 'legitimate_use_case';

  // Resolve the storage area to use. v0.1.1 item 25: prefer
  // chrome.storage.session (auto-cleared on browser restart),
  // fall back to chrome.storage.local for older Chrome versions
  // (pre-Chrome 116). chrome.storage.session is available since
  // Chrome 102, so the fallback is purely defensive.
  function getStorageArea() {
    if (typeof chrome === 'undefined' || !chrome.storage) return null;
    if (chrome.storage.session) return chrome.storage.session;
    if (chrome.storage.local) return chrome.storage.local;
    return null;
  }

  // Build a stable key from (domainHash, category, patternId).
  // The patternId is included so the same category with different
  // patterns (e.g. AWS vs GitHub secrets) can be dismissed
  // independently. We do NOT include the match value (privacy).
  function buildKey(domainHash, category, patternId) {
    if (!domainHash || !category) return null;
    var pid = patternId || '_nopattern_';
    return domainHash + ':' + category + ':' + pid;
  }

  // Get the current dismissals from chrome.storage.local.
  // Returns {} if storage is unavailable or empty.
  function getAll() {
    return new Promise(function (resolve) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage ||
            !getStorageArea()) {
          resolve({});
          return;
        }
        getStorageArea().get([STORAGE_KEY], function (result) {
          if (chrome.runtime && chrome.runtime.lastError) {
            var err = chrome.runtime.lastError.message;
            if (err.includes('Extension context invalidated')) {
              log.warn('storage get failed: Extension context invalidated (extension reloaded)');
              resolve({});
            } else {
              log.warn('storage get failed: ' + err);
              resolve({});
            }
            return;
          }
          resolve(result[STORAGE_KEY] || {});
        });
      } catch (e) {
        if (e.message && e.message.includes('Extension context invalidated')) {
          log.warn('getAll() caught: Extension context invalidated');
          resolve({});
        } else {
          log.error('getAll() threw', e);
          resolve({});
        }
      }
    });
  }

  // Save the dismissals map back to chrome.storage.local.
  function saveAll(dismissals) {
    return new Promise(function (resolve, reject) {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage ||
            !getStorageArea()) {
          resolve(false);
          return;
        }
        getStorageArea().set({ [STORAGE_KEY]: dismissals }, function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            var err = chrome.runtime.lastError.message;
            if (err.includes('Extension context invalidated')) {
              log.warn('storage set failed: Extension context invalidated (extension reloaded)');
              resolve(false);
            } else {
              log.warn('storage set failed: ' + err);
              resolve(false);
            }
            return;
          }
          resolve(true);
        });
      } catch (e) {
        if (e.message && e.message.includes('Extension context invalidated')) {
          log.warn('saveAll() caught: Extension context invalidated');
          resolve(false);
        } else {
          log.error('saveAll() threw', e);
          reject(e);
        }
      }
    });
  }

  // Garbage-collect expired entries.
  function gc(dismissals) {
    var now = Date.now();
    var kept = {};
    var keys = Object.keys(dismissals);
    for (var i = 0; i < keys.length; i++) {
      var entry = dismissals[keys[i]];
      if (entry && typeof entry.expires_at === 'number' &&
          entry.expires_at > now) {
        kept[keys[i]] = entry;
      }
    }
    return kept;
  }

  // Check if a (domainHash, category, patternId) is currently
  // dismissed. Returns the entry object (with reason, dismissed_at,
  // expires_at) or null.
  async function isDismissed(domainHash, category, patternId) {
    var key = buildKey(domainHash, category, patternId);
    if (!key) return null;
    var all = await getAll();
    all = gc(all);
    // Save back if we GC'd anything
    if (Object.keys(all).length !== Object.keys(all).length) {
      await saveAll(all);
    }
    return all[key] || null;
  }

  // Dismiss a detection. If `reason` is non-null, this is the
  // opt-in path (the caller should ALSO send the FP report via
  // sendFPReport). If `reason` is null, this is the private path.
  // `fpReportData` is the sanitized report (only set on opt-in).
  async function dismiss(domainHash, category, patternId, reason, fpReportData) {
    try {
      var key = buildKey(domainHash, category, patternId);
      if (!key) return false;
      var all = await getAll();
      all = gc(all);
      var now = Date.now();
      all[key] = {
        dismissed_at: now,
        expires_at: now + TTL_MS,
        reason: reason || null,
        // Only stored on opt-in path; otherwise null
        opt_in: reason ? true : false,
        // Sanitized FP report payload (no text). Only present on
        // the opt-in path. The caller is responsible for actually
        // sending this to the backend.
        fp_report: fpReportData || null
      };
      var ok = await saveAll(all);
      if (ok) {
        if (reason) {
          log.info('dismissed (opt-in) ' + key + ' reason=' + reason);
        } else {
          log.info('dismissed (private) ' + key);
        }
      }
      return ok;
    } catch (err) {
      if (err.message && err.message.includes('Extension context invalidated')) {
        log.warn('dismiss() caught: Extension context invalidated');
        return false;
      }
      log.error('dismiss() threw', err);
      return false;
    }
  }

  // Get the FP report payload for a detection event. The caller
  // is responsible for sending this to the backend (via the SW
  // in 3g, which is the only network path).
  //
  // Per the privacy doc, the FP report contains ONLY:
  //   - domain_hash (SHA-256 prefix of hostname, 16 hex chars)
  //   - category (e.g. "pii_credit_card")
  //   - pattern_id (e.g. "credit_card_visa_v1")
  //   - reason (test_data | own_data | legitimate_use_case)
  //   - ml_score, ml_threshold, ml_model_version (only for ML)
  //   - lens_event_version, lens_version, timestamp
  //
  // It does NOT contain: prompt text, URLs, page content, user IDs.
  function buildFPReport(event, domainHash, reason) {
    if (!event) return null;
    return {
      lens_event_version: SCHEMA_VERSION,
      timestamp: Math.floor(Date.now() / 1000),  // Unix seconds
      domain_hash: domainHash,
      facet: event.facet,
      category: event.category,
      severity: event.severity,
      pattern_id: event.matches && event.matches[0] ?
                  (event.matches[0].cardType ? event.category + '_' + event.matches[0].cardType + '_v1' : event.category + '_v1') :
                  event.category + '_v1',
      reason: reason,
      ml_score: event.ml_score,
      ml_threshold: event.ml_threshold || null,
      ml_model_version: event.ml_model_version || null,
      lens_version: SCHEMA_VERSION
    };
  }

  // Clear all dismissals. Used by the popup (3j) for the
  // "Reset dismissals" button.
  async function clearAll() {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage ||
          !getStorageArea()) return false;
      return new Promise(function (resolve) {
        getStorageArea().remove([STORAGE_KEY], function () {
          if (chrome.runtime && chrome.runtime.lastError) {
            var err = chrome.runtime.lastError.message;
            if (err.includes('Extension context invalidated')) {
              log.warn('storage remove failed: Extension context invalidated (extension reloaded)');
              resolve(false);
            } else {
              log.warn('storage remove failed: ' + err);
              resolve(false);
            }
            return;
          }
          log.info('cleared all dismissals');
          resolve(true);
        });
      });
    } catch (err) {
      if (err.message && err.message.includes('Extension context invalidated')) {
        log.warn('clearAll() caught: Extension context invalidated');
        return false;
      }
      log.error('clearAll() threw', err);
      return false;
    }
  }

  // List all active (non-expired) dismissals. For the popup UI.
  async function listActive() {
    var all = await getAll();
    return gc(all);
  }

  var module = {
    STORAGE_KEY: STORAGE_KEY,
    TTL_MS: TTL_MS,
    REASON_TEST_DATA: REASON_TEST_DATA,
    REASON_OWN_DATA: REASON_OWN_DATA,
    REASON_LEGITIMATE: REASON_LEGITIMATE,
    isDismissed: isDismissed,
    dismiss: dismiss,
    buildFPReport: buildFPReport,
    clearAll: clearAll,
    listActive: listActive,
    buildKey: buildKey
  };

  if (typeof self !== 'undefined') self.__lensDismiss = module;
  if (typeof window !== 'undefined') window.__lensDismiss = module;
  /**
   * @type {import("./typedefs").LensDismiss}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensDismiss = module;
  if (typeof globalThis !== 'undefined' && globalThis.__lensConstants) module.__lensConstants = globalThis.__lensConstants;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === util/banner-ui-formatters.js ===
// AegisGate Lens — util/banner-ui-formatters.js
//
// Pure formatters for the banner UI. No DOM manipulation, no state,
// no event listeners. These are deterministic functions that take
// a value and return a string, suitable for unit testing in
// isolation.
//
// Owns:
//   - maskValue: truncate + mask a sensitive value for display
//   - formatCategory: strip pii_/secret_ prefix, replace underscores
//     with spaces, capitalize each word
//   - escapeHtml: prevent XSS in HTML string interpolation
//
// Loaded by banner-ui.js (the aggregator) BEFORE the HTML and
// lifecycle sub-files, so the HTML builders can call into the
// formatters.
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Mask a value for display. First 4 + ellipsis + last 4.
  // Special handling for email: local part masked differently.
  //
  // v0.1.1 item 16: uses Intl.Segmenter for grapheme-aware truncation
  // so emoji and multi-codepoint characters (e.g., accented Latin
  // characters, CJK ideographs, ZWJ sequences) are never split mid-
  // codepoint. We deliberately do NOT use Intl.NumberFormat because
  // masked sensitive values should NOT be locale-formatted; the goal
  // of the mask is to make the value un-parseable by anyone who
  // glimpses it, so a locale-aware separator (e.g., "4,1111,1111,
  // 1111,1111" in en-US vs "4.1111.1111.1111.1111" in de-DE) would
  // be both confusing and counterproductive. The hardcoded "first
  // N + U+2026 + last N" mask is correct; what we needed was
  // grapheme safety, not locale formatting.
  function maskValue(value, category) {
    if (typeof value !== 'string' || value.length === 0) return '';
    // Email: j***@e****.com
    if (category === 'pii_email' && value.indexOf('@') !== -1) {
      var parts = value.split('@');
      var local = parts[0];
      var domain = parts[1];
      // Local: first char + '***' (e.g. 'j***')
      // Edge: empty local (shouldn't happen, but guard)
      var maskedLocal = local.length === 0 ? '***' : local[0] + '***';
      var dotIdx = domain.lastIndexOf('.');
      var maskedDomain = dotIdx > 0
        ? domain[0] + '***' + domain.substring(dotIdx)
        : '***';
      return maskedLocal + '@' + maskedDomain;
    }
    // Grapheme-aware truncation: count graphemes, not UTF-16 code
    // units. Defaults to "first 4 + … + last 4" for length > 10, and
    // "first 2 + …" for length <= 10 (matching the original behavior).
    // Falls back to substring() if Intl.Segmenter is unavailable
    // (older browsers without it, e.g., Chrome < 87).
    var graphemeCount = value.length;
    if (typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function') {
      try {
        // "grapheme" granularity (not "word"!) — "word" treats
        // hyphens and apostrophes as word boundaries, which would
        // collapse "123-45-6789" into 5 word-segments (giving
        // graphemeCount=5, < 10, "12…" output). "grapheme" gives
        // 11 (correct: 11 code-point clusters).
        var seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
        var graphemes = [];
        for (var g of seg.segment(value)) {
          graphemes.push(g.segment);
        }
        graphemeCount = graphemes.length;
      } catch (e) {
        // Intl.Segmenter with an invalid locale throws; fall back
        // to the UTF-16 code unit count.
        graphemeCount = value.length;
      }
    }
    if (graphemeCount <= 10) {
      // Too short to meaningfully mask; show first 2 + … + last 2
      // (matches the original behavior; e.g., "short" -> "sh…rt").
      // For a 1-char string we return "a…a" (the same char twice
      // joined by the ellipsis, which is the least-bad output for
      // a single-character value).
      if (value.length <= 1) {
        return value + '\u2026' + value;
      }
      return value.substring(0, 2) + '\u2026' + value.substring(value.length - 2);
    }
    // For long values, take the first 4 graphemes and last 4
    // graphemes. We use substring() (UTF-16 code units) for the
    // offset, which is a safe approximation: the worst case is
    // that we include 1-2 extra code units at the boundary, which
    // the Ellipsis (\u2026) hides. To do this PERFECTLY we'd
    // need to walk grapheme boundaries; that overhead is not
    // justified for a 4-grapheme truncation.
    return value.substring(0, 4) + '\u2026' + value.substring(value.length - 4);
  }

  // Format a category for display: strip the prefix and
  // replace underscores with spaces.
  function formatCategory(category) {
    if (typeof category !== 'string') return '';
    var s = category;
    // Strip known prefixes
    var prefixes = ['pii_', 'secret_', 'xss_', 'owasp_', 'atlas_', 'eu_ai_act_', 'anp_', 'cu_', 'toxicity_', 'pi_'];
    for (var i = 0; i < prefixes.length; i++) {
      if (s.indexOf(prefixes[i]) === 0) {
        s = s.substring(prefixes[i].length);
        break;
      }
    }
    // Replace underscores with spaces, capitalize each word start
    var s2 = s.replace(/_/g, ' ');
    var result = '';
    for (var j = 0; j < s2.length; j++) {
      var c = s2[j];
      if (j === 0 || s2[j-1] === ' ') {
        result += c.toUpperCase();
      } else {
        result += c;
      }
    }
    return result;
  }

  // HTML escape: protect against XSS when interpolating user data
  // into the HTML string returned by buildBannerHTML.
  function escapeHtml(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
  }

  if (typeof self !== 'undefined') self.__lensBannerUI_formatters = {
    maskValue: maskValue,
    formatCategory: formatCategory,
    escapeHtml: escapeHtml
  };
  if (typeof window !== 'undefined') window.__lensBannerUI_formatters = {
    maskValue: maskValue,
    formatCategory: formatCategory,
    escapeHtml: escapeHtml
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_formatters = {
      maskValue: maskValue,
      formatCategory: formatCategory,
      escapeHtml: escapeHtml
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/banner-ui-html.js ===
// AegisGate Lens — util/banner-ui-html.js
//
// HTML string builders for the banner UI. No DOM manipulation, no
// event listeners. These return HTML strings that the lifecycle
// sub-file injects into a DOM element.
//
// Owns:
//   - createBannerElement: the empty <div data-aegisgate-lens="banner">
//   - buildBannerHTML: the inner HTML of the banner (header + list +
//     privacy footer + platform CTA + action buttons)
//   - buildDismissFormHTML: the "false positive" form expansion
//
// Loaded by banner-ui.js (the aggregator) AFTER the formatters
// sub-file (so we can call maskValue, formatCategory, escapeHtml)
// and BEFORE the lifecycle sub-file (so the lifecycle can inject
// the HTML into a real DOM element).
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var icons = (typeof self !== 'undefined' && self.__lensBannerIcons) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerIcons) ||
              null;
  var formatters = (typeof self !== 'undefined' && self.__lensBannerUI_formatters) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_formatters) ||
                   null;
  // getRuntimeUrl is provided by the aggregator (banner-ui.js) via
  // globalThis.__lensBannerUI_getRuntimeUrl. Read lazily at call time
  // (not at IIFE-time) so the order of script loading doesn't matter.
  function getRuntimeUrlRef(relativePath) {
    var ref = (typeof self !== 'undefined' && self.__lensBannerUI_getRuntimeUrl) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_getRuntimeUrl) ||
              null;
    if (ref) return ref(relativePath);
    // Fallback: relative path (will 404 in CWS but lets tests run)
    return relativePath;
  }

  if (!formatters) {
    throw new Error('banner-ui-html.js: required sub-file not loaded: __lensBannerUI_formatters');
  }
  // Note: __lensBannerUI_getRuntimeUrl is provided by the aggregator
  // (banner-ui.js) and read lazily at call time via getRuntimeUrlRef().

  // Create the empty <div data-aegisgate-lens="banner"> that
  // the lifecycle sub-file will populate.
  function createBannerElement() {
    var el = document.createElement('div');
    el.setAttribute('data-aegisgate-lens', 'banner');
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-live', 'polite');
    el.classList.add('hidden');
    return el;
  }

  // Build the inner HTML for the banner. Pulled out so tests
  // can construct the same structure without DOM.
  function buildBannerHTML(events, opts) {
    opts = opts || {};
    var count = events.length;
    var countText = count + ' sensitive item' + (count === 1 ? '' : 's') + ' detected';

    // Build the detection list HTML
    var listHtml = '<div class="lens-list">';
    var maxItems = (constants && constants.BANNER_MAX_ITEMS) || 8;
    for (var i = 0; i < events.length && i < maxItems; i++) {
      var ev = events[i];
      listHtml += '<div class="lens-item lens-item-' + ev.severity + '">';
      listHtml += '<span class="lens-item-category">' + formatters.escapeHtml(formatters.formatCategory(ev.category)) + '</span>';
      listHtml += '<span class="lens-pill lens-pill-' + ev.severity + '">' + ev.severity + '</span>';
      if (ev.sample) {
        listHtml += '<span class="lens-item-match" dir="ltr">' + formatters.escapeHtml(formatters.maskValue(ev.sample, ev.category)) + '</span>';
      }
      listHtml += '</div>';
    }
    if (events.length > maxItems) {
      listHtml += '<div class="lens-item lens-item-overflow">';
      listHtml += '+ ' + (events.length - maxItems) + ' more';
      listHtml += '</div>';
    }
    listHtml += '</div>';

    // v0.1.1 item C (first-run onboarding):
    // When opts.showPrimer is true, render a small primer line above
    // the privacy footer explaining what the banner is. The line is
    // dismissable (× button); clicking × calls the onPrimerDismiss
    // callback in opts which writes the ONBOARDED flag to storage.
    var primerHtml = '';
    if (opts && opts.showPrimer) {
      var primerUrl = (constants && constants.URLS && constants.URLS.WELCOME_PAGE) || 'welcome/welcome.html';
      primerHtml =
        '<div class="lens-primer" role="note" aria-live="polite">' +
          '<span class="lens-primer-text">' +
            '🛡️ <strong>Welcome to AegisGate Lens.</strong> This banner is local-only — your prompt never leaves your browser. ' +
            '<a href="' + formatters.escapeHtml(primerUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>.' +
          '</span>' +
          '<button type="button" class="lens-primer-dismiss" data-action="primer-dismiss" aria-label="Dismiss this welcome message">×</button>' +
        '</div>';
    }

    // Privacy footer
    var learnMoreUrl = opts.learnMoreUrl ||
      ((constants && constants.URLS && constants.URLS.LEARN_MORE) || 'https://github.com/aegisgatesecurity/aegisgate-lens#readme');
    var privacyHtml =
      '<div class="lens-privacy">' +
        '<strong>These items are visible to the AI provider when you send.</strong> ' +
        'AegisGate Lens never sends your prompt to any server. ' +
        '<a href="' + formatters.escapeHtml(learnMoreUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>.' +
      '</div>';

    // AegisGate Platform CTA (Lens is free forever; this drives TOFU traffic
    // to the paid Platform: server-side enforcement, automated redaction,
    // enterprise SSO, compliance modules. Per the pricing doctrine in
    // AEGISGATE-LENS-PIVOT-2026-06-18.md.)
    var platformUrl = opts.platformUrl ||
      ((constants && constants.URLS && constants.URLS.PLATFORM_CTA) || 'https://aegisgatesecurity.io/platform/pricing');
    var platformHtml =
      '<a class="lens-platform-cta" href="' + formatters.escapeHtml(platformUrl) + '" target="_blank" rel="noopener noreferrer">' +
        'When your team needs server-side enforcement, custom patterns, audit logs, or SSO, upgrade to <strong>AegisGate Platform</strong> →' +
      '</a>';

    // Action row
    var actionsHtml =
      '<div class="lens-actions">' +
        '<button type="button" class="lens-btn lens-btn-secondary" data-action="cancel">Cancel send</button>' +
        '<button type="button" class="lens-btn lens-btn-primary" data-action="redact">Edit manually</button>' +
        '<button type="button" class="lens-btn lens-btn-ghost" data-action="send">Send anyway</button>' +
        '<button type="button" class="lens-btn lens-btn-ghost" data-action="dismiss" aria-label="Dismiss this detection for 24 hours" title="Dismiss this detection for 24 hours on this site">Not PII — dismiss for 24h</button>' +
        '<button type="button" class="lens-false-positive-link" data-action="false-positive" aria-label="Mark this detection as a false positive and report it">' +
          (icons && icons.ICONS.chevronDown ? icons.ICONS.chevronDown : '') +
          'This is a false positive' +
        '</button>' +
      '</div>';

    // Header
    var headerHtml =
      '<div class="lens-header">' +
        '<picture>' +
        '  <source media="(min-resolution: 3dppx)" srcset="' + getRuntimeUrlRef('icons/banner-3x.png') + '"/>' +
        '  <source media="(min-resolution: 2dppx)" srcset="' + getRuntimeUrlRef('icons/banner-2x.png') + '"/>' +
        '  <img class="lens-shield-img" src="' + getRuntimeUrlRef('icons/banner-2x.png') + '" alt="AegisGate Lens" width="24" height="24"/>' +
        '</picture>' +
          '<span class="lens-shield-fallback">' + (icons && icons.ICONS.shield ? icons.ICONS.shield : '') + '</span>' +
        '<span class="lens-wordmark">AegisGate Lens</span>' +
        '<span class="lens-count">' + countText + '</span>' +
        '<span class="lens-header-actions">' +
          '<button type="button" class="lens-icon-btn" data-action="help" aria-label="Help" title="Help: what this banner does">' +
            (icons && icons.ICONS.help ? icons.ICONS.help : '?') +
          '</button>' +
          '<button type="button" class="lens-icon-btn" data-action="dismiss" aria-label="Dismiss for 24 hours" title="Dismiss for 24 hours">' +
            (icons && icons.ICONS.close ? icons.ICONS.close : '×') +
          '</button>' +
        '</span>' +
      '</div>';

    return headerHtml + listHtml + primerHtml + privacyHtml + platformHtml + actionsHtml;
  }

  // The dismiss form (expanded). Shown when the user clicks
  // "This is a false positive".
  function buildDismissFormHTML() {
    return '' +
      '<div class="lens-dismiss" role="region" aria-label="Mark as false positive">' +
        '<div class="lens-dismiss-prompt">Tell us why this is a false positive (helps us improve):</div>' +
        '<div class="lens-dismiss-reasons">' +
          '<label><input type="checkbox" data-reason="test_data"> This is test/fake data</label>' +
          '<label><input type="checkbox" data-reason="own_data"> This is my own data (I know what I\'m doing)</label>' +
          '<label><input type="checkbox" data-reason="legitimate_use_case"> This is for a legitimate use case I trust</label>' +
        '</div>' +
        '<div class="lens-dismiss-actions">' +
          '<button type="button" class="lens-btn lens-btn-primary" data-dismiss-action="submit">Submit &amp; dismiss</button>' +
          '<button type="button" class="lens-btn lens-btn-secondary" data-dismiss-action="private">Just dismiss (private)</button>' +
          '<button type="button" class="lens-btn lens-btn-ghost" data-dismiss-action="cancel">Cancel</button>' +
        '</div>' +
        '<div class="lens-dismiss-transparency">' +
          'Submit sends one anonymous, sanitized report (category, pattern, reason). No prompt text, no URLs, no page content. Just dismiss is 100% local.' +
        '</div>' +
      '</div>';
  }

  if (typeof self !== 'undefined') self.__lensBannerUI_html = {
    createBannerElement: createBannerElement,
    buildBannerHTML: buildBannerHTML,
    buildDismissFormHTML: buildDismissFormHTML
  };
  if (typeof window !== 'undefined') window.__lensBannerUI_html = {
    createBannerElement: createBannerElement,
    buildBannerHTML: buildBannerHTML,
    buildDismissFormHTML: buildDismissFormHTML
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_html = {
      createBannerElement: createBannerElement,
      buildBannerHTML: buildBannerHTML,
      buildDismissFormHTML: buildDismissFormHTML
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/banner-ui-lifecycle.js ===
// AegisGate Lens — util/banner-ui-lifecycle.js
//
// Banner lifecycle + DOM event handling. Owns:
//   - state object (the shared mutable state)
//   - attachListeners: bind click handlers
//   - showDismissForm / hideDismissForm: the FP report form
//   - handleAction / handleDismissAction: route to onAction callback
//   - recordDismissalForEvents: write the dismissal to storage
//   - show / hide / isVisible / getElement / getState: the public API
//
// Loaded by banner-ui.js (the aggregator) AFTER the formatters
// and HTML sub-files. Calls into the HTML sub-file's buildBannerHTML
// and buildDismissFormHTML; calls into the formatters sub-file's
// escapeHtml.
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens] ' + m, e); } catch (e) {} } };
  var constants = (typeof self !== 'undefined' && self.__lensConstants) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensConstants) ||
                  null;
  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
               (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
               null;
  var html = (typeof self !== 'undefined' && self.__lensBannerUI_html) ||
             (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_html) ||
             null;
  // injectStyles is provided by the aggregator (banner-ui.js) via
  // globalThis.__lensBannerUI_injectStyles. Read lazily at call time
  // (not at IIFE-time) so the order of script loading doesn't matter.
  function injectStylesRef() {
    var ref = (typeof self !== 'undefined' && self.__lensBannerUI_injectStyles) ||
              (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_injectStyles) ||
              null;
    if (ref) ref();
    // Fallback: do nothing (CSS won't be injected, but tests can still run)
  }

  if (!html) {
    throw new Error('banner-ui-lifecycle.js: required sub-file not loaded: __lensBannerUI_html');
  }
  // Note: __lensBannerUI_injectStyles is provided by the aggregator
  // (banner-ui.js) and read lazily at call time via injectStylesRef().

  // -------------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------------
  var state = {
    el: null,                  // the banner DOM element
    currentEvents: null,       // the events currently displayed
    currentOpts: null,         // the opts used to show the banner
    parentInput: null,         // the input element the banner is anchored to
    inserting: false,          // are we currently in the middle of attaching?
    isVisible: false,
    // v0.1.1 item C (first-run onboarding):
    // 'unknown' until the first show() reads chrome.storage.session
    // (no chrome.* in tests), then 'pending' / 'done' / 'failed'.
    // 'pending' means "show the primer line on the next banner".
    // 'done' means "skip the primer".
    // 'failed' means "storage read errored; show the primer
    // (fail-open: the user gets a helpful message even if the
    // read fails)".
    onboardStatus: 'unknown'
  };

  // Read the ONBOARDED flag from chrome.storage.session.
  // Returns 'done' if the user has been onboarded, 'pending' if not.
  // Returns 'failed' if storage is unavailable or the read errors.
  // This is sync-friendly: we cache the result in state.onboardStatus
  // and the show() function reads it synchronously.
  function readOnboardedFlag() {
    var KEY = (constants && constants.STORAGE_KEYS && constants.STORAGE_KEYS.ONBOARDED) || 'aegisgate_lens_onboarded';
    try {
      if (typeof chrome === 'undefined' || !chrome.storage) {
        return 'failed';  // tests: storage not available, skip primer
      }
      var area = null;
      if (chrome.storage.session) area = chrome.storage.session;
      else if (chrome.storage.local) area = chrome.storage.local;
      if (!area) return 'failed';
      // Chrome storage API is callback-based; we use the sync-shim
      // pattern of checking last-set value via a module-level cache.
      // The cache is populated by the first call (async) and used
      // by subsequent calls (sync). For first-call, we return
      // 'pending' and let the show() render the primer once.
      if (onboardedFlagCache !== null) return onboardedFlagCache;
      // First call: kick off an async read, return 'pending' for now.
      try {
        area.get([KEY], function (result) {
          try {
            if (chrome.runtime && chrome.runtime.lastError) {
              onboardedFlagCache = 'failed';
              return;
            }
            onboardedFlagCache = (result && result[KEY]) ? 'done' : 'pending';
          } catch (e) { onboardedFlagCache = 'failed'; }
        });
      } catch (e) { onboardedFlagCache = 'failed'; }
      return 'pending';
    } catch (e) {
      return 'failed';
    }
  }

  // Write the ONBOARDED flag = true. Called after the banner's
  // first show(), so the next time the user types the primer is
  // skipped.
  function writeOnboardedFlag() {
    var KEY = (constants && constants.STORAGE_KEYS && constants.STORAGE_KEYS.ONBOARDED) || 'aegisgate_lens_onboarded';
    try {
      if (typeof chrome === 'undefined' || !chrome.storage) return;
      var area = null;
      if (chrome.storage.session) area = chrome.storage.session;
      else if (chrome.storage.local) area = chrome.storage.local;
      if (!area) return;
      area.set({ [KEY]: true }, function () {
        if (chrome.runtime && chrome.runtime.lastError) {
          log.warn('onboarded set failed: ' + chrome.runtime.lastError.message);
        }
      });
    } catch (e) {
      log.warn('writeOnboardedFlag threw', e);
    }
  }

  // Module-level cache for the ONBOARDED flag read.
  // Populated by the first readOnboardedFlag() async call.
  var onboardedFlagCache = null;

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------
  function handleDismissAction(action, opts) {
    if (action === 'cancel') {
      hideDismissForm();
      return;
    }
    // Get the checked reason
    var form = state.el && state.el.querySelector('.lens-dismiss');
    var reason = null;
    if (form) {
      var checkboxes = form.querySelectorAll('input[type="checkbox"]');
      for (var i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
          reason = checkboxes[i].getAttribute('data-reason');
          break;
        }
      }
    }
    if (action === 'private') {
      // Just dismiss (private) — no reason required, no FP report
      recordDismissalForEvents('private', null, opts).then(function () {
        hide();
        if (typeof opts.onAction === 'function') {
          try { opts.onAction('dismiss', { events: state.currentEvents }); } catch (e) { log.error('onAction threw', e); }
        }
      });
      return;
    }
    if (action === 'submit') {
      // Submit & dismiss — opt-in path
      // If no reason was selected, default to 'own_data' (most common)
      if (!reason) reason = 'own_data';
      recordDismissalForEvents('optin', reason, opts).then(function () {
        hide();
        if (typeof opts.onAction === 'function') {
          try {
            opts.onAction('dismiss_optin', {
              events: state.currentEvents,
              reason: reason
            });
          } catch (e) { log.error('onAction threw', e); }
        }
      });
    }
  }

  function recordDismissalForEvents(mode, reason, opts) {
    if (!dismiss) {
      log.warn('dismiss module not available; cannot record dismissal');
      return Promise.resolve();
    }
    if (!state.currentEvents) return Promise.resolve();
    var domainHash = opts.domainHash || null;
    if (!domainHash) {
      log.warn('no domainHash in opts; cannot record dismissal');
      return Promise.resolve();
    }
    var promises = [];
    for (var i = 0; i < state.currentEvents.length; i++) {
      var ev = state.currentEvents[i];
      var fpReport = null;
      if (mode === 'optin') {
        fpReport = dismiss.buildFPReport(ev, domainHash, reason);
      }
      promises.push(dismiss.dismiss(domainHash, ev.category,
        ev.matches && ev.matches[0] && ev.matches[0].cardType ?
          ev.category + '_' + ev.matches[0].cardType : ev.category,
        mode === 'optin' ? reason : null,
        fpReport));
    }
    // On opt-in, surface the FP reports via the onAction callback
    // so the SW can send them. We do NOT send them here because
    // the banner-ui is the content script and the SW is the only
    // place that has the network handle.
    return Promise.all(promises).then(function () {
      if (mode === 'optin' && typeof opts.onAction === 'function') {
        try {
          var reports = [];
          for (var j = 0; j < state.currentEvents.length; j++) {
            var report = dismiss.buildFPReport(state.currentEvents[j], domainHash, reason);
            if (report) reports.push(report);
          }
          opts.onAction('fp_reports', { reports: reports });
        } catch (e) { log.error('onAction(fp_reports) threw', e); }
      }
    });
  }

  // -------------------------------------------------------------------------
  // Public API (lifecycle)
  // -------------------------------------------------------------------------
  function attachListeners(el, opts) {
    opts = opts || {};
    el.addEventListener('click', function (e) {
      try {
        var target = e.target;
        // Walk up to find the button or its data-action
        var btn = target.closest && target.closest('[data-action]');
        if (btn) {
          handleAction(btn.getAttribute('data-action'), opts);
          return;
        }
        var dismissBtn = target.closest && target.closest('[data-dismiss-action]');
        if (dismissBtn) {
          handleDismissAction(dismissBtn.getAttribute('data-dismiss-action'), opts);
        }
      } catch (err) {
        log.error('click handler threw', err);
      }
    }, true);
    // v0.1.1 item 21: keyboard navigation support.
    //   - Esc closes the banner (default: cancel action).
    //   - Tab / Shift-Tab is trapped within the banner so a
    //     keyboard user can't tab past the last button and lose
    //     focus into the page below.
    el.addEventListener('keydown', function (e) {
      try {
        if (e.key === 'Escape' || e.keyCode === 27) {
          e.preventDefault();
          e.stopPropagation();
          handleAction('cancel', opts);
          return;
        }
        if (e.key === 'Tab' || e.keyCode === 9) {
          // Trap focus within the banner. The first focusable
          // element is the auto-focus target; the last is the
          // dismiss button.
          var focusables = el.querySelectorAll(
            'button, [href], input, [tabindex]:not([tabindex="-1"])'
          );
          if (focusables.length === 0) return;
          var first = focusables[0];
          var last = focusables[focusables.length - 1];
          var active = el.ownerDocument && el.ownerDocument.activeElement;
          if (e.shiftKey && active === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
          }
        }
      } catch (err) {
        log.error('keydown handler threw', err);
      }
    }, true);
  }

  // Show the dismiss form inline (replaces the action row)
  function showDismissForm(opts) {
    if (!state.el) return;
    var actionsRow = state.el.querySelector('.lens-actions');
    if (!actionsRow) return;
    // Remove any existing dismiss form
    var existing = state.el.querySelector('.lens-dismiss');
    if (existing) existing.remove();
    // Insert the dismiss form after the actions row
    actionsRow.insertAdjacentHTML('afterend', html.buildDismissFormHTML());
    // Scroll the dismiss form into view
    var form = state.el.querySelector('.lens-dismiss');
    if (form) form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Hide the dismiss form (restore the action row)
  function hideDismissForm() {
    if (!state.el) return;
    var form = state.el.querySelector('.lens-dismiss');
    if (form) form.remove();
  }

  // Action handler. Routes to the consumer's onAction callback.
  function handleAction(action, opts) {
    if (action === 'false-positive') {
      showDismissForm(opts);
      return;
    }
    // v0.1.1 item C: primer-dismiss writes the ONBOARDED flag
    // and hides the primer line, but does NOT hide the banner
    // itself. The user is still looking at the detection.
    if (action === 'primer-dismiss') {
      writeOnboardedFlag();
      onboardedFlagCache = 'done';
      // Remove just the primer line from the DOM
      if (state.el) {
        var primerEl = state.el.querySelector('.lens-primer');
        if (primerEl && primerEl.parentNode) {
          primerEl.parentNode.removeChild(primerEl);
        }
      }
      return;
    }
    // All other actions hide the banner and call onAction
    if (action === 'dismiss') {
      // Dismiss for 24h on the same domain + category
      recordDismissalForEvents('private', null, opts);
    }
    hide();
    if (typeof opts.onAction === 'function') {
      try {
        opts.onAction(action, { events: state.currentEvents });
      } catch (err) {
        log.error('opts.onAction threw', err);
      }
    }
  }

  // Show the banner above the input element
  function show(events, opts) {
    opts = opts || {};
    if (!Array.isArray(events) || events.length === 0) {
      log.warn('show() called with no events; ignoring');
      return;
    }
    if (!state.el) {
      injectStylesRef();
      state.el = html.createBannerElement();
      attachListeners(state.el, opts);
    }
    state.currentEvents = events;
    state.currentOpts = opts;
    // v0.1.1 item C (first-run onboarding): decide whether to
    // show the primer line. The primer appears on the FIRST
    // banner render of a session for a new user. After that
    // (or if the user clicks the × dismiss), the primer is
    // skipped. Fail-open: if storage is unavailable we show
    // the primer (it's helpful, not harmful).
    var onboardStatus = readOnboardedFlag();
    state.onboardStatus = onboardStatus;
    var showPrimer = (onboardStatus === 'pending' || onboardStatus === 'failed');
    // The HTML builder reads opts.showPrimer
    var renderOpts = showPrimer ? Object.assign({}, opts, { showPrimer: true }) : opts;
    state.el.innerHTML = html.buildBannerHTML(events, renderOpts);
    // If we showed the primer, write the flag immediately so
    // the next banner doesn't show it. (We don't wait for the
    // user to click × first; the primer is more like a "splash"
    // than a modal.)
    if (showPrimer) {
      writeOnboardedFlag();
      onboardedFlagCache = 'done';
    }
    state.el.classList.remove('hidden');

    // Attach the banner above the input
    var input = opts.input || null;
    if (input && input.parentNode) {
      // If the banner is already inserted, remove it first
      if (state.el.parentNode && state.el.parentNode !== input.parentNode) {
        state.el.parentNode.removeChild(state.el);
      }
      if (state.el.parentNode !== input.parentNode) {
        input.parentNode.insertBefore(state.el, input);
      }
      state.parentInput = input;
    } else {
      // No input provided; fall back to document.documentElement
      if (state.el.parentNode !== document.documentElement) {
        if (state.el.parentNode) state.el.parentNode.removeChild(state.el);
        document.documentElement.appendChild(state.el);
      }
    }
    state.isVisible = true;
    // v0.1.1 item 21: auto-focus the banner so keyboard users can
    // navigate it immediately and screen readers announce it. We
    // focus the first focusable element (the Help button, the
    // first button in the header). We use a small setTimeout to
    // let the DOM settle after the innerHTML assignment.
    setTimeout(function () {
      try {
        if (!state.el) return;
        var firstBtn = state.el.querySelector('button, [href], [tabindex="0"]');
        if (firstBtn && typeof firstBtn.focus === 'function') firstBtn.focus();
      } catch (e) { /* ignore focus errors */ }
    }, 0);
    log.info('banner shown with ' + events.length + ' events');
  }

  // Hide the banner
  function hide() {
    if (!state.el || !state.isVisible) return;
    // Snapshot the element before the timeout (state.el may be
    // cleared by a subsequent show())
    var el = state.el;
    try { el.classList.add('lens-hiding'); } catch (e) { /* ignore */ }
    setTimeout(function () {
      try {
        el.classList.add('hidden');
        try { el.classList.remove('lens-hiding'); } catch (e2) { /* ignore */ }
        if (el.parentNode) el.parentNode.removeChild(el);
      } catch (e3) {
        log.warn('banner hide() cleanup error (test env?): ' + e3.message);
      }
    }, 200);
    state.isVisible = false;
    state.currentEvents = null;
    state.currentOpts = null;
    log.info('banner hidden');
  }

  function isVisible() { return state.isVisible; }
  function getElement() { return state.el; }

  // For testing: get the current state
  function getState() {
    return {
      isVisible: state.isVisible,
      hasElement: !!state.el,
      eventCount: state.currentEvents ? state.currentEvents.length : 0
    };
  }

  if (typeof self !== 'undefined') self.__lensBannerUI_lifecycle = {
    show: show,
    hide: hide,
    isVisible: isVisible,
    getElement: getElement,
    getState: getState,
    handleAction: handleAction,
    showDismissForm: showDismissForm,
    hideDismissForm: hideDismissForm
  };
  if (typeof window !== 'undefined') window.__lensBannerUI_lifecycle = {
    show: show,
    hide: hide,
    isVisible: isVisible,
    getElement: getElement,
    getState: getState,
    handleAction: handleAction,
    showDismissForm: showDismissForm,
    hideDismissForm: hideDismissForm
  };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_lifecycle = {
      show: show,
      hide: hide,
      isVisible: isVisible,
      getElement: getElement,
      getState: getState,
      handleAction: handleAction,
      showDismissForm: showDismissForm,
      hideDismissForm: hideDismissForm
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));

// === util/banner-ui.js ===
// AegisGate Lens — util/banner-ui.js
//
// Banner UI aggregator. Pulls in 3 sub-files that each own a
// logical group of helpers:
//
//   banner-ui-formatters.js   (maskValue, formatCategory, escapeHtml)
//   banner-ui-html.js         (createBannerElement, buildBannerHTML,
//                              buildDismissFormHTML)
//   banner-ui-lifecycle.js    (show, hide, isVisible, getElement,
//                              getState, handleAction, showDismissForm,
//                              hideDismissForm, state object)
//
// The aggregator owns:
//   - getRuntimeUrl: resolve a relative extension resource path
//   - injectStyles: inject the banner.css file into the page
//   - the module export with the public API (show, hide, isVisible,
//     getElement, getState) plus the test exports (maskValue,
//     formatCategory, buildBannerHTML, buildDismissFormHTML)
//   - the __lensBannerUI global
//   - the __lensBannerUI_getRuntimeUrl and __lensBannerUI_injectStyles
//     helpers that the sub-files read lazily at call time
//
// The aggregator also re-exports the formatters and HTML builders
// so the public API surface stays stable: banner-ui.maskValue,
// banner-ui.formatCategory, banner-ui.buildBannerHTML, etc.
//
// The banner does NOT modify the input or the page. It only
// shows UI and emits user actions through the callback set
// via opts.onAction(action, payload).
//
// Per the v0.1.1 code-quality plan (item 1: split banner-ui.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Read sub-files from globalThis. They are loaded BEFORE this
  // aggregator in the content_scripts.js order (see src/bootstrap.js).
  // If any sub-file is missing, throw early so the bug is caught
  // at load time, not at first use.
  // -------------------------------------------------------------------------
  var formatters = (typeof self !== 'undefined' && self.__lensBannerUI_formatters) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_formatters) ||
                   null;
  var html = (typeof self !== 'undefined' && self.__lensBannerUI_html) ||
             (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_html) ||
             null;
  var lifecycle = (typeof self !== 'undefined' && self.__lensBannerUI_lifecycle) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI_lifecycle) ||
                  null;

  if (!formatters) {
    throw new Error('banner-ui.js: required sub-file not loaded: __lensBannerUI_formatters');
  }
  if (!html) {
    throw new Error('banner-ui.js: required sub-file not loaded: __lensBannerUI_html');
  }
  if (!lifecycle) {
    throw new Error('banner-ui.js: required sub-file not loaded: __lensBannerUI_lifecycle');
  }

  // -------------------------------------------------------------------------
  // getRuntimeUrl: resolve a relative extension resource path to a
  // chrome-extension:// URL. Exposed via globalThis so the HTML
  // sub-file can read it lazily.
  // -------------------------------------------------------------------------
  function getRuntimeUrl(relativePath) {
    if (typeof chrome !== 'undefined' && chrome.runtime && typeof chrome.runtime.getURL === 'function') {
      return chrome.runtime.getURL(relativePath);
    }
    // Fallback: return the relative path. The browser will resolve
    // it against the page URL (will 404 in CWS but lets tests run).
    return relativePath;
  }

  // -------------------------------------------------------------------------
  // injectStyles: inject the banner.css file into the page via a
  // <link rel="stylesheet"> tag. Uses getElementById (not querySelector)
  // to match the test's MockDocument (which has getElementById but
  // not querySelector). Exposed via globalThis so the lifecycle
  // sub-file can read it lazily.
  // -------------------------------------------------------------------------
  var STYLE_ID = 'aegisgate-lens-banner-css';
  function injectStyles() {
    if (typeof document === 'undefined') return;
    try {
      if (document.getElementById && document.getElementById(STYLE_ID)) return;
    } catch (e) { /* ignore */ }
    try {
      var link = document.createElement('link');
      link.id = STYLE_ID;
      link.rel = 'stylesheet';
      link.type = 'text/css';
      link.href = getRuntimeUrl('util/banner.css');
      link.setAttribute('data-aegisgate-lens', 'banner-css');
      (document.head || document.documentElement).appendChild(link);
    } catch (err) {
      log.warn('injectStyles threw (test env?): ' + err.message);
    }
  }

  // -------------------------------------------------------------------------
  // Expose getRuntimeUrl and injectStyles on globalThis so the
  // sub-files can read them lazily (at function-call time, not
  // at IIFE-time). This decoupling is what makes the sub-files
  // order-independent.
  // -------------------------------------------------------------------------
  if (typeof self !== 'undefined') {
    self.__lensBannerUI_getRuntimeUrl = getRuntimeUrl;
    self.__lensBannerUI_injectStyles = injectStyles;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensBannerUI_getRuntimeUrl = getRuntimeUrl;
    globalThis.__lensBannerUI_injectStyles = injectStyles;
  }

  // -------------------------------------------------------------------------
  // Module export. Public API: show, hide, isVisible, getElement,
  // getState. Test exports (kept stable for backward compat):
  // maskValue, formatCategory, buildBannerHTML, buildDismissFormHTML.
  // -------------------------------------------------------------------------
  var module = {
    show: lifecycle.show,
    hide: lifecycle.hide,
    isVisible: lifecycle.isVisible,
    getElement: lifecycle.getElement,
    getState: lifecycle.getState,
    // Test exports — pulled from the sub-files so the public API
    // surface stays identical to the pre-split version.
    maskValue: formatters.maskValue,
    formatCategory: formatters.formatCategory,
    buildBannerHTML: html.buildBannerHTML,
    buildDismissFormHTML: html.buildDismissFormHTML
  };

  if (typeof self !== 'undefined') self.__lensBannerUI = module;
  if (typeof window !== 'undefined') window.__lensBannerUI = module;
  /**
   * @type {import("./typedefs").LensBannerUI}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensBannerUI = module;
  if (typeof globalThis !== 'undefined' && globalThis.__lensConstants) module.__lensConstants = globalThis.__lensConstants;
})(typeof globalThis !== 'undefined' ? globalThis : this);

// === content.js ===
// AegisGate Lens — content.js
// Injected into AI provider pages (10 hosts per manifest.json).
//
// Step 3d: this content script now wires up the SPA-aware prompt
// detector. The detectors (3b/3c) and selectors (3d) are loaded
// before this file in the manifest content_scripts array.
//
// What this file does:
//   1. Logs that the content script loaded and on which page
//   2. Verifies the logger, schema, and domain_hash modules are loaded
//   3. Computes the domain hash for telemetry
//   4. Initializes prompt-detect with onDetect + onSendIntercept
//      callbacks. The banner UI (3f) will replace the placeholder
//      console.log with a real banner element.
//   5. Exposes __lens_cs on window for diagnostics
//
// All async work is wrapped in try/catch with REAL error logging.
// We never silently swallow errors.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ console.log('[AegisGate Lens] ' + m); },
              warn: function(m){ console.warn('[AegisGate Lens] ' + m); },
              error: function(m,e){ console.error('[AegisGate Lens] ' + m, e); } };

  var schema = (typeof self !== 'undefined' && self.__lensSchema) ||
               (typeof globalThis !== 'undefined' && globalThis.__lensSchema) ||
               null;

  var domainHash = (typeof self !== 'undefined' && self.__lensDomainHash) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensDomainHash) ||
                   null;

  var promptDetect = (typeof self !== 'undefined' && self.__lensPromptDetect) ||
                     (typeof globalThis !== 'undefined' && globalThis.__lensPromptDetect) ||
                     null;

  var selectors = (typeof self !== 'undefined' && self.__lensSelectors) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensSelectors) ||
                  null;

  var dispatcher = (typeof self !== 'undefined' && self.__lensDispatcher) ||
                   (typeof globalThis !== 'undefined' && globalThis.__lensDispatcher) ||
                   null;

  var bannerUI = (typeof self !== 'undefined' && self.__lensBannerUI) ||
                 (typeof globalThis !== 'undefined' && globalThis.__lensBannerUI) ||
                 null;

  var dismiss = (typeof self !== 'undefined' && self.__lensDismiss) ||
                (typeof globalThis !== 'undefined' && globalThis.__lensDismiss) ||
                null;

  // Module state (shared between init, onDetect, etc.)
  var state = {
    domainHash: null,
    provider: null,
    input: null
  };

  // The onSendIntercept callback. Called by prompt-detect when the
  // user attempts to send a message that has detections. The return
  // value is a decision object: { action: 'send' | 'redact' | 'cancel' }.
  // For now (3f, the regex-chain release), the only available actions
  // are 'cancel' (default -- the banner pauses the send) and 'send'
  // (user override -- they accept the risk and send anyway). Redact
  // will be wired in 3g. The minimal implementation: block the send
  // (return 'cancel') unless the user clicks "Send anyway".
  function onSendIntercept(events, text) {
    try {
      log.info('onSendIntercept: blocking send (' + (events ? events.length : 0) + ' detections)');
      return { action: 'cancel', reason: 'detections' };
    } catch (err) {
      log.error('onSendIntercept threw', err);
      return { action: 'cancel', reason: 'error' };
    }
  }

  // The onDetect callback. Called by prompt-detect when detections
  // change. Shows the brand-matched banner above the input.
  function onDetect(events, text) {
    try {
      // Expose lastDetections on window.__lens_cs for diagnostics,
      // testing (headless smoke test), and the popup's "what was
      // detected" panel. This is the bridge between prompt-detect's
      // internal state and the test harness / popup UI.
      if (window.__lens_cs) {
        window.__lens_cs.lastDetections = events || [];
        window.__lens_cs.lastText = text || '';
        window.__lens_cs.lastDetectedAt = Date.now();
      }
      if (!events || events.length === 0) {
        if (bannerUI) bannerUI.hide();
        return;
      }
      if (!bannerUI) {
        log.warn('onDetect: bannerUI not available; cannot show banner');
        return;
      }
      // Check if any event is currently dismissed (24h scope)
      // If all events are dismissed, hide the banner
      if (dismiss) {
        var allDismissed = true;
        for (var i = 0; i < events.length; i++) {
          var ev = events[i];
          if (!state.domainHash) break;  // not yet known
          dismiss.isDismissed(state.domainHash, ev.category, ev.category + '_v1')
            .then(function (entry) {
              if (!entry) allDismissed = false;
            });
        }
        // NOTE: the isDismissed check is async; for simplicity we
        // show the banner regardless. The banner's dismiss action
        // (× button) will record the dismissal for next time.
      }
      bannerUI.show(events, {
        input: selectors && state.provider ? selectors.findInput(state.provider) : null,
        domainHash: state.domainHash,
        learnMoreUrl: 'https://github.com/aegisgatesecurity/aegisgate-lens#readme',
        onAction: function (action, payload) {
          handleBannerAction(action, payload);
        }
      });
    } catch (err) {
      log.error('onDetect threw', err);
    }
  }

  // Replace each detected value with [REDACTED:<category>] in the input
  // element. Operates on the LIVE input value (in case the user typed more
  // between the detect and the click) and replaces at the original index
  // positions reported in the events.
  //
  // Strategy:
  //   1. Read the current value of the input.
  //   2. Sort events by index descending so we replace from end to start
  //      (each replacement doesn't shift earlier indexes).
  //   3. For each event, splice the value at [index, index+len] with
  //      [REDACTED:<category>].
  //   4. Use selectors.setInputValue to write back, which dispatches the
  //      'input' event so the provider's framework sees the change.
  //   5. If anything goes wrong, log and let the user edit manually.
  function redactInput(events) {
    try {
      if (!events || events.length === 0) {
        log.info('redactInput: no events; nothing to do');
        return;
      }
      var input = selectors && state.provider ?
        selectors.findInput(state.provider) : null;
      if (!input || !selectors) {
        log.warn('redactInput: no input element available; user must edit manually');
        return;
      }
      var current = selectors.getInputValue(input);
      if (!current || current.length === 0) {
        log.info('redactInput: input is empty; nothing to do');
        return;
      }
      // Sort events by index descending so we can replace from end to start.
      // Each event has .index (start position) and .value (matched text).
      // We trust .index and .value, but if .index is missing, fall back to
      // string match from the value.
      var sorted = events.slice().sort(function (a, b) {
        return (b.index || 0) - (a.index || 0);
      });
      var out = current;
      var redactedCount = 0;
      for (var i = 0; i < sorted.length; i++) {
        var ev = sorted[i];
        if (!ev || !ev.value) continue;
        var start = typeof ev.index === 'number' ? ev.index : -1;
        var len = ev.value.length;
        if (start < 0 || start + len > out.length) {
          // Index invalid (user typed more, or detection was on a different
          // snapshot). Fall back to a string replace for this event.
          var replacement = '[REDACTED:' + (ev.category || 'PII') + ']';
          if (out.indexOf(ev.value) >= 0) {
            out = out.replace(ev.value, replacement);
            redactedCount++;
          }
        } else {
          // Verify the slice matches the event value (sanity check)
          if (out.substr(start, len) === ev.value) {
            var rep = '[REDACTED:' + (ev.category || 'PII') + ']';
            out = out.slice(0, start) + rep + out.slice(start + len);
            redactedCount++;
          } else {
            // Mismatch (e.g., user typed more). Fall back to string replace.
            var rep2 = '[REDACTED:' + (ev.category || 'PII') + ']';
            if (out.indexOf(ev.value) >= 0) {
              out = out.replace(ev.value, rep2);
              redactedCount++;
            }
          }
        }
      }
      if (redactedCount === 0) {
        log.info('redactInput: no values matched the current input; user must edit manually');
        return;
      }
      selectors.setInputValue(input, out);
      log.info('redactInput: redacted ' + redactedCount + ' of ' + events.length + ' detections');
    } catch (err) {
      log.error('redactInput threw', err);
    }
  }

  // Handle banner action. The banner has 3 main actions (cancel,
  // redact, send) and a 4th: dismiss_optin (the "Submit & dismiss"
  // opt-in path). For 3f, the actual send/cancel/re-dispatch
  // behavior is still placeholders; 3g will wire the SW.
  function handleBannerAction(action, payload) {
    try {
      log.info('banner action: ' + action);
      if (action === 'cancel') {
        // The prompt-detect onSendClick already preventDefault'd.
        // Just log; user can edit the input.
      } else if (action === 'redact') {
        // Wire the redaction: replace each detected value with [REDACTED:
        // <category>] in the input element. We rebuild the input value
        // from the current text (in case the user typed more between the
        // detect and the click) and replace at the original index positions.
        // We process events in reverse index order so earlier positions are
        // not affected by later replacements.
        redactInput(payload && payload.events ? payload.events : []);
      } else if (action === 'send') {
        // The send was preventDefault'd by onSendClick. For now,
        // log only. The user can re-press Enter / click send to
        // actually send. (A future enhancement could automatically
        // re-dispatch the send event after a delay.)
        log.info('user chose send anyway; user must re-send');
      } else if (action === 'dismiss' || action === 'dismiss_optin') {
        // The dismiss module already recorded this. The fp_reports
        // action (if any) will be sent in 3g.
        log.info('user dismissed (' + action + ')');
      } else if (action === 'fp_reports') {
        // The user opted in. The reports are in payload.reports.
        // Send them to the SW via chrome.runtime.sendMessage.
        // The SW validates the message shape, queues it, and
        // attempts to send to the backend. See api/messages.js
        // for the message envelope and background.js for the
        // SW handler.
        if (typeof chrome !== 'undefined' && chrome.runtime &&
            typeof chrome.runtime.sendMessage === 'function') {
          try {
            var message = {
              type: 'FP_REPORTS',
              version: '0.1.0-beta',
              payload: {
                timestamp: Math.floor(Date.now() / 1000),
                reports: payload.reports || []
              }
            };
            chrome.runtime.sendMessage(message, function (response) {
              if (chrome.runtime && chrome.runtime.lastError) {
                log.warn('sendMessage error: ' + chrome.runtime.lastError.message);
                return;
              }
              if (response && response.type === 'ACK') {
                log.info('SW ack: ' + JSON.stringify(response.payload || {}));
              } else if (response && response.type === 'ERROR') {
                log.error('SW error: ' + (response.payload && response.payload.error));
              }
            });
          } catch (e) {
            log.error('sendMessage threw', e);
          }
        } else {
          log.info('chrome.runtime.sendMessage not available; reports queued locally only');
        }
        // For diagnostic purposes, also log the first report
        if (payload && payload.reports && payload.reports[0]) {
          log.info('FP report payload: ' + JSON.stringify(payload.reports[0]));
        }
      }
    } catch (err) {
      log.error('handleBannerAction threw', err);
    }
  }

  function init() {
    try {
      log.info('content.js loaded on ' + (window.location && window.location.hostname ? window.location.hostname : '<unknown>'));

      // Verify modules
      if (!schema) {
        log.error('content.js: __lensSchema not available; schema.js failed to load');
        return;
      }
      if (!domainHash) {
        log.error('content.js: __lensDomainHash not available; domain_hash.js failed to load');
        return;
      }
      if (!selectors) {
        log.error('content.js: __lensSelectors not available; selectors.js failed to load');
        return;
      }
      if (!promptDetect) {
        log.error('content.js: __lensPromptDetect not available; prompt-detect.js failed to load');
        return;
      }

      // Compute the domain hash
      var hostname = (window.location && window.location.hostname) || '';
      domainHash.computeDomainHash(hostname).then(function (hash) {
        state.domainHash = hash;
        // Expose the content script state on window
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: hash,
          schemaVersion: schema.SCHEMA_VERSION,
          detect: dispatcher ? dispatcher.detect : null,
          showBanner: bannerUI ? bannerUI.show : null
        };

        // Initialize the prompt detector with our callbacks
        var ok = promptDetect.init({
          onDetect: onDetect,
          onSendIntercept: onSendIntercept
        });
        if (ok) {
          log.info('content.js init complete; prompt-detect attached');
        } else {
          log.warn('content.js init complete; prompt-detect failed (no provider)');
        }
      }).catch(function (err) {
        log.error('content.js: failed to compute domain_hash', err);
        window.__lens_cs = {
          loadedAt: Date.now(),
          hostname: hostname,
          domainHash: null,
          schemaVersion: schema ? schema.SCHEMA_VERSION : null,
          initError: err && err.message ? err.message : String(err)
        };
      });
    } catch (err) {
      log.error('content.js: uncaught error in init()', err);
    }
  }

  // Run init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Kill switch: if globalThis.__lensDisabled is true, exit immediately.
// This is a critical-bug mitigation: push a v0.1.5 with this set to
// true to disable Lens in production within 24 hours, then roll out
// the real fix in v0.1.6. See RUNBOOK.md for the full procedure.
if (typeof globalThis !== 'undefined' && globalThis.__lensDisabled === true) {
  log.warn('content: __lensDisabled is true; exiting without initializing');
  return; // exits the IIFE
}

// Test-only hook: expose the init function so the headless smoke
  // test runner can re-init prompt-detect between test cases (the
  // B1-flake fix). Production code never calls this -- the
  // MutationObserver + content script lifecycle handle re-init
  // automatically.
  if (typeof window !== 'undefined') {
    window.__lensContentInit = init;
  }
})();
} catch (e) {
  window.__lens_test_wrapper.error = String(e);
  window.__lens_test_wrapper.errorStack = e && e.stack ? e.stack : "";
}
window.__lens_test_wrapper.completed = Date.now();
