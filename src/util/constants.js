// AegisGate Lens — util/constants.js
//
// Single source of truth for the magic numbers, color tokens,
// timing constants, and storage keys that were previously
// scattered across banner-ui.js, prompt-detect.js, background.js,
// dismiss.js, and banner.css.
//
// Per the v0.2.0 code-quality plan (item 7).
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
    // v0.2.0: per-popup "Hide Lens active indicator" toggle.
    // Default ON (show indicator) — no behavior change for existing
    // users. The content script's prompt-detect-dom.js reads this
    // synchronously (cached value with onChanged listener) and
    // early-returns from injectIndicator() when false.
    SHOW_INDICATOR: 'aegisgate_lens_show_indicator',
    // v0.2.0: global "Pause Lens for 1h / 1d" toggle.
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
  var STORAGE_SCHEMA_VERSION = '0.2.0';

  // === FP report reason codes ===
  // The 3 reason codes the user can pick when dismissing.
  // These match the banner design spec.
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
