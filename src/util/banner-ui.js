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
      link.href = getRuntimeUrl('src/util/banner.css');
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
