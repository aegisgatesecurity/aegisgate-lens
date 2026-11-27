// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens — Business Policy Enforcement (Phase 4a, Lens Business
// plan Phase 3)
// =========================================================================
//
// Admin-defined detection policy, delivered via MDM managed config
// (GPO/Intune/JAMF), ACTIVE ONLY when a valid Lens Business entitlement
// is present (the background service worker writes the active policy
// into storage; consumer users never have one).
//
//   customBlockPatterns: [{name, regex, severity?}] — pre-scan: text
//       matching a custom pattern produces a synthetic block event
//       (e.g. internal project codenames).
//   customAllowPatterns: [regex] — post-scan: events whose matched value
//       matches an allow pattern are suppressed (e.g. test-env tokens).
//   blockedCategories: [category] — post-scan: always keep these
//       categories (forced detection even if the facet is disabled).
//   facetsEnabled: {pii: true, ...} — post-scan: events on disabled
//       facets are suppressed (unless blockedCategories forces them).
//
// No UI. Admins configure via policy JSON. The popup shows "policy
// active" indirectly through enforced behavior.
// =========================================================================

var POLICY = (function () {
  'use strict';

  var state = {
    active: false,
    facetsEnabled: null,      // {facetId: bool} or null
    blockedCategories: [],     // always-keep categories
    allowedCategories: [],     // suppressed categories
    customBlockPatterns: [],   // [{name, regex, severity}]
    customAllowPatterns: []    // [regex strings]
  };

  function storageGet(key) {
    return new Promise(function (resolve) {
      try {
        chrome.storage.local.get(key, function (items) {
          resolve((items && items[key]) || null);
        });
      } catch (e) { resolve(null); }
    });
  }

  // init: load the active policy snapshot written by the background SW.
  function init() {
    return storageGet('aegisgate_lens_policy').then(function (p) {
      if (!p || p.active !== true) {
        state.active = false;
        return false;
      }
      state.active = true;
      state.facetsEnabled = p.facetsEnabled || null;
      state.blockedCategories = p.blockedCategories || [];
      state.allowedCategories = p.allowedCategories || [];
      state.customBlockPatterns = p.customBlockPatterns || [];
      state.customAllowPatterns = p.customAllowPatterns || [];
      return true;
    });
  }

  function safeTest(regexStr, text, flags) {
    try {
      return new RegExp(regexStr, flags || 'i').test(text);
    } catch (e) {
      return false; // a bad admin pattern must never break detection
    }
  }

  // preScan: custom block patterns against raw text. Returns a synthetic
  // event (facet "policy") or null.
  function preScan(text) {
    if (!state.active || !state.customBlockPatterns.length || !text) return null;
    for (var i = 0; i < state.customBlockPatterns.length; i++) {
      var rule = state.customBlockPatterns[i];
      if (rule && rule.regex && safeTest(rule.regex, text)) {
        return {
          facet: 'policy',
          category: 'custom_block_' + (rule.name || 'rule' + i),
          severity: rule.severity || 'high',
          value: '',
          count: 1
        };
      }
    }
    return null;
  }

  // filterEvents: post-scan filtering of detection events.
  function filterEvents(events, text) {
    if (!state.active || !events || !events.length) return events || [];
    var out = [];
    for (var i = 0; i < events.length; i++) {
      var ev = events[i];

      // Forced categories always survive.
      var forced = state.blockedCategories.indexOf(ev.category) !== -1;

      // Suppressed categories are dropped (unless forced).
      if (!forced && state.allowedCategories.indexOf(ev.category) !== -1) {
        continue;
      }

      // Facet gating (unless forced).
      if (!forced && state.facetsEnabled &&
          state.facetsEnabled.hasOwnProperty(ev.facet) &&
          state.facetsEnabled[ev.facet] === false) {
        continue;
      }

      // Custom allow patterns: suppress events whose matched value
      // matches an admin allow-listed pattern.
      if (!forced && state.customAllowPatterns.length && ev.value) {
        var allowed = false;
        for (var j = 0; j < state.customAllowPatterns.length; j++) {
          if (safeTest(state.customAllowPatterns[j], ev.value)) {
            allowed = true;
            break;
          }
        }
        if (allowed) continue;
      }

      out.push(ev);
    }
    return out;
  }

  function isActive() { return state.active; }

  return {
    init: init,
    preScan: preScan,
    filterEvents: filterEvents,
    isActive: isActive,
    // test hooks
    _setState: function (p) {
      state.active = p.active === true;
      state.facetsEnabled = p.facetsEnabled || null;
      state.blockedCategories = p.blockedCategories || [];
      state.allowedCategories = p.allowedCategories || [];
      state.customBlockPatterns = p.customBlockPatterns || [];
      state.customAllowPatterns = p.customAllowPatterns || [];
    },
    _getState: function () { return state; }
  };
})();

if (typeof self !== 'undefined') { self.__lensPolicy = POLICY; }
if (typeof globalThis !== 'undefined') { globalThis.__lensPolicy = POLICY; }
if (typeof module !== 'undefined' && module.exports) { module.exports = POLICY; }
