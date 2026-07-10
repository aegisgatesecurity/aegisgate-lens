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
