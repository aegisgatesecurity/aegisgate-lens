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
      'pii_ssn', 'pii_email', 'pii_phone', 'pii_credit_card',
      'pii_address', 'pii_dob', 'pii_driver_license', 'pii_passport',
      'pii_bip39_seed',
      'pii_tax_id', 'pii_bank_account', 'pii_ip_address'
    ],
    secrets: [
      'secret_aws_key', 'secret_github_token', 'secret_gcp_key',
      'secret_azure_key', 'secret_private_key_pem', 'secret_oauth_token',
      'secret_jwt', 'secret_api_key_generic', 'secret_db_connection_string',
      'secret_slack_token', 'secret_stripe_key', 'secret_twilio_key',
      'secret_sendgrid_key', 'secret_mailgun_key', 'secret_openai_key',
      'secret_anthropic_key', 'secret_heroku_key'
    ],
    xss: [
      'xss_script_tag', 'xss_event_handler', 'xss_javascript_url',
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
      'cu_consumer_rights',
      'cu_minor_protection'
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

  if (typeof self !== 'undefined') self.__lensSchema = schema;
  if (typeof window !== 'undefined') window.__lensSchema = schema;
  if (typeof globalThis !== 'undefined') globalThis.__lensSchema = schema;
})(typeof globalThis !== 'undefined' ? globalThis : this);
