/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Browser-Side Event Schema Validator (v0.2.0)
   =========================================================================

   Validates telemetry events before they leave the browser. Mirrors the
   backend's validateEvent() in pkg/lensbackend/validation.go.

   v0.2 changes from v0.1:
     - VALID_CATEGORIES expanded from 6 to all 65 detection categories
       (was a release-blocker in v0.1: schema rejected ~59 categories
       that detectors produced)
     - New "facet" field (1-6): identifies which of the 6 detection facets
       triggered. Required for FP-telemetry retraining (model decision §7).
     - model_version now permits "modernbert-v1", "toxicbert-v1", "regex-v1"
       suffixes (in addition to v0.1's MiniLM/5-way ensemble strings)

   Privacy guarantee: the schema is a CLOSED allowlist. Any field not in
   this schema causes the event to be rejected. The backend's JSON decoder
   also uses RejectUnknownFields so server-side re-validation catches any
   fields the client missed.

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * Schema version. v0.2 events use 2 (was 1 in v0.1).
   * The backend accepts only version 2 going forward; version 1 events
   * from v0.1 are still accepted during the deprecation window (6 months
   * post-v0.2 release) for migration.
   */
  /**
   * SCHEMA_VERSION is the CURRENT wire format version. v0.2.0 accepts
   * both v1 (legacy, deprecation window) and v2 (new) events per
   * ACCEPTED_SCHEMA_VERSIONS. The current wire format is v1 (matches
   * v0.1 wire compatibility for v0.2.0 launch; v2 schema is internal-only
   * and ships with the next major bump).
   */
  const SCHEMA_VERSION = 1;
  const ACCEPTED_SCHEMA_VERSIONS = [1, 2];

  // =========================================================================
  // Detection categories — ALL 65 from `from_platform.js` (v0.2 fix)
  // =========================================================================

  const VALID_CATEGORIES = Object.freeze([
    // PII (11)
    'pii_email',
    'pii_phone',
    'pii_ssn',
    'pii_credit_card',
    'pii_bank_account',
    'pii_date_of_birth',
    'pii_driver_license',
    'pii_health',
    'pii_ip_address',
    'pii_passport',
    'pii_tax_id',

    // Secrets (17)
    'secret_api_key',
    'secret_aws_key',
    'secret_google_api_key',
    'secret_anthropic_key',
    'secret_openai_key',
    'secret_sendgrid_key',
    'secret_twilio_key',
    'secret_bearer_token',
    'secret_database_url',
    'secret_encryption_key',
    'secret_generic_api_key',
    'secret_generic_token',
    'secret_jwt',
    'secret_oauth_token',
    'secret_password',
    'secret_private_key',
    'secret_webhook_secret',

    // Source code / XSS (2)
    'source_code',
    'xss_payload',

    // Synthetic category for the "Send test event" diagnostic in the
    // popup. NOT produced by detectors; only emitted by
    // service-worker.js handleTestEvent to verify the bearer token
    // round-trips. The backend filters it out of detection statistics.
    'health_check',

    // OWASP LLM Top 10 (10)
    'owasp_prompt_injection',
    'owasp_insecure_output',
    'owasp_insecure_plugin',
    'owasp_excessive_agency',
    'owasp_model_dos',
    'owasp_model_theft',
    'owasp_overreliance',
    'owasp_supply_chain',
    'owasp_training_poisoning',
    'owasp_sensitive_disclosure',

    // MITRE ATLAS (17)
    'atlas_promptinjection',
    'atlas_llmjailbreak',
    'atlas_indirectinjection',
    'atlas_promptextraction',
    'atlas_dataextraction',
    'atlas_configexfiltration',
    'atlas_contentinjection',
    'atlas_credentialforgery',
    'atlas_defenseevasion',
    'atlas_denialofservice',
    'atlas_elevationabuse',
    'atlas_endpointdenial',
    'atlas_inhibitrecovery',
    'atlas_mfabypass',
    'atlas_pluginexploitation',
    'atlas_resourceexhaustion',
    'atlas_vectordbpoisoning',

    // EU AI Act (6)
    'eu_ai_act_subliminal',
    'eu_ai_act_manipulation',
    'eu_ai_act_biometric',
    'eu_ai_act_promptinject',
    'eu_ai_act_datapoison',
    'eu_ai_act_adversarial',

    // ANP Guard (1)
    'anp_guard_injection',

    // Computer Use Guard (1)
    'computeruse_guard_sensitive',

    // Toxicity / Dangerous content (6)
    'toxicity_custom',
    'violence',
    'weapons',
    'illegal',
    'harassment',
    'self_harm',

    // ML-detected categories (NEW v0.2; replaces v0.1's prompt_injection_ml)
    'prompt_injection_ml',         // ModernBERT-base or large
    'prompt_injection_ml_long',    // (reserved; ModernBERT's 8K ctx eliminates the need)
  ]);

  // =========================================================================
  // Detection facets (NEW v0.2)
  // =========================================================================
  // 1 = PII (regex + Luhn)
  // 2 = Secrets (regex)
  // 3 = Source code / XSS (regex)
  // 4 = Compliance frameworks (regex; OWASP/ATLAS/EU AI Act/ANP/CU)
  // 5 = Toxicity (regex + toxic-bert ML)
  // 6 = Prompt injection (ModernBERT ML)

  const VALID_FACETS = Object.freeze([1, 2, 3, 4, 5, 6]);

  // =========================================================================
  // Severities and user actions
  // =========================================================================

  const VALID_SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

  const VALID_USER_ACTIONS = Object.freeze([
    'send_anyway',
    'edit',
    'cancel',
    'dismiss',
    // The presence of dismiss_false_positive (if any) is tied to the
    // fp_reason field. The backend filters fp events from the detection-rate
    // statistics.
    'dismiss_false_positive',
  ]);

  // =========================================================================
  // Field constraints
  // =========================================================================

  const DOMAIN_HASH_LENGTH = 16;
  const FP_REASON_MAX_LENGTH = 200;
  const URL_PATTERN = /https?:\/\/|\/\/[A-Za-z0-9]/;

  // Required fields in the canonical schema (deterministic order)
  const REQUIRED_FIELDS = Object.freeze([
    'lens_event_version',
    'domain_hash',
    'facet',           // NEW v0.2
    'category',
    'severity',
    'user_action',
    'timestamp',
    'model_version',
    'lens_version',
    'confidence',
  ]);

  const OPTIONAL_FIELDS = Object.freeze(['id', 'fp_reason', 'match_count']);
  const ALL_FIELDS = Object.freeze([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);

  // =========================================================================
  // Validation
  // =========================================================================

  /**
   * Validate a candidate event object. Pure function; no I/O.
   * @param {Object} event - Candidate event to validate.
   * @param {number} nowMs - Current epoch milliseconds (for timestamp check).
   * @returns {{valid: boolean, reason?: string, event?: Object}}
   *   On success, `event` is the normalized event with stable field order.
   *   On failure, `reason` is a safe-to-log message (excludes payload content).
   */
  function validate(event, nowMs) {
    if (typeof event !== 'object' || event === null || Array.isArray(event)) {
      return { valid: false, reason: 'event must be an object' };
    }

    // Reject unknown fields (privacy guardrail — closed schema)
    const seenFields = Object.keys(event);
    for (const field of seenFields) {
      if (!ALL_FIELDS.includes(field)) {
        return { valid: false, reason: `unknown field: ${field}` };
      }
    }

    // Required fields
    // Required-field check (with v1 backward compat):
    //   - facet is required for v2 events
    //   - facet is OPTIONAL for v1 events (deprecated; defaulted in normalization below)
    const requiredFields = (event.lens_event_version === 1)
      ? REQUIRED_FIELDS.filter((f) => f !== 'facet')
      : REQUIRED_FIELDS;
    for (const field of requiredFields) {
      if (!(field in event)) {
        return { valid: false, reason: `missing required field: ${field}` };
      }
    }

    // lens_event_version: integer in ACCEPTED_SCHEMA_VERSIONS
    if (typeof event.lens_event_version !== 'number' ||
        !Number.isInteger(event.lens_event_version) ||
        !ACCEPTED_SCHEMA_VERSIONS.includes(event.lens_event_version)) {
      return {
        valid: false,
        reason: `lens_event_version must be an integer (accepted versions: ${ACCEPTED_SCHEMA_VERSIONS.join(', ')}); version ${event.lens_event_version} is not accepted; got ${event.lens_event_version}`,
      };
    }

    // domain_hash: 16 lowercase hex chars (split checks for specific error messages)
    if (typeof event.domain_hash !== 'string') {
      return { valid: false, reason: `domain_hash must be a string` };
    }
    if (event.domain_hash.length !== DOMAIN_HASH_LENGTH) {
      return { valid: false, reason: `domain_hash must be ${DOMAIN_HASH_LENGTH} hex chars` };
    }
    if (!/^[0-9a-f]{16}$/.test(event.domain_hash)) {
      return { valid: false, reason: `domain_hash must be lowercase hex chars` };
    }

    // facet: NEW v0.2 — integer 1-6. For v1 events during deprecation
    // window, default the facet based on category (per the v1 → v2
    // migration table). v2 events must include facet explicitly.
    let resolvedFacet = event.facet;
    if (resolvedFacet === undefined || resolvedFacet === null) {
      if (event.lens_event_version === 1) {
        // Defer defaulting until after category check below
      } else {
        return { valid: false, reason: `facet must be integer in ${JSON.stringify(VALID_FACETS)}; got ${resolvedFacet}` };
      }
    } else if (typeof resolvedFacet !== 'number' ||
        !Number.isInteger(resolvedFacet) ||
        !VALID_FACETS.includes(resolvedFacet)) {
      return { valid: false, reason: `facet must be integer in ${JSON.stringify(VALID_FACETS)}; got ${resolvedFacet}` };
    }

    // category: in VALID_CATEGORIES
    if (typeof event.category !== 'string' || !VALID_CATEGORIES.includes(event.category)) {
      return { valid: false, reason: `category must be in VALID_CATEGORIES (${VALID_CATEGORIES.length} categories); got "${event.category}"` };
    }

    // severity: in VALID_SEVERITIES
    if (typeof event.severity !== 'string' || !VALID_SEVERITIES.includes(event.severity)) {
      return { valid: false, reason: `severity must be in ${JSON.stringify(VALID_SEVERITIES)}; got "${event.severity}"` };
    }

    // user_action: in VALID_USER_ACTIONS
    if (typeof event.user_action !== 'string' || !VALID_USER_ACTIONS.includes(event.user_action)) {
      return { valid: false, reason: `user_action must be in ${JSON.stringify(VALID_USER_ACTIONS)}; got "${event.user_action}"` };
    }

    // timestamp: integer seconds, within ±24h of now
    if (typeof event.timestamp !== 'number' || !Number.isInteger(event.timestamp)) {
      return { valid: false, reason: 'timestamp must be integer seconds' };
    }
    const nowS = Math.floor(nowMs / 1000);
    if (Math.abs(event.timestamp - nowS) > 24 * 3600) {
      return { valid: false, reason: 'timestamp must be within ±24h of current time' };
    }

    // model_version: string. v0.2 accepts modernbert-v1, toxicbert-v1, regex-v1
    // (in addition to v0.1's MiniLM/5-way strings during deprecation)
    if (typeof event.model_version !== 'string' || event.model_version.length === 0) {
      return { valid: false, reason: 'model_version must be a non-empty string' };
    }

    // lens_version: string
    if (typeof event.lens_version !== 'string' || event.lens_version.length === 0) {
      return { valid: false, reason: 'lens_version must be a non-empty string' };
    }

    // confidence: number in [0, 1]
    if (typeof event.confidence !== 'number' ||
        event.confidence < 0 || event.confidence > 1 ||
        !Number.isFinite(event.confidence)) {
      return { valid: false, reason: `confidence must be a finite number in [0, 1]; got ${event.confidence}` };
    }

    // Optional: id (string)
    if ('id' in event && (typeof event.id !== 'string' || event.id.length === 0)) {
      return { valid: false, reason: 'id must be a non-empty string when present' };
    }

    // Optional: fp_reason (string, ≤200 chars, no URL-shaped values)
    if ('fp_reason' in event) {
      if (typeof event.fp_reason !== 'string') {
        return { valid: false, reason: 'fp_reason must be a string when present' };
      }
      if (event.fp_reason.length > FP_REASON_MAX_LENGTH) {
        return { valid: false, reason: `fp_reason must be ≤${FP_REASON_MAX_LENGTH} chars (got ${event.fp_reason.length})` };
      }
      if (URL_PATTERN.test(event.fp_reason)) {
        return { valid: false, reason: 'fp_reason must not contain URL-shaped values (privacy guardrail)' };
      }
    }

    // Optional: match_count (integer ≥1; for batched detections)
    if ('match_count' in event) {
      if (typeof event.match_count !== 'number' ||
          !Number.isInteger(event.match_count) ||
          event.match_count < 1) {
        return { valid: false, reason: 'match_count must be a positive integer when present' };
      }
    }

    // Normalize field order for stable hashing
    const normalized = {};
    for (const field of REQUIRED_FIELDS) {
      normalized[field] = event[field];
    }
    // Default facet for v1 events during deprecation window
    if (resolvedFacet === undefined || resolvedFacet === null) {
      normalized.facet = mapCategoryToFacetV2(event.category);
    } else {
      normalized.facet = resolvedFacet;
    }
    if ('id' in event) normalized.id = event.id;
    if ('fp_reason' in event) normalized.fp_reason = event.fp_reason;
    if ('match_count' in event) normalized.match_count = event.match_count;

    return { valid: true, event: normalized };
  }

  /**
   * Map a v1 category to a v2 facet. Used during the deprecation
   * window to default the facet field for legacy v1 events.
   * @param {string} category
   * @returns {number} facet (1-6)
   */
  function mapCategoryToFacetV2(category) {
    if (!category) return 1;
    if (category.startsWith('pii_')) return 1;
    if (category.startsWith('secret_')) return 2;
    if (category === 'source_code' || category === 'xss_payload') return 3;
    if (category.startsWith('owasp_') || category.startsWith('atlas_') ||
        category.startsWith('eu_ai_act_') || category.startsWith('anp_') ||
        category.startsWith('computeruse_')) return 4;
    if (category === 'toxicity_custom' || category === 'violence' ||
        category === 'weapons' || category === 'illegal' ||
        category === 'harassment' || category === 'self_harm') return 5;
    if (category === 'prompt_injection_ml' || category === 'prompt_injection_ml_long') return 6;
    return 1;
  }

  NS.privacy = NS.privacy || {};
  NS.privacy.schema = {
    SCHEMA_VERSION,
    ACCEPTED_SCHEMA_VERSIONS,
    VALID_CATEGORIES,
    VALID_FACETS,
    VALID_SEVERITIES,
    VALID_USER_ACTIONS,
    REQUIRED_FIELDS,
    OPTIONAL_FIELDS,
    DOMAIN_HASH_LENGTH,
    FP_REASON_MAX_LENGTH,
    validate,
  };
})();
