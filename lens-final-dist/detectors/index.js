/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Detector Entry Point
   =========================================================================

   The detect() function is the only public API of the
   detectors/ module. It takes a string (the prompt text the
   user is typing) and returns a list of Detection objects.

   The function is deterministic, side-effect-free, and
   synchronous. The browser calls it from the content script
   (content.ts) on every input event. The Detection list is
   then:
     1. Filtered to remove overlaps (e.g., "4111-1111-1111-1111"
        matches both credit_card_visa_v1 and credit_card_amex_v1;
        keep only the highest-severity match).
     2. Displayed in the warning UI.
     3. Sent to the API (api/client.ts) LensEvent, with
        the prompt content STRIPPED — only the metadata
        (category, severity, span) crosses the wire.

   Privacy: detect() is the ONLY place in the extension that
   sees the prompt content. Every other module receives
   already-extracted metadata. This is the structural
   enforcement of the privacy boundary. See
   legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md,
   non-negotiable #1 (no logging of prompt/URL/page content).

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};
  const { COMPILED_PATTERNS: HAND_WRITTEN } = NS.detectors.regex;
  const { PATTERNS: PORTED } = (NS.detectors && NS.detectors.fromPlatform) || { PATTERNS: [] };
  const { PATTERNS: HAND_WRITTEN_V2 } = (NS.detectors && NS.detectors.regexV2) || { PATTERNS: [] };
  const { isLuhnValid } = NS.detectors.luhn;

  /**
   * Unified pattern array. Each entry has the shape:
   *   { category, regex, severity, name, description }
   * The hand-written patterns expose `{pattern, regex}` so we
   * normalize them; the ported patterns already match this shape.
   *
   * @type {Array<{category: string, regex: RegExp, severity: string, name: string, description: string}>}
   */
  const COMPILED_PATTERNS = (function () {
    const out = [];
    // Hand-written patterns (Lens-specific).
    for (let i = 0; i < HAND_WRITTEN.length; i++) {
      const p = HAND_WRITTEN[i].pattern;
      out.push({
        category: p.category,
        regex: HAND_WRITTEN[i].regex,
        severity: p.severity,
        name: p.name,
        description: p.description,
      });
    }
    // Ported patterns (from Platform's Go files).
    for (let i = 0; i < PORTED.length; i++) {
      const p = PORTED[i];
      out.push({
        category: p.category,
        regex: p.regex,
        severity: p.severity,
        name: p.name,
        description: p.description,
      });
    }
    // v0.2 expansion patterns (from regex_v2.js).
    for (let i = 0; i < HAND_WRITTEN_V2.length; i++) {
      const p = HAND_WRITTEN_V2[i];
      out.push({
        category: p.category,
        regex: p.regex,
        severity: p.severity,
        name: p.name,
        description: p.description,
      });
    }
    return out;
  })();

  /**
   * @typedef {string} Category
   *   Any of the Lens's detection categories. The set is open-ended:
   *   the Platform-ported patterns add 30+ categories (PII bank
   *   account, IP address, health info, etc.; secrets OpenAI key,
   *   Anthropic key, JWT, OAuth, bearer tokens, etc.; toxicity
   *   violence, weapons, etc.). Adding a new category is NOT a
   *   breaking change for v0.1; it becomes one at v1.0.
   */

  /**
   * @typedef {'info'|'low'|'medium'|'high'|'critical'} Severity
   *   The 5 severity levels. Matches pkg/ioc.Severity and
   *   pkg/logging.Severity so downstream IOCs are compatible.
   */

  /**
   * @typedef {Object} Detection
   * @property {Category} category
   * @property {Severity} severity
   * @property {string} match The matched substring (used locally; NEVER sent to the backend).
   * @property {number} start Start index in the source text.
   * @property {number} end   End index in the source text.
   * @property {string} pattern The pattern name that matched (e.g., "aws_access_key_v1").
   */

  /**
   * @typedef {Object} RegexPattern
   * @property {Category} category
   * @property {Severity} severity
   * @property {string} name
   * @property {string} pattern
   * @property {string} description
   */

  /**
   * Options for detect().
   *
   * @typedef {Object} DetectOptions
   * @property {Set<Category>} [disabledCategories] Categories to skip. By default, all 7 categories are
   *   checked. The user can disable specific categories in
   *   the popup UI; the popup then passes the disabled
   *   categories via this option.
   * @property {number} [maxDetections] Maximum number of detections to return. The default
   *   (50) is a conservative bound to prevent pathological
   *   inputs (e.g., a 10MB pasted document) from causing UI
   *   jank. Detections beyond the limit are discarded.
   */

  const DEFAULT_MAX_DETECTIONS = 50;

  /**
   * Run all v0.1 detectors on the input text and return the
   * list of detections.
   *
   * The function is pure: same input + same options = same
   * output. It does not retain any state.
   *
   * @param {string} text
   * @param {DetectOptions} [options]
   * @returns {ReadonlyArray<Detection>}
   */
  function detect(text, options) {
    if (typeof text !== 'string' || text.length === 0) {
      return [];
    }
    const opts = options || {};
    const max = typeof opts.maxDetections === 'number' ? opts.maxDetections : DEFAULT_MAX_DETECTIONS;
    const disabled = opts.disabledCategories || new Set();

    // Collect all raw matches.
    /** @type {Detection[]} */
    const raw = [];
    for (let i = 0; i < COMPILED_PATTERNS.length; i++) {
      const { category, regex, severity } = COMPILED_PATTERNS[i];
      if (disabled.has(category)) {
        continue;
      }
      // Defensive: matchAll requires a global regex. Some v0.1 hand-written
      // patterns don't have the 'g' flag. Add it if missing.
      const gRegex = regex.flags.includes('g') ? regex : new RegExp(regex.source, regex.flags + 'g');
      for (const match of text.matchAll(gRegex)) {
        // Top-of-loop cap check: bail out once we have
        // 4x the detection limit, before doing any work on
        // the current match. The previous implementation had
        // the check at the bottom, which could slightly
        // exceed the cap by (remaining_patterns) matches.
        if (raw.length >= max * 4) break;
        if (match.index === undefined) continue;
        const matchText = match[0];
        // Credit card patterns get the Luhn filter.
        if (category === 'pii_credit_card') {
          if (!isLuhnValid(matchText)) {
            continue;
          }
        }
        raw.push({
          category: category,
          severity: severity,
          match: matchText,
          start: match.index,
          end: match.index + matchText.length,
          pattern: COMPILED_PATTERNS[i].name,
        });
      }
      if (raw.length >= max * 4) break;
    }

    // Sort by start index, then by severity (highest first).
    raw.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      return severityRank(b.severity) - severityRank(a.severity);
    });

    // Suppress overlaps: if two detections overlap, keep the
    // one with the higher severity rank, breaking ties by
    // the longer match.
    /** @type {Detection[]} */
    const accepted = [];
    for (let i = 0; i < raw.length; i++) {
      const d = raw[i];
      if (accepted.length >= max) break;
      let overlapped = false;
      for (let j = 0; j < accepted.length; j++) {
        if (overlaps(accepted[j], d)) {
          overlapped = true;
          break;
        }
      }
      if (!overlapped) {
        accepted.push(d);
      }
    }
    return accepted;
  }

  /**
   * Two detections overlap if their character spans intersect.
   *
   * @param {Detection} a
   * @param {Detection} b
   * @returns {boolean}
   */
  function overlaps(a, b) {
    return a.start < b.end && b.start < a.end;
  }

  /**
   * Numeric rank for a severity. Higher is more severe. Mirrors
   * the Go side's severityRank function.
   *
   * @param {Severity} s
   * @returns {number}
   */
  function severityRank(s) {
    switch (s) {
      case 'critical':
        return 5;
      case 'high':
        return 4;
      case 'medium':
        return 3;
      case 'low':
        return 2;
      case 'info':
        return 1;
    }
    return 0;
  }

  /**
   * Build a stable, human-readable label for a detection.
   * Used in the warning UI.
   *
   * @param {Detection} d
   * @returns {string}
   */
  function describeDetection(d) {
    const prefix = describeCategory(d.category);
    return prefix + ' (severity: ' + d.severity + ')';
  }

  /**
   * @param {Category} c
   * @returns {string}
   */
  function describeCategory(c) {
    // Hand-written categories (Lens-specific).
    switch (c) {
      case 'prompt_injection_ml': return 'Prompt injection (ML detected)';
      case 'pii_email':         return 'Email address';
      case 'pii_phone':         return 'Phone number';
      case 'pii_ssn':           return 'Social Security number';
      case 'pii_credit_card':   return 'Credit card number';
      case 'pii_bank_account':  return 'Bank account number';
      case 'pii_date_of_birth': return 'Date of birth';
      case 'pii_driver_license':return 'Driver license number';
      case 'pii_health':        return 'Health / medical record';
      case 'pii_ip_address':    return 'IP address';
      case 'secret_api_key':    return 'API key or token';
      case 'source_code':       return 'Source code (private key)';
      case 'xss_payload':       return 'XSS payload (HTML/JavaScript injection)';
    }
    // Ported categories (from Platform).
    switch (c) {
      case 'secret_aws_key':         return 'AWS access key';
      case 'secret_bearer_token':    return 'Bearer token';
      case 'secret_jwt':             return 'JSON Web Token (JWT)';
      case 'secret_private_key':     return 'Private cryptographic key';
      case 'secret_oauth_token':     return 'OAuth access token';
      case 'secret_password':        return 'Password';
      case 'secret_database_url':    return 'Database connection string';
      case 'secret_encryption_key':  return 'Encryption key';
      case 'secret_webhook_secret':  return 'Webhook signing secret';
      case 'secret_openai_key':      return 'OpenAI API key';
      case 'secret_anthropic_key':   return 'Anthropic API key';
      case 'secret_google_api_key':  return 'Google API key';
      case 'secret_twilio_key':      return 'Twilio API key';
      case 'secret_sendgrid_key':    return 'SendGrid API key';
      case 'secret_generic_api_key': return 'Generic API key';
      case 'secret_generic_token':   return 'Generic authentication token';
      case 'violence':               return 'Violent content';
      case 'weapons':                return 'Weapons content';
      case 'illegal':                return 'Illegal activity';
      case 'self_harm':              return 'Self-harm content';
      case 'harassment':             return 'Harassment';
      case 'hate_speech':            return 'Hate speech';
      case 'sexual':                 return 'Sexual content';
    }
    // MITRE ATLAS compliance categories.
    if (c.indexOf('atlas_') === 0) {
      const atlasMap = {
        'atlas_promptinjection':  'Atlas: Prompt injection',
        'atlas_llmjailbreak':     'Atlas: LLM jailbreak attempt',
        'atlas_promptextraction': 'Atlas: Prompt extraction',
        'atlas_indirectinjection':'Atlas: Indirect prompt injection',
        'atlas_dataextraction':   'Atlas: Data extraction attempt',
        'atlas_configexfiltration':'Atlas: Config exfiltration',
        'atlas_contentinjection': 'Atlas: Content injection',
        'atlas_credentialforgery':'Atlas: Credential forgery',
        'atlas_defenseevasion':   'Atlas: Defense evasion',
        'atlas_denialofservice':  'Atlas: Denial of service',
        'atlas_elevationabuse':   'Atlas: Privilege elevation',
        'atlas_endpointdenial':   'Atlas: Endpoint denial',
        'atlas_inhibitrecovery':  'Atlas: Recovery inhibition',
        'atlas_mfabypass':        'Atlas: MFA bypass',
        'atlas_pluginexploitation':'Atlas: Plugin exploitation',
        'atlas_resourceexhaustion':'Atlas: Resource exhaustion',
        'atlas_vectordbpoisoning':'Atlas: Vector DB poisoning',
      };
      return atlasMap[c] || ('Atlas: ' + c.slice(6));
    }
    // OWASP LLM Top 10.
    if (c.indexOf('owasp_') === 0) {
      const owaspMap = {
        'owasp_prompt_injection':  'OWASP LLM01: Prompt injection',
        'owasp_insecure_output':   'OWASP LLM02: Insecure output',
        'owasp_training_poisoning':'OWASP LLM03: Training poisoning',
        'owasp_model_dos':         'OWASP LLM04: Model DoS',
        'owasp_supply_chain':      'OWASP LLM05: Supply chain',
        'owasp_sensitive_disclosure':'OWASP LLM06: Sensitive disclosure',
        'owasp_insecure_plugin':   'OWASP LLM07: Insecure plugin',
        'owasp_excessive_agency':  'OWASP LLM08: Excessive agency',
        'owasp_overreliance':      'OWASP LLM09: Overreliance',
        'owasp_model_theft':       'OWASP LLM10: Model theft',
      };
      return owaspMap[c] || ('OWASP: ' + c.slice(6));
    }
    // EU AI Act categories.
    if (c.indexOf('eu_ai_act_') === 0) {
      const euMap = {
        'eu_ai_act_subliminal':   'EU AI Act: Subliminal manipulation',
        'eu_ai_act_manipulation': 'EU AI Act: Manipulation of vulnerabilities',
        'eu_ai_act_biometric':    'EU AI Act: Biometric identification',
        'eu_ai_act_promptinject': 'EU AI Act: Prompt injection (Art 15)',
        'eu_ai_act_datapoison':   'EU AI Act: Data poisoning',
        'eu_ai_act_adversarial':  'EU AI Act: Adversarial example',
      };
      return euMap[c] || ('EU AI Act: ' + c.slice(11));
    }
    // ANP (Agent Network Protocol) guard.
    if (c.indexOf('anp_guard_') === 0) return 'ANP: ' + c.slice(10);
    // Computer Use (Anthropic API) guard.
// Prefix "computeruse_guard_" is 18 chars (c-o-m-p-u-t-e-r-u-s-e + _g-u-a-r-d-_).
// Earlier versions used c.slice(19) which truncated the leading 's' of
// the suffix (e.g., "sensitive" became "ensitive"). Fixed 2026-06-19.
    if (c.indexOf('computeruse_guard_') === 0) return 'Computer Use: ' + c.slice(18);
    return c || 'Unknown';
  }

  /**
   * Look up a pattern definition by name. Used by the
   * schema-generation step in the build tool to keep the
   * TypeScript types and the Go struct in sync.
   *
   * @param {string} name
   * @returns {RegexPattern | undefined}
   */
  function getPatternByName(name) {
    for (let i = 0; i < COMPILED_PATTERNS.length; i++) {
      if (COMPILED_PATTERNS[i].pattern.name === name) {
        return COMPILED_PATTERNS[i].pattern;
      }
    }
    return undefined;
  }

  NS.detectors = NS.detectors || {};
  NS.detectors.detect = detect;
  NS.detectors.describeDetection = describeDetection;
  NS.detectors.describeCategory = describeCategory;
  NS.detectors.getPatternByName = getPatternByName;
  NS.detectors.severityRank = severityRank;
  NS.detectors.overlaps = overlaps;
  NS.detectors.DEFAULT_MAX_DETECTIONS = DEFAULT_MAX_DETECTIONS;
})();
