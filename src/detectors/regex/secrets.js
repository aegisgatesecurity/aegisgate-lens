// AegisGate Lens — detectors/regex/secrets.js
// Facet 2: Secrets detection. Regex-based, no Luhn.
// Per schema.js VALID_CATEGORIES[2], 17 secret types are detected.
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
      // Modern PAT: ghp_; OAuth: gho_; Server: ghs_; User: ghu_
      re: /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,120}\b/g
    },
    secret_gcp_key: {
      severity: 'high',
      // Google API key: AIza + 35 chars. The Google docs are explicit
      // about 39 total chars (4 prefix + 35). We allow 30-50 for
      // forward-compat.
      re: /\bAIza[0-9A-Za-z_-]{30,50}\b/g
    },
    secret_azure_key: {
      severity: 'high',
      // Azure storage account key in connection string
      re: /(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}/g
    },
    secret_private_key_pem: {
      severity: 'critical',
      // PEM private key header (RSA, EC, DSA, OPENSSH, PGP, ENCRYPTED)
      re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
    },
    secret_oauth_token: {
      severity: 'high',
      // Generic OAuth bearer: ya29., 1//, etc.
      re: /\bya29\.[0-9A-Za-z_-]{50,}\b|\b1\/[0-9A-Za-z_-]{40,}\b/g
    },
    secret_jwt: {
      severity: 'high',
      // JWT: 3 base64url segments separated by dots
      re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g
    },
    secret_api_key_generic: {
      severity: 'high',
      // Generic API key assignment: api_key=... or apikey: ... with 20+ chars
      re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi
    },
    secret_db_connection_string: {
      severity: 'high',
      // DB connection URL with credentials
      re: /(?:mongodb|postgres|postgresql|mysql|redis|amqp)(\+\w+)?:\/\/[\w.-]+:[^\s@]+@[^\s/]+/g
    },
    secret_slack_token: {
      severity: 'high',
      // Slack: xoxb, xoxp, xoxa, xoxr, xoxs followed by digits and alnum
      re: /\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/g
    },
    secret_stripe_key: {
      severity: 'high',
      // Stripe live: sk_live_, pk_live_; test: sk_test_, pk_test_, rk_
      re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g
    },
    secret_twilio_key: {
      severity: 'high',
      // Twilio API key (SK + 32 hex) or account SID (AC + 32 hex)
      re: /\b(?:SK|AC)[a-fA-F0-9]{32}\b/g
    },
    secret_sendgrid_key: {
      severity: 'high',
      // SendGrid API key: SG. + base62 (22 chars) + . + base62 (43 chars)
      re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g
    },
    secret_mailgun_key: {
      severity: 'high',
      // Mailgun: key- + 32 hex
      re: /\bkey-[a-f0-9]{32}\b/g
    },
    secret_openai_key: {
      severity: 'high',
      // OpenAI: sk- + 20+ chars. The sk- prefix is shared with
      // Anthropic (which uses sk-ant-*), so we explicitly exclude
      // sk-ant-* to prevent cross-detection.
      re: /\bsk-(?!ant-)(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b/g
    },
    secret_anthropic_key: {
      severity: 'high',
      // Anthropic: sk-ant-api03-, sk-ant-api04-, etc.
      re: /\bsk-ant-(?:api)?\d{2}-[A-Za-z0-9_-]{20,}\b/g
    },
    secret_heroku_key: {
      severity: 'medium',
      // Heroku API key: UUID-like with heroku prefix in env vars
      re: /\bheroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g
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
          value: m[0],
          index: m.index
        });
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensSecrets = module;
  if (typeof window !== 'undefined') window.__lensSecrets = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensSecrets = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
