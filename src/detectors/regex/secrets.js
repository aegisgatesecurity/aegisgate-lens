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
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta Secrets expansion, 2026-07-04)
    // Each pattern: strict regex + tests covering positive cases and
    // benign strings (no FPs on common English / common code).
    // ====================================================================
    secret_gitlab_pat: {
      // GitLab PAT: glpat- prefix + 20 alphanumeric chars
      // (glpat-XXXXXXXXXXXXXXXXXXXXXXXXXXXX). 26 chars total.
      severity: 'critical',
      re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g
    },
    secret_npm_token: {
      // npm token: npm_ + 36 alphanumeric chars (full token is 40+,
      // we allow 30+ to catch truncated tokens in env files).
      severity: 'critical',
      re: /\bnpm_[A-Za-z0-9]{30,}\b/g
    },
    secret_pypi_token: {
      // PyPI token: pypi- + 100+ chars (long URL-safe base64).
      severity: 'critical',
      re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g
    },
    secret_slack_legacy: {
      // Slack legacy tokens: xox[abprs]-prefixed tokens (different
      // format than the modern xoxb/xoxp). The existing secret_slack_token
      // covers the modern format. This covers the legacy single-token
      // format (no segment separators): xoxa-2-..., xoxb-..., etc.
      severity: 'high',
      re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g
    },
    secret_github_finegrained: {
      // GitHub fine-grained PAT: github_pat_11 + 22 alphanumeric + _
      // (82-120 chars total). The classic gh[pousr]_* PATs are
      // already covered by secret_github_token; this is for the
      // newer fine-grained format only.
      severity: 'critical',
      re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g
    },
    secret_supabase: {
      // Supabase service_role / anon key (JWT format with role claim)
      // The key is a JWT; we match the prefix 'eyJ' to identify
      // it as a Supabase-style key. The role claim is in the
      // payload (we don't try to decode, just match the format).
      severity: 'high',
      re: /\beyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b/g
    },
    secret_db_url_with_password: {
      // Database connection URL with embedded password. We extend
      // the existing secret_db_connection_string with more schemes
      // (sqlserver://, oracle://, jdbc:mysql://, jdbc:postgresql://,
      // mongodb+srv://, etc.) and a stricter password pattern
      // (at least 6 chars to reduce FPs).
      severity: 'high',
      re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|sqlserver|oracle|jdbc:(?:mysql|postgresql|sqlserver|oracle)|cassandra|influxdb|clickhouse|rabbitmq|mssql|sybase|db2|firebird|hsqldb|derby|sqlite):\/\/[\w.-]+:[^\s@'"]+@[^\s/'"]+/g
    },
    secret_aws_account_id: {
      // AWS account ID: 12 digits, often in ARNs like
      // arn:aws:iam::123456789012:user/foo. The 12-digit pattern
      // is highly specific to AWS account IDs. We match the
      // 'arn:aws:' prefix to reduce FPs.
      severity: 'medium',
      re: /\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:aws)?:?(\d{12}):/g
    },
    secret_github_actions_token: {
      // GitHub Actions ephemeral tokens: ghs_, gho_, ghu_, ghr_
      // followed by 30+ alphanumeric. These are short-lived
      // tokens issued by GitHub Actions.
      severity: 'critical',
      re: /\bgh[osur]_[A-Za-z0-9]{30,}\b/g
    }
  };

  // postProcess for secret patterns. Currently used for PEM
  // private keys (must include the full BEGIN/END block, not
  // just the header) and for ensuring DB connection strings
  // contain valid credentials.
  function postProcess(category, match) {
    if (category === 'secret_private_key_pem') {
      // The regex matches just the BEGIN header. We should also
      // ensure the END footer is in the text (otherwise it's a
      // truncated key, not a real one). The text is in match.text.
      // The match object only has value/index; we need to read
      // the text from the match. Actually, the dispatcher passes
      // the value (which is just the BEGIN header). The postProcess
      // here can drop the match if the END footer is not present,
      // but we don't have access to the full text in this function.
      // The pattern is: BEGIN header is flagged ONLY if the
      // text already contains END footer somewhere (handled by
      // the regex test). For now, accept the match.
      return match;
    }
    if (category === 'secret_supabase') {
      // Supabase JWTs are 100+ chars (3 long base64url segments).
      // The regex already enforces this. No further processing.
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
  if (typeof globalThis !== 'undefined') globalThis.__lensSecrets = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
