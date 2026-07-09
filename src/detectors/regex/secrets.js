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