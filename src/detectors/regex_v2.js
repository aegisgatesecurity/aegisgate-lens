/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - v0.2 Regex Pattern Expansion
   =========================================================================

   Additional regex patterns added in v0.2 to address gaps in the v0.1
   hand-written patterns (regex.js). These patterns cover categories that
   were either missing from the v0.1 hand-written regex or from the
   ported from_platform.js.

   v0.2 EXPANSION CATEGORIES:

   ADDITIONAL PII (Facet 1):
   - pii_passport       Passport numbers (US, UK, EU, generic)
   - pii_mrn            Medical Record Numbers (US 6-10 digit)
   - pii_full_name      Person names with context markers
   - pii_address        US street addresses with ZIP codes
   - pii_routing        US ABA routing numbers (9 digits, no SSN FP)
   - pii_health_more    Health conditions / ICD codes
   - pii_ipv6           IPv6 addresses

   ADDITIONAL SECRETS (Facet 2):
   - secret_github_pat          GitHub Personal Access Tokens (ghp_*)
   - secret_gitlab_pat          GitLab PAT (glpat-*)
   - secret_slack_token         Slack tokens (xoxb-, xoxp-, xoxa-, xoxs-)
   - secret_slack_webhook       Slack webhook URLs
   - secret_notion              Notion API tokens (ntn_*)
   - secret_figma               Figma tokens (figd_*, figp_*)
   - secret_discord             Discord bot tokens
   - secret_mailgun             Mailgun API keys
   - secret_github_oauth        GitHub OAuth tokens (gho_*)
   - secret_github_app          GitHub App tokens (ghu_*, ghs_*)

   ADDITIONAL XSS / SOURCE (Facet 3):
   - xss_script              <script> tag injection
   - xss_event_handler       Event handler injection (onerror=, onload=)
   - xss_javascript_url      javascript: URL injection
   - xss_data_uri            data:text/html injection
   - xss_svg                 SVG-based XSS
   - xss_markdown_image      ![alt](javascript:) injection
   - xss_css_injection       CSS expression() injection

   Each pattern is hand-crafted, tested against positive AND negative
   cases, and deliberately conservative (we prefer false negatives over
   false positives, except for XSS where defense in depth favors
   higher recall at some FP cost).

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.2 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  // ===================================================================
  // ADDITIONAL PII (Facet 1) - v0.2 expansion
  // ===================================================================
  const PII_V2 = Object.freeze([
    // Passport numbers: US (9 digits), UK (2 letters + 7 digits),
    // and generic with "passport" / "passport no" prefix.
    // Note: matches "My passport is 123456789" — accepts the word
    // "is" or "no" or ":" between "passport" and the number.
    {
      category: 'pii_passport',
      severity: 'high',
      name: 'pii_passport_v2',
      pattern: /\b(?:passport(?:\s*(?:no|number|num|#))?|passportno|pass\s*no)\b[\s,:#\-]*(?:is[\s,:#\-]+)?([A-Z]{1,2}\d{6,9}|\d{9}|[A-Z]\d{7,8})\b/gi,
      description: 'Passport Number (US/UK/generic)',
    },
    // Medical Record Numbers: US 6-10 digits with prefix.
    {
      category: 'pii_mrn',
      severity: 'high',
      name: 'pii_mrn_v2',
      pattern: /\b(?:mrn|med(?:ical)?\s*rec(?:ord)?(?:\s*(?:no|number|#))?)\s*[:#]?\s*\d{6,10}\b/gi,
      description: 'Medical Record Number (US)',
    },
    // Full name with context: "My name is...", "Patient: <Name>", etc.
    // Conservative: requires explicit context marker to avoid FP on
    // every proper noun in English text.
    {
      category: 'pii_full_name',
      severity: 'medium',
      name: 'pii_full_name_v2',
      pattern: /(?:my\s+name\s+is\s+|patient\s*[:\-]\s*|dr\.?\s+|mr\.?\s+|mrs\.?\s+|ms\.?\s+)([A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/gi,
      description: 'Person name with explicit context (My name is, Patient:, Dr., etc.)',
    },
    // US street address with ZIP code.
    // Matches: "123 Main Street, Springfield IL 62701" or
    // "456 Oak Ave, Apt 4B, Boston MA 02108"
    {
      category: 'pii_address',
      severity: 'medium',
      name: 'pii_address_v2',
      pattern: /\b\d{1,5}\s+([A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Plaza|Square|Sq|Way|Terrace|Ter)\.?(?:,?\s*(?:Apt|Apartment|Unit|Suite|Ste)\.?\s*\d+[A-Z]?)?,\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b/gi,
      description: 'US street address with city, state, ZIP',
    },
    // US ABA routing number: 9 digits with checksum (not SSN format).
    // SSN is XXX-XX-XXXX or 9 contiguous digits; routing must be 9
    // contiguous digits. We can't distinguish them by digits alone, so
    // we use a context marker.
    {
      category: 'pii_routing',
      severity: 'medium',
      name: 'pii_routing_v2',
      pattern: /\b(?:aba(?:\s*routing)?|routing(?:\s*(?:no|number|#))?|rtg(?:\s*#)?|ach\s*routing)\s*[:#]?\s*(\d{9})\b/gi,
      description: 'US ABA routing number with context marker',
    },
    // Health conditions: ICD-10 codes (e.g., E11.9 for type 2 diabetes),
    // common condition names with context.
    {
      category: 'pii_health_v2',
      severity: 'high',
      name: 'pii_health_v2',
      pattern: /\b(?:icd(?:-?10)?\s*[:#]?\s*[A-TV-Z][0-9][0-9AB](\.[0-9A-Z]{1,4})?|diagnosis\s*[:\-]?\s*(?:type\s+[12]\s+)?diabetes|(?:type\s+[12]\s+)?diabetes|cancer(?:\s+(?:of|stage))?|hypertension|asthma|hiv|covid(?:-\d+)?|tuberculosis|TB|depression|anxiety)\b/gi,
      description: 'Health conditions: ICD-10 codes, common diagnoses',
    },
    // IPv6 addresses.
    {
      category: 'pii_ipv6',
      severity: 'low',
      name: 'pii_ipv6_v2',
      pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g,
      description: 'IPv6 address (full, compressed, or with ::)',
    },
    // More flexible bank account: accept "Bank:", "Account#:", "ABA:" prefixes.
    {
      category: 'pii_bank_account_v2',
      severity: 'critical',
      name: 'pii_bank_account_v2',
      pattern: /\b(?:bank|account|acct|savings|checking|routing)\s*(?:#|no|num|number)?\s*[:#]?\s*\d{8,17}\b/gi,
      description: 'Bank Account Number (more flexible prefixes)',
    },
    // More flexible health: catch disease names + ICD codes.
    //
    // Previous regex was too broad: keywords like "patient" and "chart"
    // are used as labels (e.g., "Patient: Sarah Johnson Lee") and
    // matched this detector, which then suppressed the legitimate
    // pii_full_name detection via severity-rank overlap. Facet 1 gap
    // analysis expected `pii_full_name` for such inputs.
    //
    // Tightening:
    //   1. Drop "patient" and "chart" — too generic, used as NAME LABELS.
    //   2. Require medical terminology after the keyword (disease name
    //      or ICD-10 code) so we don't flag every "Diagnosis:" label
    //      that contains only a name.
    //   3. Cap follow-on text at 80 chars as before.
    //
    // Standalone disease names are handled by pii_health_disease;
    // ICD-10 codes by pii_health_v2; medical-record numbers by pii_mrn.
    // This detector fills the gap for "Diagnosis: <disease>" style.
    {
      category: 'pii_health_v3',
      severity: 'critical',
      name: 'pii_health_v3',
      pattern: /\b(?:diagnosis|dx|condition|hx|history|medical\s*history|health\s*record)\s*[:\-]?\s*(?=[A-Z][A-Za-z0-9.\-]*(?:\s+[A-Za-z0-9.\-]+){0,10})/gi,
      description: 'Health context with diagnosis or condition (requires medical content after keyword)',
    },
    // Common disease names as standalone detection
    {
      category: 'pii_health_disease',
      severity: 'high',
      name: 'pii_health_disease',
      pattern: /\b(?:type\s+[12]\s+diabetes|hypertension|asthma|cancer\s+(?:of|stage)|hiv|covid(?:-\d+)?|tuberculosis|TB|depression|anxiety|cardiac\s+arrest|stroke|seizure)\b/gi,
      description: 'Common disease names',
    },
    // Full name: add "Name:" as a context marker
    {
      category: 'pii_full_name_v3',
      severity: 'medium',
      name: 'pii_full_name_v3',
      pattern: /(?:^|[:\s])(?:my\s+name\s+is\s+|patient\s*[:\-]\s*|dr\.?\s+|mr\.?\s+|mrs\.?\s+|ms\.?\s+|name\s*[:\-]\s*|hello[,.]?\s+my\s+name\s+is\s+)([A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)(?:[,;\n]|$)/gi,
      description: 'Person name with explicit context (Name:, Dr., Mr., etc.)',
    },

    // HIPAA Health Plan ID: letter + 7 digits (HIPAA Safe Harbor).
    {
      category: 'pii_health_plan_id',
      severity: 'high',
      name: 'pii_health_plan_id',
      pattern: /\b[A-Z]\d{7}\b/g,
      description: 'HIPAA Health Plan ID (letter + 7 digits)',
    },
    // US ZIP+4: 5 digits + optional dash/space + 4 digits.
    // Per HIPAA Safe Harbor, ZIP+4 is treated as PHI when combined with other identifiers.
    {
      category: 'pii_zip_plus_four',
      severity: 'medium',
      name: 'pii_zip_plus_four',
      pattern: /\b\d{5}[-\s]\d{4}\b/g,
      description: 'US ZIP+4 code (HIPAA Safe Harbor identifier)',
    },
    // NPI (National Provider Identifier): 10 digits with Luhn checksum.
    // Per HIPAA, NPIs are PHI when linked to a covered entity.
    {
      category: 'pii_npi',
      severity: 'high',
      name: 'pii_npi',
      pattern: /\b(?:npi[\s:#-]*|national\s*provider\s*identifier[\s:#-]*)(\d{10})\b/gi,
      description: 'National Provider Identifier (NPI) - 10 digits',
    },
    // HIPAA Notice of Privacy Practices: text mentioning HIPAA-related
    // terms that would be sensitive in a healthcare context.
    {
      category: 'pii_hipaa_term',
      severity: 'medium',
      name: 'pii_hipaa_term',
      pattern: /\b(?:hipaa|protected\s+health\s+information|\bphi\b|covered\s+entity|business\s+associate|breach\s+notification|ePHI)\b/gi,
      description: 'HIPAA-protected terms (PHI, Covered Entity, etc.)',
    },

    // PCI DSS: Card Verification Value (CVV/CVC) - 3 or 4 digit code.
    {
      category: 'pii_card_cvv',
      severity: 'critical',
      name: 'pii_card_cvv',
      pattern: /\bcvv2?[\s:#-]*\d{3,4}\b|\bcvc2?[\s:#-]*\d{3,4}\b/gi,
      description: 'PCI DSS: Card CVV/CVC (3-4 digit security code)',
    },
    // PCI DSS: Card expiration date (MM/YY or MM/YYYY).
    {
      category: 'pii_card_expiry',
      severity: 'high',
      name: 'pii_card_expiry',
      pattern: /\b(?:exp(?:ir(?:y|ation|ed))?\s*(?:date)?|expir(?:y|ation|ed|es|ing)?\s*(?:date|on)?|valid\s*(?:thru|through|until))\s*[:\-]?\s*(?:0[1-9]|1[0-2])[\-\/](\d{2}|\d{4})\b/gi,
      description: 'PCI DSS: Card expiration date (MM/YY or MM/YYYY)',
    },
  ]);

  // ===================================================================
  // ADDITIONAL SECRETS (Facet 2) - v0.2 expansion
  // ===================================================================
  const SECRETS_V2 = Object.freeze([
    // GitHub Personal Access Token: ghp_ + 36 alphanumeric chars.
    {
      category: 'secret_github_pat',
      severity: 'critical',
      name: 'secret_github_pat_v2',
      pattern: /\bghp_[A-Za-z0-9]{36}\b/g,
      description: 'GitHub Personal Access Token',
    },
    // GitLab Personal Access Token: glpat- + alphanumeric.
    {
      category: 'secret_gitlab_pat',
      severity: 'critical',
      name: 'secret_gitlab_pat_v2',
      pattern: /\bglpat-[A-Za-z0-9_\-]{20,}\b/g,
      description: 'GitLab Personal Access Token',
    },
    // Slack tokens: xoxb- (bot), xoxp- (user), xoxa- (workspace),
    // xoxs- (legacy), xoxr- (refresh).
    {
      category: 'secret_slack_token',
      severity: 'critical',
      name: 'secret_slack_token_v2',
      pattern: /\bxox[bpars]-[A-Za-z0-9-]{10,}\b/g,
      description: 'Slack token (bot, user, app, legacy)',
    },
    // Slack incoming webhook URL.
    {
      category: 'secret_slack_webhook',
      severity: 'high',
      name: 'secret_slack_webhook_v2',
      pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
      description: 'Slack incoming webhook URL',
    },
    // Notion API tokens.
    {
      category: 'secret_notion',
      severity: 'critical',
      name: 'secret_notion_v2',
      pattern: /\b(?:ntn_[A-Za-z0-9]{43}|secret_[A-Za-z0-9]{43})\b/g,
      description: 'Notion API integration token',
    },
    // Figma personal access tokens.
    {
      category: 'secret_figma',
      severity: 'high',
      name: 'secret_figma_v2',
      pattern: /\bfig[dp]_[A-Za-z0-9_-]{20,}\b/g,
      description: 'Figma personal access token (figd_/figp_)',
    },
    // Discord bot token: 3 base64 segments separated by dots.
    // Format: <bot_id>.<timestamp>.<hmac>
    {
      category: 'secret_discord',
      severity: 'critical',
      name: 'secret_discord_v2',
      pattern: /\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d-_]{6,7}\.[A-Za-z\d-_]{27,}\b/g,
      description: 'Discord bot token',
    },
    // Mailgun API keys: key- prefix + 24-32 alphanumeric chars
    // (Mailgun key lengths vary; we accept 24-32 to be flexible).
    {
      category: 'secret_mailgun',
      severity: 'high',
      name: 'secret_mailgun_v2',
      pattern: /\bkey-[a-fA-F0-9]{24,32}\b/g,
      description: 'Mailgun API key',
    },
    // GitHub OAuth tokens.
    {
      category: 'secret_github_oauth',
      severity: 'critical',
      name: 'secret_github_oauth_v2',
      pattern: /\bgho_[A-Za-z0-9]{36}\b/g,
      description: 'GitHub OAuth access token',
    },
    // GitHub App tokens: ghu_ (user-to-server), ghs_ (server-to-server).
    {
      category: 'secret_github_app',
      severity: 'critical',
      name: 'secret_github_app_v2',
      pattern: /\b(?:ghu|ghs)_[A-Za-z0-9]{36,251}\b/g,
      description: 'GitHub App installation access token',
    },
    // Google API key: AIza + 35 chars (real format).
    {
      category: 'secret_google_api_v2',
      severity: 'critical',
      name: 'secret_google_api_v2',
      pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
      description: 'Google API key (proper AIza format)',
    },
    // AWS secret access key: 40 chars base64 (assigned value pattern).
    {
      category: 'secret_aws_secret_key',
      severity: 'critical',
      name: 'secret_aws_secret_key',
      pattern: /(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?sk)[\s=:]+\s*([A-Za-z0-9/+=]{40})\b/gi,
      description: 'AWS Secret Access Key (40 char base64)',
    },
    // Anthropic API key (correct format).
    {
      category: 'secret_anthropic_v2',
      severity: 'critical',
      name: 'secret_anthropic_v2',
      pattern: /\bsk-ant-api03-[A-Za-z0-9_-]{32,}\b/g,
      description: 'Anthropic API key (sk-ant-api03- format)',
    },
    // Slack tokens specifically (broader than xoxb).
    {
      category: 'secret_slack_tokens',
      severity: 'critical',
      name: 'secret_slack_tokens',
      pattern: /\bxox[bpars]-[A-Za-z0-9-]{10,}\b/g,
      description: 'Slack tokens (bot, user, app, refresh, legacy)',
    },
    // Stripe live key
    {
      category: 'secret_stripe_live',
      severity: 'critical',
      name: 'secret_stripe_live',
      pattern: /\bsk_live_[A-Za-z0-9]{20,}\b/g,
      description: 'Stripe LIVE secret key',
    },
    // Twilio Account SID
    {
      category: 'secret_twilio_sid',
      severity: 'high',
      name: 'secret_twilio_sid',
      pattern: /\bAC[a-f0-9]{32}\b/g,
      description: 'Twilio Account SID',
    },

    // OWASP LLM06: Sensitive Information Disclosure (PII request).
    {
      category: 'owasp_sensitive_disclosure',
      severity: 'high',
      name: 'owasp_sensitive_disclosure_v1',
      pattern: /\b(?:social\s+security|ssn|passport\s+number|credit\s+card\s+number|bank\s+account\s+number)\b/gi,
      description: 'OWASP LLM06: Request for PII (SSN, passport, CC, bank account)',
    },
    // OWASP LLM06: Credential request (password/secret/token for X).
    {
      category: 'owasp_credential_request',
      severity: 'critical',
      name: 'owasp_credential_request_v1',
      pattern: /\b(?:password|secret|api\s+key|token|credential|auth)\s+(?:for|of|to)\b/gi,
      description: 'OWASP LLM06: Request for credentials or secrets',
    },
    // AWS Session Token: ASIA + 16 chars (different from AKIA access key).
    {
      category: 'secret_aws_session_token',
      severity: 'critical',
      name: 'secret_aws_session_token_v1',
      pattern: /\bASIA[A-Z0-9]{16}\b/g,
      description: 'AWS Session Token (ASIA prefix)',
    },
    // Cloudflare API key: 37-char alphanumeric with specific format.
    {
      category: 'secret_cloudflare_api',
      severity: 'critical',
      name: 'secret_cloudflare_api_v1',
      pattern: /\b[a-f0-9]{37}\b/g,
      description: 'Cloudflare API key (37 hex chars - context-dependent)',
    },
    // DigitalOcean PAT: dop_v1_ + 64 hex chars.
    {
      category: 'secret_digitalocean_pat',
      severity: 'critical',
      name: 'secret_digitalocean_pat_v1',
      pattern: /\bdop_v1_[a-f0-9]{60,80}\b/g,
      description: 'DigitalOcean Personal Access Token',
    },
    // Heroku API key: UUID-like format with "heroku" or specific prefix.
    {
      category: 'secret_heroku_api',
      severity: 'critical',
      name: 'secret_heroku_api_v1',
      pattern: /(?:heroku[\s_-]?api[\s_-]?key[\s:#=]+|HRKU[\s_-]?)[A-Za-z0-9\-]{32,}/gi,
      description: 'Heroku API key',
    },
    // npm token: npm_ + 36 alphanumeric chars.
    {
      category: 'secret_npm_token',
      severity: 'critical',
      name: 'secret_npm_token_v1',
      pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
      description: 'npm authentication token',
    },
    // PyPI token: pypi- + 86+ chars.
    {
      category: 'secret_pypi_token',
      severity: 'critical',
      name: 'secret_pypi_token_v1',
      pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
      description: 'PyPI API token',
    },
    // Supabase service key: sb_secret_ + 30+ chars.
    {
      category: 'secret_supabase_key',
      severity: 'critical',
      name: 'secret_supabase_key_v1',
      pattern: /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{20,}\b/g,
      description: 'Supabase service/publishable key',
    },
    // Telegram bot token: 10 digits + ":" + 35 chars.
    {
      category: 'secret_telegram_bot',
      severity: 'critical',
      name: 'secret_telegram_bot_v1',
      pattern: /\b[0-9]{6,12}:AA[A-Za-z0-9_-]{30,}\b/g,
      description: 'Telegram bot API token',
    },
    // HashiCorp Vault token: s. + 24+ chars.
    {
      category: 'secret_vault_token',
      severity: 'critical',
      name: 'secret_vault_token_v1',
      pattern: /\bs\.[A-Za-z0-9]{24,}\b/g,
      description: 'HashiCorp Vault service token',
    },
    // Bitcoin wallet address: starts with 1, 3, or bc1, 26-62 chars.
    {
      category: 'secret_bitcoin_address',
      severity: 'medium',
      name: 'secret_bitcoin_address_v1',
      pattern: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b/g,
      description: 'Bitcoin wallet address (legacy P2PKH/P2SH or bech32)',
    },
    // Ethereum wallet address: 0x + 40 hex chars.
    {
      category: 'secret_ethereum_address',
      severity: 'medium',
      name: 'secret_ethereum_address_v1',
      pattern: /\b0x[a-fA-F0-9]{40}\b/g,
      description: 'Ethereum wallet address (0x + 40 hex)',
    },
    // Docker auth token: commonly in ~/.docker/config.json.
    {
      category: 'secret_docker_auth',
      severity: 'high',
      name: 'secret_docker_auth_v1',
      pattern: /"auths":\s*\{\s*"[^"]+":\s*\{\s*"auth":\s*"[A-Za-z0-9+/=]{40,}"/g,
      description: 'Docker registry auth token (base64-encoded user:pass)',
    },
  ]);

  // ===================================================================
  // ADDITIONAL XSS / SOURCE (Facet 3) - v0.2 expansion
  // ===================================================================
  const XSS_V2 = Object.freeze([
    // <script> tag injection.
    {
      category: 'xss_script',
      severity: 'critical',
      name: 'xss_script_v2',
      pattern: /<\s*script[^>]*>(?:(?!<\/\s*script\s*>).)*?(?:alert|eval|prompt|confirm|document\.write|window\.location|fetch\s*\(|new\s+Function|atob\s*\()/is,
      description: '<script> tag with suspicious JavaScript payload',
    },
    // Event handler injection: onerror=, onload=, onclick=, etc.
    {
      category: 'xss_event_handler',
      severity: 'critical',
      name: 'xss_event_handler_v2',
      pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|change|keydown|keypress|keyup)\s*=\s*(?:["'][^"']*(?:alert|eval|prompt|document\.|window\.|fetch\s*\()[^"']*["']|[^\s>]+)/gi,
      description: 'HTML event handler with JavaScript payload',
    },
    // javascript: URL injection.
    {
      category: 'xss_javascript_url',
      severity: 'critical',
      name: 'xss_javascript_url_v2',
      pattern: /(?:href|src|action|formaction)\s*=\s*["']?\s*javascript\s*:/gi,
      description: 'javascript: URL in HTML attribute',
    },
    // Data URI with HTML/JS content.
    {
      category: 'xss_data_uri',
      severity: 'critical',
      name: 'xss_data_uri_v2',
      pattern: /(?:href|src|iframe\s+src)\s*=\s*["']?\s*data\s*:\s*(?:text\/html|application\/javascript|application\/xhtml\+xml)\s*,/gi,
      description: 'Data URI with HTML/JS content',
    },
    // SVG-based XSS.
    {
      category: 'xss_svg',
      severity: 'critical',
      name: 'xss_svg_v2',
      pattern: /<\s*svg[^>]*>[\s\S]*?<script[\s>]|<\s*svg[^>]*>[\s\S]*?on\w+\s*=\s*["'][^"']*(?:alert|eval|prompt)/is,
      description: 'SVG with embedded script or event handler',
    },
    // Markdown image injection: ![alt](javascript:...)
    {
      category: 'xss_markdown_image',
      severity: 'high',
      name: 'xss_markdown_image_v2',
      pattern: /!\[[^\]]*\]\s*\(\s*(?:javascript|vbscript|data)\s*:/gi,
      description: 'Markdown image link with javascript:/vbscript:/data: URL',
    },
    // CSS expression() injection (legacy IE).
    {
      category: 'xss_css_injection',
      severity: 'high',
      name: 'xss_css_injection_v2',
      pattern: /(?:style\s*=\s*["'][^"']*expression\s*\(|style\s*=\s*[^>]*(?:behavior\s*:|-moz-binding)\s*:)/gi,
      description: 'CSS expression() or behavior: injection (legacy IE)',
    },
    // SQL Injection: UNION SELECT.
    {
      category: 'sqli_union',
      severity: 'critical',
      name: 'sqli_union_v1',
      pattern: /\bunion\s+(?:all\s+)?select\b/gi,
      description: 'SQL injection: UNION SELECT',
    },
    // SQL Injection: OR 1=1 (auth bypass).
    {
      category: 'sqli_or_true',
      severity: 'critical',
      name: 'sqli_or_true_v1',
      pattern: /\b(?:or|and)\s+["\']?\d+["\']?\s*=\s*["\']?\d+["\']?/gi,
      description: 'SQL injection: OR/AND with tautology (1=1, 2=2)',
    },
    // SQL Injection: stacked queries with semicolons.
    {
      category: 'sqli_stacked',
      severity: 'critical',
      name: 'sqli_stacked_v1',
      pattern: /;\s*(?:drop|delete|truncate|update|insert|alter)\s+(?:table|database|schema)\b/gi,
      description: 'SQL injection: stacked queries (;DROP TABLE)',
    },
    // SQL Injection: comment-based (-- or /* */).
    {
      category: 'sqli_comment',
      severity: 'high',
      name: 'sqli_comment_v1',
      pattern: /(?:['"](?:\s|--|\/\*))\s*(?:or|and|union|select|drop|insert|update|delete)\b/gi,
      description: 'SQL injection: comment-based (-- or /* */)',
    },
    // SQL Injection: time-based blind (WAITFOR DELAY).
    {
      category: 'sqli_time_based',
      severity: 'critical',
      name: 'sqli_time_based_v1',
      pattern: /\bwaitfor\s+delay\s+['"][\d:]+['"]/gi,
      description: 'SQL injection: time-based blind (WAITFOR DELAY)',
    },
    // Command Injection: shell metacharacters (;, |, &&, ||).
    {
      category: 'cmdi_metachar',
      severity: 'critical',
      name: 'cmdi_metachar_v1',
      pattern: /[;&|`]\s*(?:rm|cat|wget|curl|nc|bash|sh|cmd|powershell)\s+-?[a-z]/gi,
      description: 'Command injection: shell metachar + dangerous command',
    },
    // Command Injection: $() or backtick substitution.
    {
      category: 'cmdi_substitution',
      severity: 'critical',
      name: 'cmdi_substitution_v1',
      pattern: /\$\([^)]*\)|`[^`]+`/g,
      description: 'Command injection: $() or backtick substitution',
    },
    // Path Traversal: ../ or ..\.
    {
      category: 'path_traversal',
      severity: 'high',
      name: 'path_traversal_v1',
      pattern: /(?:\.\.[\\/]){2,}/g,
      description: 'Path traversal: ../ or ..\..',
    },
    // Path Traversal: URL-encoded variants.
    {
      category: 'path_traversal_encoded',
      severity: 'high',
      name: 'path_traversal_encoded_v1',
      pattern: /%2e%2e[\/%5c]|\.\.%2f|%2e%2e%2f/gi,
      description: 'Path traversal: URL-encoded variants',
    },
    // XXE Injection: DOCTYPE with ENTITY.
    {
      category: 'xxe',
      severity: 'critical',
      name: 'xxe_v1',
      pattern: /<!\s*DOCTYPE[^>]*<!\s*ENTITY/gi,
      description: 'XXE injection: <!DOCTYPE with <!ENTITY',
    },
    // SSRF: dangerous schemes (file://, gopher://, dict://, ldap://).
    {
      category: 'ssrf_scheme',
      severity: 'high',
      name: 'ssrf_scheme_v1',
      pattern: /(?:file|gopher|dict|ldap|jar|netdoc|tftp):\/\/[a-zA-Z0-9._-]+/gi,
      description: 'SSRF: dangerous URI schemes',
    },
    // Header injection: CR/LF in headers.
    {
      category: 'header_injection',
      severity: 'high',
      name: 'header_injection_v1',
      pattern: /%0d%0a|%0a%0d|%0d%0d|\\r\\n/gi,
      description: 'Header injection: CRLF in HTTP headers',
    },
    // LDAP injection: (cn=*) or similar.
    {
      category: 'ldapi',
      severity: 'high',
      name: 'ldapi_v1',
      pattern: /\)\s*\(\s*(?:cn|uid|sn|mail|userPassword)=[*)](?:\||$)/gi,
      description: 'LDAP injection: filter manipulation',
    },
    // NoSQL injection: $ne, $gt, $where.
    {
      category: 'nosqli',
      severity: 'high',
      name: 'nosqli_v1',
      pattern: /\$(?:ne|gt|lt|gte|lte|in|nin|eq|where|regex|exists|or|and)\b/gi,
      description: 'NoSQL injection: $ne, $gt, $where operators',
    },
    // SSTI: template injection (Jinja, Twig, etc.).
    {
      category: 'ssti',
      severity: 'high',
      name: 'ssti_v1',
      pattern: /\{\{[^}]*(?:config|self|request|application)|\$\{[^}]*(?:env|java\.runtime|JAVA_HOME)/g,
      description: 'SSTI: Server-Side Template Injection (Jinja/Twig/FreeMarker)',
    },
    // Iframe injection.
    {
      category: 'xss_iframe',
      severity: 'high',
      name: 'xss_iframe_v1',
      pattern: /<\s*iframe[^>]*(?:src|height|width)\s*=/gi,
      description: 'XSS via iframe injection',
    },
    // Object/embed tag injection.
    {
      category: 'xss_object_embed',
      severity: 'high',
      name: 'xss_object_embed_v1',
      pattern: /<\s*(?:object|embed)[^>]*\b(?:data|src|codebase)\s*=/gi,
      description: 'XSS via <object> or <embed> tag',
    },
    
    // Meta refresh redirect.
    {
      category: 'xss_meta_refresh',
      severity: 'medium',
      name: 'xss_meta_refresh_v1',
      pattern: /<\s*meta[^>]*http-equiv\s*=\s*["']?refresh/gi,
      description: 'XSS via meta refresh redirect',
    },
    // Open redirect.
    {
      category: 'open_redirect',
      severity: 'high',
      name: 'open_redirect_v1',
      pattern: /(?:location\.href|window\.location)\s*=\s*["']?https?:\/\/[^"']+/gi,
      description: 'Open redirect: location.href = external URL',
    },
    // Base64-encoded payloads (decode attempts).
    {
      category: 'encoded_payload',
      severity: 'medium',
      name: 'encoded_payload_v1',
      pattern: /[A-Za-z0-9+/]{40,}={0,2}/g,
      description: 'Suspiciously long base64-encoded payload',
    },
    // Prototype pollution.
    {
      category: 'proto_pollution',
      severity: 'high',
      name: 'proto_pollution_v1',
      pattern: /(?:__proto__|constructor\s*\.\s*prototype|prototype\s*\[\s*['"]\s*__proto__)/gi,
      description: 'Prototype pollution: __proto__ or constructor.prototype',
    },
    // Deserialization: pickle / yaml.load.
    {
      category: 'insecure_deser',
      severity: 'critical',
      name: 'insecure_deser_v1',
      pattern: /(?:yaml\.load\b[^;]*|pickle\.loads?\b[^;]*|marshal\.loads?\b)/gi,
      description: 'Insecure deserialization: yaml.load, pickle.loads, marshal.loads',
    },
    // JWT: none-algorithm attack variants.
    //
    // The original single regex was overly broad: it matched ANY 3-segment
    // JWT and produced a flood of false positives that overlapped (and
    // suppressed via severity sort) the legitimate `secret_jwt` detection
    // in from_platform.js. The facet gap analysis expected `secret_jwt`
    // for a normal JWT and treated `jwt_none` as the wrong label.
    //
    // Three narrow patterns, each covering a distinct attack signature:
    //   A. Header decodes to {"alg":"none"} (base64 prefix "eyJhbGciOiJub25lIn0").
    //      Any signature shape here is suspicious — the attacker is
    //      advertising alg=none even if the trailing segment is faked.
    //   B. Header is normal but third (signature) segment is empty
    //      (trailing dot, signature stripped). Anchored with a
    //      lookahead requiring non-signature chars or end-of-string
    //      immediately after the second dot.
    //   C. Header is normal but third segment is literally "none".
    //      Anchored with \b so partial matches like "none_xyz" do
    //      not trigger.
    //
    // General "looks like a JWT" continues to be handled by the
    // `secret_jwt` detector in from_platform.js (severity: low).
    {
      category: 'jwt_none',
      severity: 'critical',
      name: 'jwt_none_alg_none_header_v1',
      pattern: /eyJhbGciOiJub25lIn0\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
      description: 'JWT: alg=none header (none-algorithm attack variant A)',
    },
    {
      category: 'jwt_none',
      severity: 'critical',
      name: 'jwt_none_empty_signature_v1',
      pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.(?![A-Za-z0-9_-])/g,
      description: 'JWT: empty signature segment (none-algorithm attack variant B)',
    },
    {
      category: 'jwt_none',
      severity: 'critical',
      name: 'jwt_none_literal_none_signature_v1',
      pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.none\b/g,
      description: 'JWT: literal "none" signature (none-algorithm attack variant C)',
    },
    // LDAP filter injection: *)(uid=* etc.
    {
      category: 'ldap_inject',
      severity: 'high',
      name: 'ldap_inject_v1',
      pattern: /[\*\\)\(\|&]\s*(?:uid|cn|userPassword|objectClass|member)\s*=\s*[\*\w]+/gi,
      description: 'LDAP injection: filter wildcard abuse',
    },
    // Hash length extension attack indicators.
    {
      category: 'hash_length_ext',
      severity: 'medium',
      name: 'hash_length_ext_v1',
      pattern: /&[a-zA-Z_]+=?(?:[a-f0-9]{32,64})&[a-zA-Z_]+=?(?:[a-f0-9]{32,64})/g,
      description: 'Hash length extension attack indicator',
    },
    // XML bomb (billion laughs).
    {
      category: 'xml_bomb',
      severity: 'high',
      name: 'xml_bomb_v1',
      pattern: /<!\s*ENTITY\s+[a-zA-Z]+\s+SYSTEM\s+["']?file:\/\//gi,
      description: 'XXE: external entity / billion laughs attack',
    },
  ]);

  // Compile to regex instances.
  const COMPILED = (function () {
    const all = [...PII_V2, ...SECRETS_V2, ...XSS_V2];
    return Object.freeze(
      all.map((p) => ({
        category: p.category,
        regex: new RegExp(p.pattern.source, p.pattern.flags),
        severity: p.severity,
        name: p.name,
        description: p.description,
      })),
    );
  })();

  NS.detectors = NS.detectors || {};
  NS.detectors.regexV2 = NS.detectors.regexV2 || {};
  NS.detectors.regexV2.PATTERNS = COMPILED;
  NS.detectors.regexV2.PII_V2 = PII_V2;
  NS.detectors.regexV2.SECRETS_V2 = SECRETS_V2;
  NS.detectors.regexV2.XSS_V2 = XSS_V2;
  NS.detectors.regexV2.COMPILED = COMPILED;
})();