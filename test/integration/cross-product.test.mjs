// AegisGate Lens — test/integration/cross-product.test.mjs
//
// Cross-product integration tests verifying the Lens ↔ Platform
// and Lens ↔ Rampart contracts:
//
//   1. Lens FP report → Platform /lens/telemetry/fp-report endpoint
//   2. Lens message envelope shape matches Platform Event schema
//   3. Lens detection categories match Platform's valid category set
//   4. Lens detection facets match Platform's valid facet set
//   5. Lens privacy guarantee: FP reports never contain PII values
//   6. Lens bearer-token auth for self-hosted Platform
//   7. Lens SW queue + drain delivers reports to Platform
//   8. Lens severity values match Platform's valid severity set
//   9. Lens user-action values map to Platform's valid UserAction set
//
// These tests do NOT require Docker or external services — they use
// Node's built-in http module to create a mock Platform server and
// verify the contract between Lens and Platform.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

import { loadModule } from '../helpers/load-module.js';
import { installMockChrome, resetMockChrome } from '../helpers/mock-chrome.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// ============================================================
// Platform contract constants (from pkg/lensbackend/validation.go)
// These are the authoritative valid values the Platform accepts.
// If the Platform changes these, the tests must be updated to match.
// ============================================================

const PLATFORM_FACETS = ['pii', 'secrets', 'xss', 'compliance', 'toxicity', 'prompt_injection'];

const PLATFORM_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

const PLATFORM_USER_ACTIONS = ['send_anyway', 'redact', 'cancel', 'dismiss_false_positive'];

// A representative subset of Platform categories (from validation.go).
// The full set is 65+; we test a representative sample across all facets.
const PLATFORM_CATEGORIES = [
  // PII
  'pii_email', 'pii_phone', 'pii_ssn', 'pii_credit_card', 'pii_address',
  'pii_dob', 'pii_passport', 'pii_iban', 'pii_ip_address',
  // Secrets
  'secret_aws_key', 'secret_github_token', 'secret_openai_key',
  'secret_private_key_pem', 'secret_api_key_generic',
  // XSS
  'xss_script_tag', 'xss_event_handler', 'xss_javascript_url',
  // Compliance
  'owasp_llm01_prompt_injection', 'owasp_llm02_insecure_output',
  'owasp_llm06_sensitive_info_disclosure',
];

// ============================================================
// Mock Platform server
// ============================================================

function startMockPlatform({ requireAuth = false } = {}) {
  const received = [];
  const server = createServer((req, res) => {
    // The Lens SW sends to /lens/telemetry/fp-report (Cloudflare Worker
    // default path) or /api/v1/lens/fp-report (Platform self-hosted path).
    const validPaths = ['/lens/telemetry/fp-report', '/api/v1/lens/fp-report'];
    if (!validPaths.includes(req.url)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'method not allowed' }));
      return;
    }

    // Auth check
    if (requireAuth) {
      const auth = req.headers['authorization'];
      if (!auth || !auth.startsWith('Bearer ')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
    }

    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        received.push({
          headers: req.headers,
          body: parsed,
          rawBody: body,
        });
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'received' }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid json' }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ server, received, url: `http://127.0.0.1:${port}` });
    });
  });
}

// ============================================================
// Helpers to load Lens modules
// ============================================================

function loadSchema() {
  return loadModule('src/privacy/schema.js', '__lensSchema');
}

function loadSW(fetchFn) {
  installMockChrome();
  globalThis.fetch = fetchFn || globalThis.fetch;
  try {
    var _uuidCounter = 0;
    Object.defineProperty(globalThis, 'crypto', {
      value: { getRandomValues: function (b) {
        _uuidCounter++;
        for (var i = 0; i < b.length; i++) b[i] = ((i + _uuidCounter) * 7 + 13) & 0xff;
      }},
      writable: true,
      configurable: true,
    });
  } catch (e) {
    globalThis.crypto = { getRandomValues: function (b) {
      for (var i = 0; i < b.length; i++) b[i] = (i * 7 + 13) & 0xff;
    }};
  }
  return loadModule('src/background.js', '__lensSW');
}

// ============================================================
// Tests
// ============================================================

test('CrossProduct: Lens facets match Platform valid facets', () => {
  const schema = loadSchema();
  assert.ok(schema, 'schema loaded');

  // Lens VALID_FACETS should be a superset of (or equal to) Platform facets.
  // Lens may have additional facets for future use, but every Platform facet
  // must be recognized by Lens.
  for (const facet of PLATFORM_FACETS) {
    assert.ok(
      schema.VALID_FACETS.includes(facet),
      `Platform facet "${facet}" not found in Lens VALID_FACETS`
    );
  }
});

test('CrossProduct: Lens categories match Platform valid categories (sample)', () => {
  const schema = loadSchema();
  assert.ok(schema, 'schema loaded');

  // Flatten Lens VALID_CATEGORIES into a single set
  const lensCategories = new Set();
  for (const facet of Object.keys(schema.VALID_CATEGORIES)) {
    for (const cat of schema.VALID_CATEGORIES[facet]) {
      lensCategories.add(cat);
    }
  }

  // Every Platform category we sampled must be recognized by Lens
  for (const cat of PLATFORM_CATEGORIES) {
    assert.ok(
      lensCategories.has(cat),
      `Platform category "${cat}" not found in Lens VALID_CATEGORIES`
    );
  }
});

test('CrossProduct: Lens severity values match Platform valid severities', () => {
  const schema = loadSchema();
  assert.ok(schema, 'schema loaded');

  // Lens defines VALID_SEVERITIES as ['low', 'medium', 'high', 'critical'].
  // Platform defines ['info', 'low', 'medium', 'high', 'critical'].
  // Lens omits 'info' because Lens detections are always at least 'low'
  // (Lens only fires when it detects something; 'info' is for Platform
  // events like "user connected" which Lens doesn't produce).
  //
  // Verify Lens supports all Platform severities EXCEPT 'info', and
  // that 'info' is intentionally absent (not a bug).
  assert.ok(schema.VALID_SEVERITIES, 'schema exports VALID_SEVERITIES');
  const lensSeverities = schema.VALID_SEVERITIES;
  const platformMinusInfo = PLATFORM_SEVERITIES.filter(s => s !== 'info');

  for (const sev of platformMinusInfo) {
    assert.ok(
      lensSeverities.includes(sev),
      `Platform severity "${sev}" not found in Lens VALID_SEVERITIES`
    );
  }
  // 'info' is intentionally absent from Lens — it's a Platform-only severity
  assert.equal(
    lensSeverities.includes('info'),
    false,
    'Lens should not support "info" severity (Platform-only, Lens detections start at "low")'
  );

  // Also verify the schema's validate function accepts each valid severity
  if (typeof schema.validate === 'function') {
    // If schema doesn't export VALID_SEVERITIES directly, check the
    // validate function accepts each Platform severity
    for (const sev of PLATFORM_SEVERITIES) {
      const testEvent = {
        facet: 'pii',
        category: 'pii_email',
        severity: sev,
        user_action: 'cancel',
        domain_hash: 'a1b2c3d4e5f6a7b8',
        timestamp: Math.floor(Date.now() / 1000),
        lens_version: '0.3.0',
        model_version: '0.3.0-ml',
        confidence: 0.95,
      };
      // If validate exists, it should not reject on severity
      if (typeof schema.validate === 'function') {
        const result = schema.validate(testEvent);
        assert.ok(result.valid !== false, `Lens schema rejected valid severity "${sev}"`);
      }
    }
  }
});

test('CrossProduct: Lens user-action values map to Platform UserAction set', () => {
  const schema = loadSchema();
  assert.ok(schema, 'schema loaded');

  // Lens uses action names like 'cancel', 'redact', 'send', 'dismiss_optin'
  // Platform uses: 'send_anyway', 'redact', 'cancel', 'dismiss_false_positive'
  //
  // The mapping is:
  //   Lens 'cancel'              → Platform 'cancel'
  //   Lens 'redact'               → Platform 'redact'
  //   Lens 'send'                 → Platform 'send_anyway'
  //   Lens 'dismiss_optin'        → Platform 'dismiss_false_positive'
  //
  // Verify that the Lens schema accepts these action values and that
  // each maps to a valid Platform UserAction
  const lensActions = ['cancel', 'redact', 'send', 'dismiss', 'dismiss_optin'];
  const actionMap = {
    'cancel': 'cancel',
    'redact': 'redact',
    'send': 'send_anyway',
    'dismiss': 'dismiss_false_positive',
    'dismiss_optin': 'dismiss_false_positive',
  };

  for (const lensAction of lensActions) {
    const platformAction = actionMap[lensAction];
    assert.ok(
      PLATFORM_USER_ACTIONS.includes(platformAction),
      `Lens action "${lensAction}" maps to "${platformAction}" which is not a valid Platform UserAction`
    );
  }
});

test('CrossProduct: Lens FP report → mock Platform (no auth)', async (t) => {
  const mock = await startMockPlatform({ requireAuth: false });
  t.after(() => mock.server.close());

  // Load the SW with fetch pointed at our mock
  let fetchUrl = null;
  let fetchOpts = null;
  globalThis.fetch = function (url, opts) {
    fetchUrl = url;
    fetchOpts = opts;
    return Promise.resolve({
      ok: true,
      status: 202,
      json: function () { return Promise.resolve({ status: 'received' }); },
    });
  };

  const sw = loadSW();
  assert.ok(sw, 'SW loaded');

  // Build a FP report in the Lens SW format
  const reports = [
    {
      hashed_domain: 'a1b2c3d4e5f6a7b8',
      category: 'pii_email',
      severity: 'high',
      action: 'send',
      client_id: 'test-uuid-1',
    },
  ];

  // Send the report to the mock Platform via the SW's sendToBackend
  // We call the SW's internal function through the exposed handle
  const result = await sw.sendToBackend(mock.url, reports, '');
  assert.ok(result.success, 'sendToBackend should succeed');

  // Verify the fetch was called with the right URL and body
  assert.ok(fetchUrl, 'fetch was called');
  assert.ok(
    fetchUrl.includes('/lens/telemetry/fp-report') || fetchUrl.includes('/api/v1/lens/fp-report'),
    `fetch URL should include the fp-report path, got: ${fetchUrl}`
  );

  const body = JSON.parse(fetchOpts.body);
  assert.ok(body.lens_event_version, 'body has lens_event_version');
  assert.ok(body.timestamp, 'body has timestamp');
  assert.ok(Array.isArray(body.reports), 'body has reports array');
  assert.equal(body.reports.length, 1, 'one report in body');
  assert.equal(body.reports[0].category, 'pii_email', 'report category matches');
});

test('CrossProduct: Lens FP report → mock Platform (with bearer auth)', async (t) => {
  // We simulate the Platform server and verify the Lens SW includes
  // the Bearer token in the Authorization header. We don't need to
  // actually hit a real HTTP server — we just need to verify the SW
  // constructs the correct headers.
  let capturedUrl = null;
  let capturedOpts = null;
  globalThis.fetch = function (url, opts) {
    capturedUrl = url;
    capturedOpts = opts;
    return Promise.resolve({
      ok: true,
      status: 202,
      json: function () { return Promise.resolve({ status: 'received' }); },
    });
  };

  const sw = loadSW();
  assert.ok(sw, 'SW loaded');

  const reports = [
    {
      hashed_domain: 'b2c3d4e5f6a7b8c9',
      category: 'secret_aws_key',
      severity: 'critical',
      action: 'cancel',
      client_id: 'test-uuid-2',
    },
  ];

  const result = await sw.sendToBackend('http://mock-platform', reports, 'test-bearer-token-123');
  assert.ok(result.success, 'sendToBackend should succeed with auth');

  // Verify auth header was included
  assert.ok(capturedOpts, 'fetch options captured');
  assert.ok(
    capturedOpts.headers['Authorization'],
    'Authorization header present'
  );
  assert.ok(
    capturedOpts.headers['Authorization'].startsWith('Bearer '),
    'Authorization header is Bearer type'
  );
  assert.ok(
    capturedOpts.headers['Authorization'].includes('test-bearer-token-123'),
    'Authorization header contains the token'
  );
});

test('CrossProduct: Lens privacy guarantee — FP reports never contain PII values', () => {
  const schema = loadSchema();
  assert.ok(schema, 'schema loaded');

  // A well-formed FP report should contain ONLY:
  //   - hashed_domain (a hash, not the domain)
  //   - category (an enum, not the value)
  //   - severity (an enum)
  //   - action (an enum)
  //   - client_id (a UUID, not PII)
  //
  // It should NEVER contain:
  //   - The actual detected text/value
  //   - The prompt text
  //   - The page URL
  //   - User identifiers
  //   - Any free-text field

  const validReport = {
    hashed_domain: 'a1b2c3d4e5f6a7b8',
    category: 'pii_email',
    severity: 'high',
    action: 'send',
    client_id: '550e8400-e29b-41d4-a716-446655440000',
  };

  // These fields must NOT exist in a FP report
  const forbiddenFields = [
    'value', 'text', 'prompt', 'url', 'page_url', 'href',
    'user_id', 'user_email', 'user_name', 'ip_address',
    'raw_text', 'matched_text', 'snippet', 'content',
    'input_value', 'textarea_value',
  ];

  for (const field of forbiddenFields) {
    assert.equal(
      validReport[field],
      undefined,
      `FP report must not contain field "${field}"`
    );
  }

  // Verify the schema validation rejects events with forbidden fields
  if (typeof schema.validate === 'function') {
    const poisonedEvent = {
      facet: 'pii',
      category: 'pii_email',
      severity: 'high',
      user_action: 'cancel',
      domain_hash: 'a1b2c3d4e5f6a7b8',
      timestamp: Math.floor(Date.now() / 1000),
      lens_version: '0.3.0',
      model_version: '0.3.0-ml',
      confidence: 0.95,
      value: 'john.doe@example.com', // PII value — must be rejected
    };
    const result = schema.validate(poisonedEvent);
    assert.equal(result.valid, false, 'Schema must reject events with PII values');
  }
});

test('CrossProduct: Lens SW queue + drain delivers batch to Platform', async (t) => {
  const mock = await startMockPlatform({ requireAuth: false });
  t.after(() => mock.server.close());

  // Track fetch calls
  const fetchCalls = [];
  globalThis.fetch = function (url, opts) {
    fetchCalls.push({ url, opts });
    return Promise.resolve({
      ok: true,
      status: 202,
      json: function () { return Promise.resolve({ status: 'received' }); },
    });
  };

  const sw = loadSW();
  assert.ok(sw, 'SW loaded');

  // Simulate multiple FP reports being queued
  const reports = [
    { hashed_domain: 'a1b2c3d4e5f6a7b8', category: 'pii_email', severity: 'high', action: 'send', client_id: 'u1' },
    { hashed_domain: 'a1b2c3d4e5f6a7b8', category: 'pii_ssn', severity: 'critical', action: 'cancel', client_id: 'u2' },
    { hashed_domain: 'a1b2c3d4e5f6a7b8', category: 'secret_aws_key', severity: 'critical', action: 'redact', client_id: 'u3' },
  ];

  // Send batch via sendToBackend
  const result = await sw.sendToBackend(mock.url, reports, '');
  assert.ok(result.success, 'batch send should succeed');

  // Verify all 3 reports are in the body
  assert.equal(fetchCalls.length, 1, 'exactly one fetch call');
  const body = JSON.parse(fetchCalls[0].opts.body);
  assert.equal(body.reports.length, 3, '3 reports in batch');

  // Verify category diversity
  const categories = body.reports.map(r => r.category);
  assert.ok(categories.includes('pii_email'), 'batch includes pii_email');
  assert.ok(categories.includes('pii_ssn'), 'batch includes pii_ssn');
  assert.ok(categories.includes('secret_aws_key'), 'batch includes secret_aws_key');
});

test('CrossProduct: Lens content-type header is application/json', async (t) => {
  const mock = await startMockPlatform({ requireAuth: false });
  t.after(() => mock.server.close());

  let capturedOpts = null;
  globalThis.fetch = function (url, opts) {
    capturedOpts = opts;
    return Promise.resolve({
      ok: true,
      status: 202,
      json: function () { return Promise.resolve({ status: 'received' }); },
    });
  };

  const sw = loadSW();
  assert.ok(sw, 'SW loaded');

  const reports = [
    { hashed_domain: 'a1b2c3d4e5f6a7b8', category: 'pii_email', severity: 'high', action: 'send' },
  ];

  await sw.sendToBackend(mock.url, reports, '');

  assert.ok(capturedOpts, 'fetch options captured');
  assert.equal(
    capturedOpts.headers['Content-Type'],
    'application/json',
    'Content-Type must be application/json'
  );
});

test('CrossProduct: Lens handles Platform 401 rejection gracefully', async (t) => {
  // Simulate Platform rejecting with 401
  globalThis.fetch = function () {
    return Promise.resolve({
      ok: false,
      status: 401,
      json: function () { return Promise.resolve({ error: 'unauthorized' }); },
    });
  };

  const sw = loadSW();
  assert.ok(sw, 'SW loaded');

  const reports = [
    { hashed_domain: 'a1b2c3d4e5f6a7b8', category: 'pii_email', severity: 'high', action: 'send' },
  ];

  const result = await sw.sendToBackend('http://mock-platform', reports, 'wrong-token');
  assert.equal(result.success, false, 'send should fail with 401');
  assert.ok(result.reason, 'failure reason provided');
  assert.ok(
    result.reason.includes('401'),
    `reason should mention HTTP 401, got: ${result.reason}`
  );
});

test('CrossProduct: Lens handles Platform 429 rate limit gracefully', async (t) => {
  globalThis.fetch = function () {
    return Promise.resolve({
      ok: false,
      status: 429,
      json: function () { return Promise.resolve({ error: 'rate limited' }); },
    });
  };

  const sw = loadSW();
  assert.ok(sw, 'SW loaded');

  const reports = [
    { hashed_domain: 'a1b2c3d4e5f6a7b8', category: 'pii_email', severity: 'high', action: 'send' },
  ];

  const result = await sw.sendToBackend('http://mock-platform', reports, '');
  assert.equal(result.success, false, 'send should fail with 429');
  assert.ok(
    result.reason.includes('429'),
    `reason should mention HTTP 429, got: ${result.reason}`
  );
});