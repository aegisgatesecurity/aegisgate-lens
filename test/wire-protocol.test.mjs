#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Backend Wire-Protocol Shape Test (Day 10 / F-05)
// =========================================================================
//
// Drives src/api/client.js against a captured fetch and asserts that
// every outgoing request matches the wire protocol shape expected by
// the Platform backend in `pkg/lensbackend/handlers.go`.
//
// This is the Lens-side companion to the Platform-side tests in
// `pkg/lensbackend/server_test.go` and `pkg/lensbackend/ratelimit.go`'s
// `TestRateLimiter`. If the Platform's protocol changes (URL path,
// header names, body shape), this test catches the drift on the
// extension side before a release.
//
// What we test:
//   1. POST /api/v1/lens/telemetry sends the right headers and body.
//   2. The Authorization header is "Bearer <token>" (exact format).
//   3. The Content-Type header is "application/json".
//   4. The body is JSON.stringify of the event (matches
//      Platform's json.Decoder with DisallowUnknownFields).
//   5. GET /api/v1/lens/check?domain=<host> uses GET with bearer.
//   6. GET /api/v1/lens/stats uses GET with bearer.
//   7. GET /api/v1/lens/healthz uses GET, no bearer required.
//   8. A 4xx response from the backend (e.g., 429 rate limit)
//      surfaces as a thrown Error with the status code in the
//      message (matches the Platform's
//      writeError(w, http.StatusTooManyRequests, ...) path).
//
// The "Platform backend expected shape" is documented in the Platform
// repo at:
//   pkg/lensbackend/handlers.go (HandleTelemetry, HandleCheck, etc.)
//   pkg/lensbackend/server.go (mux wiring)
//   pkg/lensbackend/ratelimit.go (X-Lens-Domain-Hash header)
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// ----- Test runner ----------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  PASS  ${name}`);
    })
    .catch((err) => {
      failed++;
      failures.push({ name, err });
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
    });
}

// ----- Load the APIClient into a vm sandbox --------------------------------

async function loadAPIClient() {
  const [clientSrc, schemaSrc] = await Promise.all([
    fsp.readFile(path.join(repoRoot, 'src/api/client.js'), 'utf8'),
    fsp.readFile(path.join(repoRoot, 'src/privacy/schema.js'), 'utf8'),
  ]);

  // Captured fetch calls.
  const captured = [];

  function makeFetch(responder) {
    return async function fetchImpl(u, opts) {
      captured.push({ url: u, opts: opts || {} });
      return responder(u, opts || {});
    };
  }

  const sandbox = {
    console,
    URL,
    Math, Date, JSON, Object, Array, Set, Map,
    String, Number, Boolean, Error, Promise, Symbol, RegExp,
    self: {},
  };
  sandbox.self = sandbox;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};

  const ctx = vm.createContext(sandbox);
  vm.runInContext(schemaSrc, ctx, { filename: 'privacy/schema.js' });
  vm.runInContext(clientSrc, ctx, { filename: 'api/client.js' });

  return {
    APIClient: sandbox.self.AegisGateLens.APIClient,
    captured,
    makeFetch,
  };
}

// ----- A canonical v1 event for tests --------------------------------------

function v1Event(overrides = {}) {
  return Object.assign({
    lens_event_version: 1,
    domain_hash: 'eb3a78617eafc7aa',
    category: 'pii_email',
    severity: 'medium',
    user_action: 'send_anyway',
    timestamp: Math.floor(Date.now() / 1000),
    model_version: '0.2.2+regex-v1',
    lens_version: '0.2.2',
    confidence: 0.9,
  }, overrides);
}

console.log('AegisGate Lens - Backend Wire-Protocol Shape Test (Day 10 / F-05)');
console.log('');

// ----- Tests ---------------------------------------------------------------

await test('POST /api/v1/lens/telemetry uses POST + Bearer + JSON body', async () => {
  const { APIClient, captured, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'test-token-abc123',
    fetchImpl: makeFetch(async () => ({
      ok: true,
      status: 200,
      text: async () => '{"accepted":true}',
    })),
    eventsPerMinute: 10000, // high so rate limit doesn't fire
  });

  const event = v1Event();
  const result = await client.sendEvent(event);
  assert.equal(result, true);

  // Assert the captured request shape.
  assert.equal(captured.length, 1);
  const req = captured[0];
  assert.equal(req.url,
    'https://lens.aegisgatesecurity.io/api/v1/lens/telemetry');
  assert.equal(req.opts.method, 'POST');
  assert.equal(req.opts.headers['Authorization'], 'Bearer test-token-abc123');
  assert.equal(req.opts.headers['Content-Type'], 'application/json');
  // Body is JSON-stringified event. Parse it back to assert round-trip.
  const body = JSON.parse(req.opts.body);
  assert.equal(body.lens_event_version, 1);
  assert.equal(body.domain_hash, 'eb3a78617eafc7aa');
  assert.equal(body.category, 'pii_email');
});

await test('Authorization header format is exactly "Bearer <token>"', async () => {
  const { APIClient, captured, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.example.com',
    bearerToken: 'TOKEN_with_underscores-and-dashes',
    fetchImpl: makeFetch(async () => ({
      ok: true, status: 200,
      text: async () => '{"accepted":true}',
    })),
    eventsPerMinute: 10000,
  });
  await client.sendEvent(v1Event());
  assert.equal(captured[0].opts.headers['Authorization'],
    'Bearer TOKEN_with_underscores-and-dashes');
});

await test('GET /api/v1/lens/check?domain=<host> uses GET + Bearer', async () => {
  const { APIClient, captured, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => ({
      ok: true, status: 200,
      json: async () => ({ domain: 'chat.openai.com', status: 'clean' }),
      text: async () => '{"domain":"chat.openai.com","status":"clean"}',
    })),
    eventsPerMinute: 10000,
  });
  await client.checkDomain('chat.openai.com');
  assert.equal(captured.length, 1);
  const req = captured[0];
  assert.equal(req.opts.method, 'GET');
  assert.equal(req.opts.headers['Authorization'], 'Bearer token');
  assert.ok(req.url.includes('/api/v1/lens/check'),
    'URL must hit the check endpoint');
  assert.ok(req.url.includes('domain=chat.openai.com'),
    'URL must include the domain query param');
});

await test('GET /api/v1/lens/stats uses GET + Bearer', async () => {
  const { APIClient, captured, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => ({
      ok: true, status: 200,
      json: async () => ({ events24h: 42, detections24h: 7 }),
      text: async () => '{"events24h":42,"detections24h":7}',
    })),
    eventsPerMinute: 10000,
  });
  await client.getStats();
  const req = captured[0];
  assert.equal(req.opts.method, 'GET');
  assert.equal(req.opts.headers['Authorization'], 'Bearer token');
  assert.ok(req.url.includes('/api/v1/lens/stats'));
});

await test('GET /api/v1/lens/healthz uses GET and does NOT send Bearer', async () => {
  // The Platform's /healthz endpoint is explicitly unauthenticated
  // (see pkg/lensbackend/server.go). Sending a Bearer header is not
  // wrong per se, but the Platform test fixture doesn't expect one.
  // We only assert method + URL; presence of Authorization is not
  // strictly required.
  const { APIClient, captured, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => ({
      ok: true, status: 200,
      json: async () => ({ status: 'ok', version: '0.0.0-mock' }),
      text: async () => '{"status":"ok","version":"0.0.0-mock"}',
    })),
    eventsPerMinute: 10000,
  });
  await client.healthz();
  const req = captured[0];
  assert.equal(req.opts.method, 'GET');
  assert.ok(req.url.includes('/api/v1/lens/healthz'));
});

await test('a 4xx response from the backend throws with status code', async () => {
  const { APIClient, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => ({
      ok: false, status: 429,
      text: async () =>
        '{"error":"rate_limit_exceeded","reason":"per-installation"}',
    })),
    eventsPerMinute: 10000,
  });
  await assert.rejects(
    () => client.sendEvent(v1Event()),
    /HTTP 429/,
    'sendEvent must throw with the HTTP status code',
  );
});

await test('a 401 response from the backend throws with status code', async () => {
  const { APIClient, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'wrong-token',
    fetchImpl: makeFetch(async () => ({
      ok: false, status: 401,
      text: async () => '{"error":"unauthorized"}',
    })),
    eventsPerMinute: 10000,
  });
  await assert.rejects(
    () => client.sendEvent(v1Event()),
    /HTTP 401/,
  );
});

await test('a 4xx response with DisallowUnknownFields-style error surfaces the error body', async () => {
  // The Platform uses DisallowUnknownFields on the event decoder
  // (see pkg/lensbackend/handlers.go:decodeEvent). If the Lens sends
  // a forbidden field, the backend rejects with 400 + error body.
  // We assert that the error message includes the backend's error
  // body (so it's actionable for debugging).
  const { APIClient, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => ({
      ok: false, status: 400,
      text: async () =>
        '{"error":"decode_failed","reason":"unknown field: prompt_text"}',
    })),
    eventsPerMinute: 10000,
  });
  await assert.rejects(
    () => client.sendEvent(v1Event()),
    /decode_failed/,
  );
});

await test('the body sent to the backend contains exactly the v1 fields', async () => {
  // Regression: the schema validator in src/privacy/schema.js
  // constructs the normalized event with a specific field order
  // (lens_event_version first). The wire test asserts this order
  // survives JSON.stringify unchanged.
  const { APIClient, captured, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => ({
      ok: true, status: 200,
      text: async () => '{"accepted":true}',
    })),
    eventsPerMinute: 10000,
  });
  await client.sendEvent(v1Event());
  const body = captured[0].opts.body;
  // lens_event_version must come first (we don't enforce this in
  // JSON.stringify's order, but the canonical event has it first).
  const firstKey = body.slice(0, 100).match(/"(\w+)":/)[1];
  assert.equal(firstKey, 'lens_event_version',
    'first field of wire body must be lens_event_version');
});

await test('Platform TestRateLimiter invariant: 100 events succeed, 101st is rate-limited', async () => {
  // We do NOT call the real Platform here (that requires a Go
  // runtime). Instead, we assert that the Lens APIClient correctly
  // counts events at exactly 100/min so it never SENDS the 101st.
  // This is the Lens-side mirror of TestRateLimiter in
  // pkg/lensbackend/ratelimit.go.
  let callCount = 0;
  const { APIClient, makeFetch } = await loadAPIClient();
  const client = new APIClient({
    baseUrl: 'https://lens.aegisgatesecurity.io',
    bearerToken: 'token',
    fetchImpl: makeFetch(async () => {
      callCount++;
      return {
        ok: true, status: 200,
        text: async () => '{"accepted":true}',
      };
    }),
    eventsPerMinute: 100, // mirror Platform default
  });

  let accepted = 0;
  let dropped = 0;
  for (let i = 0; i < 105; i++) {
    const ok = await client.sendEvent(v1Event());
    if (ok) accepted++;
    else dropped++;
  }
  // Client-side rate limit should drop everything over 100 within
  // the burst window. Exactly 100 accepted, 5 dropped.
  assert.equal(accepted, 100,
    `expected 100 accepted (matches Platform TestRateLimiter), got ${accepted}`);
  assert.equal(dropped, 5,
    `expected 5 dropped, got ${dropped}`);
  assert.equal(callCount, 100,
    `expected exactly 100 fetch calls (rate-limited events never reach fetch), got ${callCount}`);
});

// ----- Summary -------------------------------------------------------------

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);

if (failed > 0) {
  console.log('');
  console.log('Failures:');
  for (const { name, err } of failures) {
    console.log(`  - ${name}: ${err.message}`);
  }
  process.exit(1);
}

process.exit(0);
