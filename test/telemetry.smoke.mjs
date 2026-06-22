#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Telemetry Smoke Test (Day 2)
// =========================================================================
//
// End-to-end smoke test for the telemetry path:
//   src/privacy/schema.js (validate) -> src/api/client.js (sendEvent)
//     -> fetch -> mock backend -> JSONL file
//
// Boots the mock backend on 127.0.0.1:<random free port>, loads the
// browser-side api/client.js into a vm context with stubbed globals,
// drives a real APIClient through real fetch calls, then asserts on:
//   - 1 valid event reaches the backend and lands in the JSONL.
//   - 1 event with a forbidden field is rejected by validate().
//   - 1 event with a missing lens_event_version is rejected.
//   - 100 events in <1s are accepted; the 101st is dropped (rate limit).
//   - 1 http://production-style URL is rejected at construction time.
//   - 1 http://localhost URL is allowed at construction time.
//
// All chrome.* APIs are stubbed; only fetch (globalThis) and window/self
// are needed by api/client.js.
//
// Usage:
//   node test/telemetry.smoke.mjs
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fs from 'node:fs';
import nodeFs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
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

// ----- Boot the mock backend -----------------------------------------------

function bootMockBackend() {
  return new Promise((resolve, reject) => {
    const output = path.join(repoRoot, 'test/mock-output/events.jsonl');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, '');

    const events = [];

    const server = http.createServer(async (req, res) => {
      const parsed = url.parse(req.url, true);
      const route = parsed.pathname;

      function jsonResp(status, body) {
        const payload = JSON.stringify(body);
        res.writeHead(status, {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Length': Buffer.byteLength(payload),
        });
        res.end(payload);
      }

      if (route === '/api/v1/lens/healthz') {
        return jsonResp(200, { status: 'ok', version: '0.0.0-mock' });
      }
      if (route === '/api/v1/lens/telemetry' && req.method === 'POST') {
        const auth = req.headers['authorization'] || '';
        if (!auth.startsWith('Bearer ')) {
          return jsonResp(401, { error: 'missing bearer token' });
        }
        const chunks = [];
        for await (const c of req) chunks.push(c);
        let body;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch (err) {
          return jsonResp(400, { error: 'invalid JSON: ' + err.message });
        }
        events.push(body);
        fs.appendFileSync(output, JSON.stringify(body) + '\n');
        return jsonResp(200, { accepted: true, id: 'mock-id-' + events.length });
      }
      return jsonResp(404, { error: 'not found' });
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        server,
        events,
        baseUrl: `http://127.0.0.1:${addr.port}`,
        outputPath: output,
      });
    });

    server.on('error', reject);
  });
}

function shutdown(server) {
  return new Promise((resolve) => {
    server.close(() => resolve());
    setTimeout(() => resolve(), 500).unref();
  });
}

// ----- Load browser modules into a vm context ------------------------------

async function loadBrowserModules(baseUrl) {
  const schemaSource = await fsp.readFile(
    path.join(repoRoot, 'src/privacy/schema.js'),
    'utf8',
  );
  const clientSource = await fsp.readFile(
    path.join(repoRoot, 'src/api/client.js'),
    'utf8',
  );

  // vm contexts do NOT inherit Node globals. We expose the
  // ones that src/api/client.js touches: URL, fetch (Node 20+),
  // and the URL constructor itself. console is also exposed so
  // log.* calls from the IIFE work.
  const sandbox = {
    console,
    URL,
    fetch: (...args) => globalThis.fetch(...args),
    globalThis: {},
    window: {},
    self: {},
  };
  sandbox.window = sandbox.self;
  sandbox.globalThis = sandbox;

  // Schema doesn't need fetch or chrome, but it does need window/self.
  const ctx = vm.createContext(sandbox);
  vm.runInContext(schemaSource, ctx, { filename: 'privacy/schema.js' });
  vm.runInContext(clientSource, ctx, { filename: 'api/client.js' });

  return {
    APIClient: sandbox.self.AegisGateLens.APIClient,
    validate: sandbox.self.AegisGateLens.privacy.schema.validate,
    baseUrl,
  };
}

// ----- Tests ---------------------------------------------------------------

const mock = await bootMockBackend();
console.log('AegisGate Lens - Telemetry Smoke Test (Day 2)');
console.log(`Mock backend: ${mock.baseUrl}`);
console.log(`JSONL output: ${mock.outputPath}`);
console.log('');

const { APIClient, validate } = await loadBrowserModules(mock.baseUrl);

// The bearer token doesn't need to match anything in the mock - we just
// check that *some* bearer is present.
const TOKEN = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

await test('healthz round-trips through the APIClient', async () => {
  const c = new APIClient({ baseUrl: mock.baseUrl, bearerToken: TOKEN });
  const h = await c.healthz();
  assert.equal(h.status, 'ok');
});

await test('a valid event reaches the mock backend (1/1)', async () => {
  const c = new APIClient({ baseUrl: mock.baseUrl, bearerToken: TOKEN });
  const ev = {
    lens_event_version: 1,
    domain_hash: '0a1b2c3d4e5f6071',
    category: 'pii_email',
    severity: 'medium',
    user_action: 'edit',
    timestamp: Math.floor(Date.now() / 1000),
    model_version: '0.2.2+regex-v1',
    lens_version: '0.2.2',
    confidence: 0.92,
  };
  const ok = await c.sendEvent(ev);
  assert.equal(ok, true);
  await new Promise((r) => setTimeout(r, 50)); // let the fs.appendFile flush
  assert.equal(mock.events.length, 1, 'mock backend received 1 event');
  assert.equal(mock.events[0].lens_event_version, 1);
  assert.equal(mock.events[0].category, 'pii_email');
});

await test('a forbidden field is rejected by validate()', () => {
  const ev = {
    lens_event_version: 1,
    domain_hash: '0a1b2c3d4e5f6071',
    category: 'pii_email',
    severity: 'medium',
    user_action: 'edit',
    timestamp: Math.floor(Date.now() / 1000),
    model_version: '0.2.2+regex-v1',
    lens_version: '0.2.2',
    confidence: 0.92,
    prompt_text: 'this is the secret prompt', // privacy violation
  };
  const r = validate(ev);
  assert.equal(r.valid, false);
  assert.match(r.reason, /unknown field: prompt_text/);
});

await test('a versionless event is rejected by validate()', () => {
  const ev = {
    // No lens_event_version!
    domain_hash: '0a1b2c3d4e5f6071',
    category: 'pii_email',
    severity: 'medium',
    user_action: 'edit',
    timestamp: Math.floor(Date.now() / 1000),
    model_version: '0.2.2+regex-v1',
    lens_version: '0.2.2',
    confidence: 0.92,
  };
  const r = validate(ev);
  assert.equal(r.valid, false);
  assert.match(r.reason, /lens_event_version/);
});

await test('sendEvent propagates validation errors as throws', async () => {
  const c = new APIClient({ baseUrl: mock.baseUrl, bearerToken: TOKEN });
  const before = mock.events.length;
  await assert.rejects(
    () =>
      c.sendEvent({
        lens_event_version: 1,
        domain_hash: '0a1b2c3d4e5f6071',
        category: 'super_secret', // invalid
        severity: 'medium',
        user_action: 'edit',
        timestamp: Math.floor(Date.now() / 1000),
        model_version: '0.2.2+regex-v1',
        lens_version: '0.2.2',
        confidence: 0.92,
      }),
    /client-side validation failed/,
  );
  // The mock should not have received this event.
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(mock.events.length, before, 'no event reached mock');
});

await test('rate limit: 100 events succeed, 101st is silently dropped', async () => {
  const c = new APIClient({ baseUrl: mock.baseUrl, bearerToken: TOKEN });
  const before = mock.events.length;
  const baseTs = Math.floor(Date.now() / 1000);
  let accepted = 0;
  let dropped = 0;
  for (let i = 0; i < 105; i++) {
    const ok = await c.sendEvent({
      lens_event_version: 1,
      domain_hash: '0a1b2c3d4e5f6071',
      category: 'pii_email',
      severity: 'low',
      user_action: 'dismiss',
      timestamp: baseTs,
      model_version: '0.2.2+regex-v1',
      lens_version: '0.2.2',
      confidence: 0.5,
    });
    if (ok) accepted++;
    else dropped++;
  }
  assert.equal(accepted, 100, `expected exactly 100 accepted, got ${accepted}`);
  assert.equal(dropped, 5, `expected exactly 5 dropped, got ${dropped}`);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(mock.events.length - before, 100, 'mock saw exactly 100 new events');
});

await test('http://production-style URL is rejected at construction', () => {
  // The constructor may reject this at two points: the scheme check
  // (if http is not in the allowlist) or the host check (if http is
  // allowed but the host isn't localhost). Both are correct outcomes
  // for "production-style http is not allowed."
  assert.throws(
    () => new APIClient({ baseUrl: 'http://lens.aegisgatesecurity.io', bearerToken: TOKEN }),
    /unsupported scheme|http is only allowed for localhost/,
  );
});

await test('https:// is allowed at construction', () => {
  assert.doesNotThrow(
    () => new APIClient({ baseUrl: 'https://lens.aegisgatesecurity.io', bearerToken: TOKEN }),
  );
});

await test('http://127.0.0.1 (localhost) is allowed', () => {
  assert.doesNotThrow(
    () => new APIClient({ baseUrl: 'http://127.0.0.1:8080', bearerToken: TOKEN }),
  );
});

await test('http://example.com is rejected (not localhost)', () => {
  assert.throws(
    () => new APIClient({ baseUrl: 'http://example.com', bearerToken: TOKEN }),
    /localhost\/127.0.0.1/,
  );
});

await test('missing bearer token is rejected at construction', () => {
  assert.throws(
    () => new APIClient({ baseUrl: mock.baseUrl, bearerToken: '' }),
    /bearerToken must be non-empty/,
  );
});

await test('invalid baseUrl is rejected at construction', () => {
  assert.throws(
    () => new APIClient({ baseUrl: 'not a url', bearerToken: TOKEN }),
    /invalid baseUrl/,
  );
});

await test('JSONL output contains every accepted event (one per line)', async () => {
  // The mock writes each accepted event to the JSONL. We verify the file
  // exists and contains parseable lines.
  const raw = nodeFs.readFileSync(mock.outputPath, 'utf8');
  const lines = raw.split('\n').filter((l) => l.length > 0);
  assert.ok(lines.length >= 101, `expected >= 101 lines, got ${lines.length}`);
  for (const line of lines) {
    const obj = JSON.parse(line);
    assert.equal(obj.lens_event_version, 1);
  }
});

// ----- Cleanup + summary ---------------------------------------------------

await shutdown(mock.server);

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
