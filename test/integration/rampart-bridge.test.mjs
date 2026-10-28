// AegisGate Lens — test/integration/rampart-bridge.test.mjs
//
// Integration tests for the Lens Rampart Signal Bridge (src/rampart-bridge.js).
//
// Verifies the Lens → Rampart signal correlation contract:
//   1. Module loads and exports __aegisgateRampartBridge
//   2. checkAvailability() detects running Rampart (mock HTTP 200)
//   3. checkAvailability() detects Rampart not running (connection refused)
//   4. checkAvailability() caches result for 30 seconds
//   5. sendSignal() sends detection metadata to Rampart
//   6. sendSignal() silently drops when Rampart not available
//   7. sendSignal() handles correlation result (escalated, recommend_block)
//   8. sendSignal() validates required fields (hashed_domain, category, severity)
//   9. setBaseUrl() changes endpoint URLs
//  10. Privacy: signal contains only metadata, no PII values
//  11. Stats are tracked correctly
//  12. Signal format matches Rampart's LensSignal struct
//
// These tests do NOT require Docker — they use Node's http module
// to create a mock Rampart server and verify the contract.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { installMockChrome, resetMockChrome } from '../helpers/mock-chrome.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// ============================================================
// Mock Rampart server (signal receiver + healthz)
// ============================================================

function startMockRampart({ healthStatus = 200, signalResponse = null } = {}) {
  const received = [];
  const server = createServer((req, res) => {
    // CORS headers (Rampart sends these for browser extension access)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Connection': 'close' });
      res.end();
      return;
    }

    // Health check endpoint
    if (req.url.includes('/healthz')) {
      res.writeHead(healthStatus, { 'Content-Type': 'application/json', 'Connection': 'close' });
      res.end(JSON.stringify({
        status: 'ok',
        signal_count: 0,
        detection_count: 0,
      }));
      return;
    }

    // Signal endpoint
    if (req.url.includes('/lens-signals') && req.method === 'POST') {
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

          // Default response: no correlation (Rampart has no matching detections)
          const response = signalResponse || {
            escalated: false,
            recommend_block: false,
            reason: 'no matching Rampart detections in correlation window',
          };
          res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify(response));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({ error: 'invalid JSON' }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json', 'Connection': 'close' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        received,
        url: `http://127.0.0.1:${port}`,
        close: () => { server.closeAllConnections?.(); server.close(); },
      });
    });
  });
}

// ============================================================
// Helper to load the Rampart Bridge module fresh
// ============================================================

async function loadRampartBridge() {
  installMockChrome();
  if (globalThis.__aegisgateRampartBridge) {
    delete globalThis.__aegisgateRampartBridge;
  }
  const src = readFileSync(join(LENS_ROOT, 'src', 'rampart-bridge.js'), 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis.__aegisgateRampartBridge;
}

// ============================================================
// Tests
// ============================================================

test('RampartBridge: module loads and exports __aegisgateRampartBridge', async () => {
  const mod = await loadRampartBridge();
  assert.ok(mod, '__aegisgateRampartBridge is defined');
  assert.equal(typeof mod.checkAvailability, 'function', 'has checkAvailability()');
  assert.equal(typeof mod.sendSignal, 'function', 'has sendSignal()');
  assert.equal(typeof mod.setBaseUrl, 'function', 'has setBaseUrl()');
  assert.equal(typeof mod.getStats, 'function', 'has getStats()');
});

test('RampartBridge: checkAvailability() detects running Rampart', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  const available = await new Promise((resolve) => {
    mod.checkAvailability(function (avail) {
      resolve(avail);
    });
  });

  assert.equal(available, true, 'Rampart should be available');
  assert.equal(mod.rampartAvailable, true, 'rampartAvailable flag set');
});

test('RampartBridge: checkAvailability() detects Rampart not running', async () => {
  const mod = await loadRampartBridge();
  // Point at an unreachable port
  mod.setBaseUrl('http://127.0.0.1:1');

  const available = await new Promise((resolve) => {
    mod.checkAvailability(function (avail) {
      resolve(avail);
    });
  });

  assert.equal(available, false, 'Rampart should not be available');
  assert.equal(mod.rampartAvailable, false, 'rampartAvailable flag false');
});

test('RampartBridge: checkAvailability() caches result for 30 seconds', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  // First check — hits server
  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  // Stop the server to simulate Rampart going down
  mock.server.close();

  // Second check — should use cached result (within 30s window)
  const available = await new Promise((resolve) => {
    mod.checkAvailability(function (avail) {
      resolve(avail);
    });
  });

  assert.equal(available, true, 'should return cached result (true) within 30s window');
});

test('RampartBridge: sendSignal() sends detection metadata to Rampart', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  // First make Rampart available
  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  const detection = {
    hashedDomain: 'a1b2c3d4e5f6a7b8',
    category: 'pii_email',
    severity: 'high',
    ruleId: 'pii_email',
    direction: 'page',
    action: 'warned',
  };

  const result = await new Promise((resolve) => {
    mod.sendSignal(detection, function (r) { resolve(r); });
  });

  assert.ok(result, 'should receive correlation result');
  assert.equal(mock.received.length, 1, 'Rampart received 1 signal');

  // Verify signal format matches Rampart's LensSignal struct
  const signal = mock.received[0].body;
  assert.equal(signal.hashed_domain, 'a1b2c3d4e5f6a7b8', 'hashed_domain matches');
  assert.equal(signal.category, 'pii_email', 'category matches');
  assert.equal(signal.severity, 'high', 'severity matches');
  assert.equal(signal.rule_id, 'pii_email', 'rule_id matches');
  assert.equal(signal.direction, 'page', 'direction matches');
  assert.equal(signal.action, 'warned', 'action matches');
  assert.ok(signal.timestamp, 'timestamp present');
});

test('RampartBridge: sendSignal() silently drops when Rampart not available', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  // Don't check availability — rampartAvailable defaults to false
  mod.setBaseUrl(mock.url);
  mod.rampartAvailable = false;

  const detection = {
    hashedDomain: 'a1b2c3d4e5f6a7b8',
    category: 'pii',
    severity: 'high',
    ruleId: 'test',
    direction: 'page',
    action: 'warned',
  };

  const result = await new Promise((resolve) => {
    mod.sendSignal(detection, function (r) { resolve(r); });
  });

  assert.equal(result, null, 'should return null when Rampart not available');
  assert.equal(mock.received.length, 0, 'no signal sent to Rampart');
});

test('RampartBridge: sendSignal() handles escalation correlation result', async (t) => {
  const mock = await startMockRampart({
    signalResponse: {
      escalated: true,
      recommend_block: true,
      original_severity: 'high',
      escalated_severity: 'critical',
      reason: 'cross-layer correlation: both Lens and Rampart detected on same domain',
    },
  });
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  const detection = {
    hashedDomain: 'domain-x',
    category: 'pii',
    severity: 'high',
    ruleId: 'pii_ssn',
    direction: 'page',
    action: 'warned',
  };

  const result = await new Promise((resolve) => {
    mod.sendSignal(detection, function (r) { resolve(r); });
  });

  assert.ok(result, 'correlation result received');
  assert.equal(result.escalated, true, 'escalated flag set');
  assert.equal(result.recommend_block, true, 'recommend_block flag set');

  const stats = mod.getStats();
  assert.equal(stats.signalsSent, 1, '1 signal sent');
  assert.equal(stats.escalations, 1, '1 escalation recorded');
  assert.equal(stats.blocksRecommended, 1, '1 block recommendation recorded');
});

test('RampartBridge: sendSignal() validates required fields', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  // Missing hashedDomain — defaults to '', fails validation
  const result1 = await new Promise((resolve) => {
    mod.sendSignal({ category: 'pii', severity: 'high' }, function (r) { resolve(r); });
  });
  assert.equal(result1, null, 'missing hashedDomain returns null');

  // Missing category — defaults to '', fails validation
  const result2 = await new Promise((resolve) => {
    mod.sendSignal({ hashedDomain: 'abc', severity: 'high' }, function (r) { resolve(r); });
  });
  assert.equal(result2, null, 'missing category returns null');

  // Missing severity — defaults to 'low' (by design), signal IS sent
  const result3 = await new Promise((resolve) => {
    mod.sendSignal({ hashedDomain: 'abc', category: 'pii' }, function (r) { resolve(r); });
  });
  assert.ok(result3, 'missing severity defaults to low, signal is sent');

  assert.equal(mock.received.length, 1, '1 signal sent (only severity-missing case defaults to low)');
});

test('RampartBridge: setBaseUrl() changes endpoint URLs', async () => {
  const mod = await loadRampartBridge();

  const defaultSignal = mod.signalEndpoint;
  const defaultHealth = mod.healthEndpoint;
  assert.ok(defaultSignal.includes('127.0.0.1:8443'), 'default signal endpoint');
  assert.ok(defaultHealth.includes('127.0.0.1:8443'), 'default health endpoint');

  mod.setBaseUrl('http://127.0.0.1:9999');

  assert.ok(mod.signalEndpoint.includes('127.0.0.1:9999'), 'signal endpoint updated');
  assert.ok(mod.healthEndpoint.includes('127.0.0.1:9999'), 'health endpoint updated');
  assert.equal(mod.rampartAvailable, false, 'availability reset after URL change');
  assert.equal(mod.lastHealthCheck, 0, 'health check cache reset');
});

test('RampartBridge: privacy — signal contains only metadata, no PII values', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  const detection = {
    hashedDomain: 'a1b2c3d4e5f6a7b8',
    category: 'pii_email',
    severity: 'high',
    ruleId: 'pii_email',
    direction: 'page',
    action: 'warned',
  };

  await new Promise((resolve) => {
    mod.sendSignal(detection, function () { resolve(); });
  });

  const rawBody = mock.received[0].rawBody;

  // These PII / content fields must NOT appear in the signal
  const forbiddenPatterns = [
    'john.doe@example.com',
    '123-45-6789',
    '4532-1234',
    'prompt',
    'raw_text',
    'matched_text',
    'snippet',
    'content',
    'page_url',
    'href',
    'user_id',
    'ip_address',
  ];

  for (const pattern of forbiddenPatterns) {
    assert.ok(
      !rawBody.toLowerCase().includes(pattern.toLowerCase()),
      `Signal body must not contain "${pattern}"`
    );
  }

  // Verify only allowed fields are present
  const signal = mock.received[0].body;
  const allowedKeys = ['hashed_domain', 'category', 'severity', 'rule_id', 'timestamp', 'direction', 'action'];
  for (const key of Object.keys(signal)) {
    assert.ok(
      allowedKeys.includes(key),
      `Signal has unexpected field "${key}"`
    );
  }
});

test('RampartBridge: stats are tracked correctly', async (t) => {
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);
  mod.resetStats();

  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  // Send a successful signal
  await new Promise((resolve) => {
    mod.sendSignal({
      hashedDomain: 'd1',
      category: 'pii',
      severity: 'high',
      ruleId: 'test',
    }, function () { resolve(); });
  });

  const stats = mod.getStats();
  assert.equal(stats.signalsSent, 1, '1 signal sent');
  assert.equal(stats.signalsFailed, 0, '0 failures');
});

test('RampartBridge: signal format matches Rampart LensSignal struct', async (t) => {
  // Verify the JSON field names match exactly what Rampart's
  // pkg/lenscorrelation/receiver.go LensSignal struct expects:
  //   hashed_domain, category, severity, rule_id, timestamp, direction, action
  const mock = await startMockRampart();
  t.after(() => mock.close());

  const mod = await loadRampartBridge();
  mod.setBaseUrl(mock.url);

  await new Promise((resolve) => {
    mod.checkAvailability(function () { resolve(); });
  });

  await new Promise((resolve) => {
    mod.sendSignal({
      hashedDomain: 'test123',
      category: 'secrets',
      severity: 'critical',
      ruleId: 'secret_aws_key',
      direction: 'request',
      action: 'blocked',
    }, function () { resolve(); });
  });

  const signal = mock.received[0].body;

  // Exact field names matching Go struct JSON tags
  assert.equal(typeof signal.hashed_domain, 'string', 'hashed_domain is string');
  assert.equal(typeof signal.category, 'string', 'category is string');
  assert.equal(typeof signal.severity, 'string', 'severity is string');
  assert.equal(typeof signal.rule_id, 'string', 'rule_id is string');
  assert.equal(typeof signal.timestamp, 'string', 'timestamp is string');
  assert.equal(typeof signal.direction, 'string', 'direction is string');
  assert.equal(typeof signal.action, 'string', 'action is string');

  // Severity must be one of Rampart's valid values
  const validSeverities = ['low', 'medium', 'high', 'critical'];
  assert.ok(validSeverities.includes(signal.severity), 'severity is valid');
});

test('RampartBridge: health check endpoint path matches Rampart convention', async () => {
  // Rampart's lenscorrelation receiver exposes healthz at
  // /api/v1/lens-signals/healthz — verify the bridge uses this path
  const mod = await loadRampartBridge();

  assert.ok(
    mod.healthEndpoint.includes('/api/v1/lens-signals/healthz'),
    'health endpoint uses /api/v1/lens-signals/healthz path'
  );
  assert.ok(
    mod.signalEndpoint.includes('/api/v1/lens-signals'),
    'signal endpoint uses /api/v1/lens-signals path'
  );
  assert.ok(
    !mod.signalEndpoint.includes('healthz'),
    'signal endpoint does not include healthz'
  );
});