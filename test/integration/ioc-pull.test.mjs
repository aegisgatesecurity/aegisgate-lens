// AegisGate Lens — test/integration/ioc-pull.test.mjs
//
// Integration tests for the Lens IOC Pull module (src/ioc-pull.js).
//
// Verifies the Lens ← Platform IOC pull contract:
//   1. Module loads and exports __aegisgateIOCPull
//   2. init() with enabled=true starts a pull loop
//   3. pull() fetches IOCs from mock Platform endpoint
//   4. pull() sends Bearer auth when API key is configured
//   5. pull() handles 304 Not Modified (uses cache)
//   6. pull() handles 401 auth failure gracefully
//   7. pull() handles network errors gracefully
//   8. checkFingerprint() finds matching IOC by fingerprint
//   9. checkRuleDomain() finds matching IOC by rule_id + hashed_domain
//  10. IOCs are persisted in chrome.storage.local
//  11. Privacy: IOC data contains only hashes, no PII values
//  12. Stats are tracked correctly
//
// These tests do NOT require Docker — they use Node's http module
// to create a mock Platform server and verify the contract.
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
// Mock Platform IOC endpoint server
// ============================================================

function startMockIOCPlatform({ requireAuth = false, statusOverride = null } = {}) {
  const received = [];
  const server = createServer((req, res) => {
    if (req.url.includes('/api/v1/ioc/latest')) {
      received.push({
        url: req.url,
        headers: req.headers,
        method: req.method,
      });

      // Handle auth check
      if (requireAuth) {
        const auth = req.headers['authorization'];
        if (!auth || !auth.startsWith('Bearer ')) {
          res.writeHead(401, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({ error: 'unauthorized' }));
          return;
        }
      }

      // Handle status override (for error testing)
      if (statusOverride) {
        res.writeHead(statusOverride, { 'Content-Type': 'application/json', 'Connection': 'close' });
        res.end(JSON.stringify({ error: 'test error' }));
        return;
      }

      // Return valid IOC response
      const iocResponse = {
        api_version: 'v1',
        iocs: [
          {
            fingerprint: 'sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
            rule_id: 'pii_ssn',
            severity: 'high',
            category: 'pii',
            peer_count: 3,
            first_seen: '2026-10-14T10:00:00Z',
            last_seen: '2026-10-14T15:00:00Z',
          },
          {
            fingerprint: 'sha256:789abc012def789abc012def789abc012def789abc012def789abc012def789a',
            rule_id: 'secret_aws_key',
            severity: 'critical',
            category: 'secrets',
            peer_count: 5,
            first_seen: '2026-10-13T08:00:00Z',
            last_seen: '2026-10-14T14:00:00Z',
          },
        ],
        updated_at: '2026-10-14T15:30:00Z',
      };

      res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
      res.end(JSON.stringify(iocResponse));
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
// Helper to load the IOC Pull module fresh
// ============================================================

async function loadIOCPull() {
  installMockChrome();
  // Clear any previous load
  if (globalThis.__aegisgateIOCPull) {
    delete globalThis.__aegisgateIOCPull;
  }
  const src = readFileSync(join(LENS_ROOT, 'src', 'ioc-pull.js'), 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis.__aegisgateIOCPull;
}

// ============================================================
// Tests
// ============================================================

test('IOCPull: module loads and exports __aegisgateIOCPull', async () => {
  const mod = await loadIOCPull();
  assert.ok(mod, '__aegisgateIOCPull is defined');
  assert.equal(typeof mod.init, 'function', 'has init()');
  assert.equal(typeof mod.pull, 'function', 'has pull()');
  assert.equal(typeof mod.checkFingerprint, 'function', 'has checkFingerprint()');
  assert.equal(typeof mod.checkRuleDomain, 'function', 'has checkRuleDomain()');
  assert.equal(typeof mod.startPullLoop, 'function', 'has startPullLoop()');
  assert.equal(typeof mod.stopPullLoop, 'function', 'has stopPullLoop()');
  assert.equal(typeof mod.getStats, 'function', 'has getStats()');
});

test('IOCPull: init() with enabled=false does not start pull loop', async () => {
  const mod = await loadIOCPull();
  mod.init({ enabled: false });
  assert.equal(mod.enabled, false);
  assert.equal(mod.pullTimer, null, 'pull loop not started when disabled');
});

test('IOCPull: pull() returns false when disabled', async () => {
  const mod = await loadIOCPull();
  mod.init({ enabled: false });
  const result = await new Promise((resolve) => {
    mod.pull(function (success, count) {
      resolve({ success, count });
    });
  });
  assert.equal(result.success, false, 'disabled pull should fail');
  assert.equal(result.count, 0, 'disabled pull should return 0 count');
});

test('IOCPull: pull() fetches IOCs from mock Platform', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({
    enabled: true,
    platformUrl: mock.url,
    apiKey: 'test-key-123',
  });

  // Stop the auto-started pull loop to avoid interfering
  mod.stopPullLoop();

  const result = await new Promise((resolve) => {
    mod.pull(function (success, count) {
      resolve({ success, count });
    });
  });

  assert.equal(result.success, true, 'pull should succeed');
  assert.equal(result.count, 2, 'should receive 2 IOCs');
  assert.equal(mod.getIOCCount(), 2, 'cache should have 2 IOCs');
});

test('IOCPull: pull() sends Bearer auth when API key configured', async (t) => {
  const mock = await startMockIOCPlatform({ requireAuth: true });
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({
    enabled: true,
    platformUrl: mock.url,
    apiKey: 'secret-bearer-token',
  });
  mod.stopPullLoop();

  const result = await new Promise((resolve) => {
    mod.pull(function (success, count) {
      resolve({ success, count });
    });
  });

  assert.equal(result.success, true, 'pull should succeed with valid auth');
  assert.equal(mock.received.length, 1, 'one request received');
  const authHeader = mock.received[0].headers['authorization'];
  assert.ok(authHeader, 'Authorization header present');
  assert.ok(authHeader.startsWith('Bearer '), 'Bearer type');
  assert.ok(authHeader.includes('secret-bearer-token'), 'contains API key');
});

test('IOCPull: pull() handles 304 Not Modified', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  // First pull — gets IOCs
  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });
  assert.equal(mod.getIOCCount(), 2, '2 IOCs after first pull');

  // Now mock returns 304
  mock.server.removeAllListeners('request');
  mock.server.on('request', (req, res) => {
    if (req.url.includes('/api/v1/ioc/latest')) {
      res.writeHead(304, { 'Connection': 'close' });
      res.end();
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const result = await new Promise((resolve) => {
    mod.pull(function (success, count) {
      resolve({ success, count });
    });
  });

  assert.equal(result.success, true, '304 should be treated as success');
  assert.equal(result.count, 0, 'no new IOCs on 304');
  assert.equal(mod.getIOCCount(), 2, 'cache still has 2 IOCs from first pull');
});

test('IOCPull: pull() handles 401 auth failure', async (t) => {
  const mock = await startMockIOCPlatform({ statusOverride: 401 });
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url, apiKey: 'wrong-key' });
  mod.stopPullLoop();

  const result = await new Promise((resolve) => {
    mod.pull(function (success, count) {
      resolve({ success, count });
    });
  });

  assert.equal(result.success, false, '401 should fail');
  assert.equal(result.count, 0, 'no IOCs on failure');
  assert.equal(mod.getStats().pullsFailed, 1, 'failed count incremented');
});

test('IOCPull: pull() handles network errors gracefully', async () => {
  const mod = await loadIOCPull();
  // Point at an unreachable port
  mod.init({ enabled: true, platformUrl: 'http://127.0.0.1:1' });
  mod.stopPullLoop();

  const result = await new Promise((resolve) => {
    mod.pull(function (success, count) {
      resolve({ success, count });
    });
  });

  assert.equal(result.success, false, 'network error should fail');
  assert.equal(result.count, 0, 'no IOCs on error');
  assert.equal(mod.getStats().pullsFailed, 1, 'failed count incremented');
});

test('IOCPull: checkFingerprint() finds matching IOC', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });

  const fp = 'sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd';
  const match = mod.checkFingerprint(fp);
  assert.ok(match, 'matching IOC found');
  assert.equal(match.rule_id, 'pii_ssn', 'rule_id matches');
  assert.equal(match.severity, 'high', 'severity matches');

  // Non-matching fingerprint
  const noMatch = mod.checkFingerprint('sha256:nonexistent0000000000000000000000000000000000000000000000000000');
  assert.equal(noMatch, null, 'non-matching fingerprint returns null');
});

test('IOCPull: checkRuleDomain() finds matching IOC', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });

  // The mock IOCs don't have hashed_domain fields, so we manually
  // add one to test checkRuleDomain
  mod.iocs[0].hashed_domain = 'a1b2c3d4e5f6a7b8';
  mod.iocs[0].rule_id = 'pii_ssn';

  const match = mod.checkRuleDomain('pii_ssn', 'a1b2c3d4e5f6a7b8');
  assert.ok(match, 'matching IOC found by rule+domain');
  assert.equal(match.rule_id, 'pii_ssn', 'rule_id matches');

  // Non-matching
  const noMatch = mod.checkRuleDomain('wrong_rule', 'a1b2c3d4e5f6a7b8');
  assert.equal(noMatch, null, 'non-matching rule returns null');
});

test('IOCPull: IOCs are persisted in chrome.storage.local', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  installMockChrome();
  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });

  // Check chrome.storage.local for persisted IOCs
  const stored = await new Promise((resolve) => {
    chrome.storage.local.get(['__aegisgate_iocs'], function (result) {
      resolve(result);
    });
  });

  assert.ok(stored.__aegisgate_iocs, 'IOCs stored in chrome.storage.local');
  assert.equal(stored.__aegisgate_iocs.length, 2, '2 IOCs persisted');
});

test('IOCPull: privacy — IOC data contains only hashes, no PII values', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });

  const allIOCs = mod.getAllIOCs();
  assert.equal(allIOCs.length, 2, '2 IOCs in cache');

  // Serialize and verify no PII values are present
  const raw = JSON.stringify(allIOCs);

  // These PII patterns must NOT appear in IOC data
  const forbiddenPatterns = [
    'john.doe@example.com',
    '123-45-6789',
    '4532-1234-5678-9010',
    'sk-1234567890',
    'prompt',
    'raw_text',
    'matched_text',
    'snippet',
    'content',
  ];

  for (const pattern of forbiddenPatterns) {
    assert.ok(
      !raw.toLowerCase().includes(pattern.toLowerCase()),
      `IOC data must not contain "${pattern}"`
    );
  }

  // IOC entries should only contain: fingerprint, rule_id, severity, category, peer_count, timestamps
  const ioc = allIOCs[0];
  const allowedKeys = ['fingerprint', 'rule_id', 'severity', 'category', 'peer_count', 'first_seen', 'last_seen', 'hashed_domain'];
  for (const key of Object.keys(ioc)) {
    assert.ok(
      allowedKeys.includes(key),
      `IOC entry has unexpected key "${key}"`
    );
  }
});

test('IOCPull: stats are tracked correctly', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();
  mod.resetStats();

  // Successful pull
  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });

  const stats = mod.getStats();
  assert.equal(stats.pullsSuccessful, 1, '1 successful pull');
  assert.equal(stats.pullsFailed, 0, '0 failed pulls');
  assert.equal(stats.iocsLoaded, 2, '2 IOCs loaded');
  assert.ok(stats.lastPullTime, 'lastPullTime set');
});

test('IOCPull: setPullInterval() and pull loop control', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  // Verify loop is stopped
  assert.equal(mod.pullTimer, null, 'pull timer null after stop');

  // Change interval
  mod.setPullInterval(100);
  assert.equal(mod.pullInterval, 100, 'interval updated to 100ms');

  // Start loop
  mod.startPullLoop();
  assert.ok(mod.pullTimer, 'pull timer set after start');

  // Stop loop
  mod.stopPullLoop();
  assert.equal(mod.pullTimer, null, 'pull timer null after stop');
});

test('IOCPull: clearCache() removes all IOCs', async (t) => {
  const mock = await startMockIOCPlatform();
  t.after(() => mock.close());

  const mod = await loadIOCPull();
  mod.init({ enabled: true, platformUrl: mock.url });
  mod.stopPullLoop();

  await new Promise((resolve) => {
    mod.pull(function () { resolve(); });
  });
  assert.equal(mod.getIOCCount(), 2, '2 IOCs before clear');

  mod.clearCache();
  assert.equal(mod.getIOCCount(), 0, '0 IOCs after clear');
  assert.equal(mod.lastUpdated, null, 'lastUpdated reset');
});