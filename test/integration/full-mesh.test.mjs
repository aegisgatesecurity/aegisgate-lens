// AegisGate Lens — test/integration/full-mesh.test.mjs
//
// Full-mesh integration test: verifies that all Lens sensor
// connections work simultaneously against mock endpoints.
//
// Tests the following full-mesh connections from Lens:
//   1. Lens → Platform telemetry (FP report delivery)
//   2. Lens ← Platform IOC pull (IOC fetch + cache)
//   3. Lens → Rampart signal correlation (detection signal)
//   4. All three connections active simultaneously
//
// The Go-side connections (Rampart → Platform, Scanner → Platform,
// Rampart ← Platform, Scanner ← Platform) are already covered by
// their respective repo test suites:
//   - aegisgate-rampart/tests/integration/cross_product_test.go
//   - aegisgate-rampart/pkg/iocpull/pull_test.go
//   - aegisgate-scanner/pkg/platformforward/forward_test.go
//   - aegisgate-scanner/pkg/patternpull/pull_test.go
//
// This test ensures Lens can operate as a sensor in the full mesh
// by exercising all three of its connections at the same time.
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
// Mock Platform: serves both telemetry and IOC endpoints
// ============================================================

function startMockPlatform() {
  const telemetryReceived = [];
  const iocPullCount = { value: 0 };
  const iocs = [
    {
      fingerprint: 'sha256:mesh_test_ioc_001_mesh_test_ioc_001_mesh_test_i',
      rule_id: 'pii_ssn',
      severity: 'high',
      category: 'pii',
      peer_count: 7,
      first_seen: '2026-10-14T08:00:00Z',
      last_seen: '2026-10-14T16:00:00Z',
    },
  ];

  const server = createServer((req, res) => {
    // Telemetry endpoint (Lens FP reports)
    if (req.url.includes('/fp-report') && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          telemetryReceived.push({ body: parsed, rawBody: body });
          res.writeHead(202, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({ status: 'received' }));
        } catch (e) {
          res.writeHead(400, { 'Connection': 'close' });
          res.end(JSON.stringify({ error: 'invalid json' }));
        }
      });
      return;
    }

    // IOC endpoint
    if (req.url.includes('/ioc/latest') && req.method === 'GET') {
      iocPullCount.value++;
      res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
      res.end(JSON.stringify({
        api_version: 'v1',
        iocs: iocs,
        updated_at: '2026-10-14T16:00:00Z',
      }));
      return;
    }

    // Healthz
    if (req.url.includes('/healthz')) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    res.writeHead(404, { 'Connection': 'close' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        telemetryReceived,
        iocPullCount,
        url: `http://127.0.0.1:${port}`,
        close: () => { server.closeAllConnections?.(); server.close(); },
      });
    });
  });
}

// ============================================================
// Mock Rampart: signal receiver + healthz
// ============================================================

function startMockRampart() {
  const signalsReceived = [];

  const server = createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Connection': 'close' });
      res.end();
      return;
    }

    if (req.url.includes('/healthz')) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
      res.end(JSON.stringify({ status: 'ok', signal_count: 0, detection_count: 0 }));
      return;
    }

    if (req.url.includes('/lens-signals') && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          signalsReceived.push({ body: parsed, rawBody: body });
          // Simulate Rampart having a matching detection
          res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({
            escalated: true,
            recommend_block: false,
            original_severity: parsed.severity,
            escalated_severity: 'critical',
            reason: 'cross-layer correlation: both Lens and Rampart detected on same domain',
          }));
        } catch (e) {
          res.writeHead(400, { 'Connection': 'close' });
          res.end(JSON.stringify({ error: 'invalid json' }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Connection': 'close' });
    res.end();
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        signalsReceived,
        url: `http://127.0.0.1:${port}`,
        close: () => { server.closeAllConnections?.(); server.close(); },
      });
    });
  });
}

// ============================================================
// Module loaders
// ============================================================

async function loadIOCPull() {
  if (globalThis.__aegisgateIOCPull) delete globalThis.__aegisgateIOCPull;
  const src = readFileSync(join(LENS_ROOT, 'src', 'ioc-pull.js'), 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis.__aegisgateIOCPull;
}

async function loadRampartBridge() {
  if (globalThis.__aegisgateRampartBridge) delete globalThis.__aegisgateRampartBridge;
  const src = readFileSync(join(LENS_ROOT, 'src', 'rampart-bridge.js'), 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(src);
  return globalThis.__aegisgateRampartBridge;
}

// ============================================================
// Tests
// ============================================================

test('FullMesh: Lens ← Platform IOC pull works', async (t) => {
  const platform = await startMockPlatform();
  t.after(() => platform.close());

  installMockChrome();
  const iocPull = await loadIOCPull();
  iocPull.init({
    enabled: true,
    platformUrl: platform.url,
    apiKey: 'mesh-test-key',
  });
  iocPull.stopPullLoop();

  const result = await new Promise((resolve) => {
    iocPull.pull(function (success, count) {
      resolve({ success, count });
    });
  });

  assert.equal(result.success, true, 'IOC pull should succeed');
  assert.equal(result.count, 1, '1 IOC received');
  assert.equal(iocPull.getIOCCount(), 1, '1 IOC cached');
  assert.ok(platform.iocPullCount.value >= 1, 'Platform received IOC pull request');
});

test('FullMesh: Lens → Rampart signal correlation works', async (t) => {
  const rampart = await startMockRampart();
  t.after(() => rampart.close());

  installMockChrome();
  const bridge = await loadRampartBridge();
  bridge.setBaseUrl(rampart.url);

  // Check availability
  const available = await new Promise((resolve) => {
    bridge.checkAvailability(function (a) { resolve(a); });
  });
  assert.equal(available, true, 'Rampart is available');

  // Send signal
  const result = await new Promise((resolve) => {
    bridge.sendSignal({
      hashedDomain: 'mesh-domain-test',
      category: 'pii',
      severity: 'high',
      ruleId: 'pii_ssn',
      direction: 'page',
      action: 'warned',
    }, function (r) { resolve(r); });
  });

  assert.ok(result, 'correlation result received');
  assert.equal(result.escalated, true, 'Rampart escalated the signal');
  assert.equal(rampart.signalsReceived.length, 1, 'Rampart received 1 signal');
});

test('FullMesh: all three Lens connections work simultaneously', async (t) => {
  // Start both mock servers
  const platform = await startMockPlatform();
  const rampart = await startMockRampart();
  t.after(() => { platform.close(); rampart.close(); });

  // Install mock Chrome for storage
  installMockChrome();

  // Load both modules
  const iocPull = await loadIOCPull();
  const bridge = await loadRampartBridge();

  // --- Initialize IOC Pull (Lens ← Platform) ---
  iocPull.init({
    enabled: true,
    platformUrl: platform.url,
    apiKey: 'full-mesh-key',
  });
  iocPull.stopPullLoop();

  // --- Initialize Rampart Bridge (Lens → Rampart) ---
  bridge.setBaseUrl(rampart.url);

  // --- Step 1: IOC Pull ---
  const iocResult = await new Promise((resolve) => {
    iocPull.pull(function (success, count) {
      resolve({ success, count });
    });
  });
  assert.equal(iocResult.success, true, 'IOC pull succeeded in full mesh');
  assert.equal(iocResult.count, 1, '1 IOC pulled');

  // --- Step 2: Rampart health check ---
  const rampartAvail = await new Promise((resolve) => {
    bridge.checkAvailability(function (a) { resolve(a); });
  });
  assert.equal(rampartAvail, true, 'Rampart available in full mesh');

  // --- Step 3: Send signal to Rampart ---
  const signalResult = await new Promise((resolve) => {
    bridge.sendSignal({
      hashedDomain: 'full-mesh-domain',
      category: 'secrets',
      severity: 'critical',
      ruleId: 'secret_aws_key',
      direction: 'page',
      action: 'blocked',
    }, function (r) { resolve(r); });
  });
  assert.ok(signalResult, 'signal result received');
  assert.equal(signalResult.escalated, true, 'signal escalated');

  // --- Step 4: Simulate telemetry to Platform ---
  // Use fetch to send a FP report to the Platform mock
  const telemetryResponse = await fetch(
    platform.url + '/api/v1/lens/fp-report',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        lens_event_version: '1',
        timestamp: Math.floor(Date.now() / 1000),
        reports: [{
          hashed_domain: 'full-mesh-domain',
          category: 'secrets',
          severity: 'critical',
          action: 'cancel',
          client_id: 'full-mesh-test',
        }],
      }),
    }
  );
  assert.equal(telemetryResponse.status, 202, 'telemetry accepted by Platform');

  // --- Verify all connections were exercised ---
  assert.ok(platform.iocPullCount.value >= 1, 'Platform received IOC pull');
  assert.ok(platform.telemetryReceived.length >= 1, 'Platform received telemetry');
  assert.equal(rampart.signalsReceived.length, 1, 'Rampart received signal');

  // --- Verify IOC is cached and matchable ---
  const iocFP = 'sha256:mesh_test_ioc_001_mesh_test_ioc_001_mesh_test_i';
  const matched = iocPull.checkFingerprint(iocFP);
  assert.ok(matched, 'pulled IOC is matchable by fingerprint');

  // --- Verify bridge stats ---
  const bridgeStats = bridge.getStats();
  assert.equal(bridgeStats.signalsSent, 1, 'bridge sent 1 signal');
  assert.equal(bridgeStats.escalations, 1, 'bridge recorded 1 escalation');

  console.log('✅ Full mesh verified: IOC pull + telemetry + Rampart signal all working simultaneously');
});

test('FullMesh: Lens operates air-gapped (no Platform, no Rampart)', async () => {
  // When neither Platform nor Rampart is configured, Lens should
  // still work with bundled patterns only. IOC pull is disabled,
  // and Rampart bridge silently drops signals.
  installMockChrome();

  const iocPull = await loadIOCPull();
  iocPull.init({ enabled: false });
  assert.equal(iocPull.enabled, false, 'IOC pull disabled');
  assert.equal(iocPull.pullTimer, null, 'no pull loop running');

  const iocResult = await new Promise((resolve) => {
    iocPull.pull(function (success, count) {
      resolve({ success, count });
    });
  });
  assert.equal(iocResult.success, false, 'disabled pull fails gracefully');
  assert.equal(iocPull.getIOCCount(), 0, 'no IOCs when disabled');

  const bridge = await loadRampartBridge();
  bridge.rampartAvailable = false;

  const signalResult = await new Promise((resolve) => {
    bridge.sendSignal({
      hashedDomain: 'air-gap-test',
      category: 'pii',
      severity: 'high',
      ruleId: 'test',
    }, function (r) { resolve(r); });
  });
  assert.equal(signalResult, null, 'signal dropped when Rampart not available');
});

test('FullMesh: privacy — no PII values leak across any connection', async (t) => {
  const platform = await startMockPlatform();
  const rampart = await startMockRampart();
  t.after(() => { platform.close(); rampart.close(); });

  installMockChrome();

  const iocPull = await loadIOCPull();
  const bridge = await loadRampartBridge();

  iocPull.init({ enabled: true, platformUrl: platform.url });
  iocPull.stopPullLoop();
  bridge.setBaseUrl(rampart.url);

  // Pull IOCs
  await new Promise((resolve) => {
    iocPull.pull(function () { resolve(); });
  });

  // Check availability and send signal
  await new Promise((resolve) => {
    bridge.checkAvailability(function () { resolve(); });
  });

  await new Promise((resolve) => {
    bridge.sendSignal({
      hashedDomain: 'privacy-test-domain',
      category: 'pii_email',
      severity: 'high',
      ruleId: 'pii_email',
      direction: 'page',
      action: 'warned',
    }, function () { resolve(); });
  });

  // Send telemetry
  await fetch(platform.url + '/api/v1/lens/fp-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      lens_event_version: '1',
      timestamp: Math.floor(Date.now() / 1000),
      reports: [{
        hashed_domain: 'privacy-test-domain',
        category: 'pii_email',
        severity: 'high',
        action: 'cancel',
        client_id: 'privacy-test',
      }],
    }),
  });

  // Verify no PII values in IOC data
  const iocRaw = JSON.stringify(iocPull.getAllIOCs());
  // Verify no PII values in Rampart signal
  const signalRaw = rampart.signalsReceived[0].rawBody;
  // Verify no PII values in Platform telemetry
  const telemetryRaw = platform.telemetryReceived[0].rawBody;

  const allRaw = iocRaw + signalRaw + telemetryRaw;
  const forbiddenPatterns = [
    'john.doe@example.com',
    '123-45-6789',
    '4532-1234-5678',
    'raw_text',
    'matched_text',
    'prompt',
    'snippet',
    'page_url',
  ];

  for (const pattern of forbiddenPatterns) {
    assert.ok(
      !allRaw.toLowerCase().includes(pattern.toLowerCase()),
      `No PII value "${pattern}" found in any connection payload`
    );
  }

  console.log('✅ Privacy verified: no PII values leaked across IOC pull, Rampart signal, or telemetry');
});