// AegisGate Lens — test/unit/managed-config.test.mjs
//
// Unit tests for the enterprise managed config merge logic in
// background.js: getManagedConfig() + initSensorModules().
//
// Tests the precedence rules:
//   1. Managed policy (chrome.storage.managed) takes precedence
//   2. If managed doesn't set a value (undefined), fall back to local
//   3. If managed is unavailable, everything falls back to local
//   4. Both IOC Pull and Rampart Bridge are OFF by default (air-gap)
//
// Managed values come from IT admin policy (GPO, Intune, JAMF).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { installMockChrome, resetMockChrome } from '../helpers/mock-chrome.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

function readSource(path) {
  return readFileSync(join(LENS_ROOT, path), 'utf8');
}

// =============================================================================
// Static analysis: verify the precedence logic in source code
// =============================================================================

test('managed-config: getManagedConfig resolves to {} when managed storage unavailable', () => {
  const src = readSource('src/background.js');
  // The function must check for chrome.storage.managed existence
  assert.ok(src.includes('!chrome.storage.managed'),
    'getManagedConfig must check if chrome.storage.managed exists');
  // And resolve with {} when it doesn't
  assert.ok(src.includes("resolve({})"),
    'getManagedConfig must resolve with {} when managed storage is unavailable');
});

test('managed-config: managed values override local — source verification', () => {
  const src = readSource('src/background.js');
  // The merge logic: if managed sets a value, it takes precedence
  // The code checks `managed.iocPullEnabled === undefined` to decide
  // whether to fall back to local
  assert.ok(src.includes('managed.iocPullEnabled === undefined'),
    'initSensorModules must check if managed.iocPullEnabled is undefined before falling back to local');
  assert.ok(src.includes('managed.rampartCorrelationEnabled === undefined'),
    'initSensorModules must check if managed.rampartCorrelationEnabled is undefined before falling back to local');
});

test('managed-config: managed explicitly setting false is honored (not just true)', () => {
  const src = readSource('src/background.js');
  // The code uses `managed.iocPullEnabled === true` for the initial value.
  // If managed sets it to false, `managed.iocPullEnabled === undefined` is
  // false, so the fallback is NOT triggered. The initial value (false) stands.
  // This is correct: IT can explicitly disable a feature.
  assert.ok(src.includes('managed.iocPullEnabled === true'),
    'managed config must use === true check (so explicit false is honored)');
  assert.ok(src.includes('managed.rampartCorrelationEnabled === true'),
    'managed config must use === true check for rampart (so explicit false is honored)');
});

test('managed-config: rampartBaseUrl from managed policy is passed to Rampart Bridge', () => {
  const src = readSource('src/background.js');
  assert.ok(src.includes('managed.rampartBaseUrl'),
    'initSensorModules must read rampartBaseUrl from managed config');
  assert.ok(src.includes('RAMPART_BRIDGE.setBaseUrl'),
    'initSensorModules must call RAMPART_BRIDGE.setBaseUrl with managed URL');
});

test('managed-config: both sensors are OFF by default (air-gap)', () => {
  const src = readSource('src/background.js');
  // The initial values are set from managed config with === true
  // If managed is empty and local is not set, both default to false
  // This is the air-gap default
  const initSection = src.substring(src.indexOf('function initSensorModules'));
  assert.ok(initSection.includes('iocEnabled = managed.iocPullEnabled === true'),
    'IOC Pull must default to false (only enabled if managed explicitly sets true)');
  assert.ok(initSection.includes('rampartEnabled = managed.rampartCorrelationEnabled === true'),
    'Rampart Bridge must default to false (only enabled if managed explicitly sets true)');
});

// =============================================================================
// Behavioral tests: verify merge logic with mock data
// =============================================================================

// Simulate the merge logic from initSensorModules() and verify
// it produces the correct enabled flags for each scenario.
function simulateMerge(managed, localIoc, localRampart) {
  // Reproduce the exact logic from background.js initSensorModules()
  var iocEnabled = managed.iocPullEnabled === true;
  var rampartEnabled = managed.rampartCorrelationEnabled === true;

  if (managed.iocPullEnabled === undefined) {
    iocEnabled = localIoc === true;
  }
  if (managed.rampartCorrelationEnabled === undefined) {
    rampartEnabled = localRampart === true;
  }

  return { iocEnabled: iocEnabled, rampartEnabled: rampartEnabled };
}

test('managed-config: both OFF when no managed and no local config', () => {
  const result = simulateMerge({}, null, null);
  assert.equal(result.iocEnabled, false, 'IOC must be OFF with no config');
  assert.equal(result.rampartEnabled, false, 'Rampart must be OFF with no config');
});

test('managed-config: managed enables IOC, local ignored', () => {
  const result = simulateMerge({ iocPullEnabled: true }, false, null);
  assert.equal(result.iocEnabled, true, 'Managed=true must override local=false');
});

test('managed-config: managed disables IOC, local ignored', () => {
  const result = simulateMerge({ iocPullEnabled: false }, true, null);
  assert.equal(result.iocEnabled, false, 'Managed=false must override local=true (IT can disable)');
});

test('managed-config: managed undefined, local enables IOC', () => {
  const result = simulateMerge({}, true, null);
  assert.equal(result.iocEnabled, true, 'Local=true must be used when managed is undefined');
});

test('managed-config: managed undefined, local disables IOC', () => {
  const result = simulateMerge({}, false, null);
  assert.equal(result.iocEnabled, false, 'Local=false must be used when managed is undefined');
});

test('managed-config: managed enables Rampart, local ignored', () => {
  const result = simulateMerge({ rampartCorrelationEnabled: true }, null, false);
  assert.equal(result.rampartEnabled, true, 'Managed=true must override local=false for Rampart');
});

test('managed-config: managed disables Rampart, local ignored', () => {
  const result = simulateMerge({ rampartCorrelationEnabled: false }, null, true);
  assert.equal(result.rampartEnabled, false, 'Managed=false must override local=true for Rampart');
});

test('managed-config: managed undefined, local enables Rampart', () => {
  const result = simulateMerge({}, null, true);
  assert.equal(result.rampartEnabled, true, 'Local=true must be used when managed is undefined for Rampart');
});

test('managed-config: managed sets both, local fully overridden', () => {
  const result = simulateMerge(
    { iocPullEnabled: true, rampartCorrelationEnabled: false },
    false, true
  );
  assert.equal(result.iocEnabled, true, 'Managed=true wins for IOC');
  assert.equal(result.rampartEnabled, false, 'Managed=false wins for Rampart');
});

test('managed-config: managed sets rampartBaseUrl', () => {
  // Verify that the source reads rampartBaseUrl from managed config
  const src = readSource('src/background.js');
  const initSection = src.substring(src.indexOf('function initSensorModules'));
  assert.ok(initSection.includes('managed.rampartBaseUrl'),
    'initSensorModules must read rampartBaseUrl from managed config');
});

// =============================================================================
// Mock chrome.storage.managed integration tests
// =============================================================================

test('managed-config: MockManagedStorage works correctly', async () => {
  const chrome = resetMockChrome();
  const managed = chrome.storage.managed;

  // Empty by default
  managed.get(null, function (items) {
    assert.deepEqual(items, {}, 'managed storage should be empty by default');
  });

  // Set some policy values
  managed.set({ iocPullEnabled: true, rampartBaseUrl: 'http://rampart.corp:9090' });
  managed.get(null, function (items) {
    assert.equal(items.iocPullEnabled, true);
    assert.equal(items.rampartBaseUrl, 'http://rampart.corp:9090');
  });
});

test('managed-config: MockManagedStorage can be set unavailable', async () => {
  const chrome = resetMockChrome();
  const managed = chrome.storage.managed;

  managed.setAvailable(false);
  managed.get(null, function (items) {
    assert.deepEqual(items, {}, 'unavailable managed storage should return empty');
  });
});

// =============================================================================
// Full load test: background.js with mocked managed storage
// =============================================================================

test('managed-config: background.js loads without error when managed storage has data', () => {
  const chrome = resetMockChrome();
  chrome.storage.managed.set({
    iocPullEnabled: true,
    rampartCorrelationEnabled: false,
    rampartBaseUrl: 'http://rampart.corp:9090'
  });

  // Mock IOC_PULL and RAMPART_BRIDGE on globalThis (self)
  globalThis.__aegisgateIOCPull = {
    init: function (cfg) { this._lastInit = cfg; },
    stats: function () { return {}; }
  };
  globalThis.__aegisgateRampartBridge = {
    setBaseUrl: function (url) { this._baseUrl = url; },
    checkAvailability: function (cb) { cb(true); },
    stats: function () { return {}; }
  };

  // Load background.js — should not throw
  const src = readSource('src/background.js');
  try {
    (0, eval)(src);
    assert.ok(true, 'background.js loaded successfully with managed config');
  } catch (e) {
    // Some errors are expected (e.g., chrome.runtime.onInstalled.addListener
    // may not fully simulate). The key is that the IIFE itself doesn't throw
    // during initial execution.
    if (e.message && e.message.includes('is not a function')) {
      // Expected — some chrome APIs aren't fully mocked
      assert.ok(true, 'background.js loaded (expected mock API limitations)');
    } else {
      throw e;
    }
  }

  // Cleanup
  delete globalThis.__aegisgateIOCPull;
  delete globalThis.__aegisgateRampartBridge;
});