#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - WebGPU Execution-Provider Selection Validation Test
//
// Day 31 / Action 2: validate the runtime WebGPU detection + execution
// provider selection logic added to src/util/transformer-engine.js
// (the new EP-selection block).
//
// What this test verifies:
//   1. When navigator.gpu is undefined  -> executionProviders = ['wasm']
//   2. When navigator.gpu exists but requestAdapter() returns null ->
//      executionProviders = ['wasm']
//   3. When navigator.gpu exists AND requestAdapter() returns a valid
//      adapter -> executionProviders = ['webgpu', 'wasm']
//   4. When navigator.gpu.requestAdapter() throws ->
//      executionProviders = ['wasm']  (graceful fallback)
//
// We test by:
//   - Loading the modified transformer-engine.js into a vm sandbox
//   - Stubbing ort to capture executionProviders in the create() call
//   - Stubbing bundleLoader + fetch to return a fake bundle
//   - Stubbing globalThis.navigator.gpu with controllable behavior
//
// This test does NOT require real Chrome WebGPU support. It exercises
// the detection logic with controlled stubs in a Node.js vm context.
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.test_url || `file://${process.argv[1]}`));
const repoRoot = path.resolve(here, '..');

// ----- Load the modified transformer-engine.js -----------------------------

const teText = await fsp.readFile(
  path.join(repoRoot, 'src/util/transformer-engine.js'),
  'utf8'
);

// ----- Build a sandbox for one scenario -----------------------------------

function makeSandbox({ gpuBehavior }) {
  // gpuBehavior: 'absent' | 'null-adapter' | 'valid-adapter' | 'throws'

  const sandbox = {
    console,
    setTimeout,
    clearTimeout,
    Date,
    Object,
    Array,
    Math,
    JSON,
    String,
    Number,
    Boolean,
    Promise,
    Error,
    Map,
    Set,
    TextDecoder,
    TextEncoder,
    BigInt64Array,
    BigInt,
    Response,
    atob,
    Uint8Array,
    ArrayBuffer,
    Buffer,

    // Mock logger: captures all log calls
    _logs: [],
    logger: undefined,  // assigned below to use _logs via this

    // Mock ort (ONNX Runtime Web). Captures create() arguments.
    _ortCreateCall: null,
    ort: {
      Tensor: class {
        constructor(type, data, dims) {
          this.type = type;
          this.data = data;
          this.dims = dims;
        }
      },
      InferenceSession: {
        async create(bytes, options) {
          // IMPORTANT: capture into the LOCAL sandbox reference, not a
          // closure-captured outer variable. Each makeSandbox() call gets
          // its own sandbox; the closure must bind to the sandbox where
          // InferenceSession was defined.
          sandbox._ortCreateCall = {
            bytesLength: bytes.byteLength || bytes.length || 0,
            options: JSON.parse(JSON.stringify(options, (_k, v) =>
              typeof v === 'bigint' ? v.toString() : v
            )),
          };
          return { inputNames: ['input_ids', 'attention_mask'], outputNames: ['logits'] };
        },
      },
    },

    // Mock chrome.runtime for the extension-context branch of getBundleUrl
    chrome: {
      runtime: {
        getURL: (rel) => 'chrome-extension://fake/' + rel,
        getManifest: () => ({ version: '0.2.2' }),
      },
    },

    // Stub fetch so transformer-engine's getBundleUrl() -> fetch path returns
    // a minimal valid ArrayBuffer. parseBundle is also stubbed but loadBundle
    // calls fetch() first, so we have to satisfy that path too.
    fetch: async (url) => {
      // Return a minimal valid Response-like object that arrayBuffer() works on
      return {
        ok: true,
        status: 200,
        async arrayBuffer() {
          // Tiny buffer; the bundle parser is stubbed anyway, so contents don't matter
          return new ArrayBuffer(16);
        },
      };
    },

    // Mock navigator.gpu according to scenario. When gpuBehavior is
    // 'absent', we deliberately OMIT navigator entirely so the source's
    // `typeof navigator !== 'undefined' && navigator.gpu` check returns
    // false. For all other behaviors, we provide navigator with a stub gpu.
    navigator: gpuBehavior === 'absent' ? undefined : {
      gpu: {
        async requestAdapter() {
          // Trace for debugging state-leakage between scenarios.
          sandbox._logs.push(['trace', 'requestAdapter called, behavior=' + gpuBehavior]);
          if (gpuBehavior === 'throws') {
            throw new Error('Simulated WebGPU probe failure');
          }
          if (gpuBehavior === 'null-adapter') {
            return null;
          }
          // 'valid-adapter'
          return {
            requestAdapterInfo: async () => ({ vendor: 'stub', architecture: 'stub-arch' }),
            limits: {},
          };
        },
      },
    },
  };

  // Wire the logger to capture into _logs
  sandbox.logger = {
    info: (...args) => { sandbox._logs.push(['info', ...args]); },
    warn: (...args) => { sandbox._logs.push(['warn', ...args]); },
    error: (...args) => { sandbox._logs.push(['error', ...args]); },
    debug: (...args) => { sandbox._logs.push(['debug', ...args]); },
  };

  vm.createContext(sandbox);

  // Initialize the AegisGateLens namespace and inject dependencies BEFORE
  // running transformer-engine.js, because the source reads
  // NS.logger and NS.bundleLoader at IIFE-load time.
  vm.runInContext(`
    var AegisGateLens = (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens =
      (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens || {};
    AegisGateLens.logger = logger;
    AegisGateLens.bundleLoader = {
      parseBundle: async function (buf) {
        return {
          models: [
            {
              name: 'minilm_model__int8.onnx',
              data: {
                format: 'onnx',
                quantization: 'int8',
                data_b64: Buffer.from(new Uint8Array([8, 7, 1, 2, 3])).toString('base64'),
              },
            },
            {
              name: 'vocab.txt',
              data: ['[PAD]', '[UNK]', '[CLS]', '[SEP]', 'hello', 'world'],
            },
            {
              name: 'minilm_config.json',
              data: { max_length: 128, threshold: 0.5 },
            },
          ],
        };
      },
    };
  `, sandbox);

  vm.runInContext(teText, sandbox, { filename: 'transformer-engine.js' });

  return sandbox;
}

// ----- Test runner ---------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err.message}`);
    if (err.stack) console.log(err.stack.split('\n').slice(1, 5).join('\n'));
  }
}

// prewarm() is fire-and-forget; we need to wait for it to finish.
// Approach: call prewarm(), then poll for cachedSession until it appears,
// or for the error log to appear. Maximum wait = 2s.
async function waitForPrewarm(sb, timeoutMs = 2000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const engine = sb.AegisGateLens.transformerEngine;
    if (engine && engine.isLoaded && engine.isLoaded()) return 'loaded';
    const errLog = sb._logs.find(l => l[0] === 'warn' && String(l[1]).includes('prewarm failed'));
    if (errLog) throw new Error('prewarm failed: ' + errLog.slice(1).join(' '));
    await new Promise(r => setTimeout(r, 25));
  }
  // Surface whatever logs we have so we can debug
  const lastLogs = sb._logs.slice(-5).map(l => `[${l[0]}] ${String(l[1]).substring(0, 100)}`);
  throw new Error('prewarm timed out. Last logs: ' + JSON.stringify(lastLogs));
}

// =========================================================================
// Scenario 1: navigator.gpu is absent (most common case in production today)
// =========================================================================
await test('Scenario 1: navigator.gpu absent -> EP = ["wasm"]', async () => {
  const sb = makeSandbox({ gpuBehavior: 'absent' });
  const engine = sb.AegisGateLens.transformerEngine;
  assert(engine, 'transformerEngine should be exposed on AegisGateLens namespace');
  assert(engine.prewarm, 'engine should expose prewarm()');

  engine.prewarm();
  await waitForPrewarm(sb);

  const epCall = sb._ortCreateCall;
  assert(epCall, 'ort.InferenceSession.create should have been called');
  assert.deepStrictEqual(
    epCall.options.executionProviders,
    ['wasm'],
    'Expected executionProviders = ["wasm"] when navigator.gpu is absent'
  );

  // Verify the log message mentions wasm and NOT webgpu
  const epLog = sb._logs.find(l => l[0] === 'info' && String(l[1]).includes('Execution provider'));
  assert(epLog, 'Expected an info log about execution provider selection');
  assert(String(epLog[1]).includes('wasm'), 'Log should mention wasm');
  assert(!String(epLog[1]).includes('webgpu'), 'Log should NOT mention webgpu');
});

// =========================================================================
// Scenario 2: navigator.gpu present but requestAdapter returns null
// =========================================================================
await test('Scenario 2: navigator.gpu present, adapter null -> EP = ["wasm"]', async () => {
  const sb = makeSandbox({ gpuBehavior: 'null-adapter' });
  const engine = sb.AegisGateLens.transformerEngine;
  engine.prewarm();
  await waitForPrewarm(sb);

  const epCall = sb._ortCreateCall;
  assert(epCall);
  assert.deepStrictEqual(
    epCall.options.executionProviders,
    ['wasm'],
    'Expected executionProviders = ["wasm"] when requestAdapter returns null'
  );
});

// =========================================================================
// Scenario 3: navigator.gpu present AND adapter available (the happy path)
// =========================================================================
await test('Scenario 3: navigator.gpu present, adapter valid -> EP = ["webgpu", "wasm"]', async () => {
  const sb = makeSandbox({ gpuBehavior: 'valid-adapter' });
  const engine = sb.AegisGateLens.transformerEngine;
  engine.prewarm();
  await waitForPrewarm(sb);

  const epCall = sb._ortCreateCall;
  assert(epCall);
  assert.deepStrictEqual(
    epCall.options.executionProviders,
    ['webgpu', 'wasm'],
    'Expected executionProviders = ["webgpu", "wasm"] when WebGPU adapter is valid'
  );

  // Verify the log message
  const epLogs = sb._logs.filter(l => l[0] === 'info' && String(l[1]).includes('Execution provider'));
  assert(epLogs.length >= 1);
  const logText = epLogs.map(l => String(l[1])).join(' ');
  assert(logText.includes('Execution provider: webgpu'), 'Log should identify webgpu as selected');
  assert(logText.includes('webgpu > wasm'), 'Log should show full fallback list');
});

// =========================================================================
// Scenario 4: navigator.gpu.requestAdapter() throws
// =========================================================================
await test('Scenario 4: navigator.gpu.requestAdapter throws -> EP = ["wasm"] (graceful fallback)', async () => {
  const sb = makeSandbox({ gpuBehavior: 'throws' });
  const engine = sb.AegisGateLens.transformerEngine;

  // Should NOT throw; should fall through to WASM
  engine.prewarm();
  await waitForPrewarm(sb);

  const epCall = sb._ortCreateCall;
  assert(epCall);
  assert.deepStrictEqual(
    epCall.options.executionProviders,
    ['wasm'],
    'Expected executionProviders = ["wasm"] when WebGPU probe throws'
  );
});

// =========================================================================
// Scenario 5: graphOptimizationLevel preserved (regression check)
// =========================================================================
await test('Scenario 5: graphOptimizationLevel preserved as "all" (regression check)', async () => {
  const sb = makeSandbox({ gpuBehavior: 'valid-adapter' });
  const engine = sb.AegisGateLens.transformerEngine;
  engine.prewarm();
  await waitForPrewarm(sb);

  const epCall = sb._ortCreateCall;
  assert(epCall);
  assert.strictEqual(
    epCall.options.graphOptimizationLevel,
    'all',
    'graphOptimizationLevel should remain "all" after the WebGPU patch'
  );
});

// =========================================================================
// Scenario 6: detect-shape regression — existing transformer-engine tests
// (tokenizeSimple, isLoaded, etc.) still pass without changes
// =========================================================================
await test('Scenario 6: engine still exposes expected public surface', async () => {
  const sb = makeSandbox({ gpuBehavior: 'absent' });
  const engine = sb.AegisGateLens.transformerEngine;
  assert(engine, 'engine exposed');
  assert(typeof engine.prewarm === 'function', 'prewarm is a function');
  assert(typeof engine.isLoaded === 'function', 'isLoaded is a function');
  assert(typeof engine.scoreTransformer === 'function', 'scoreTransformer is a function');
  assert(typeof engine.getSession === 'function' || typeof engine.getTokenizer === 'function',
    'exposes getters for sliding-window integration');
  assert.strictEqual(engine.isLoaded(), false, 'isLoaded() returns false before prewarm');
});

// ----- Summary -------------------------------------------------------------

console.log('');
console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
if (failures.length > 0) {
  console.log('');
  console.log('Failures:');
  for (const f of failures) {
    console.log(`  - ${f.name}: ${f.err.message}`);
  }
  process.exit(1);
}
console.log('All WebGPU validation tests passed.');