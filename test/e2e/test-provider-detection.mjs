#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - E2E Provider Detection Test (Day 27)
// =========================================================================
//
// Verifies that each of the 5 canonical AI provider's prompt format is
// correctly classified by the production Tier 3 v9 model.
//
// What this test does:
//   1. Loads each provider's DOM fixture (test/e2e/fixtures/*.dom.json).
//   2. For each fixture, reads the expectedAttacks dict (e.g.,
//      {direct_injection, jailbreak_dan, benign_fiction}).
//   3. Runs each prompt through the Tier 3 ONNX model with sliding-
//      window inference (the production inference path).
//   4. Asserts that:
//        - Attack-class prompts (label=1 in the fixture) are flagged
//          as injection.
//        - Benign-class prompts (those that are LEGITIMATELY benign,
//          e.g., "benign_translation") are classified as benign.
//
// What this test does NOT do:
//   - Drive a real browser. That happens in the Platform monorepo's
//     tools/test-extension/ Go harness using chromedp.
//   - Test the content-script-to-service-worker event flow. That's
//     test/integration.test.mjs.
//
// Why this test exists:
//   - Verifies the Tier 3 model handles EACH provider's typical prompt
//     format. A model that works on ChatGPT prompts may not work on
//     Gemini contenteditable inputs.
//   - Catches regressions when the corpus changes (e.g., adding
//     multilingual prompts that the model hasn't been trained on).
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');

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

// ----- Tier 3 inference wrapper (Node, no deps) ----------------------------
//
// Uses Python's existing ONNX inference (pen-test/tier3_inference.py)
// as a subprocess. The Node side pipes JSON in/out.
//
// Why subprocess instead of in-process:
//   - Tier 3 inference depends on onnxruntime, transformers, numpy -
//     all Python-only. Reimplementing them in Node is a no-deps-rule
//     violation.
//   - The production code path is Python via pen-test/tier3_inference.py;
//     we just delegate to it from Node.
//
// The subprocess uses stdin/stdout JSON for IPC:
//   Node -> Python: {"text": "...", "stride": 64}
//   Python -> Node: {"label": 1, "confidence": 0.97, "n_chunks": 1}

import { spawn } from 'node:child_process';

/**
 * Start a long-running Python worker that classifies prompts via the
 * Tier 3 ONNX model. Communicates over stdin/stdout line-delimited JSON.
 *
 * Returns:
 *   - classify(text, stride) -> Promise<{label, confidence, n_chunks}>
 *   - close() -> cleanup
 */
function startTier3Worker(opts = {}) {
  const modelDir = opts.modelDir
    || path.join(repoRoot, 'ml-artifacts/dist_tier3_v9');
  const stride = opts.stride || 64;
  const python = opts.python
    || path.join(repoRoot, 'pen-test/.venv-tier4/bin/python');

  // Python worker is in test/e2e/_tier3_worker.py (committed). It
  // expects LENS_TIER3_MODEL_DIR env var. Communication is JSON lines
  // over stdin/stdout.
  const workerScript = path.join(here, '_tier3_worker.py');

  const proc = spawn(python, [workerScript], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, LENS_TIER3_MODEL_DIR: modelDir },
  });

  // Buffer for stdout (line-delimited JSON).
  let buf = '';
  const pending = new Map();
  let nextId = 1;
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      try {
        const resp = JSON.parse(line);
        if (resp.id && pending.has(resp.id)) {
          const { resolve, reject } = pending.get(resp.id);
          pending.delete(resp.id);
          if (resp.error) reject(new Error(resp.error));
          else resolve(resp);
        }
      } catch (e) {
        // Ignore malformed lines.
      }
    }
  });

  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk) => {
    process.stderr.write(`[tier3] ${chunk}`);
  });

  function classify(text, strideOverride) {
    const id = nextId++;
    const payload = JSON.stringify({ id, text, stride: strideOverride || stride });
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      try {
        proc.stdin.write(payload + '\n');
      } catch (e) {
        pending.delete(id);
        reject(e);
      }
    });
  }

  function close() {
    try { proc.stdin.end(); } catch (_) { /* ignore */ }
    try { proc.kill(); } catch (_) { /* ignore */ }
  }

  return { classify, close };
}

// ----- Test data ------------------------------------------------------------

// Which attack classes are expected to be flagged as injection (label=1)
// vs which are LEGITIMATELY benign (label=0).
const BENIGN_ATTACK_KEYS = new Set([
  'benign_translation',
  'benign_fiction',
  'benign_normal',
  // long_context is attack-embedded-in-benign. We test the WHOLE
  // prompt as one unit; the Tier 3 model may or may not catch the
  // embedded attack depending on sliding-window chunk coverage. We
  // don't assert on long_context here.
]);

// ----- Tests ----------------------------------------------------------------

console.log('AegisGate Lens - E2E Provider Detection Test (Day 27)');
console.log('');

// Load fixtures.
const fixturesDir = path.join(here, 'fixtures');
const fxFiles = (await fsp.readdir(fixturesDir)).filter(f => f.endsWith('.dom.json'));
const fixtures = await Promise.all(
  fxFiles.map(async f => ({
    file: f,
    fixture: JSON.parse(await fsp.readFile(path.join(fixturesDir, f), 'utf8')),
  }))
);

// Spin up the Tier 3 worker.
console.log('Starting Tier 3 ONNX worker (may take ~5s to load model)...');
const worker = startTier3Worker();
let workerReady = false;
worker.classify('warmup').then(() => {
  workerReady = true;
}).catch((err) => {
  console.error('Worker failed to start:', err.message);
});
// Wait for worker warmup (max 30s).
for (let i = 0; i < 60 && !workerReady; i++) {
  await new Promise(r => setTimeout(r, 500));
}
if (!workerReady) {
  console.error('Tier 3 worker did not become ready in 30s. Aborting.');
  worker.close();
  process.exit(1);
}
console.log('Worker ready.');
console.log('');

// Per-provider tests.
for (const { file, fixture } of fixtures) {
  const { provider, expectedAttacks } = fixture;
  if (!expectedAttacks) continue;

  for (const [key, prompt] of Object.entries(expectedAttacks)) {
    const expectedLabel = BENIGN_ATTACK_KEYS.has(key) ? 0 : 1;

    await test(`[${provider}] ${key} -> label=${expectedLabel}`, async () => {
      const result = await worker.classify(prompt);
      assert.equal(result.label, expectedLabel,
        `[${provider}] ${key}: expected label=${expectedLabel} but got label=${result.label} conf=${result.confidence.toFixed(3)} for prompt: ${JSON.stringify(prompt.slice(0, 80))}`);
    });
  }
}

// Sanity check: direct_injection across all providers should be label=1.
await test('every provider flags direct_injection as injection', async () => {
  for (const { fixture } of fixtures) {
    const prompt = fixture.expectedAttacks?.direct_injection;
    if (!prompt) continue;
    const result = await worker.classify(prompt);
    assert.equal(result.label, 1,
      `[${fixture.provider}] direct_injection was not flagged: ${JSON.stringify(prompt.slice(0, 80))}`);
  }
});

// Cleanup.
worker.close();

// ----- Summary --------------------------------------------------------------

console.log('');
console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);

if (failed > 0) {
  console.log('');
  console.log('Failures:');
  for (const f of failures) {
    console.log(`  - ${f.name}: ${f.err.message}`);
  }
  process.exit(1);
}
process.exit(0);
