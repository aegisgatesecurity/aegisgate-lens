#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.2 - Sliding Window Algorithm Test
//
// Tests the sliding window algorithm using a mock ORT session.
// Validates the full pipeline: text → tokenize → extractWindows →
// mock score per window → max-pool → threshold.

import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const tmSrc = fs.readFileSync(
  path.join(repoRoot, 'src/util/transformer-modernbert.js'),
  'utf8'
);

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  PASS  ${name}`);
    })
    .catch((err) => {
      failed++;
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
    });
}

console.log('AegisGate Lens v0.2 - Sliding Window Algorithm Test');
console.log('');

function loadTM(defaultScore) {
  // Create a FRESH AegisGateLens per test (not shared across tests)
  const AegisGateLens = { logger: console };

  // Build mock session. To produce a target probability P via
  // softmax([0, logit1])[1] = P, we need logit1 = ln(P / (1 - P)).
  function logitFromProb(p) {
    return Math.log(p / (1 - p));
  }
  const mockSession = {
    inputNames: ['input_ids', 'attention_mask'],
    outputNames: ['logits'],
    run: async function (feeds) {
      const batchSize = feeds.input_ids.dims[0];
      const data = new Float64Array(batchSize * 2);
      for (let b = 0; b < batchSize; b++) {
        data[b * 2] = 0;
        data[b * 2 + 1] = logitFromProb(defaultScore);
      }
      return { logits: { dims: [batchSize, 2], data: Float32Array.from(data) } };
    },
  };

  // Mock tokenizer: HuggingFace-style object with .model.vocab
  const mockVocab = {};
  for (let i = 0; i < 50000; i++) {
    mockVocab['tok_' + i] = i;
  }
  mockVocab['[UNK]'] = 3;
  mockVocab['[PAD]'] = 1;
  mockVocab['[CLS]'] = 0;
  mockVocab['[SEP]'] = 2;

  const mockTokenizer = {
    model: { vocab: mockVocab },
  };

  // Mock ort namespace
  const mockOrt = {
    Tensor: function (type, data, dims) {
      this.type = type;
      this.data = data;
      this.dims = dims;
    },
  };

  const sandbox = {
    console,
    crypto: globalThis.crypto,
    TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise,
    Number, Set, String, Boolean, Buffer,
    Date, Math: Math,
    performance: { now: () => Date.now() },
    self: {},
    ort: mockOrt,
    AegisGateLens,
  };
  sandbox.self.AegisGateLens = AegisGateLens;

  const ctx = vm.createContext(sandbox);
  vm.runInContext(tmSrc, ctx, { filename: 'transformer-modernbert.js' });

  return AegisGateLens.util.transformerModernBert.prewarm({
    session: mockSession,
    tokenizer: mockTokenizer,
    tokenizerConfig: { cls_token_id: 0, sep_token_id: 1, pad_token_id: 2, unk_token_id: 3 },
    modelMaxLength: 8192,
  }).then(() => AegisGateLens.util.transformerModernBert);
}

// ============================================================================
// Tests
// ============================================================================

await test('T1: extractWindows with short text (adaptive short-circuit)', async () => {
  const tm = await loadTM(0.1);
  // 100 chars → 1 window padded to 512 (ADAPTIVE_SHORT_THRESHOLD)
  const ids = Array.from({ length: 100 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  assert.equal(windows.length, 1, 'short text should produce 1 window');
});

await test('T2: extractWindows with text = 2048 tokens (1 window)', async () => {
  const tm = await loadTM(0.1);
  const ids = Array.from({ length: 2048 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  assert.equal(windows.length, 1);
});

await test('T3: extractWindows with text = 3000 tokens (2 windows)', async () => {
  const tm = await loadTM(0.1);
  const ids = Array.from({ length: 3000 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  assert.equal(windows.length, 2);
});

await test('T4: extractWindows with 10000 tokens (4 sliding + 1 tail = 5 windows)', async () => {
  const tm = await loadTM(0.1);
  const ids = Array.from({ length: 10000 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  // MAX_WINDOWS=4 sliding + 1 right-aligned tail when MAX hit and tokens remain
  assert.equal(windows.length, 5, '10000 tokens → 4 sliding + 1 tail = 5 windows');
  // Tail window should be right-aligned: covers [10000-2048, 10000]
  // The first token in a window is always CLS (id 0), so we look at the
  // position past CLS to verify the data alignment.
  const tailInputIds = windows[4].inputIds;
  assert.equal(Number(tailInputIds[1]), 7952, 'tail window data starts at 7952');
});

await test('T5: score returns mock score (mock returns configured value)', async () => {
  const tm = await loadTM(0.6);
  // Long text → multiple windows. Mock returns 0.6 for all.
  // But tokenizeFull may lose some text due to BPE simplification.
  // So we just check that the score is in a reasonable range.
  const text = 'a'.repeat(5000);
  const score = await tm.score(text);
  assert.ok(score >= 0 && score <= 1, 'score should be in [0, 1]');
  // With our mock, score should be near 0.6 (max-pool of same value)
  assert.ok(Math.abs(score - 0.6) < 0.1, 'mock score should be near 0.6, got ' + score);
});

await test('T6: classify with mock score 0.8 → attack (>= 0.05)', async () => {
  const tm = await loadTM(0.8);
  const result = await tm.classify('a'.repeat(1000));
  assert.ok(result.attack === true, 'mock score 0.8 should classify as attack (>= 0.05)');
  assert.ok(result.score >= 0.7, 'mock score 0.8 should be returned, got ' + result.score);
});

await test('T7: classify with mock score 0.001 → benign (< 0.05)', async () => {
  const tm = await loadTM(0.001);
  const result = await tm.classify('a'.repeat(1000));
  // After sigmoid + softmax + inverse, low logit → low probability.
  // Threshold is 0.05 so 0.001 logit should produce ~0.005 probability.
  assert.ok(result.attack === false, 'mock score 0.001 should classify as benign (< 0.05)');
  assert.ok(result.score < 0.05, 'mock score should be < 0.05, got ' + result.score);
});

await test('T8: getConfig returns sliding window params', async () => {
  const tm = await loadTM(0.1);
  const cfg = tm.getConfig();
  assert.equal(cfg.threshold, 0.05);
  assert.equal(cfg.max_length, 2048);  // Note: getConfig uses max_length, not sliding_window
  assert.equal(cfg.stride, 1024);
  assert.equal(cfg.max_windows, 4);
  assert.equal(cfg.adaptive_short_threshold, 512);
  assert.equal(cfg.aggregation, 'max');
});

await test('T9: getStats tracks inference count', async () => {
  const tm = await loadTM(0.5);
  await tm.score('a'.repeat(1000));
  await tm.score('b'.repeat(1000));
  const stats = tm.getStats();
  assert.ok(stats.inference_count >= 2, 'should have at least 2 inferences');
  assert.ok(stats.total_windows_scored >= 2, 'should have scored windows');
});

await test('T10: short text bypasses sliding (adaptive short-circuit)', async () => {
  const tm = await loadTM(0.5);
  await tm.score('short');  // < 512 adaptive threshold
  const stats = tm.getStats();
  assert.ok(stats.short_circuit_count >= 1, 'should have at least 1 short-circuit count');
});

await test('T11: long text uses sliding window', async () => {
  const tm = await loadTM(0.5);
  await tm.score('a'.repeat(1000));
  const stats = tm.getStats();
  assert.ok(stats.sliding_count >= 1, 'should have at least 1 sliding count');
});

await test('T12: 4-window sliding cap is enforced (4 + 1 tail = 5)', async () => {
  const tm = await loadTM(0.5);
  const ids = Array.from({ length: 20000 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  assert.equal(windows.length, 5, '20K tokens → 5 windows (4 sliding + 1 tail)');
  // Verify cap holds for even longer text
  const ids2 = Array.from({ length: 50000 }, (_, i) => i);
  const windows2 = tm._extractWindows(ids2, 2048, 1024, 4);
  assert.equal(windows2.length, 5, '50K tokens → 5 windows (cap holds)');
});

await test('T13: runBatch with mock session returns per-window scores', async () => {
  const tm = await loadTM(0.42);
  const ids = Array.from({ length: 5000 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  const probs = await tm._runBatch(windows);
  assert.equal(probs.length, windows.length, 'one score per window');
  for (const p of probs) {
    assert.ok(p >= 0 && p <= 1, 'probability should be in [0, 1]');
  }
});

await test('T14: buildWindow adds CLS, SEP, PADs to max_length', async () => {
  const tm = await loadTM(0.1);
  // Test the buildWindow via extractWindows
  const ids = Array.from({ length: 100 }, (_, i) => i);
  const windows = tm._extractWindows(ids, 2048, 1024, 4);
  const w = windows[0];
  // Short text → padded to 512 (ADAPTIVE_SHORT_THRESHOLD)
  assert.equal(w.inputIds.length, 512, 'short text padded to 512');
  assert.equal(w.attentionMask.length, 512);
  // CLS is first token, SEP is after content, then PADs
  assert.equal(w.inputIds[0], 0, 'first token should be CLS (0)');
});

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);
if (failed > 0) process.exit(1);