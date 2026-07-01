#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens — transformer-toxicity.test.mjs (Phase 2 — Facet 5)
// =========================================================================
//
// Tests for the toxicity inference path.
// Mirrors the transformer-modernbert.test.mjs pattern: mocked ort, vm
// context, and a synthetic tokenizer (HuggingFace tokenizers are too heavy
// for a unit test).
//
// Coverage:
//   1.  Module loads without errors
//   2.  Public API surface is complete
//   3.  Constants match bundle-registry (max_length=512, 6 categories)
//   4.  Pre-warm with injected session/tokenizer works
//   5.  score() raises error when not prewarmed
//   6.  score() returns null on empty text
//   7.  Tokenize produces 512-token arrays with correct CLS/SEP/PAD layout
//   8.  Tokenize handles short text (pads to MAX_LENGTH)
//   9.  Sigmoid: handles positive and negative logits correctly
//   10. score() with mocked session returns 6-category results
//   11. score() flagged=true when any category >= 0.5
//   12. score() flagged=false when all categories < 0.5
//   13. anyToxic=true only when "toxic" category flagged
//   14. Severity mapping is correct (severe_toxic=critical, threat=high, etc.)
//   15. isToxic() fast path returns true/false correctly
//   16. Stats: nScored, nFlagged, nByCategory all update
//   17. isLoaded() returns false before prewarm, true after
//   18. getConfig() exposes the canonical toxicity config
//   19. score() returns null on inference error (graceful degradation)
//   20. FPR sanity: synthetic high-prob-toxic input → flagged
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// ----- Test runner --------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log(`  PASS  ${name}`); })
    .catch((err) => {
      failed++;
      failures.push({ name, err });
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
    });
}

// ----- Load transformer-toxicity.js into a vm context ---------------------

function loadContext({ mockSession = null } = {}) {
  const ctx = {
    console,
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Array,
    Map,
    Object,
    Math,
    JSON,
    Promise,
    Number,
    Set,
    String,
    Boolean,
    Buffer,
    BigInt,
    BigInt64Array,
    performance: { now: () => Date.now() },
    self: {},
  };
  ctx.self = ctx;
  ctx.self.AegisGateLens = {};
  ctx.self.AegisGateLens.logger = {
    info: () => {},
    warn: (...a) => console.warn('[Lens]', ...a),
    error: (...a) => console.error('[Lens]', ...a),
  };

  // Mock ort if no real session provided
  if (mockSession) {
    ctx.ort = {
      InferenceSession: {
        create: async () => mockSession,
      },
    };
  } else {
    ctx.ort = {
      InferenceSession: {
        create: async (bytes, opts) => {
          if (!bytes || bytes.length === 0) throw new Error('empty bytes');
          return null;
        },
      },
    };
  }

  vm.createContext(ctx);

  // Load the file
  const code = fs.readFileSync(path.join(repoRoot, 'lens-final-dist/util/transformer-toxicity.js'), 'utf-8');
  vm.runInContext(code, ctx, { filename: 'transformer-toxicity.js' });

  return ctx;
}

// ----- Synthetic tokenizer (mimics toxic-bert's HF tokenizer) ------------

function makeFakeTokenizer() {
  // BPE-style: encode text by splitting on whitespace, mapping to fake IDs
  let counter = 1000;
  const vocab = new Map();
  function tok(text) {
    if (!vocab.has(text)) vocab.set(text, counter++);
    return vocab.get(text);
  }
  return {
    pad_token_id: 0,
    cls_token_id: 101,
    sep_token_id: 102,
    encode: (text, opts = {}) => {
      // Realistic-ish: split on whitespace, add CLS/SEP, cap at max_length
      const tokens = [101]; // CLS
      const words = String(text).split(/\s+/).filter(Boolean);
      for (const w of words) {
        tokens.push(tok(w.toLowerCase()));
        if (opts.max_length && tokens.length >= opts.max_length - 1) break;
      }
      tokens.push(102); // SEP
      return opts.truncation && opts.max_length ? tokens.slice(0, opts.max_length) : tokens;
    },
  };
}

// ----- Synthetic session (returns pre-canned logits) ---------------------

function makeFakeSession({ logits }) {
  return {
    run: async (feeds) => {
      // Verify the 3 inputs are present and have the right shape
      assert.ok(feeds.input_ids, 'input_ids missing');
      assert.ok(feeds.attention_mask, 'attention_mask missing');
      assert.ok(feeds.token_type_ids, 'token_type_ids missing');
      assert.strictEqual(feeds.input_ids.length, 512, 'input_ids wrong length');
      // Return logits as a BigInt64Array-like (ort returns Tensor, but for
      // testing we wrap in the shape the consumer expects)
      return {
        logits: { data: logits, dims: [1, 6] },
      };
    },
  };
}

// ----- Tests -------------------------------------------------------------

console.log('AegisGate Lens — transformer-toxicity.test.mjs');
console.log('Phase 2 — Facet 5 (Toxicity) Inference');
console.log();

(async () => {
  const F = 'transformerToxicity';

  await test('1. module loads without errors', () => {
    const ctx = loadContext();
    assert.ok(ctx.self.AegisGateLens.util.transformerToxicity, 'export missing');
  });

  await test('2. public API surface is complete', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    for (const m of ['prewarm', 'score', 'isToxic', 'isLoaded', 'getConfig', 'getStats', 'resetStats', '_reset']) {
      assert.strictEqual(typeof tm[m], 'function', `missing method: ${m}`);
    }
  });

  await test('3. constants match bundle-registry (max_length=512, 6 categories)', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    const cfg = tm.getConfig();
    assert.strictEqual(cfg.maxLength, 512);
    assert.strictEqual(cfg.categories.length, 6);
    assert.strictEqual(cfg.categories[0], 'toxic');
    assert.strictEqual(cfg.categories[1], 'severe_toxic');
    assert.strictEqual(cfg.categories[2], 'obscene');
    assert.strictEqual(cfg.categories[3], 'threat');
    assert.strictEqual(cfg.categories[4], 'insult');
    assert.strictEqual(cfg.categories[5], 'identity_hate');
    assert.strictEqual(cfg.facet, 5);
    assert.strictEqual(cfg.facetName, 'toxicity');
  });

  await test('4. pre-warm with injected session/tokenizer works', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    const tok = makeFakeTokenizer();
    const sess = makeFakeSession({ logits: [0, 0, 0, 0, 0, 0] });
    return tm.prewarm({ session: sess, tokenizer: tok }).then((r) => {
      assert.strictEqual(r.ok, true);
      assert.ok(r.prewarmMs >= 0);
      assert.strictEqual(tm.isLoaded(), true);
    });
  });

  await test('5. score() raises error when not prewarmed', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    return tm.score('hello world').then(
      () => { throw new Error('expected error'); },
      (e) => { assert.match(e.message, /prewarm/); }
    );
  });

  await test('6. score() returns null on empty text', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    tm._setSessionForTest(makeFakeSession({ logits: [0, 0, 0, 0, 0, 0] }));
    return tm.score('').then((r) => { assert.strictEqual(r, null); });
  });

  await test('7. tokenize produces 512-token arrays with correct CLS/SEP/PAD layout', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    const out = tm._tokenize('hello world test');
    assert.strictEqual(out.inputIds.length, 512);
    assert.strictEqual(out.attentionMask.length, 512);
    assert.strictEqual(out.tokenTypeIds.length, 512);
    assert.strictEqual(Number(out.inputIds[0]), 101, 'first token should be CLS');
    // Find SEP (should be after the non-pad tokens)
    let lastNonPad = -1;
    for (let i = 511; i >= 0; i--) {
      if (Number(out.attentionMask[i]) === 1) { lastNonPad = i; break; }
    }
    assert.strictEqual(Number(out.inputIds[lastNonPad]), 102, 'last non-pad token should be SEP');
    // Token type ids should all be 0 (single segment)
    for (let i = 0; i < 512; i++) {
      assert.strictEqual(Number(out.tokenTypeIds[i]), 0, `token_type_ids[${i}] should be 0`);
    }
  });

  await test('8. tokenize handles short text (pads to MAX_LENGTH)', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    const out = tm._tokenize('short');
    // 3 tokens: CLS + "short" + SEP, then 509 PAD
    let nNonPad = 0;
    for (let i = 0; i < 512; i++) {
      if (Number(out.attentionMask[i]) === 1) nNonPad++;
    }
    assert.strictEqual(nNonPad, 3, `expected 3 non-pad tokens, got ${nNonPad}`);
  });

  await test('9. sigmoid: handles positive and negative logits correctly', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    assert.ok(Math.abs(tm._sigmoid(0) - 0.5) < 0.001, 'sigmoid(0) should be 0.5');
    assert.ok(tm._sigmoid(10) > 0.99, 'sigmoid(10) should be ~1');
    assert.ok(tm._sigmoid(-10) < 0.01, 'sigmoid(-10) should be ~0');
    // Numerical stability: very large values must not return NaN or Infinity.
    // For x=-1000 the true sigmoid is indistinguishable from 0 (1e-434);
    // a clamp to 0 is correct and what real inference engines do.
    assert.ok(!isNaN(tm._sigmoid(-1000)), 'sigmoid should not be NaN for -1000');
    assert.ok(isFinite(tm._sigmoid(-1000)), 'sigmoid should be finite for -1000');
    assert.ok(tm._sigmoid(1000) > 0.99, 'sigmoid(1000) should be ~1');
    assert.ok(tm._sigmoid(-1000) >= 0, 'sigmoid should be >= 0 (clamp at 0 is OK)');
  });

  await test('10. score() with mocked session returns 6-category results', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    // Logits that produce: toxic=0.88, severe_toxic=0.05, obscene=0.12, threat=0.73, insult=0.40, identity_hate=0.04
    // Use logits = log(p/(1-p))
    function toLogit(p) { return Math.log(p / (1 - p)); }
    tm._setSessionForTest(makeFakeSession({
      logits: [toLogit(0.88), toLogit(0.05), toLogit(0.12), toLogit(0.73), toLogit(0.40), toLogit(0.04)],
    }));
    return tm.score('some text').then((r) => {
      assert.ok(r, 'result should not be null');
      assert.strictEqual(r.facet, 5);
      assert.strictEqual(r.facetName, 'toxicity');
      assert.strictEqual(typeof r.flagged, 'boolean');
      assert.ok(r.categories.toxic, 'should have toxic category');
      assert.ok(r.categories.severe_toxic);
      assert.ok(r.categories.obscene);
      assert.ok(r.categories.threat);
      assert.ok(r.categories.insult);
      assert.ok(r.categories.identity_hate);
    });
  });

  await test('11. score() flagged=true when any category >= 0.5', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    function toLogit(p) { return Math.log(p / (1 - p)); }
    tm._setSessionForTest(makeFakeSession({
      // Only threat is above 0.5
      logits: [toLogit(0.1), toLogit(0.05), toLogit(0.1), toLogit(0.9), toLogit(0.1), toLogit(0.05)],
    }));
    return tm.score('a bomb threat').then((r) => {
      assert.strictEqual(r.flagged, true, 'flagged should be true (threat crossed threshold)');
      assert.strictEqual(r.categories.threat.flagged, true);
      assert.strictEqual(r.categories.toxic.flagged, false);
    });
  });

  await test('12. score() flagged=false when all categories < 0.5', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    function toLogit(p) { return Math.log(p / (1 - p)); }
    tm._setSessionForTest(makeFakeSession({
      logits: [toLogit(0.05), toLogit(0.01), toLogit(0.05), toLogit(0.02), toLogit(0.1), toLogit(0.01)],
    }));
    return tm.score('completely benign text').then((r) => {
      assert.strictEqual(r.flagged, false);
      assert.strictEqual(r.anyToxic, false);
    });
  });

  await test('13. anyToxic=true only when "toxic" category flagged', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    function toLogit(p) { return Math.log(p / (1 - p)); }
    // Only threat flagged, not toxic
    tm._setSessionForTest(makeFakeSession({
      logits: [toLogit(0.1), toLogit(0.05), toLogit(0.1), toLogit(0.9), toLogit(0.1), toLogit(0.05)],
    }));
    return tm.score('test').then((r) => {
      assert.strictEqual(r.flagged, true, 'flagged should be true (threat)');
      assert.strictEqual(r.anyToxic, false, 'anyToxic should be false (toxic label not flagged)');
    });
  });

  await test('14. severity mapping is correct', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    const cfg = tm.getConfig();
    assert.strictEqual(cfg.severity.severe_toxic, 'critical');
    assert.strictEqual(cfg.severity.threat, 'high');
    assert.strictEqual(cfg.severity.identity_hate, 'high');
    assert.strictEqual(cfg.severity.toxic, 'medium');
    assert.strictEqual(cfg.severity.obscene, 'medium');
    assert.strictEqual(cfg.severity.insult, 'medium');
  });

  await test('15. isToxic() fast path returns true/false correctly', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    function toLogit(p) { return Math.log(p / (1 - p)); }
    // Test 1: all low → false
    tm._setSessionForTest(makeFakeSession({
      logits: [toLogit(0.05), toLogit(0.05), toLogit(0.05), toLogit(0.05), toLogit(0.05), toLogit(0.05)],
    }));
    return tm.isToxic('innocent').then((r1) => {
      assert.strictEqual(r1, false);
      // Test 2: threat high → true
      tm._setSessionForTest(makeFakeSession({
        logits: [toLogit(0.05), toLogit(0.05), toLogit(0.05), toLogit(0.95), toLogit(0.05), toLogit(0.05)],
      }));
      return tm.isToxic('kill you');
    }).then((r2) => {
      assert.strictEqual(r2, true);
    });
  });

  await test('16. stats: nScored, nFlagged, nByCategory all update', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    function toLogit(p) { return Math.log(p / (1 - p)); }
    tm._setSessionForTest(makeFakeSession({
      logits: [toLogit(0.8), toLogit(0.05), toLogit(0.05), toLogit(0.8), toLogit(0.05), toLogit(0.05)],
    }));
    tm.resetStats();
    return tm.score('test 1').then(() => {
      const s = tm.getStats();
      assert.strictEqual(s.nScored, 1);
      assert.strictEqual(s.nFlagged, 1);
      assert.strictEqual(s.nByCategory.toxic, 1);
      assert.strictEqual(s.nByCategory.threat, 1);
      assert.strictEqual(s.nByCategory.obscene, 0);
    });
  });

  await test('17. isLoaded() returns false before prewarm, true after', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._reset();
    assert.strictEqual(tm.isLoaded(), false);
    tm._setSessionForTest(makeFakeSession({ logits: [0, 0, 0, 0, 0, 0] }));
    tm._setTokenizerForTest(makeFakeTokenizer());
    assert.strictEqual(tm.isLoaded(), true);
  });

  await test('18. getConfig() exposes the canonical toxicity config', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    const cfg = tm.getConfig();
    assert.strictEqual(cfg.facet, 5);
    assert.strictEqual(cfg.facetName, 'toxicity');
    assert.ok(cfg.modelVersion.startsWith('lens-v0.2.0+toxicity'));
    assert.ok(cfg.thresholds.toxic === 0.5);
  });

  await test('19. score() returns null on inference error (graceful degradation)', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    tm._setSessionForTest({
      run: async () => { throw new Error('ort inference crashed'); },
    });
    return tm.score('test').then((r) => {
      assert.strictEqual(r, null, 'should return null on error');
    });
  });

  await test('20. FPR sanity: synthetic high-prob-toxic input → flagged', () => {
    const ctx = loadContext();
    const tm = ctx.self.AegisGateLens.util.transformerToxicity;
    tm._setTokenizerForTest(makeFakeTokenizer());
    function toLogit(p) { return Math.log(p / (1 - p)); }
    // All categories high
    tm._setSessionForTest(makeFakeSession({
      logits: [toLogit(0.99), toLogit(0.99), toLogit(0.99), toLogit(0.99), toLogit(0.99), toLogit(0.99)],
    }));
    return tm.score('test').then((r) => {
      assert.strictEqual(r.flagged, true);
      assert.strictEqual(r.anyToxic, true);
      // All categories should be flagged
      for (const c of ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']) {
        assert.strictEqual(r.categories[c].flagged, true, `${c} should be flagged`);
      }
    });
  });

  console.log();
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  if (failed > 0) {
    console.log();
    for (const f of failures) {
      console.log(`  FAIL: ${f.name}: ${f.err.message}`);
    }
    process.exit(1);
  }
})();
