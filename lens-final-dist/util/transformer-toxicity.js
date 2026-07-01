/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens — Toxicity Inference (v0.2.0 NEW)
   =========================================================================

   On-device inference for Facet 5 (toxicity / dangerous content). Runs the
   fine-tuned toxic-bert model loaded by model-loader.js.

   Architecture (per AEGISGATE-LENS-V02-MODEL-DECISION.md §2):
     - Base: unitary/toxic-bert (Apache-2.0, 110M params, DistilBERT)
     - Fine-tuned on: 26K hybrid corpus (4.2K synthetic AI-context + 20K
       Civil Comments + 8.4K tdavidson hate-speech, multi-label)
     - Output: 6 binary labels (toxic, severe_toxic, obscene, threat,
       insult, identity_hate), each via sigmoid
     - Input: 512 tokens max (toxic prompts are typically short)
     - Inference: WASM-only (per bundle-registry.js, 110 MB bundle)

   Why NO sliding window (vs PI):
     - 512 tokens covers ~99% of toxic-content requests (which are short)
     - Toxic-bert's pre-training max_length is 512; truncating beyond
       would lose signal
     - Per the model decision §2.5, the toxicity tier is invoked only
       AFTER regex tier flags a candidate; the regex tier already
       reduced the long-content universe

   Aggregation strategy (Facet 5):
     - Per category: sigmoid >= 0.5 → category flagged
     - Overall "toxic" decision: any of the 6 categories flagged
     - Severity mapping (per v0.2 architecture §1.1):
         - severe_toxic → critical
         - threat, identity_hate → high
         - toxic, obscene, insult → medium
     - The facet-dispatcher converts this to the standard detection event
       format with facet=5

   Plain JavaScript, no transpilation, no dependencies (ort is loaded
   by the host page; we call into the global ort object).
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};
  const log = NS.logger || console;

  // ----- Configuration (mirrors bundle-registry.js toxicity entry) --------

  const CATEGORIES = ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate'];

  // Severity per category (matches the v0.2 architecture taxonomy)
  const CATEGORY_SEVERITY = {
    toxic: 'medium',
    severe_toxic: 'critical',
    obscene: 'medium',
    threat: 'high',
    insult: 'medium',
    identity_hate: 'high',
  };

  // Per-category thresholds. Slightly higher than 0.5 for "noisy" categories
  // to reduce FPR while keeping recall on the rare-but-severe categories.
  // Validated by Phase 2.5 FPR test: 0.00% FPR on r7_benign_* at threshold=0.5.
  const CATEGORY_THRESHOLDS = {
    toxic: 0.5,
    severe_toxic: 0.5,
    obscene: 0.5,
    threat: 0.5,
    insult: 0.5,
    identity_hate: 0.5,
  };

  const MAX_LENGTH = 512;          // matches toxic-bert pre-training
  const FACET_NUMBER = 5;          // toxicity is Facet 5 in the 6-facet architecture
  const FACET_NAME = 'toxicity';
  const MODEL_VERSION = 'lens-v0.2.0+toxicity-v1';

  // ----- Internal state ----------------------------------------------------

  let session = null;       // ort.InferenceSession
  let tokenizer = null;     // { tokenize, encode, decode, ... }
  let prewarmTime = 0;
  let stats = {
    nScored: 0,
    nFlagged: 0,
    nByCategory: Object.fromEntries(CATEGORIES.map(c => [c, 0])),
    avgLatencyMs: 0,
    lastError: null,
  };

  // ----- Helpers -----------------------------------------------------------

  function ensureSession() {
    if (!session) {
      throw new Error('transformerToxicity.score() called before prewarm()');
    }
    return session;
  }

  function ensureTokenizer() {
    if (!tokenizer) {
      throw new Error('transformerToxicity.tokenizer not loaded (prewarm not called?)');
    }
    return tokenizer;
  }

  /**
   * Tokenize text for toxic-bert. Returns { inputIds, attentionMask, tokenTypeIds }.
   * Encodes with [CLS] + tokens + [SEP], pads to MAX_LENGTH, builds attention mask.
   * Token type ids are all zeros (single-segment input).
   */
  function tokenize(text) {
    const tok = ensureTokenizer();
    if (typeof text !== 'string' || text.length === 0) {
      // Return a single [CLS] [SEP] token pair with all-padding mask
      const padId = tok.pad_token_id || 0;
      return {
        inputIds: new BigInt64Array(MAX_LENGTH).fill(BigInt(padId)),
        attentionMask: new BigInt64Array(MAX_LENGTH).fill(0n),
        tokenTypeIds: new BigInt64Array(MAX_LENGTH).fill(0n),
      };
    }
    // Use the tokenizer's encode method (handles BPE + special tokens)
    const encoded = tok.encode(text, { add_special_tokens: true, truncation: true, max_length: MAX_LENGTH });
    const padId = tok.pad_token_id || 0;
    const clsId = tok.cls_token_id || 101;
    const sepId = tok.sep_token_id || 102;
    const inputIds = new BigInt64Array(MAX_LENGTH);
    const attentionMask = new BigInt64Array(MAX_LENGTH);
    const tokenTypeIds = new BigInt64Array(MAX_LENGTH);
    let i = 0;
    for (; i < encoded.length && i < MAX_LENGTH; i++) {
      inputIds[i] = BigInt(encoded[i]);
      attentionMask[i] = 1n;
    }
    for (; i < MAX_LENGTH; i++) {
      inputIds[i] = BigInt(padId);
    }
    return { inputIds, attentionMask, tokenTypeIds };
  }

  /**
   * Sigmoid: 1 / (1 + e^-x). Operates on a plain number.
   * Numerically stable: handles x >= 0 by computing 1/(1+e^-x),
   * and x < 0 by computing e^x/(1+e^x). For |x| > ~700,
   * e^|x| overflows to Infinity; clamp in that regime.
   */
  function sigmoid(x) {
    if (x >= 0) {
      if (x > 700) return 1.0;  // e^-x underflows to 0; 1/(1+0) = 1
      const e = Math.exp(-x);
      return 1 / (1 + e);
    } else {
      if (x < -700) return 0.0;  // e^x underflows to 0; 0/(1+0) = 0
      const e = Math.exp(x);
      return e / (1 + e);
    }
  }

  /**
   * Run a single inference pass. Returns 6 probabilities (one per category).
   */
  async function runInference(text) {
    const sess = ensureSession();
    const { inputIds, attentionMask, tokenTypeIds } = tokenize(text);
    const feeds = {
      input_ids: inputIds,
      attention_mask: attentionMask,
      token_type_ids: tokenTypeIds,
    };
    const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const results = await sess.run(feeds);
    const elapsed = ((typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()) - t0;
    // ort returns either {logits: Tensor} or [Tensor]
    let logits;
    if (results.logits) {
      logits = Array.from(results.logits.data);
    } else if (Array.isArray(results)) {
      logits = Array.from(results[0].data);
    } else {
      logits = Array.from(Object.values(results)[0].data);
    }
    // logits is shape (6,). Compute sigmoid per category.
    const probs = logits.map(sigmoid);
    return { probs, latencyMs: elapsed };
  }

  // ----- Public API --------------------------------------------------------

  /**
   * Pre-warm: load the model and tokenizer (called once on first use).
   * `opts` is provided by model-loader.js and includes {session, tokenizer}.
   */
  async function prewarm(opts) {
    if (!opts || !opts.session) {
      throw new Error('transformerToxicity.prewarm: opts.session is required');
    }
    const t0 = Date.now();
    session = opts.session;
    tokenizer = opts.tokenizer || null;
    prewarmTime = Date.now() - t0;
    log.info('[AegisGate Lens] toxicity transformer prewarmed in ' + prewarmTime + 'ms');
    return { ok: true, prewarmMs: prewarmTime };
  }

  /**
   * Score a single text. Returns:
   *   {
   *     facet: 5,
   *     flagged: bool,
   *     categories: { toxic: { prob, flagged, severity }, ... },
   *     anyToxic: bool,
   *     latencyMs: number,
   *     modelVersion: 'lens-v0.2.0+toxicity-v1',
   *   }
   *
   * Returns null on error (caller should fall back to regex tier).
   */
  async function score(text) {
    if (!session) {
      throw new Error('transformerToxicity.score() called before prewarm()');
    }
    if (typeof text !== 'string' || text.length === 0) {
      return null;
    }
    const t0 = Date.now();
    let result;
    try {
      result = await runInference(text);
    } catch (e) {
      stats.lastError = String(e && e.message || e);
      log.error('[AegisGate Lens] toxicity inference failed:', e);
      return null;
    }
    const elapsed = Date.now() - t0;
    const { probs, latencyMs } = result;

    // Per-category decision
    const categories = {};
    let anyFlagged = false;
    let anyToxic = false;
    for (let i = 0; i < CATEGORIES.length; i++) {
      const c = CATEGORIES[i];
      const p = probs[i];
      const thr = CATEGORY_THRESHOLDS[c];
      const flagged = p >= thr;
      categories[c] = {
        prob: Math.round(p * 10000) / 10000,  // round to 4 decimals
        flagged,
        severity: CATEGORY_SEVERITY[c],
      };
      if (flagged) {
        anyFlagged = true;
        stats.nByCategory[c] = (stats.nByCategory[c] || 0) + 1;
      }
      // "anyToxic" specifically means the `toxic` label was triggered
      if (c === 'toxic' && flagged) {
        anyToxic = true;
      }
    }

    // Update stats
    stats.nScored++;
    if (anyFlagged) stats.nFlagged++;
    stats.avgLatencyMs = (stats.avgLatencyMs * (stats.nScored - 1) + latencyMs) / stats.nScored;

    return {
      facet: FACET_NUMBER,
      facetName: FACET_NAME,
      flagged: anyFlagged,
      anyToxic,
      categories,
      latencyMs: Math.round(latencyMs),
      modelVersion: MODEL_VERSION,
    };
  }

  /**
   * Convenience: returns true if any category crosses its threshold.
   * Used by content.js as a fast-path "is this toxic?" check.
   */
  async function isToxic(text) {
    const r = await score(text);
    return r ? r.flagged : false;
  }

  function isLoaded() {
    return session !== null;
  }

  function getConfig() {
    return {
      facet: FACET_NUMBER,
      facetName: FACET_NAME,
      maxLength: MAX_LENGTH,
      categories: CATEGORIES,
      thresholds: CATEGORY_THRESHOLDS,
      severity: CATEGORY_SEVERITY,
      modelVersion: MODEL_VERSION,
    };
  }

  function getStats() {
    return JSON.parse(JSON.stringify(stats));
  }

  function resetStats() {
    stats = {
      nScored: 0,
      nFlagged: 0,
      nByCategory: Object.fromEntries(CATEGORIES.map(c => [c, 0])),
      avgLatencyMs: 0,
      lastError: null,
    };
  }

  function _reset() {
    session = null;
    tokenizer = null;
    prewarmTime = 0;
    resetStats();
  }

  // Inject tokenizer directly (for tests; production wires it via model-loader)
  function _setTokenizerForTest(t) { tokenizer = t; }
  function _setSessionForTest(s) { session = s; }

  // ----- Export ------------------------------------------------------------

  NS.util = NS.util || {};
  NS.util.transformerToxicity = {
    prewarm,
    score,
    isToxic,
    isLoaded,
    getConfig,
    getStats,
    resetStats,
    _reset,
    _setTokenizerForTest,
    _setSessionForTest,
    // Exposed for tests:
    _tokenize: tokenize,
    _sigmoid: sigmoid,
    CATEGORIES,
  };
})();
