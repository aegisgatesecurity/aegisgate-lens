/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - ONNX Inference Engine (v0.2.0)

   Runs the MiniLM transformer via ONNX Runtime Web for Tier 3
   of the 3-tier cascade. This file is loaded LAZILY only when
   the TF-IDF ensemble is uncertain (probability 0.3-0.7).

   The ONNX model is INT8 quantized (~67MB) and loaded from a
   signed single-file bundle (aegisgate-lens-transformer-v0.2.0.bundle).

   Plain JavaScript, no transpilation, no dependencies beyond
   ONNX Runtime Web (Apache 2.0).

   v0.2.0 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens =
    (typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : self)).AegisGateLens || {};
  const log = NS.logger || console;
  const bundleLoader = NS.bundleLoader || null;

  // Tokenization matching MiniLM (WordPiece tokenizer)
  // For v0.2.0, we use a simple approximation matching the MiniLM
  // WordPiece tokenizer's behavior. The actual WordPiece algorithm
  // is complex; for the initial implementation, we use a basic
  // whitespace + punctuation tokenizer and rely on the model's
  // robustness to handle out-of-vocab tokens.

  function tokenizeSimple(text, vocab, maxLength) {
    // Basic tokenization: lowercase, split on whitespace and punctuation
    text = text.toLowerCase();
    // Replace punctuation with spaces
    text = text.replace(/[.,!?;:'"()\[\]{}]/g, ' ');
    // Split on whitespace
    const words = text.split(/\s+/).filter(w => w.length > 0);

    // Convert words to token IDs (with UNK fallback)
    const unkId = vocab['[UNK]'] || 100;
    const clsId = vocab['[CLS]'] || 101;
    const sepId = vocab['[SEP]'] || 102;
    const padId = vocab['[PAD]'] || 0;

    // Build [CLS] word1 word2 ... [SEP] [PAD] [PAD] ...
    const tokenIds = [clsId];
    for (let i = 0; i < words.length && tokenIds.length < maxLength - 1; i++) {
      const word = words[i];
      // Try whole word first
      if (vocab[word] !== undefined) {
        tokenIds.push(vocab[word]);
      } else {
        // Try with "##" prefix for subword (WordPiece)
        let found = false;
        for (let j = 1; j < word.length; j++) {
          const subword = '##' + word.substring(j);
          if (vocab[subword] !== undefined) {
            tokenIds.push(vocab[subword]);
            found = true;
            break;
          }
        }
        if (!found) {
          tokenIds.push(unkId);
        }
      }
    }
    tokenIds.push(sepId);

    // Pad to maxLength
    while (tokenIds.length < maxLength) {
      tokenIds.push(padId);
    }

    // Attention mask: 1 for real tokens, 0 for padding
    const attentionMask = tokenIds.map(id => id === padId ? 0 : 1);

    return { inputIds: tokenIds, attentionMask: attentionMask };
  }

  // ONNX inference engine
  let cachedSession = null;
  let cachedTokenizer = null;
  let cachedConfig = null;
  let loadingPromise = null;

  function getBundleUrl() {
    if (typeof window !== 'undefined' && window.__lensTransformerBundleUrl) {
      return window.__lensTransformerBundleUrl;
    }
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
      return chrome.runtime.getURL('aegisgate-lens-transformer-v0.2.0.bundle');
    }
    return './aegisgate-lens-transformer-v0.2.0.bundle';
  }

  async function loadBundle() {
    if (!bundleLoader) {
      throw new Error('bundleLoader not loaded');
    }
    const url = getBundleUrl();
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error('Failed to fetch transformer bundle: ' + response.status);
    }
    const buffer = await response.arrayBuffer();
    return await bundleLoader.parseBundle(buffer);
  }

  async function ensureSession() {
    if (cachedSession) return { session: cachedSession, tokenizer: cachedTokenizer, config: cachedConfig };
    if (loadingPromise) return loadingPromise;
    loadingPromise = (async function () {
      try {
        // Load ONNX Runtime Web dynamically (it's a large dependency)
        if (typeof ort === 'undefined') {
          log.warn('[AegisGate Lens] ONNX Runtime Web not loaded. Make sure ort.min.js is included before this script.');
          throw new Error('ort global not found');
        }

        // Load and parse the bundle
        const parsed = await loadBundle();
        const byName = {};
        for (let i = 0; i < parsed.models.length; i++) {
          byName[parsed.models[i].name] = parsed.models[i].data;
        }

        // Find ONNX model and config
        const onnxFileName = Object.keys(byName).find(k => k.endsWith('.onnx'));
        if (!onnxFileName) throw new Error('No ONNX model found in bundle');
        const onnxData = byName[onnxFileName];

        // The ONNX model is stored as a JSON object with base64 data + metadata
        // Format: { format: 'onnx', quantization: 'int8', compression: 'gzip', data_b64: '...' }
        let onnxBytes;
        if (typeof onnxData === 'object' && onnxData.data_b64) {
          onnxBytes = base64ToBytes(onnxData.data_b64);
          if (onnxData.compression === 'gzip') {
            // Use DecompressionStream (browser API) for gzip
            const stream = new Response(onnxBytes).body.pipeThrough(new DecompressionStream('gzip'));
            onnxBytes = await new Response(stream).arrayBuffer();
          }
        } else {
          // Raw base64 string
          onnxBytes = base64ToBytes(onnxData);
        }

        // Load tokenizer vocab
        const vocab = {};
        const vocabData = byName['vocab.json'] || byName['vocab.txt'];
        if (typeof vocabData === 'object' && vocabData.vocab) {
          Object.assign(vocab, vocabData.vocab);
        } else if (Array.isArray(vocabData)) {
          // vocab.txt is one token per line
          vocabData.forEach((token, idx) => { vocab[token] = idx; });
        }

        // Load config
        const config = byName['minilm_config.json'] || {
          max_length: 128,
          threshold: 0.50,
        };

        // Create ONNX session
        log.info('[AegisGate Lens] Loading transformer ONNX model...');
        const session = await ort.InferenceSession.create(onnxBytes, {
          executionProviders: ['wasm'],
          graphOptimizationLevel: 'all',
        });

        cachedSession = session;
        cachedTokenizer = { vocab: vocab };
        cachedConfig = config;

        log.info('[AegisGate Lens] Transformer loaded: ' + (onnxBytes.length / 1024 / 1024).toFixed(1) + ' MB');
        return { session, tokenizer: cachedTokenizer, config };
      } catch (err) {
        loadingPromise = null;
        throw err;
      }
    })();
    return loadingPromise;
  }

  function base64ToBytes(b64) {
    // Remove data URI prefix if present
    if (b64.startsWith('data:')) {
      b64 = b64.substring(b64.indexOf(',') + 1);
    }
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Score a prompt using the transformer.
   * @param {string} text
   * @returns {Promise<{score: number, isAttack: boolean}>}
   */
  async function scoreTransformer(text) {
    try {
      const { session, tokenizer, config } = await ensureSession();
      const maxLength = config.max_length || 128;

      // Tokenize
      const { inputIds, attentionMask } = tokenizeSimple(text, tokenizer.vocab, maxLength);

      // Run inference
      const feeds = {
        input_ids: new ort.Tensor('int64', BigInt64Array.from(inputIds.map(BigInt)), [1, maxLength]),
        attention_mask: new ort.Tensor('int64', BigInt64Array.from(attentionMask.map(BigInt)), [1, maxLength]),
      };
      const results = await session.run(feeds);
      const logits = results.logits.data;

      // Apply softmax to get probabilities
      const maxLogit = Math.max(logits[0], logits[1]);
      const exp0 = Math.exp(logits[0] - maxLogit);
      const exp1 = Math.exp(logits[1] - maxLogit);
      const probAttack = exp1 / (exp0 + exp1);

      const threshold = config.threshold || 0.50;
      return {
        score: probAttack,
        isAttack: probAttack >= threshold,
        threshold: threshold,
      };
    } catch (err) {
      log.warn('[AegisGate Lens] Transformer inference failed:', err);
      return { score: 0, isAttack: false, threshold: 0, loaded: false };
    }
  }

  function isLoaded() {
    return cachedSession !== null;
  }

  function prewarm() {
    if (cachedSession || loadingPromise) return;
    ensureSession().catch(err => {
      log.warn('[AegisGate Lens] Transformer prewarm failed:', err);
    });
  }

  NS.transformerEngine = {
    scoreTransformer: scoreTransformer,
    isLoaded: isLoaded,
    prewarm: prewarm,
  };
})();
