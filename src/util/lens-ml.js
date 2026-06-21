/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - ML Inference Module (5-Way Ensemble, Bundle Loader)

   Detects prompt injection attacks using a 5-way ensemble:
     1. Logistic Regression (LR) - 30K features, 2.5MB
     2. MLP small (original) - 5K features, 64-32 hidden, INT8
     3. MLP small_dolphin - dolphin adversarial training, INT8
     4. MLP small_ollama - ollama adversarial training, INT8
     5. MLP small_augmented - heavy obfuscation training, INT8

   Total bundle: 8.35MB. Single signed file (aegisgate-lens-v0.1.0.bundle).
   Loaded LAZILY on first detection.

   The bundle is:
     - Single self-contained file (8.57MB)
     - Ed25519 signed (signature verified on load)
     - SHA-256 manifest (each file's hash verified)
     - Zero external dependencies at load time

   Privacy: Zero network calls at inference (after bundle is loaded).
   The bundle is fetched ONCE and cached. No telemetry on model output.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};
  const log = NS.logger || console;
  const bundleLoader = NS.bundleLoader || null;

  // ===================================================================
  // Tokenization (must match Python training exactly)
  // ===================================================================

  function tokenize(text) {
    const features = new Map();
    const textLower = text.toLowerCase();

    // Word 1-grams (2+ chars)
    const words = textLower.match(/\b\w+\b/g) || [];
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      if (w.length >= 2) {
        const key = 'w=' + w;
        features.set(key, (features.get(key) || 0) + 1);
      }
    }

    // Word 2-grams (use __ separator to keep as single token)
    for (let i = 0; i < words.length - 1; i++) {
      const bg = 'w=' + words[i] + '__' + words[i + 1];
      features.set(bg, (features.get(bg) || 0) + 1);
    }

    // Char 3-5 grams within words (no word boundaries)
    const normalizedWords = textLower.match(/[a-z0-9]+/g) || [];
    const normalized = normalizedWords.join('__');
    for (let n = 3; n <= 5; n++) {
      for (let i = 0; i <= normalized.length - n; i++) {
        const substr = normalized.substring(i, i + n);
        if (substr.indexOf('__') === -1) {
          const key = 'c=' + substr;
          features.set(key, (features.get(key) || 0) + 1);
        }
      }
    }

    return features;
  }

  // ===================================================================
  // LR inference
  // ===================================================================

  function scoreLR(tf, vocabMap, idfMap, coefMap, intercept) {
    let score = intercept;
    let sumSquares = 0;
    const entries = [];
    const tfEntries = tf.entries();
    for (let it = tfEntries.next(); !it.done; it = tfEntries.next()) {
      const feature = it.value[0];
      const count = it.value[1];
      const vocabIdx = vocabMap.get(feature);
      if (vocabIdx === undefined) continue;
      const idfWeight = idfMap.get(feature);
      if (idfWeight === undefined) continue;
      const coef = coefMap.get(String(vocabIdx));
      if (coef === undefined || coef === 0) continue;
      const tfidf = count * idfWeight;
      entries.push({ tfidf: tfidf, coef: coef });
      sumSquares += tfidf * tfidf;
    }
    const norm = Math.sqrt(sumSquares);
    if (norm === 0) {
      return 1 / (1 + Math.exp(-score));
    }
    for (let i = 0; i < entries.length; i++) {
      score += (entries[i].tfidf / norm) * entries[i].coef;
    }
    return 1 / (1 + Math.exp(-score));
  }

  // ===================================================================
  // MLP inference (with INT8 dequantization)
  // ===================================================================

  function scoreMLP(features, mlpConfig, mlpWeights, mlpBiases) {
    const nLayers = mlpConfig.n_layers;
    const quantScales = mlpConfig.quant_scales;
    const quantZeros = mlpConfig.quant_zeros;

    let activations = new Float32Array(mlpConfig.layer_sizes[0]);
    const featEntries = features.entries();
    for (let it = featEntries.next(); !it.done; it = featEntries.next()) {
      const vocabIdxStr = it.value[0];
      const tfidf = it.value[1];
      const idx = parseInt(vocabIdxStr, 10);
      if (idx < activations.length) {
        activations[idx] = tfidf;
      }
    }

    for (let layer = 0; layer < nLayers; layer++) {
      const inSize = mlpConfig.layer_sizes[layer];
      const outSize = mlpConfig.layer_sizes[layer + 1];
      const W = mlpWeights[layer];
      const b = mlpBiases[layer];
      const scale = quantScales[layer];
      const zero = quantZeros[layer];

      const output = new Float32Array(outSize);

      if (Array.isArray(W)) {
        if (Array.isArray(W[0])) {
          for (let r = 0; r < inSize; r++) {
            const a = activations[r];
            if (a === 0) continue;
            for (let c = 0; c < outSize; c++) {
              const wq = W[r][c];
              const w = (wq - zero) * scale;
              output[c] += a * w;
            }
          }
        } else {
          for (let r = 0; r < inSize; r++) {
            const a = activations[r];
            if (a === 0) continue;
            for (let c = 0; c < outSize; c++) {
              const wq = W[r * outSize + c];
              const w = (wq - zero) * scale;
              output[c] += a * w;
            }
          }
        }
      } else {
        const wEntries = Object.entries(W);
        for (let i = 0; i < wEntries.length; i++) {
          const flatIdx = parseInt(wEntries[i][0], 10);
          const wq = wEntries[i][1];
          const r = Math.floor(flatIdx / outSize);
          const c = flatIdx % outSize;
          const w = (wq - zero) * scale;
          output[c] += activations[r] * w;
        }
      }

      for (let c = 0; c < outSize; c++) {
        output[c] += b[c];
        if (layer < nLayers - 1) {
          if (output[c] < 0) output[c] = 0;
        } else {
          output[c] = 1.0 / (1.0 + Math.exp(-output[c]));
        }
      }
      activations = output;
    }
    return activations[0];
  }

  // ===================================================================
  // Feature vectorization (L2-normalized)
  // ===================================================================

  function buildFeatureVector(tf, vocabMap, idfMap) {
    const vec = new Map();
    let sumSquares = 0;
    const entries = [];
    const tfEntries = tf.entries();
    for (let it = tfEntries.next(); !it.done; it = tfEntries.next()) {
      const feature = it.value[0];
      const count = it.value[1];
      const vocabIdx = vocabMap.get(feature);
      if (vocabIdx === undefined) continue;
      const idfWeight = idfMap.get(feature);
      if (idfWeight === undefined) continue;
      const tfidf = count * idfWeight;
      entries.push({ vocabIdx: vocabIdx, tfidf: tfidf });
      sumSquares += tfidf * tfidf;
    }
    const norm = Math.sqrt(sumSquares);
    if (norm === 0) return vec;
    for (let i = 0; i < entries.length; i++) {
      vec.set(String(entries[i].vocabIdx), entries[i].tfidf / norm);
    }
    return vec;
  }

  // ===================================================================
  // N-Model engine
  // ===================================================================

  function createEngine(modelSpecs, options) {
    const threshold = (options && options.threshold) || 0.85;
    const strategy = (options && options.strategy) || 'average';

    const processed = modelSpecs.map(function (spec) {
      const vocabMap = new Map(Object.entries(spec.vocabulary));
      const idfMap = new Map(Object.entries(spec.idf));
      const result = { type: spec.type, vocabMap: vocabMap, idfMap: idfMap };
      if (spec.type === 'lr') {
        result.coefMap = new Map(Object.entries(spec.coefficients));
        result.intercept = spec.config.intercept;
      } else if (spec.type === 'mlp') {
        result.config = spec.config;
        result.weights = spec.weights;
        result.biases = spec.biases;
      }
      return result;
    });

    return function predict(text) {
      const tf = tokenize(text);
      const scores = [];
      for (let i = 0; i < processed.length; i++) {
        const m = processed[i];
        if (m.type === 'lr') {
          scores.push(scoreLR(tf, m.vocabMap, m.idfMap, m.coefMap, m.intercept));
        } else {
          const features = buildFeatureVector(tf, m.vocabMap, m.idfMap);
          scores.push(scoreMLP(features, m.config, m.weights, m.biases));
        }
      }

      let score;
      if (strategy === 'average') {
        let sum = 0;
        for (let i = 0; i < scores.length; i++) sum += scores[i];
        score = sum / scores.length;
      } else if (strategy === 'min') {
        score = Math.min.apply(null, scores);
      } else if (strategy === 'max') {
        score = Math.max.apply(null, scores);
      } else if (strategy === 'product') {
        let prod = 1;
        for (let i = 0; i < scores.length; i++) prod *= scores[i];
        score = Math.pow(prod, 1 / scores.length);
      } else {
        score = scores[0];
      }

      return {
        score: score,
        scores: scores,
        isAttack: score >= threshold,
        threshold: threshold,
      };
    };
  }

  // ===================================================================
  // Bundle loading
  // ===================================================================

  let cachedEngine = null;
  let loadingPromise = null;

  function getBundleUrl() {
    if (typeof window !== 'undefined' && window.__lensBundleUrl) {
      return window.__lensBundleUrl;
    }
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
      return chrome.runtime.getURL('aegisgate-lens-v0.1.0.bundle');
    }
    return './aegisgate-lens-v0.1.0.bundle';
  }

  async function loadAndVerifyBundle() {
    if (!bundleLoader) {
      throw new Error('bundleLoader not loaded - make sure bundle-loader.js is included before lens-ml.js');
    }
    const url = getBundleUrl();
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error('Failed to fetch bundle: ' + response.status + ' ' + response.statusText);
    }
    const buffer = await response.arrayBuffer();
    return await bundleLoader.parseBundle(buffer);
  }

  async function ensureEngine() {
    if (cachedEngine) return cachedEngine;
    if (loadingPromise) return loadingPromise;
    loadingPromise = (async function () {
      try {
        const parsed = await loadAndVerifyBundle();
        const { models, config } = bundleLoader.reconstructModels(parsed);
        cachedEngine = createEngine(models, {
          threshold: config.threshold,
          strategy: config.strategy,
        });
        log.info('[AegisGate Lens] ML engine loaded from signed bundle v' +
                 parsed.header.bundle_version + ' (' + models.length + ' models, threshold=' + config.threshold + ')');
        return cachedEngine;
      } catch (err) {
        log.warn('[AegisGate Lens] ML engine load failed:', err);
        loadingPromise = null;
        throw err;
      }
    })();
    return loadingPromise;
  }

  // ===================================================================
  // Public API
  // ===================================================================

  /**
   * Score a prompt text for prompt-injection likelihood.
   * @param {string} text The prompt text.
   * @returns {Promise<{score: number, isAttack: boolean, threshold: number, loaded: boolean}>}
   */
  async function scoreText(text) {
    try {
      const engine = await ensureEngine();
      const r = engine(text);
      return {
        score: r.score,
        scores: r.scores,
        isAttack: r.isAttack,
        threshold: r.threshold,
        loaded: true,
      };
    } catch (err) {
      log.warn('[AegisGate Lens] ML score failed:', err);
      return { score: 0, isAttack: false, threshold: 0, loaded: false };
    }
  }

  function isLoaded() {
    return cachedEngine !== null;
  }

  function prewarm() {
    if (cachedEngine || loadingPromise) return;
    ensureEngine().catch(function (err) {
      log.warn('[AegisGate Lens] ML prewarm failed:', err);
    });
  }

  NS.mlEngine = {
    scoreText: scoreText,
    isLoaded: isLoaded,
    prewarm: prewarm,
  };
})();
