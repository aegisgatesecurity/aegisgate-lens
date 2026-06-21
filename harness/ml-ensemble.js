/**
 * AegisGate Lens - Ensemble ML Inference Module (LR + MLP)
 *
 * Loads two model artifacts:
 *   - LR (Logistic Regression) - small, fast, low FPR
 *   - MLP (Multi-Layer Perceptron) - larger, captures non-linear patterns
 *
 * Combines them by averaging probabilities. This ensemble achieved
 * TPR 98.05% @ FPR 0.46% in offline evaluation.
 *
 * The model is INT8 quantized for size (1.5MB total MLP), validated
 * against the original (max diff 0.004 on test cases).
 *
 * ZERO runtime dependencies. Pure vanilla JS.
 */

'use strict';

// =============================================================================
// Tokenization (must match Python training exactly)
// =============================================================================

/**
 * Tokenize text into TF-IDF features. Identical to Python's tokenize() in
 * train_mlp.py. Returns a Map<feature_name, count> of term frequencies.
 */
function tokenize(text) {
  const features = new Map();
  const textLower = text.toLowerCase();

  // Word 1-grams (2+ chars)
  const words = textLower.match(/\b\w+\b/g) || [];
  for (const w of words) {
    if (w.length >= 2) {
      const key = `w=${w}`;
      features.set(key, (features.get(key) || 0) + 1);
    }
  }

  // Word 2-grams with __ separator
  for (let i = 0; i < words.length - 1; i++) {
    const bg = `w=${words[i]}__${words[i+1]}`;
    features.set(bg, (features.get(bg) || 0) + 1);
  }

  // Char 3-5 grams within words only
  const normalizedWords = textLower.match(/[a-z0-9]+/g) || [];
  const normalized = normalizedWords.join('__');
  for (let n = 3; n <= 5; n++) {
    for (let i = 0; i <= normalized.length - n; i++) {
      const substr = normalized.substring(i, i + n);
      if (!substr.includes('__')) {
        const key = `c=${substr}`;
        features.set(key, (features.get(key) || 0) + 1);
      }
    }
  }

  return features;
}

// =============================================================================
// LR inference (Logistic Regression with L2 normalization)
// =============================================================================

/**
 * Compute LR probability for a tokenized text.
 * Returns probability in [0, 1].
 */
function scoreLR(tf, vocabMap, idfMap, coefMap, intercept) {
  let score = intercept;

  // First pass: TF-IDF values + L2 norm
  let sumSquares = 0;
  const entries = [];
  for (const [feature, count] of tf) {
    const vocabIdx = vocabMap.get(feature);
    if (vocabIdx === undefined) continue;
    const idfWeight = idfMap.get(feature);
    if (idfWeight === undefined) continue;
    const coef = coefMap.get(String(vocabIdx));
    if (coef === undefined || coef === 0) continue;
    const tfidf = count * idfWeight;
    entries.push({ tfidf, coef });
    sumSquares += tfidf * tfidf;
  }

  // L2 normalization
  const norm = Math.sqrt(sumSquares);
  if (norm === 0) {
    return 1 / (1 + Math.exp(-score));
  }

  // Second pass: dot product with normalized TF-IDF
  for (const { tfidf, coef } of entries) {
    score += (tfidf / norm) * coef;
  }

  return 1 / (1 + Math.exp(-score));
}

// =============================================================================
// MLP inference (with INT8 dequantization)
// =============================================================================

/**
 * Compute MLP probability for a feature vector.
 * INT8 weights are stored as quantized values; we dequantize at runtime.
 */
function scoreMLP(features, mlpConfig, mlpWeights, mlpBiases) {
  const nLayers = mlpConfig.n_layers;
  const quantScales = mlpConfig.quant_scales;
  const quantZeros = mlpConfig.quant_zeros;

  // Build input vector (n_features) from TF features
  // features: Map<vocab_idx, normalized_tfidf>
  let activations = new Float32Array(mlpConfig.layer_sizes[0]);

  for (const [vocabIdxStr, tfidf] of features) {
    const idx = parseInt(vocabIdxStr);
    if (idx < activations.length) {
      activations[idx] = tfidf;
    }
  }

  // Forward pass through each layer
  for (let layer = 0; layer < nLayers; layer++) {
    const inSize = mlpConfig.layer_sizes[layer];
    const outSize = mlpConfig.layer_sizes[layer + 1];
    const W = mlpWeights[layer];
    const b = mlpBiases[layer];
    const scale = quantScales[layer];
    const zero = quantZeros[layer];

    const output = new Float32Array(outSize);

    // Determine format: dense (list of lists) or sparse (dict)
    if (Array.isArray(W)) {
      // Dense format
      if (Array.isArray(W[0])) {
        // list of lists
        for (let r = 0; r < inSize; r++) {
          if (activations[r] === 0) continue;
          for (let c = 0; c < outSize; c++) {
            const wq = W[r][c];
            const w = (wq - zero) * scale;
            output[c] += activations[r] * w;
          }
        }
      } else {
        // flat array
        for (let r = 0; r < inSize; r++) {
          if (activations[r] === 0) continue;
          for (let c = 0; c < outSize; c++) {
            const wq = W[r * outSize + c];
            const w = (wq - zero) * scale;
            output[c] += activations[r] * w;
          }
        }
      }
    } else {
      // Sparse format: {flat_index: int8_value}
      for (const [flatIdxStr, wq] of Object.entries(W)) {
        const flatIdx = parseInt(flatIdxStr);
        const r = Math.floor(flatIdx / outSize);
        const c = flatIdx % outSize;
        const w = (wq - zero) * scale;
        output[c] += activations[r] * w;
      }
    }

    // Add bias and apply activation
    for (let c = 0; c < outSize; c++) {
      output[c] += b[c];
      if (layer < nLayers - 1) {
        // ReLU
        output[c] = Math.max(0, output[c]);
      } else {
        // Sigmoid (output layer)
        output[c] = 1.0 / (1.0 + Math.exp(-output[c]));
      }
    }

    activations = output;
  }

  return activations[0];
}

// =============================================================================
// Feature vectorization (shared between LR and MLP)
// =============================================================================

/**
 * Build a normalized feature vector that both LR and MLP can use.
 * Returns a Map<vocab_idx_string, normalized_tfidf>.
 */
function buildFeatureVector(tf, vocabMap, idfMap) {
  const vec = new Map();
  let sumSquares = 0;
  const entries = [];
  for (const [feature, count] of tf) {
    const vocabIdx = vocabMap.get(feature);
    if (vocabIdx === undefined) continue;
    const idfWeight = idfMap.get(feature);
    if (idfWeight === undefined) continue;
    const tfidf = count * idfWeight;
    entries.push({ vocabIdx, tfidf });
    sumSquares += tfidf * tfidf;
  }
  const norm = Math.sqrt(sumSquares);
  if (norm === 0) {
    return vec;
  }
  for (const { vocabIdx, tfidf } of entries) {
    vec.set(String(vocabIdx), tfidf / norm);
  }
  return vec;
}

// =============================================================================
// Main inference function
// =============================================================================

/**
 * Create an ML inference engine from loaded artifacts.
 * Returns a function: text -> { score, isAttack, latencyMs }
 */
function createEngine(artifacts) {
  const {
    vocabulary,        // LR vocabulary: feature_name -> index
    idf,               // LR idf: feature_name -> idf_value
    lrConfig,          // { intercept, threshold, ... }
    lrCoefficients,    // { index_string -> coef }
    mlpVocabulary,     // MLP vocabulary: feature_name -> index (subset of LR)
    mlpIdf,            // MLP idf: feature_name -> idf_value
    mlpConfig,         // { n_layers, layer_sizes, quant_scales, quant_zeros, threshold }
    mlpWeights,        // [w0, w1, ...]
    mlpBiases,         // [b0, b1, ...]
  } = artifacts;

  const vocabMap = new Map(Object.entries(vocabulary));
  const idfMap = new Map(Object.entries(idf));
  const lrCoefMap = new Map(Object.entries(lrCoefficients));

  // MLP uses its own vocabulary (may differ from LR)
  const mlpVocabMap = mlpVocabulary ? new Map(Object.entries(mlpVocabulary)) : vocabMap;
  const mlpIdfMap = mlpIdf ? new Map(Object.entries(mlpIdf)) : idfMap;

  return function predict(text) {
    const t0 = (typeof performance !== 'undefined' ? performance.now() : Date.now());
    const tf = tokenize(text);

    // LR uses LR's vocabulary/IDF
    const lrScore = scoreLR(tf, vocabMap, idfMap, lrCoefMap, lrConfig.intercept);

    // MLP uses MLP's vocabulary/IDF
    const mlpFeatures = buildFeatureVector(tf, mlpVocabMap, mlpIdfMap);
    const mlpScore = scoreMLP(mlpFeatures, mlpConfig, mlpWeights, mlpBiases);

    // Average ensemble
    const score = (lrScore + mlpScore) / 2;
    const isAttack = score >= mlpConfig.threshold;

    const t1 = (typeof performance !== 'undefined' ? performance.now() : Date.now());
    return {
      score,
      lrScore,
      mlpScore,
      isAttack,
      latencyMs: t1 - t0,
    };
  };
}

// Export for Node.js / browser / extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createEngine, tokenize, scoreLR, scoreMLP, buildFeatureVector };
}
