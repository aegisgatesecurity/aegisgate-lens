/**
 * AegisGate Lens - N-Model Ensemble ML Inference Module
 *
 * Supports an arbitrary number of models (LR + MLPs). Each model is
 * scored independently and the results are averaged.
 *
 * Configuration: pass an array of model specs to createEngine().
 * Each spec has:
 *   - type: 'lr' or 'mlp'
 *   - vocabulary, idf (for that model's training vocab)
 *   - config, coefficients/weights/biases
 *
 * The final probability is the AVERAGE of all model probabilities.
 * This is the "soft voting" ensemble strategy.
 *
 * ZERO runtime dependencies. Pure vanilla JS.
 */

'use strict';

// =============================================================================
// Tokenization (must match Python training exactly)
// =============================================================================

function tokenize(text) {
  const features = new Map();
  const textLower = text.toLowerCase();

  const words = textLower.match(/\b\w+\b/g) || [];
  for (const w of words) {
    if (w.length >= 2) {
      const key = `w=${w}`;
      features.set(key, (features.get(key) || 0) + 1);
    }
  }

  for (let i = 0; i < words.length - 1; i++) {
    const bg = `w=${words[i]}__${words[i+1]}`;
    features.set(bg, (features.get(bg) || 0) + 1);
  }

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
// LR inference
// =============================================================================

function scoreLR(tf, vocabMap, idfMap, coefMap, intercept) {
  let score = intercept;
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
  const norm = Math.sqrt(sumSquares);
  if (norm === 0) {
    return 1 / (1 + Math.exp(-score));
  }
  for (const { tfidf, coef } of entries) {
    score += (tfidf / norm) * coef;
  }
  return 1 / (1 + Math.exp(-score));
}

// =============================================================================
// MLP inference (with INT8 dequantization)
// =============================================================================

function scoreMLP(features, mlpConfig, mlpWeights, mlpBiases) {
  const nLayers = mlpConfig.n_layers;
  const quantScales = mlpConfig.quant_scales;
  const quantZeros = mlpConfig.quant_zeros;

  let activations = new Float32Array(mlpConfig.layer_sizes[0]);
  for (const [vocabIdxStr, tfidf] of features) {
    const idx = parseInt(vocabIdxStr);
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
          if (activations[r] === 0) continue;
          for (let c = 0; c < outSize; c++) {
            const wq = W[r][c];
            const w = (wq - zero) * scale;
            output[c] += activations[r] * w;
          }
        }
      } else {
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
      for (const [flatIdxStr, wq] of Object.entries(W)) {
        const flatIdx = parseInt(flatIdxStr);
        const r = Math.floor(flatIdx / outSize);
        const c = flatIdx % outSize;
        const w = (wq - zero) * scale;
        output[c] += activations[r] * w;
      }
    }

    for (let c = 0; c < outSize; c++) {
      output[c] += b[c];
      if (layer < nLayers - 1) {
        output[c] = Math.max(0, output[c]);
      } else {
        output[c] = 1.0 / (1.0 + Math.exp(-output[c]));
      }
    }

    activations = output;
  }

  return activations[0];
}

// =============================================================================
// Feature vectorization
// =============================================================================

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
  if (norm === 0) return vec;
  for (const { vocabIdx, tfidf } of entries) {
    vec.set(String(vocabIdx), tfidf / norm);
  }
  return vec;
}

// =============================================================================
// N-Model engine
// =============================================================================

/**
 * Create an ensemble engine from an array of model specs.
 *
 * Each model spec has:
 *   { type: 'lr' | 'mlp', vocabulary, idf, ...model-specific }
 *
 * Returns: function(text) -> { score, scores, isAttack, latencyMs }
 *   - score: averaged probability
 *   - scores: array of per-model probabilities (for analysis)
 *   - isAttack: score >= threshold
 *   - latencyMs: total inference time
 */
function createEngine(modelSpecs, options = {}) {
  const threshold = options.threshold || 0.85;
  const strategy = options.strategy || 'average';  // 'average' | 'min' | 'max' | 'product'

  // Pre-process each model
  const processed = modelSpecs.map(spec => {
    const vocabMap = new Map(Object.entries(spec.vocabulary));
    const idfMap = new Map(Object.entries(spec.idf));
    const result = { type: spec.type, vocabMap, idfMap };

    if (spec.type === 'lr') {
      result.coefMap = new Map(Object.entries(spec.coefficients));
      result.intercept = spec.config.intercept;
    } else if (spec.type === 'mlp') {
      result.config = spec.config;
      result.weights = spec.weights;
      result.biases = spec.biases;
    } else {
      throw new Error(`Unknown model type: ${spec.type}`);
    }
    return result;
  });

  return function predict(text) {
    const t0 = (typeof performance !== 'undefined' ? performance.now() : Date.now());
    const tf = tokenize(text);

    const scores = [];
    for (const m of processed) {
      if (m.type === 'lr') {
        scores.push(scoreLR(tf, m.vocabMap, m.idfMap, m.coefMap, m.intercept));
      } else {
        // MLP needs feature vector built with its own vocab/idf
        const features = buildFeatureVector(tf, m.vocabMap, m.idfMap);
        scores.push(scoreMLP(features, m.config, m.weights, m.biases));
      }
    }

    let score;
    if (strategy === 'average') {
      score = scores.reduce((a, b) => a + b, 0) / scores.length;
    } else if (strategy === 'min') {
      score = Math.min(...scores);
    } else if (strategy === 'max') {
      score = Math.max(...scores);
    } else if (strategy === 'product') {
      score = scores.reduce((a, b) => a * b, 1);
      score = Math.pow(score, 1 / scores.length);  // geometric mean
    } else {
      throw new Error(`Unknown strategy: ${strategy}`);
    }

    const isAttack = score >= threshold;
    const t1 = (typeof performance !== 'undefined' ? performance.now() : Date.now());
    return {
      score,
      scores,
      isAttack,
      latencyMs: t1 - t0,
    };
  };
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createEngine, tokenize, scoreLR, scoreMLP, buildFeatureVector };
}
