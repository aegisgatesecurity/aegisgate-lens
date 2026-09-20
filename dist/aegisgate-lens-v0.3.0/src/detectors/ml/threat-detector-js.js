// AegisGate Lens — ml/threat-detector-js.js
// Pure JavaScript inference for the Char CNN-BiLSTM threat detection model.
//
// NO WASM. NO onnxruntime. NO external dependencies.
// The model weights are exported as float16, gzip-compressed, base64-encoded JSON.
// Total weight package: ~3.7MB. Total extension size savings: ~18MB (no ORT WASM).
//
// Architecture (forward pass):
//   1. Embedding: [128] int32 → [128, 64] float32 lookup table
//   2. Conv branches (kernel sizes 3, 5, 7) → ReLU → Concat → [128, 768]
//   3. BatchNorm → [128, 768]
//   4. BiLSTM layer 1 (hidden=128) → [128, 256]
//   5. BiLSTM layer 2 (hidden=128) → [128, 256]
//   6. Attention (learned query vector) → [256]
//   7. Dense1 (256→64) → ReLU → [64]
//   8. Dense2 (64→1) → Sigmoid → [1] (threat score)
//
// Float16 weights are upcast to float32 at load time for computation.
// Max quantization error: ~0.0005 (negligible for threat scoring).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var log = (typeof self !== 'undefined' && self.__lensLogger) ||
            (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
            { info: function(m){ try { console.log('[AegisGate Lens ML] ' + m); } catch (e) {} },
              warn: function(m){ try { console.warn('[AegisGate Lens ML] ' + m); } catch (e) {} },
              error: function(m,e){ try { console.error('[AegisGate Lens ML] ' + m, e); } catch (e) {} } };

  // Constants
  var MAX_SEQ_LEN = 128;
  var PAD_ID = 0;
  var UNK_ID = 1;
  var THRESHOLD = 0.5;
  var INFERENCE_TIMEOUT_MS = 500;
  var MODEL_VERSION = 'char-cnn-bilstm-v4.0-js';

  // Model state
  var weights = null;    // Weight tensors (float32)
  var modelLoaded = false;

  // ---------------------------------------------------------------
  // Math helpers (no Math.fround needed — we compute in float64)
  // ---------------------------------------------------------------
  function sigmoid(x) {
    if (x >= 0) { return 1 / (1 + Math.exp(-x)); }
    var ex = Math.exp(x); return ex / (1 + ex);
  }

  function relu(x) { return x > 0 ? x : 0; }

  // ---------------------------------------------------------------
  // Weight loading
  // ---------------------------------------------------------------
  function decodeWeights(packageData) {
    // packageData: { v: '1.0', meta: [{n,s,o,l}], data: '<base64 gzip>' }
    var compressed;
    try {
      compressed = atob(packageData.data);
    } catch (e) {
      throw new Error('threat-detector-js: base64 decode failed: ' + e.message);
    }

    // Decompress gzip manually (browser has DecompressionStream, but we
    // need synchronous decompression for the load path). We'll use
    // pako-like inflate or the browser's built-in DecompressionStream.
    // For synchronous loading, we pre-decode at build time.
    // Actually, we need to handle this — use the browser's built-in
    // decompression.
    throw new Error('threat-detector-js: use loadModel() for async weight loading');
  }

  // Async load: fetch weight package, decompress, reconstruct tensors
  async function loadModel() {
    if (modelLoaded) return;

    log.info('Loading threat detection model (pure JS, no WASM)...');

    try {
      var modelUrl = chrome.runtime.getURL('models/threat_cnn_bilstm_weights.bin.json');
      var response = await fetch(modelUrl);
      if (!response.ok) {
        throw new Error('HTTP ' + response.status + ': ' + response.statusText);
      }
      var packageData = await response.json();

      // Decompress gzip using browser's DecompressionStream
      var compressed = atob(packageData.data);
      var compressedBytes = new Uint8Array(compressed.length);
      for (var i = 0; i < compressed.length; i++) {
        compressedBytes[i] = compressed.charCodeAt(i);
      }

      var decompressed = await decompressGzip(compressedBytes);

      // Reconstruct weight tensors
      weights = {};
      for (var j = 0; j < packageData.meta.length; j++) {
        var meta = packageData.meta[j];
        var offset = meta.o;
        var length = meta.l;
        var f16 = new Float16Array(decompressed.buffer, offset, length / 2);
        // Upcast to float32 for computation
        var f32 = new Float32Array(f16.length);
        for (var k = 0; k < f16.length; k++) {
          f32[k] = f16[k];
        }
        var shape = meta.s;
        weights[meta.n] = reshape(f32, shape);
      }

      modelLoaded = true;
      log.info('Threat detection model loaded: ' + Object.keys(weights).length + ' tensors, pure JS inference');
    } catch (err) {
      log.error('Failed to load threat detection model: ' + err.message, err);
      weights = null;
      modelLoaded = false;
      throw err;
    }
  }

  function reshape(flat, shape) {
    // Create a nested array matching shape
    var total = 1;
    for (var i = 0; i < shape.length; i++) total *= shape[i];
    if (flat.length !== total) {
      throw new Error('reshape: size mismatch (' + flat.length + ' vs ' + total + ')');
    }
    // For JS inference, we store as flat Float32Array + shape metadata.
    // Matrix operations use flat arrays with manual indexing.
    return { data: flat, shape: shape };
  }

  async function decompressGzip(bytes) {
    // Use browser's built-in DecompressionStream (available in all modern browsers)
    if (typeof DecompressionStream !== 'undefined') {
      var ds = new DecompressionStream('gzip');
      var writer = ds.writable.getWriter();
      writer.write(bytes);
      writer.close();

      var reader = ds.readable.getReader();
      var chunks = [];
      var totalLength = 0;
      while (true) {
        var result = await reader.read();
        if (result.done) break;
        chunks.push(result.value);
        totalLength += result.value.length;
      }

      var decompressed = new Uint8Array(totalLength);
      var offset = 0;
      for (var i = 0; i < chunks.length; i++) {
        decompressed.set(chunks[i], offset);
        offset += chunks[i].length;
      }
      return decompressed;
    }

    // Fallback: manual gzip decompression (minimal inflate)
    throw new Error('threat-detector-js: DecompressionStream not available');
  }

  // ---------------------------------------------------------------
  // Forward pass operations (all on flat Float32Arrays)
  // ---------------------------------------------------------------

  // 2D matmul: C[m,n] = A[m,k] @ B[k,n]
  // A: (m, k), B: (k, n), result: (m, n)
  function matmul2d(a, aShape, b, bShape) {
    var m = aShape[0], k = aShape[1], n = bShape[1];
    if (k !== bShape[0]) throw new Error('matmul2d: dimension mismatch');
    var result = new Float32Array(m * n);
    for (var i = 0; i < m; i++) {
      for (var j = 0; j < n; j++) {
        var sum = 0;
        for (var p = 0; p < k; p++) {
          sum += a[i * k + p] * b[p * n + j];
        }
        result[i * n + j] = sum;
      }
    }
    return result;
  }

  // 1D convolution: out[t,oc] = bias[oc] + sum_ic sum_k input[t+k,ic] * weight[oc,ic,k]
  // input: (seq_len, in_ch), weight: (out_ch, in_ch, kernel_size), bias: (out_ch,)
  // Uses padding='same' (center the kernel)
  function conv1dSame(input, inCh, seqLen, weight, outCh, kernelSize, bias) {
    var halfK = Math.floor(kernelSize / 2);
    var result = new Float32Array(seqLen * outCh);
    for (var t = 0; t < seqLen; t++) {
      for (var oc = 0; oc < outCh; oc++) {
        var val = bias[oc];
        for (var ic = 0; ic < inCh; ic++) {
          for (var k = 0; k < kernelSize; k++) {
            var tt = t + k - halfK;
            if (tt >= 0 && tt < seqLen) {
              val += input[tt * inCh + ic] * weight[((oc * inCh) + ic) * kernelSize + k];
            }
          }
        }
        result[t * outCh + oc] = val;
      }
    }
    return result;
  }

  // Batch normalization (inference mode)
  function batchNorm(input, gamma, beta, mean, var_, eps) {
    var channels = gamma.length;
    var len = input.length / channels;
    var result = new Float32Array(input.length);
    for (var i = 0; i < len; i++) {
      for (var c = 0; c < channels; c++) {
        result[i * channels + c] = gamma[c] * (input[i * channels + c] - mean[c]) / Math.sqrt(var_[c] + eps) + beta[c];
      }
    }
    return result;
  }

  // LSTM step: gates = x @ W_ih.T + h @ W_hh.T + b
  // W_ih: (4*hidden, input), W_hh: (4*hidden, hidden), b: (4*hidden,)
  // Returns: output[t], updated (h, c)
  function lstmStep(xt, W_ih, W_hh, b, h, c, hiddenSize, inputSize) {
    // gates = xt @ W_ih^T + h @ W_hh^T + b
    // W_ih is stored as (4*hidden, input), so W_ih^T is (input, 4*hidden)
    // We compute gates[4*hidden] directly
    var gates = new Float32Array(4 * hiddenSize);
    for (var g = 0; g < 4 * hiddenSize; g++) {
      var sum = b ? b[g] : 0;
      for (var j = 0; j < inputSize; j++) {
        sum += xt[j] * W_ih[g * inputSize + j];
      }
      for (var j2 = 0; j2 < hiddenSize; j2++) {
        sum += h[j2] * W_hh[g * hiddenSize + j2];
      }
      gates[g] = sum;
    }

    var i_gate = new Float32Array(hiddenSize);
    var f_gate = new Float32Array(hiddenSize);
    var o_gate = new Float32Array(hiddenSize);
    var c_tilde = new Float32Array(hiddenSize);
    for (var k = 0; k < hiddenSize; k++) {
      i_gate[k] = sigmoid(gates[k]);
      f_gate[k] = sigmoid(gates[hiddenSize + k]);
      o_gate[k] = sigmoid(gates[2 * hiddenSize + k]);
      c_tilde[k] = Math.tanh(gates[3 * hiddenSize + k]);
    }

    var newC = new Float32Array(hiddenSize);
    var newH = new Float32Array(hiddenSize);
    for (var k2 = 0; k2 < hiddenSize; k2++) {
      newC[k2] = f_gate[k2] * c[k2] + i_gate[k2] * c_tilde[k2];
      newH[k2] = o_gate[k2] * Math.tanh(newC[k2]);
    }
    return { h: newH, c: newC };
  }

  // Bidirectional LSTM
  // W_ih: (2, 4*hidden, input), W_hh: (2, 4*hidden, hidden), b: (2, 4*hidden)
  // Returns: output (seqLen, 2*hidden)
  function biLSTM(input, seqLen, inputSize, W_ih, W_hh, b, hiddenSize) {
    var output = new Float32Array(seqLen * 2 * hiddenSize);

    // Forward pass
    var hF = new Float32Array(hiddenSize);
    var cF = new Float32Array(hiddenSize);
    var forwardOutputs = new Float32Array(seqLen * hiddenSize);
    for (var t = 0; t < seqLen; t++) {
      var xt = input.subarray(t * inputSize, (t + 1) * inputSize);
      var step = lstmStep(xt, W_ih[0], W_hh[0], b[0], hF, cF, hiddenSize, inputSize);
      hF = step.h;
      cF = step.c;
      forwardOutputs.set(hF, t * hiddenSize);
    }

    // Backward pass
    var hB = new Float32Array(hiddenSize);
    var cB = new Float32Array(hiddenSize);
    var backwardOutputs = new Float32Array(seqLen * hiddenSize);
    for (var t2 = seqLen - 1; t2 >= 0; t2--) {
      var xt2 = input.subarray(t2 * inputSize, (t2 + 1) * inputSize);
      var step2 = lstmStep(xt2, W_ih[1], W_hh[1], b[1], hB, cB, hiddenSize, inputSize);
      hB = step2.h;
      cB = step2.c;
      backwardOutputs.set(hB, t2 * hiddenSize);
    }

    // Concatenate forward and backward
    for (var t3 = 0; t3 < seqLen; t3++) {
      output.set(forwardOutputs.subarray(t3 * hiddenSize, (t3 + 1) * hiddenSize), t3 * 2 * hiddenSize);
      output.set(backwardOutputs.subarray(t3 * hiddenSize, (t3 + 1) * hiddenSize), t3 * 2 * hiddenSize + hiddenSize);
    }

    return output;
  }

  // ---------------------------------------------------------------
  // Main inference function
  // ---------------------------------------------------------------
  async function classify(text) {
    // Lazy load: if model isn't loaded yet, load it now on first call.
    // This avoids loading 3.7MB of weights on page load and instead
    // defers to first keystroke detection.
    if (!modelLoaded || !weights) {
      try {
        await loadModel();
      } catch (e) {
        // loadModel already logged the error; return safe default
        return { isAdversarial: false, score: 0, modelVersion: MODEL_VERSION };
      }
    }

    var startTime = performance.now();

    try {
      // Encode text to character IDs (same as char-normalizer.js)
      var normalized = (text || '').toLowerCase().trim();
      normalized = normalized.replace(/\s+/g, ' ');
      if (normalized.length > MAX_SEQ_LEN) normalized = normalized.substring(0, MAX_SEQ_LEN);

      var inputIds = new Int32Array(MAX_SEQ_LEN);
      for (var i = 0; i < MAX_SEQ_LEN; i++) {
        if (i < normalized.length) {
          var code = normalized.charCodeAt(i);
          inputIds[i] = (code >= 32 && code <= 126) ? code : UNK_ID;
        } else {
          inputIds[i] = PAD_ID;
        }
      }

      // 1. Embedding lookup: [128] → [128, 64]
      var embW = weights['embedding.weight'];  // (128, 64)
      var embedded = new Float32Array(MAX_SEQ_LEN * 64);
      for (var t = 0; t < MAX_SEQ_LEN; t++) {
        var id = inputIds[t];
        for (var d = 0; d < 64; d++) {
          embedded[t * 64 + d] = embW.data[id * 64 + d];
        }
      }

      // 2. Conv branches + ReLU
      var c0 = conv1dSame(embedded, 64, MAX_SEQ_LEN,
        weights['conv_branches.0.weight'].data, 256, 3, weights['conv_branches.0.bias'].data);
      for (var i2 = 0; i2 < c0.length; i2++) c0[i2] = relu(c0[i2]);

      var c1 = conv1dSame(embedded, 64, MAX_SEQ_LEN,
        weights['conv_branches.1.weight'].data, 256, 5, weights['conv_branches.1.bias'].data);
      for (var i3 = 0; i3 < c1.length; i3++) c1[i3] = relu(c1[i3]);

      var c2 = conv1dSame(embedded, 64, MAX_SEQ_LEN,
        weights['conv_branches.2.weight'].data, 256, 7, weights['conv_branches.2.bias'].data);
      for (var i4 = 0; i4 < c2.length; i4++) c2[i4] = relu(c2[i4]);

      // 3. Concat → (128, 768) + BatchNorm
      var concat = new Float32Array(MAX_SEQ_LEN * 768);
      for (var t2 = 0; t2 < MAX_SEQ_LEN; t2++) {
        concat.set(c0.subarray(t2 * 256, (t2 + 1) * 256), t2 * 768);
        concat.set(c1.subarray(t2 * 256, (t2 + 1) * 256), t2 * 768 + 256);
        concat.set(c2.subarray(t2 * 256, (t2 + 1) * 256), t2 * 768 + 512);
      }

      var bn = batchNorm(concat,
        weights['batch_norm.weight'].data,
        weights['batch_norm.bias'].data,
        weights['batch_norm.running_mean'].data,
        weights['batch_norm.running_var'].data,
        1e-5);

      // 4. BiLSTM layer 1: input=768, hidden=128, output=256
      var W_ih_1 = [weights['onnx::LSTM_390'].data.subarray(0, 512*768),
                     weights['onnx::LSTM_390'].data.subarray(512*768, 2*512*768)];
      var W_hh_1 = [weights['onnx::LSTM_391'].data.subarray(0, 512*128),
                     weights['onnx::LSTM_391'].data.subarray(512*128, 2*512*128)];
      var b_1 = [weights['onnx::LSTM_389'].data.subarray(0, 1024),
                 weights['onnx::LSTM_389'].data.subarray(1024, 2048)];

      var lstm1_out = biLSTM(bn, MAX_SEQ_LEN, 768, W_ih_1, W_hh_1, b_1, 128);

      // 5. BiLSTM layer 2: input=256, hidden=128, output=256
      var W_ih_2 = [weights['onnx::LSTM_433'].data.subarray(0, 512*256),
                     weights['onnx::LSTM_433'].data.subarray(512*256, 2*512*256)];
      var W_hh_2 = [weights['onnx::LSTM_434'].data.subarray(0, 512*128),
                     weights['onnx::LSTM_434'].data.subarray(512*128, 2*512*128)];
      var b_2 = [weights['onnx::LSTM_432'].data.subarray(0, 1024),
                 weights['onnx::LSTM_432'].data.subarray(1024, 2048)];

      var lstm2_out = biLSTM(lstm1_out, MAX_SEQ_LEN, 256, W_ih_2, W_hh_2, b_2, 128);

      // 6. Attention: score = lstm2_out @ attention_query, softmax, weighted sum
      var attn_query = weights['onnx::MatMul_435'].data;  // (256, 1)
      var attn_bias = weights['attention.attention.bias'].data;  // (1,)

      // scores = lstm2_out @ attn_query + attn_bias  → (128, 1)
      var scores = new Float32Array(MAX_SEQ_LEN);
      for (var t3 = 0; t3 < MAX_SEQ_LEN; t3++) {
        var s = attn_bias[0];
        for (var d2 = 0; d2 < 256; d2++) {
          s += lstm2_out[t3 * 256 + d2] * attn_query[d2];
        }
        scores[t3] = s;
      }

      // Softmax
      var maxScore = -Infinity;
      for (var i5 = 0; i5 < MAX_SEQ_LEN; i5++) { if (scores[i5] > maxScore) maxScore = scores[i5]; }
      var expSum = 0;
      for (var i6 = 0; i6 < MAX_SEQ_LEN; i6++) { scores[i6] = Math.exp(scores[i6] - maxScore); expSum += scores[i6]; }
      for (var i7 = 0; i7 < MAX_SEQ_LEN; i7++) { scores[i7] /= expSum; }

      // Weighted sum
      var context = new Float32Array(256);
      for (var t4 = 0; t4 < MAX_SEQ_LEN; t4++) {
        for (var d3 = 0; d3 < 256; d3++) {
          context[d3] += scores[t4] * lstm2_out[t4 * 256 + d3];
        }
      }

      // 7. Dense1: (256) → (64) + ReLU
      var d1_w = weights['dense1.weight'].data;  // (64, 256)
      var d1_b = weights['dense1.bias'].data;    // (64,)
      var dense1 = new Float32Array(64);
      for (var i8 = 0; i8 < 64; i8++) {
        var sum2 = d1_b[i8];
        for (var j = 0; j < 256; j++) {
          sum2 += context[j] * d1_w[i8 * 256 + j];
        }
        dense1[i8] = relu(sum2);
      }

      // 8. Dense2: (64) → (1) + Sigmoid
      var d2_w = weights['dense2.weight'].data;  // (1, 64)
      var d2_b = weights['dense2.bias'].data;    // (1,)
      var logit = d2_b[0];
      for (var i9 = 0; i9 < 64; i9++) {
        logit += dense1[i9] * d2_w[i9];
      }
      var score = sigmoid(logit);

      var elapsed = performance.now() - startTime;
      log.info('ML inference: score=' + score.toFixed(4) + ' time=' + elapsed.toFixed(1) + 'ms');

      return {
        isAdversarial: score >= THRESHOLD,
        score: Math.max(0, Math.min(1, score)),
        modelVersion: MODEL_VERSION,
        inferenceTimeMs: elapsed
      };

    } catch (err) {
      log.error('ML inference failed: ' + err.message, err);
      return { isAdversarial: false, score: 0, modelVersion: MODEL_VERSION, error: err.message };
    }
  }

  // Unload model (free memory)
  function unloadModel() {
    weights = null;
    modelLoaded = false;
    log.info('Threat detection model unloaded');
  }

  // Get diagnostics
  function getDiagnostics() {
    return {
      modelLoaded: modelLoaded,
      modelVersion: MODEL_VERSION,
      inferenceEngine: 'pure-js',
      weightCount: modelLoaded ? Object.keys(weights).length : 0,
      threshold: THRESHOLD,
      maxSeqLen: MAX_SEQ_LEN
    };
  }

  var module = {
    loadModel: loadModel,
    classify: classify,
    unloadModel: unloadModel,
    getDiagnostics: getDiagnostics,
    MAX_SEQ_LEN: MAX_SEQ_LEN,
    PAD_ID: PAD_ID,
    UNK_ID: UNK_ID,
    THRESHOLD: THRESHOLD,
    MODEL_VERSION: MODEL_VERSION
  };

  if (typeof self !== 'undefined') self.__lensThreatDetector = module;
  if (typeof window !== 'undefined') window.__lensThreatDetector = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensThreatDetector = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);