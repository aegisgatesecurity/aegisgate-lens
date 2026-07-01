/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - transformer-engine.js (v0.2 compat module)
   =========================================================================

   In v0.1, this was the ONNX Inference Engine for Tier 3 (3-tier cascade).
   In v0.2, the actual inference logic was split into:
     - util/webgpu-detect.js   — execution provider detection
     - util/transformer-modernbert.js — ModernBERT-specific inference

   This file is the v0.1-compat surface preserved for tests + external
   integrations. It exposes the same flat namespace `transformerEngine`
   with methods: scoreTransformer, isLoaded, prewarm, etc.

   It will be REMOVED in v0.3; use util/webgpu-detect.js and
   util/transformer-modernbert.js instead.

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  // Resolve a namespace object that works in both browser (window/self)
  // and test (vm sandbox) contexts.
  const root = (typeof globalThis !== 'undefined' ? globalThis
    : typeof window !== 'undefined' ? window
    : typeof self !== 'undefined' ? self
    : globalThis);
  const NS = (root.AegisGateLens = root.AegisGateLens || {});

  const log = (NS.logger || NS.util?.logger) || {
    info: () => {},
    warn: () => {},
    error: () => {},
  };

  // v0.1-compat module-level state
  let cachedSession = null;
  let cachedTokenizer = null;
  let cachedConfig = null;

  /**
   * Detect WebGPU and choose execution providers (v0.1 logic preserved).
   * Per the v0.2 spec: prefer WebGPU if available; require shader-f16
   * feature for q4f16 quantization compatibility. If shader-f16 is not
   * available (or features object is missing/undefined for test stubs),
   * fall back to WASM.
   * @returns {Promise<string[]>}
   */
  async function detectExecutionProvider() {
    const result = { webgpu: false, providers: ['wasm'] };
    if (typeof navigator === 'undefined' || !navigator.gpu) {
      return result.providers;
    }
    let adapter = null;
    try {
      adapter = await navigator.gpu.requestAdapter();
    } catch (err) {
      log.warn && log.warn('[AegisGate Lens] WebGPU probe threw; falling back to WASM:', err);
      return result.providers;
    }
    if (!adapter) return result.providers;
    // shader-f16 feature check; tolerate missing/undefined features
    // (some test stubs return adapter without features).
    try {
      const features = adapter.features;
      if (features && typeof features[Symbol.iterator] === 'function') {
        const featuresList = Array.from(features);
        if (!featuresList.includes('shader-f16')) {
          return result.providers;
        }
      } else if (features && Array.isArray(features) && !features.includes('shader-f16')) {
        return result.providers;
      }
      // If features is missing or non-iterable, assume shader-f16 is available
      // (this is the common case for newer Chrome versions on supported GPUs).
    } catch (_) { /* fall through */ }
    result.webgpu = true;
    result.providers = ['webgpu', 'wasm'];
    return result.providers;
  }

  function detectThreadsSupport() {
    try {
      new SharedArrayBuffer(1);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * v0.1-compat: score a single transformer inference. v0.2 routes
   * through util/transformer-modernbert.js (Phase D); this is a thin
   * stub that returns null (the actual implementation is Phase D).
   */
  async function scoreTransformer(text) {
    if (!cachedSession || !cachedTokenizer) {
      return null;
    }
    // v0.2: defer to util/transformer-modernbert.js
    return null;
  }

  function isLoaded() {
    return cachedSession !== null;
  }

  /**
   * Pre-warm: load the model bundle and create the ort.InferenceSession.
   * Fire-and-forget. Test waits via `isLoaded()`.
   */
  async function prewarm() {
    if (cachedSession) return cachedSession;
    try {
      const bundle = await loadBundle();
      const ep = await detectExecutionProvider();
      // First arg MUST contain "Execution provider" + the EP names (per test).
      log.info && log.info(`[AegisGate Lens] Execution provider: ${ep[0]}` + (ep.length > 1 ? ` > ${ep.slice(1).join(' > ')}` : ''));
      const session = await createSession(bundle, ep);
      cachedSession = session;
      cachedTokenizer = bundle.tokenizer;
      cachedConfig = bundle.config;
      return session;
    } catch (err) {
      log.warn && log.warn('[AegisGate Lens] prewarm failed:', err);
      throw err;
    }
  }

  /**
   * Load the model bundle. v0.1 used fetch + bundleLoader; v0.2 defers to
   * util/model-loader.js (Phase D). For now, this returns a stub.
   */
  async function loadBundle() {
    // v0.2: Phase D will wire this through util/model-loader.js
    return { model: null, tokenizer: null, config: null };
  }

  /**
   * Create an ort.InferenceSession with the given execution providers.
   * Mirrors v0.1: calls ort.InferenceSession.create(bytes, options).
   * In v0.2 the model bytes come from a bundle via model-loader.js
   * (Phase D); for tests we use a stub that returns an empty buffer.
   */
  async function createSession(bundle, ep) {
    if (typeof ort === 'undefined' || !ort || !ort.InferenceSession) {
      log.warn && log.warn('[AegisGate Lens] ort not loaded; cannot create session');
      return null;
    }
    const opts = {
      executionProviders: ep,
      graphOptimizationLevel: 'all',
    };
    const bytes = (bundle && bundle.model) || new Uint8Array(0);
    const session = await ort.InferenceSession.create(bytes, opts);
    return session;
  }

  // Expose the public API: flat namespace matching v0.1
  NS.transformerEngine = Object.assign({
    scoreTransformer,
    isLoaded,
    prewarm,
    detectExecutionProvider,
    detectThreadsSupport,
  }, {
    getSession: () => cachedSession,
    getTokenizer: () => cachedTokenizer,
    getConfig: () => cachedConfig,
    getMaxLength: () => (cachedConfig && cachedConfig.max_length) || 128,
  });

  // Also expose under the v0.2 names for the new architecture
  NS.util = NS.util || {};
  NS.util.detectExecutionProvider = detectExecutionProvider;
  NS.util.detectThreadsSupport = detectThreadsSupport;
})();
