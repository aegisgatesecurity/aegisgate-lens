/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - WebGPU Execution Provider Detection (v0.2.0)
   =========================================================================

   Runtime detection of WebGPU capabilities and execution provider selection
   for ONNX Runtime Web inference.

   Algorithm:
     1. Check navigator.gpu exists (Chrome 113+, Edge 113+, Opera 99+)
     2. Probe requestAdapter() — some installs have navigator.gpu but no
        adapter (e.g., headless Chrome without --enable-unsafe-webgpu)
     3. Verify adapter has shader-f16 feature (needed for q4f16 inference)
     4. Return execution provider list ['webgpu', 'wasm'] or ['wasm'] only
     5. Detect SharedArrayBuffer support for threaded WASM fallback

   This module is referenced by model-loader.js (service worker) and
   transformer-modernbert.js (content script).

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * @typedef {Object} EPDetectionResult
   * @property {boolean} webgpu - WebGPU is available and meets feature requirements
   * @property {boolean} wasm - WASM is always available (Chrome 116+)
   * @property {boolean} threads - SharedArrayBuffer available (for threaded WASM)
   * @property {object|null} adapter - The WebGPU adapter object (or null)
   * @property {string[]} providers - Ordered list of execution providers to try
   */

  /**
   * Detect WebGPU capability and build an execution provider list.
   * @returns {Promise<EPDetectionResult>}
   */
  async function detectExecutionProvider() {
    const result = {
      webgpu: false,
      wasm: true,  // always available
      threads: detectThreadsSupport(),
      adapter: null,
      providers: ['wasm'],
    };

    // 1. Check navigator.gpu exists
    if (typeof navigator === 'undefined' || !navigator.gpu) {
      return result;
    }

    // 2. Probe adapter
    let adapter = null;
    try {
      adapter = await navigator.gpu.requestAdapter();
    } catch (err) {
      log.warn('[AegisGate Lens] WebGPU probe threw; falling back to WASM:', err);
      return result;
    }

    if (!adapter) {
      return result;
    }

    // 3. Verify adapter has required features (shader-f16 needed for q4f16)
    try {
      const features = Array.from(adapter.features || []);
      if (!features.includes('shader-f16')) {
        log.warn('[AegisGate Lens] WebGPU adapter lacks shader-f16; falling back to WASM');
        return result;
      }
    } catch (err) {
      log.warn('[AegisGate Lens] WebGPU feature probe threw; falling back to WASM:', err);
      return result;
    }

    result.adapter = adapter;
    result.webgpu = true;
    result.providers = ['webgpu', 'wasm'];
    return result;
  }

  /**
   * Detect SharedArrayBuffer availability (for threaded WASM fallback).
   * MV3 requires cross-origin isolation for SharedArrayBuffer; many
   * extensions don't have this.
   * @returns {boolean}
   */
  function detectThreadsSupport() {
    try {
      new SharedArrayBuffer(1);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get execution providers for a specific model. Some models (e.g.,
   * toxic-bert) prefer WASM-only because their size doesn't justify WebGPU
   * overhead.
   * @param {string} modelId - 'prompt-injection' | 'toxicity'
   * @returns {Promise<string[]>}
   */
  async function getExecutionProvidersFor(modelId) {
    const ep = await detectExecutionProvider();
    if (modelId === 'toxicity') {
      // toxic-bert (DistilBERT, 110M, 512 ctx) — WASM is fast enough;
      // WebGPU overhead exceeds benefit for short inputs
      return ['wasm'];
    }
    // Default: WebGPU first, WASM fallback
    return ep.providers;
  }

  NS.util = NS.util || {};
  NS.util.webgpuDetect = {
    detectExecutionProvider,
    detectThreadsSupport,
    getExecutionProvidersFor,
  };
})();
