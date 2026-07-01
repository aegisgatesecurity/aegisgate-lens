/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Bundle Registry (v0.2.0 NEW)
   =========================================================================

   Central registry of every model bundle the Lens ships. The service worker
   and content script use this registry to look up bundles by facet name
   without hardcoding paths or versions.

   This file is the single source of truth for bundle metadata. Any new
   bundle ships an entry here. The build pipeline verifies every bundle in
   the registry is present in `vendor/bundles/` and signed.

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * The canonical bundle registry. Format:
   *   facet_name: {
   *     bundle_filename: <string>,
   *     bundle_sha256: <hex string>,
   *     signing_pub_key_id: <string>,
   *     base_checkpoint: <HuggingFace model ID>,
   *     base_license: <license string>,
   *     onnx_format: <quantization format>,
   *     expected_size_bytes: <int>,
   *     max_context_tokens: <int>,
   *     inference: 'webgpu-or-wasm' | 'wasm-only',
   *   }
   *
   * The sha256 values are populated post-training (step 5). Until then,
   * placeholders are used; the build pipeline rejects placeholder values
   * before release.
   */
  const BUNDLE_REGISTRY = Object.freeze({
    'prompt-injection': {
      bundle_filename: 'aegisgate-lens-prompt-injection-int8-v0.2.0.bundle',
      bundle_sha256: '243b18dd4a57b1836d30d2541f6cf0cb372eab680147660e8b6a9192d2036e82',
      signing_pub_key_id: 'lens-v02-2026-06-29',
      base_checkpoint: 'answerdotai/ModernBERT-base',
      base_license: 'Apache-2.0',
      onnx_format: 'int8',  // dynamic INT8 quantization (74.9% size reduction)
      expected_size_bytes: 147 * 1024 * 1024,  // 147 MB (INT8), down from 574 MB (FP32)
      max_context_tokens: 8192,
      inference: 'webgpu-or-wasm',
    },
    'toxicity': {
      bundle_filename: 'aegisgate-lens-toxicity-v0.2.0.bundle',
      bundle_sha256: 'PLACEHOLDER_FILLED_AT_TRAIN_TIME',
      signing_pub_key_id: 'lens-v02-2026-06-26',
      base_checkpoint: 'unitary/toxic-bert',
      base_license: 'Apache-2.0',
      onnx_format: 'int8',
      // The on-disk bundle ships BOTH model.onnx (417 MB FP32) and
      // model_int8.onnx (105 MB int8) for forward-compatibility with
      // downstream tooling. The int8 model is what gets loaded (see
      // model-loader.js createSession), so the effective runtime
      // footprint is `model_size_bytes` (105 MB). The build pipeline
      // (post-train) fills bundle_sha256 and expected_size_bytes.
      expected_size_bytes: 110 * 1024 * 1024,  // filled post-train (see bundle-registry.js in lens-final-dist)
      model_size_bytes: 105 * 1024 * 1024,     // 105 MB (int8 model, what gets loaded)
      max_context_tokens: 512,
      inference: 'wasm-only',
    },
  });

  /**
   * Look up a bundle by facet name.
   * @param {string} facetName - 'prompt-injection' | 'toxicity'
   * @returns {Object|null} The bundle entry, or null if unknown.
   */
  function getBundle(facetName) {
    return BUNDLE_REGISTRY[facetName] || null;
  }

  /**
   * List all known bundle filenames (used by the build pipeline to verify
   * every bundle is present in vendor/bundles/).
   * @returns {string[]}
   */
  function listBundleFilenames() {
    return Object.values(BUNDLE_REGISTRY).map(b => b.bundle_filename);
  }

  /**
   * Get the total expected bundle cache size in bytes (for storage quota
   * planning).
   * @returns {number}
   */
  function totalExpectedSizeBytes() {
    return Object.values(BUNDLE_REGISTRY).reduce(
      (sum, b) => sum + b.expected_size_bytes, 0
    );
  }

  NS.util = NS.util || {};
  NS.util.bundleRegistry = {
    BUNDLE_REGISTRY,
    getBundle,
    listBundleFilenames,
    totalExpectedSizeBytes,
  };
})();
