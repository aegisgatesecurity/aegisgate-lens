/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Model Bundle Loader (v0.2.0 NEW)
   =========================================================================

   Lazy-loads ML model bundles from chrome.runtime.getURL(), verifies their
   Ed25519 signature, audits their license, and creates ONNX inference
   sessions. Caches loaded sessions across service-worker restarts in
   chrome.storage.local.

   Per architecture §2.1-2.3. The key property: bundles are fetched on
   first use, verified, cached. Subsequent calls are cache-fast.

   This file is a SKELETON for v0.2.0 bootstrap. The full implementation
   requires the trained bundles (step 5 of the v0.2 plan). What this skeleton
   provides:
     - BundleRegistry lookup (uses bundle-registry.js)
     - License audit (uses license-checker.js; rejects Elastic 2.0 etc.)
     - Bundle signature verification (uses bundle-loader.js from v0.1)
     - chrome.storage.local caching
     - ONNX inference session creation (defers to ort)
     - Cache invalidation on SHA mismatch

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  const { BUNDLE_REGISTRY, getBundle } = NS.util.bundleRegistry;
  const { auditBundleLicense } = NS.util.licenseChecker;
  const bundleLoader = NS.util.bundleLoader;  // from v0.1, ported
  const { detectExecutionProvider } = NS.util.webgpuDetect;
  const log = NS.logger || NS.util?.logger || {
    info: () => {},
    warn: () => {},
    error: () => {},
  };

  /**
   * In-memory cache: facetName → { session, loadedAt, version }
   */
  const inMemoryCache = new Map();

  /**
   * Get or load the ONNX inference session for a given facet.
   * @param {string} facetName - 'prompt-injection' | 'toxicity'
   * @returns {Promise<object>} ort.InferenceSession
   * @throws {Error} If license is rejected, signature fails, or bundle
   *   can't be loaded.
   */
  async function ensureSession(facetName) {
    const entry = getBundle(facetName);
    if (!entry) {
      throw new Error(`unknown facet: ${facetName}`);
    }

    // Check in-memory cache
    const cacheKey = `${facetName}@${entry.signing_pub_key_id}`;
    if (inMemoryCache.has(cacheKey)) {
      return inMemoryCache.get(cacheKey).session;
    }

    // License audit (rejects Elastic 2.0 etc.)
    const audit = auditBundleLicense(entry);
    if (!audit.ok) {
      throw new Error(`license audit failed: ${audit.reason}`);
    }

    // 1. Check chrome.storage.local for cached ArrayBuffer
    const storageKey = `bundle_cache.${entry.bundle_filename}`;
    let buffer = await readFromStorage(storageKey, entry);

    let parsed;
    if (!buffer) {
      // 2. Download from extension URL (lazy-load)
      buffer = await downloadBundle(entry);
      // 3. Verify Ed25519 signature + per-file SHA-256, returns parsed bundle
      parsed = await verifyBundle(buffer, entry);
      // 4. Cache in chrome.storage.local
      await writeToStorage(storageKey, buffer);
    } else {
      // Cached buffer: parse again (cheap — just header + file lookups)
      parsed = await verifyBundle(buffer, entry);
    }

    // 5. Create ONNX inference session
    const ep = await detectExecutionProvider();
    const providers = entry.inference === 'wasm-only'
      ? ['wasm']
      : ep.providers;

    session = await createSession(parsed, providers);

    inMemoryCache.set(cacheKey, {
      session,
      loadedAt: Date.now(),
      version: entry.signing_pub_key_id,
    });

    return session;
  }

  /**
   * Read cached bundle from chrome.storage.local. Returns null if not
   * cached or if SHA mismatch (bundle was updated).
   */
  async function readFromStorage(storageKey, entry) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return null;
    }
    const stored = await new Promise((resolve) => {
      chrome.storage.local.get(storageKey, (result) => resolve(result));
    });
    const buffer = stored[storageKey];
    if (!buffer) return null;

    // Verify SHA-256 still matches expected (handles bundle updates)
    const sha = await sha256Hex(buffer);
    if (sha !== entry.bundle_sha256) {
      log.warn(`[AegisGate Lens] cached bundle SHA mismatch for ${entry.bundle_filename}; re-downloading`);
      await new Promise((resolve) => {
        chrome.storage.local.remove(storageKey, () => resolve());
      });
      return null;
    }
    return buffer;
  }

  /**
   * Write bundle to chrome.storage.local. Requires `unlimitedStorage`
   * permission (declared in manifest.json).
   */
  async function writeToStorage(storageKey, buffer) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return;
    }
    await new Promise((resolve, reject) => {
      chrome.storage.local.set({ [storageKey]: buffer }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Download bundle from chrome.runtime.getURL().
   * The bundle file must be declared in `web_accessible_resources`.
   */
  async function downloadBundle(entry) {
    const url = chrome.runtime.getURL(
      `vendor/bundles/${entry.bundle_filename}`
    );
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`failed to download ${entry.bundle_filename}: HTTP ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  /**
   * Verify bundle signature using bundle-loader.js (v0.1, ported).
   * The bundle contains the model.safetensors (or model.onnx in v0.2),
   * tokenizer.json, and tokenizer_config.json. Ed25519 signature covers
   * the entire pre-signature byte range.
   */
  async function verifyBundle(buffer, entry) {
    const parsed = await bundleLoader.parseBundle(buffer);
    // Verify bundle SHA matches registry (defense-in-depth: catches
    // bundle swaps after the initial signature verification).
    const sha = await sha256Hex(buffer);
    if (sha !== entry.bundle_sha256) {
      throw new Error(`bundle SHA mismatch: expected ${entry.bundle_sha256}, got ${sha}`);
    }
    // Verify the bundle contains the expected files.
    // Verify the bundle contains the expected files.
    // The model file may be `model.onnx` (FP32) or `model_int8.onnx`
    // (int8-quantized). At least one of them must be present.
    // The loader prefers int8 when both are available (see createSession).
    const tokenizerFiles = ['tokenizer.json', 'tokenizer_config.json'];
    for (const f of tokenizerFiles) {
      if (!parsed.rawFiles[f] && !parsed.models.find(m => m.name === f)) {
        throw new Error(`bundle missing required file: ${f}`);
      }
    }
    if (!parsed.rawFiles['model.onnx']
        && !parsed.rawFiles['model_int8.onnx']
        && !parsed.models.find(m => m.name === 'model.onnx' || m.name === 'model_int8.onnx')) {
      throw new Error('bundle missing required file: model.onnx or model_int8.onnx');
    }
    // Verify license is acceptable.
    const license = parsed.header && parsed.header.license;
    if (license && license !== 'Apache-2.0' && license !== 'MIT') {
      throw new Error(`unsupported bundle license: ${license}`);
    }
    log.info(`[AegisGate Lens] bundle verified: ${entry.bundle_filename} ` +
      `(${parsed.header.files.length} files, license=${license || 'unknown'})`);
    return parsed;
  }

  /**
   * Lazy-load ORT Runtime if not already available. In browser content
   * scripts, ORT is not a global — we use dynamic import to load it
   * from the web_accessible_resource. In Node.js tests, ORT may already
   * be a global.
   *
   * @returns {Promise<object>} ORT module with Tensor, InferenceSession, env.
   */
  async function loadORT() {
    if (typeof ort !== 'undefined' && ort.Tensor && ort.InferenceSession) {
      return ort;
    }
    // Check for service-worker context (importScripts not available in MV3 modules)
    // — fall back to dynamic import.
    const ortUrls = [
      chrome.runtime.getURL('vendor/onnxruntime/ort.min.js'),
      chrome.runtime.getURL('vendor/onnxruntime/ort-wasm-simd-threaded.mjs'),
    ];
    // Try classic script injection first (works in content scripts).
    for (const url of ortUrls) {
      try {
        const result = await new Promise((resolve, reject) => {
          const script = document.createElement('script');
          script.src = url;
          script.onload = () => resolve(true);
          script.onerror = () => reject(new Error('script load failed: ' + url));
          (document.head || document.documentElement).appendChild(script);
        });
        if (typeof ort !== 'undefined' && ort.Tensor) {
          log.info('[AegisGate Lens] ORT loaded from ' + url);
          return ort;
        }
      } catch (e) {
        // Continue to next URL
      }
    }
    // Try dynamic import (works in module scripts).
    for (const url of ortUrls) {
      try {
        const mod = await import(url);
        if (mod.Tensor || mod.InferenceSession) {
          log.info('[AegisGate Lens] ORT loaded via dynamic import: ' + url);
          return mod;
        }
      } catch (e) {
        // Continue
      }
    }
    throw new Error('model-loader: ORT Runtime not available (tried ' + ortUrls.length + ' URLs)');
  }

  /**
   * Create ort.InferenceSession from bundle. The bundle contains the
   * ONNX model bytes; we extract them and pass to ort.InferenceSession.create.
   * Also stashes the tokenizer on the session object for transformer-modernbert.
   */
  async function createSession(parsed, providers) {
    const ortMod = await loadORT();
    if (!parsed.rawFiles) {
      throw new Error('bundle has no rawFiles');
    }
    // Prefer model_int8.onnx (the int8-quantized version) when the bundle
    // contains both. This is the production path for the toxicity bundle,
    // which currently ships both model.onnx (417 MB FP32) and
    // model_int8.onnx (105 MB int8) inside a 549 MB container. The int8
    // model is byte-identical at inference (within rounding) but ~4x
    // smaller and ~3-4x faster to load. Fall back to model.onnx (FP32)
    // for bundles that only contain the FP32 model (e.g., legacy prompt-
    // injection bundles built before int8 quantization was added).
    let modelBytes;
    let modelNameUsed;
    if (parsed.rawFiles['model_int8.onnx']) {
      modelBytes = parsed.rawFiles['model_int8.onnx'];
      modelNameUsed = 'model_int8.onnx';
    } else if (parsed.rawFiles['model.onnx']) {
      modelBytes = parsed.rawFiles['model.onnx'];
      modelNameUsed = 'model.onnx';
    } else {
      throw new Error('bundle has no model.onnx or model_int8.onnx');
    }
    const opts = {
      executionProviders: providers,
      graphOptimizationLevel: 'all',
    };
    const session = await ortMod.InferenceSession.create(modelBytes, opts);

    // Stash tokenizer on the session for transformer-modernbert.js to pick up
    const tokJson = parsed.models.find(m => m.name === 'tokenizer.json');
    const tokCfg = parsed.models.find(m => m.name === 'tokenizer_config.json');
    if (tokJson && tokJson.data) {
      session._lens_tokenizer = tokJson.data;
    }
    if (tokCfg && tokCfg.data) {
      session._lens_tokenizer_config = tokCfg.data;
    }

    log.info(`[AegisGate Lens] session created: providers=${providers.join(',')}, ` +
      `model=${modelNameUsed} (${(modelBytes.length / 1024 / 1024).toFixed(1)} MB), ` +
      `inputs=${session.inputNames.join(',')}, outputs=${session.outputNames.join(',')}`);
    return session;
  }

  /**
   * Compute SHA-256 hex digest of an ArrayBuffer.
   */
  async function sha256Hex(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  NS.util = NS.util || {};
  NS.util.modelLoader = {
    ensureSession,
    inMemoryCache,  // exposed for testing
    createSession,  // exposed for testing (verifies int8 preference)
    verifyBundle,   // exposed for testing (verifies file-presence logic)
  };
})();
