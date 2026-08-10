# No External Dependencies

**This repository has zero third-party dependencies.** This is a hard constraint, not a guideline. Any PR that adds a third-party dependency will be rejected. See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the rule and the rationale.

## Pure JS ML Inference (v0.3.0)

Starting in v0.3.0, the Lens includes an **on-device ML threat detector** that runs entirely in pure JavaScript — no WASM, no onnxruntime, no external runtime. The Char CNN-BiLSTM model weights are stored as float16 in a gzip-compressed, base64-encoded JSON file and decompressed at load time using the browser's built-in `DecompressionStream`.

| Asset | Path | Size | Purpose |
|-------|------|------|---------|
| `threat-detector-js.js` | `src/detectors/ml/` | ~14KB | Pure JS forward pass (embedding → conv → BiLSTM → attention → dense) |
| `char-normalizer.js` | `src/detectors/ml/` | ~3KB | Character-level encoder (text → Int32Array) |
| `threat_cnn_bilstm_weights.bin.json` | `models/` | ~3.7MB | Float16 weights, gzip+base64 encoded |

**Why this is acceptable:**

1. **Not an npm dependency.** The inference engine is hand-written vanilla JS — no imports, no bundler, no transpiler. The weights are a static JSON file loaded via `fetch(chrome.runtime.getURL())`.
2. **No WASM, no eval.** The CSP is `script-src 'self'; object-src 'self'` — no `wasm-unsafe-eval`, no `eval()`, no `Function()`. This is a hard requirement per the security model.
3. **Verified supply chain.** The model is the same Char CNN-BiLSTM used by AegisGate Platform v4.0.0. Weights are float16-quantized (max error ~0.0005) from the Platform's float32 ONNX model.
4. **Privacy-preserving.** All ML inference happens in the browser's JS engine. No data leaves the device. The model file is bundled in the extension package.
5. **Auditable.** The inference engine is ~500 lines of readable JS. No black-box runtime.

**What was removed in v0.3.0 (from the initial ONNX approach):**

The first implementation used ONNX Runtime Web (WASM). This was replaced with pure JS because `wasm-unsafe-eval` in the CSP violated our "no unsafe-eval" policy. The removal saved ~18MB of WASM/ORC files and reduced the extension from 25MB to 4.2MB.

| Removed | Size | Reason |
|---------|------|--------|
| `ort.min.js` | 436KB | ONNX Runtime Web JS API (replaced by pure JS) |
| `ort-wasm-simd.wasm` | 9.6MB | WASM runtime (replaced by pure JS) |
| `ort-wasm.wasm` | 8.8MB | WASM fallback (replaced by pure JS) |
| `threat_cnn_bilstm.onnx` | 6.1MB | Float32 ONNX model (replaced by float16 JSON) |

**Performance:**

| Metric | Node.js (test) | Chrome V8 (estimated) |
|--------|-----------------|----------------------|
| Model load time | ~120ms | ~50-100ms |
| Inference p50 | ~420ms | ~5-50ms |
| Inference p99 | ~480ms | ~50-100ms |
| Extension size | 4.2MB | 4.2MB |
| CSP requirement | N/A | `script-src 'self'` only |

Chrome V8's TurboFan/Maglev JIT is expected to be ~10x faster than Node.js for this workload. The actual browser performance will be measured in production.

## What this means in practice

| Category | Allowed? | Examples |
|----------|----------|----------|
| `package.json` | ❌ No | The file does not exist in this repo. |
| `node_modules/` | ❌ No | The directory does not exist in this repo. |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | ❌ No | None of these exist. |
| Third-party JS libraries (npm install) | ❌ No | No `transformers.js`, `react`, `lodash`, `axios`, etc. |
| Vendored WASM binaries | ❌ No | Removed in v0.3.0. Pure JS inference instead. |
| Vendored ONNX Runtime | ❌ No | Removed in v0.3.0. Pure JS inference instead. |
| Pure JS inference (hand-written) | ✅ Yes | `threat-detector-js.js`, `char-normalizer.js` |
| Model weights (float16 JSON) | ✅ Yes | `threat_cnn_bilstm_weights.bin.json` |
| Bundlers (`esbuild`, `webpack`, `rollup`, etc.) | ❌ No | The build is a Go program in the Platform monorepo. |
| Transpilers (`tsc`, `babel`, `swc`) | ❌ No | The code is hand-written ES2020. No transpilation. |
| Test frameworks (Jest, Mocha, Vitest, etc.) | ❌ No | `node:test` only. |
| Linters (ESLint, etc.) | ❌ No | No linter in this repo. |
| Formatters (Prettier, etc.) | ❌ No | No formatter in this repo. |
| Remote code loading at runtime (`import()`, `eval`, `Function`, `innerHTML`) | ❌ No | Browser-native APIs only. |

## The build pipeline

The build pipeline lives in the [AegisGate Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform) at `tools/build-lens-extension/`. It is a Go program that:

1. Reads the source files from this repo's `src/` directory.
2. Bundles the JS source into a single `dist/content.js` and `dist/service-worker.js`.
3. Copies the `manifest.json`, models, and assets to `dist/`.
4. Packages the `dist/` directory into a single ZIP.
5. Computes the SHA-256 of the ZIP and emits it as the build's release identity.

The CI in the Platform monorepo runs this tool and publishes the ZIP as a release artifact. The build is reproducible because the Platform's Go toolchain is pinned by SHA256 digest.

## Why this constraint

1. **Privacy.** The Lens is a privacy product. Every third-party package is a potential supply-chain attack vector. The audit burden should be zero, not "audited quarterly."
2. **Operational simplicity.** No `package-lock.json` drift, no `npm audit` failures at 2am, no transitive dep surprises.
3. **Consistency with the Platform.** The Platform is Go-only with a closed dep set. The Lens matches.
4. **Security posture.** No `wasm-unsafe-eval`, no `eval()`, no `Function()`, no remote code loading. The CSP is `script-src 'self'; object-src 'self'` — the strictest practical CSP for a Chrome extension.
5. **Solo-dev pragmatism.** One founder, one repo, one binary, zero supply-chain surprises.

## What to do if you need a new dependency

Open an issue first. The bar is "is this strictly necessary to ship the feature set, AND is there a stdlib alternative?" If both answers are not "yes," the answer is no.