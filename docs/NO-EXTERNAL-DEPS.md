# No External Dependencies

**This repository has zero third-party dependencies.** This is a hard constraint, not a guideline. Any PR that adds a third-party dependency will be rejected. See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the rule and the rationale.

## Vendored WASM Exception (v0.3.0)

Starting in v0.3.0, the Lens includes a **vendored** copy of ONNX Runtime Web for on-device ML inference. This is a controlled exception to the zero-dependency policy, not a precedent.

| Asset | Path | Size | Purpose |
|-------|------|------|---------|
| `ort.min.js` | `vendor/onnxruntime-web/ort.min.js` | 436KB | ONNX Runtime Web JS API |
| `ort-wasm-simd.wasm` | `vendor/onnxruntime-web/ort-wasm-simd.wasm` | 9.6MB | WASM runtime (SIMD-optimized) |
| `ort-wasm.wasm` | `vendor/onnxruntime-web/ort-wasm.wasm` | 8.8MB | WASM runtime (non-SIMD fallback) |
| `threat_cnn_bilstm_int8.onnx` | `models/threat_cnn_bilstm_int8.onnx` | 1.56MB | INT8-quantized ML model |

**Why this is acceptable:**

1. **Not an npm dependency.** These are pre-compiled static files vendored directly in the repo. No `package.json`, no `node_modules`, no transitive dependencies.
2. **No runtime code fetching.** The WASM and model files are bundled in the extension package and loaded via `chrome.runtime.getURL()`. The CSP (`script-src 'self'; object-src 'self'`) prohibits remote code loading.
3. **Verified supply chain.** Each file's SHA-256 hash is verified at load time. The `ort.min.js` is the minified distribution from the official [onnxruntime-web npm package](https://www.npmjs.com/package/onnxruntime-web) (MIT license).
4. **Consistent with the model card.** The ONNX model is the same Char CNN-BiLSTM used by AegisGate Platform v4.0.0, quantized to INT8 for browser use.
5. **Privacy-preserving.** All ML inference happens in the browser's WASM sandbox. No data leaves the device.

**Updating vendored files:**

When updating ONNX Runtime Web:
1. Download the new version from [npm](https://www.npmjs.com/package/onnxruntime-web)
2. Replace the files in `vendor/onnxruntime-web/`
3. Update the version comment in `vendor/onnxruntime-web/VERSION`
4. Update `EXPECTED_MODEL_HASH` in `src/detectors/ml/threat-detector.js` if the model changes
5. Run `test/unit/manifest-hosts.test.mjs` to verify manifest sync

## What this means in practice

| Category | Allowed? | Examples |
|----------|----------|----------|
| `package.json` | ❌ No | The file does not exist in this repo. |
| `node_modules/` | ❌ No | The directory does not exist. |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | ❌ No | None of these exist. |
| Third-party JS libraries (npm install) | ❌ No | No `transformers.js`, `react`, `lodash`, `axios`, etc. |
| Vendored WASM binaries (pre-compiled static files) | ✅ Yes (v0.3.0+) | ONNX Runtime Web (`vendor/onnxruntime-web/`), ML model (`models/`) |
| Bundlers (`esbuild`, `webpack`, `rollup`, etc.) | ❌ No | The build is a Go program in the Platform monorepo. |
| Transpilers (`tsc`, `babel`, `swc`) | ❌ No | The TypeScript is hand-written ES2020. No transpilation. |
| Test frameworks (Jest, Mocha, Vitest, etc.) | ❌ No | The test harness is a Go program in the Platform monorepo. |
| Linters (ESLint, etc.) | ❌ No | The linter is a Go program in the Platform monorepo. |
| Formatters (Prettier, etc.) | ❌ No | The formatter is a Go program in the Platform monorepo. |
| `actions/setup-node` in CI | ❌ No | The CI runs Go only. |
| Remote code loading at runtime (`import()`, `eval`, `Function`, `innerHTML`) | ❌ No | Browser-native APIs only. |

## The build pipeline

The build pipeline lives in the [AegisGate Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform) at `tools/build-lens-extension/`. It is a Go program that:

1. Reads the source files from this repo's `src/` directory.
2. (Optionally) generates a JSON schema from the Go structs in the Platform's `pkg/lensbackend/validation.go`.
3. Bundles the TypeScript source into a single `dist/content.js` and `dist/service-worker.js`.
4. Copies the `manifest.json` and assets to `dist/`.
5. Packages the `dist/` directory into a single ZIP.
6. Computes the SHA-256 of the ZIP and emits it as the build's release identity.

The CI in the Platform monorepo runs this tool and publishes the ZIP as a release artifact. The build is reproducible because the Platform's Go toolchain is pinned by SHA256 digest.

## The CI enforcement

The Platform's CI runs the following check on every PR and every release:

```bash
# Reject any npm artifacts.
if [ -f package.json ] || [ -d node_modules ] || [ -f package-lock.json ] || [ -f yarn.lock ]; then
  echo "ERROR: npm artifacts found in repo"
  exit 1
fi

# Reject any third-party Go imports outside the Platform's existing dep set.
go list -deps ./tools/build-lens-extension/... \
  | grep -vE '^github\.com/aegisgatesecurity' \
  | grep -vE '^(crypto|encoding|errors|expvar|flag|fmt|go|hash|html|image|index|io|log|math|mime|net|os|path|reflect|regexp|runtime|sort|strconv|strings|sync|syscall|testing|text|time|unicode|unsafe|archive|compress|container|debug|embed|internal|unique)' \
  && { echo "ERROR: third-party Go import detected"; exit 1; } || true
```

The first check rejects `npm` artifacts. The second check rejects new third-party Go modules. Both are part of the §10 release gate in the Privacy Policy.

## Why this constraint

1. **Privacy.** The Lens is a privacy product. Every third-party package is a potential supply-chain attack vector. The audit burden should be zero, not "audited quarterly."
2. **Operational simplicity.** No `package-lock.json` drift, no `npm audit` failures at 2am, no transitive dep surprises.
3. **Consistency with the Platform.** The Platform is Go-only with a closed dep set. The Lens matches.
4. **Solo-dev pragmatism.** One founder, one repo, one binary, zero supply-chain surprises.

## What to do if you need a new dependency

Open an issue first. The bar is "is this strictly necessary to ship the v0.1 feature set, AND is there a stdlib alternative?" If both answers are not "yes," the answer is no.

The v0.1 feature set is locked. The feature set is documented in the [Roadmap](ROADMAP.md). If your feature is not in the v0.1 set, it is v0.2+ at the earliest.
