# Changelog

All notable changes to AegisGate Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Firefox support (MV3)** — AegisGate Lens now supports Firefox 128+ via Manifest V3. Added `browser_specific_settings.gecko` with AMO extension ID `lens@aegisgate.security` and `strict_min_version: 128.0`.
- **`src/browser-compat.js`** — Tiny compatibility shim loaded as the first content script. Aliases `browser.*` to `chrome.*` if `chrome` is undefined (Firefox pre-128 or GeckoView). No-op on Chrome and Firefox 128+ where `chrome.*` is native.
- **`background.scripts`** — Added `scripts: ["src/background.js"]` alongside `service_worker` in the manifest. Firefox MV3 uses `scripts` as a fallback for background execution; Chrome uses `service_worker`. Both are declared for cross-browser compatibility.
- **Dynamic injection file list fix** — The `chrome.scripting.executeScript()` file list in `background.js` was missing 13 of 29 content script files and all paths lacked the `src/` prefix. This was a pre-existing bug causing silent dynamic injection failures. Fixed to exactly match `manifest.json content_scripts[0].js`.
- **New tests** — Firefox AMO compatibility test, background scripts fallback test, browser-compat.js presence test, and dynamic injection file list consistency test.

### Changed
- **Manifest content_scripts expanded** — Added `src/browser-compat.js` as the first script, and added `src/util/constants.js`, `src/util/typedefs.js`, `src/detectors/regex/pii-us-core.js`, `src/detectors/regex/pii-us-extended.js`, `src/detectors/regex/pii-international-id.js`, `src/detectors/regex/pii-financial.js`, `src/detectors/ml/char-normalizer.js`, `src/detectors/ml/threat-detector-js.js`, `src/util/prompt-detect-dom.js`, `src/util/prompt-detect-lifecycle.js`, `src/util/banner-ui-formatters.js`, `src/util/banner-ui-html.js`, `src/util/banner-ui-lifecycle.js` to match what background.js dynamic injection expects.

## [0.3.0] — 2026-08-05

### Added
- **ML threat detector** — Char CNN-BiLSTM with Attention (1.58M parameters) detects adversarial prompt injections including instruction override, roleplay injection, and obfuscated commands. Pure JavaScript inference, no WASM, no onnxruntime, no external dependencies. Runs asynchronously after regex detection for defense-in-depth.
- **DeepSeek provider** — `chat.deepseek.com` with verified selectors for textarea input and send button.
- **Meta AI provider** — `meta.ai` / `www.meta.ai` with verified selectors for text input.
- **Lazy model loading** — 3.7MB model weights (float16, gzip-compressed) load on first `classify()` call, not on page load. Reduces initial page impact to zero.
- **504 total tests** — 492 unit + 12 ML performance/stress tests.
- **ML performance benchmark** — `test/benchmarks/results/v0.3.0-ml-perf.json` with latency, accuracy, and stress test metrics.

### Changed
- **CSP tightened** — `script-src 'self'; object-src 'self'` only. Removed `wasm-unsafe-eval`. No `eval()`, no `Function()`, no WASM.
- **Extension size reduced from 25MB to 4.2MB** — removed ONNX Runtime Web (18.4MB WASM) and float32 ONNX model (6.1MB). Replaced with pure JS inference (488 lines) and float16 JSON weights (3.7MB).
- **Detection pipeline** — `onInput()` now runs sync regex immediately (0.3ms), then fires async ML enrichment that updates the banner when ready (~5-50ms in Chrome). `detectPromptAsync()` provides the full 5-facet pipeline.
- **Welcome page** — refreshed for v0.3.0 with 5-facet feature grid, ML badge, updated privacy promise.
- **Legal docs** — TERMS-OF-SERVICE, SECURITY, PRODUCT-SUMMARY, PRIVACY-POLICY updated for v0.3.0 with ML disclosure, DeepSeek/Meta AI, and lazy loading details.
- **MODEL-CARD** — full ML model card with architecture, evaluation metrics, performance benchmarks, limitations, and ethical considerations.
- **NO-EXTERNAL-DEPS** — updated to reflect pure JS inference (WASM exception removed).

### Fixed
- **ML pipeline activation** — `classify()` was never called at runtime. Wired through `detectPromptAsync()` → `onInput()` → banner enrichment.
- **Manifest** — removed invalid `privacy_policy` and `privacy_policy_url` keys (CWS sets these in the developer dashboard, not manifest.json).

## [0.2.0] — 2026-07-09

### Added
- **11 security findings fixed** (F-01 through F-11) from the v0.1.4 audit.
- **405 unit tests** + 3 Go integration tests + 16 headless smoke tests.
- **131 regex patterns** across 4 facets (PII, Secrets, XSS, Compliance).
- **A11Y audit** — 32 findings addressed, WCAG 2.1 AA compliance for all static surfaces.
- **Responsive icon set** for the in-page banner.
- **Dismiss flow** — end-to-end tested (PII → banner → click dismiss → verify hidden → re-type → verify no banner).
- **Global pause** — cached `_pausedUntil` state for pause/resume from popup.
- **Opt-in telemetry** — per-dismissal, domain-hashed, category-only. OFF by default.

### Changed
- **Detection count** — 120 → 131 regex patterns.
- **PII tightening** — phone number regex tightened to reduce false positives.
- **Sender-id validation** in service worker (F-01).
- **Domain hashing** for opt-in telemetry (F-12).

## [0.1.4] — 2026-07-05

### Added
- Initial public release.
- 120 regex patterns across 4 facets.
- 8 AI provider integrations (ChatGPT, Claude, Gemini, Copilot, Perplexity, Mistral, Duck.ai, Grok).
- In-page banner with PII/secrets/XSS/compliance detection.
- Chrome Manifest V3 extension.

[0.3.0]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.1.4