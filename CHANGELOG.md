# Changelog

All notable changes to AegisGate Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] — 2026-08-29 - Security Audit Remediation 🔒

> **v0.3.2** resolves all 27 findings from the comprehensive security audit (1 CRITICAL, 5 HIGH, 10 MEDIUM, 11 LOW). 25 fixes applied, 2 accepted with documented justifications. CI hardened (16 action tags pinned, shell injection fixed).

### Critical Fix (1)

- **C-1: SHA-256 model weight integrity verification** — `threat-detector-js.js` now verifies a hardcoded hash (`38ea1563...`) of model weights via `crypto.subtle.digest` before parsing. Prevents supply-chain tampering of the ML model that could silently bypass ML detection.

### High Fixes (5)

- **H-1: ReDoS in `pii_phone_intl_strict`** — Required first separator between digit groups, preventing catastrophic backtracking on long digit sequences.
- **H-2: ReDoS in `xss_mutation_xss`** — Simplified to bounded `[\s\S]{0,500}?` instead of nested alternation with unbounded backtracking.
- **H-3: Path traversal in `build-bundle.py`** — `os.path.realpath()` check ensures all file paths stay within DIST directory.
- **H-4: Double-close panic in `pimltest/devtools.go`** — Added `sync.Once` to guard channel close and prevent panic on concurrent close calls.
- **H-5: SSRF via backend URL in `background.js`** — Added `isValidBackendUrl()` requiring HTTPS, validating via `new URL()`, warning on loopback/private IPs.

### Medium Fixes (10)

- **M-1: XSS via unescaped `ev.severity` in banner HTML** — Now escaped via `formatters.escapeHtml()`.
- **M-2: Kill switch ineffective** — Moved `__lensDisabled` check BEFORE `init()` call. Was checked after init, making it completely non-functional.
- **M-3: Event listeners never removed** — Stored function refs (`_onKeyDown`, `_onSendClick`) during `attach()`, used same refs in `detach()`. Removed `arguments.callee` (throws in strict mode).
- **M-4: No input length cap** — Added `MAX_INPUT_LENGTH = 50000` in `detectors/index.js` with truncation + warning log.
- **M-5: BIP39 wordlist per-call allocation** — Moved to module-level cached `Set` (`BIP39_SET`), converted from `indexOf` to `has()` for O(1) lookups.
- **M-6: No bundle checksum** — Added SHA-256 sidecar file computation in `build-bundle.py`.
- **M-7: Raw PII in event objects** — Added `maskSampleValue()` function. `sample` field now shows masked value while `matches[].value` retains full value for redaction feature.
- **M-8: Bearer token plaintext** — **Accepted risk** (same model as AWS CLI credentials file).
- **M-9: Unpinned CI actions** — All 16 action references pinned to full semver (e.g., `@v6.0.0`).
- **M-10: Shell injection in DCO check** — Replaced `${{ github.event.before }}` with env vars.

### Low Fixes (11)

- **L-1: Prompt text exposed on window** — Replaced `window.__lens_cs.lastText` with `window.__lens_cs.lastTextLength` (no raw prompt text on global).
- **L-2: FP report metadata logged to console** — Gated behind `__lensDebug` flag.
- **L-3: `gc()` save-back condition always false** — Fixed to compare pre-GC count to post-GC count (was self-comparison).
- **L-4: `isValidFPReports` skips validation** — Added validation for `reason`, `timestamp`, `pattern_id`, `ml_score`, `ml_threshold`, `ml_model_version`.
- **L-5: Async dismiss check is a no-op** — Made `onDetect` async, properly `await`s `dismiss.isDismissed()` before showing banner.
- **L-6: Wrong prototype setter** — Uses `HTMLInputElement.prototype` for `<input>`, `HTMLTextAreaElement.prototype` for `<textarea>`.
- **L-7: WAR matches `<all_urls>`** — Restricted to 16 specific AI provider domains.
- **L-8: Zero-width character evasion** — Added `stripZeroWidth()` to strip zero-width chars (U+200B/C/D/E/F, U+FEFF, U+00AD) before regex detection.
- **L-9: Unlabeled CPT/HCPCS patterns** — Removed `pii_cpt_code` and `pii_hcpcs_level2` patterns (were matching any 5-digit number / any letter+4digits).
- **L-10: JSON injection in pimltest** — Base64-encoded JSON content in `pimltest/main.go` to prevent injection via file content.
- **L-11: JS injection in flow/runner.go** — **Accepted risk** (test-only, hardcoded test cases).

### Verification

- node --test: 518/518 pass, 0 fail
- Custom linter: 12/12 pass, 0 warnings
- OPSEC scan: 0 failures
- gitleaks: 14 (all in test/README examples, not real secrets)
- semgrep OWASP+audit: 0 findings
- CI tag pinning: 0 unpinned
- CI shell injection: 0 findings
- Go build/test (pimltest): OK, 3/3 pass

### Accepted Risks (2)

- **M-8:** Bearer token in `chrome.storage.local` — same model as AWS CLI credentials file.
- **L-11:** JS injection in `flow/runner.go` — test-only tool, hardcoded test cases, not shipped.

### Audit Report

Full audit report: `.plans/SECURITY-AUDIT-2026-08-29.md`

---

## [0.3.1] — 2026-08-13

### Added
- **23 New SOC Detection Patterns** — SWIFT/BIC banking codes (3 patterns), CPT/HCPCS medical billing codes (11 patterns), and OT/ICS protocol patterns (9 patterns: Modbus, DNP3, OPC-UA). Parity with Platform v4.1.0 and Rampart v0.6.1. Total regex patterns: 155.

- **Firefox support (MV3)** — AegisGate Lens now supports Firefox 142+ via Manifest V3. Added `browser_specific_settings.gecko` with AMO extension ID `lens@aegisgate.security` and `strict_min_version: 142.0`.
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

[0.3.1]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.1.4