# AegisGate Lens — AMO Release Notes (v0.3.1)

**Extension ID:** `lens@aegisgate.security`
**Version:** 0.3.1
**Date:** 2026-08-13
**License:** Apache 2.0

---

## Version Notes (for AMO listing)

### What's New in v0.3.1

- **23 New SOC Detection Patterns** — SWIFT/BIC banking codes (3), CPT/HCPCS medical billing codes (11), and OT/ICS protocol patterns (9: Modbus, DNP3, OPC-UA). Brings total to 155 regex patterns.
- **Firefox MV3 Support** — Firefox 142+ via Manifest V3 with `browser_specific_settings.gecko`.
- **Browser compatibility shim** — `src/browser-compat.js` aliases `browser.*` to `chrome.*` for cross-browser support. No-op on Chrome.
- **Dynamic injection fix** — Background.js content script file list corrected to match manifest.
- **530 tests** — 518 passing + 12 skipped (ML perf tests). All green.

### What This Extension Does

AegisGate Lens is a privacy-first browser extension that detects sensitive data in AI chat prompts **before you hit send**. It runs 100% on-device — no prompt text, URLs, or page content ever leaves your browser.

When you type into an AI chat (ChatGPT, Claude, Gemini, Copilot, etc.), Lens scans your prompt in real-time (debounced 250ms) and shows a banner if it detects:

1. **PII** — SSN, email, phone, credit cards, medical record numbers, CPT/HCPCS codes, driver's license, passport, bank accounts, SWIFT/BIC codes, international IDs (69 patterns)
2. **Secrets** — API keys (AWS, GitHub, OpenAI, Stripe, Slack), OAuth tokens, private keys, database credentials (41 patterns)
3. **XSS** — Cross-site scripting payloads (12 patterns)
4. **Compliance** — OWASP LLM Top 10, MITRE ATLAS, EU AI Act, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA (24 patterns)
5. **OT/ICS Protocols** — Modbus, DNP3, OPC-UA control manipulation (9 patterns)
6. **ML Threat** — Adversarial prompt injection detection via Char CNN-BiLSTM neural network running in pure JavaScript (1 model, ~5-50ms)

The banner lets you **Cancel send**, **Edit manually**, or **Send anyway**. You can also dismiss false positives for 24 hours.

### Privacy

- **Zero telemetry by default.** No prompt text, no URLs, no page content, no PII, no keystroke timing, no mouse movement, no session IDs, no IP addresses ever collected.
- **100% on-device processing.** All detection runs in the browser content script.
- **Opt-in anonymous telemetry only.** If the user explicitly enables it, only hashed domain names and rounded timestamps are sent — never prompt content.
- **12 privacy non-negotiables** documented in `docs/PRIVACY-POLICY.md` and `docs/SECURITY.md`.
- **`data_collection_permissions`** in the manifest declares `"required": ["none"]` — no data collection is required for the extension to function.

### Permissions Explained

| Permission | Why it's needed |
|-----------|----------------|
| `storage` | Store the "dismiss for 24h" flag, onboarding status, and user preferences (hide indicator, pause). All local — never synced. |
| `scripting` | Inject the content script into AI provider pages to scan prompt text. |
| `unlimitedStorage` | The ML model weights file (~3.9MB) is cached locally for on-device inference. |
| Host permissions (10 AI providers) | Content scripts must run on ChatGPT, Claude, Gemini, Copilot, DuckDuckGo, Perplexity, Grok, Mistral, DeepSeek, and Meta AI pages to scan prompts. |
| `host_permissions: lens.aegisgate.security.io` | Fetch extension updates and version check info. No user data is sent. |

### Security

- **Apache 2.0 open source** — full source code at https://github.com/aegisgatesecurity/aegisgate-lens
- **Zero external dependencies** — no npm, no node_modules, no bundled libraries. All code is hand-written ES2020.
- **Strict CSP** — `script-src 'self'; object-src 'self'`. No inline scripts, no remote code, no eval.
- **No `eval()`, no `Function()`, no dynamic `<script>` injection.**
- **All dynamic content is HTML-escaped** via `escapeHtml()` before display.
- **DOM manipulation uses safe APIs** — detached elements for HTML insertion (no `innerHTML` on connected elements).
- **Vulnerability disclosure** — RFC 9116 compliant, `security@aegisgatesecurity.io`

### ML Model

The ML threat detector (Char CNN-BiLSTM with Attention) runs in pure JavaScript — no WASM, no ONNX Runtime, no external inference library. The model weights are stored as a JSON file (`models/threat_cnn_bilstm_weights.bin.json`, 3.9MB) and loaded locally. The inference code (`src/detectors/ml/threat-detector-js.js`) implements the forward pass in vanilla JS. Both files are included in the package.

If the ML files are missing (e.g., open-source build without proprietary weights), the extension gracefully falls back to regex-only detection — the ML facet simply reports no findings.

### Test Coverage

- **530 total tests**: 505 Node unit tests, 25 E2e manifest validation, 12 ML perf/stress, 3 Go unit tests, 16 headless smoke tests in real Chrome, 1 platform FPR test
- **2.31% false positive rate** on 6,500 WildChat prompts
- **0/119 false positives** on per-pattern must-not-trigger corpus
- **Sub-millisecond regex detection** (avg 0.34ms; p99 0.36ms for 2000 chars)
- Full test suite: `bash tools/test-local.sh`

### Supported AI Providers (10)

ChatGPT, Claude, Gemini, Microsoft Copilot, DuckDuckGo AI, Perplexity, Grok, Mistral Le Chat, DeepSeek, Meta AI.

### Links

- **Source code:** https://github.com/aegisgatesecurity/aegisgate-lens
- **Privacy policy:** https://aegisgatesecurity.io/lens/privacy
- **Homepage:** https://aegisgatesecurity.io/lens
- **Security policy:** security@aegisgatesecurity.io (RFC 9116)

---

## Reviewer Notes (internal — not published on listing)

### For AMO Reviewer

**Thank you for reviewing AegisGate Lens.** Here are some notes that may help:

1. **This is a content-script-only extension.** All detection logic runs in content scripts injected into AI chat pages. The background service worker handles extension lifecycle (install, update) and the popup provides user controls.

2. **The `innerHTML` usage** (if flagged by the linter): All HTML strings are built by `src/util/banner-ui-html.js` using template literals. All dynamic values (detection category, sample text, URLs) are passed through `escapeHtml()` which escapes `&`, `<`, `>`, `"`, and `'`. As of v0.3.1, we've switched to using detached DOM elements for HTML insertion (no `innerHTML` or `insertAdjacentHTML` on connected elements) to address AMO security warnings.

3. **The ML inference code** (`src/detectors/ml/threat-detector-js.js`) is a pure JavaScript implementation of a Char CNN-BiLSTM neural network. It does not use WASM, eval, or any external library. It reads model weights from a JSON file and performs matrix multiplication in vanilla JS. The code is proprietary (not in the open-source GitHub repo) but is included in the AMO package for full functionality.

4. **The `unlimitedStorage` permission** is needed because the ML model weights file is ~3.9MB. Without this permission, the extension would hit Chrome's 5MB storage quota when combined with other local data.

5. **No network requests are made** by the content scripts or the ML detector. The only network request is to `lens.aegisgate.security.io` for version checking, which sends no user data (just an extension version number).

6. **The `scripting` permission** is used to dynamically inject content scripts into AI provider pages. This is necessary because the extension needs to read the prompt textarea value on each supported AI chat page.

7. **Zero npm dependencies.** The extension has no `package.json`, no `node_modules`, no bundled libraries. All code is original, hand-written ES2020 JavaScript.

8. **Firefox-specific:** The `browser_specific_settings.gecko` block declares `strict_min_version: 142.0` and `data_collection_permissions.required: ["none"]`. The `background.scripts` array is provided alongside `service_worker` for Firefox MV3 compatibility.