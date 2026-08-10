<div align="center">

# 🛡️ AegisGate Lens

**Privacy-first browser extension that warns you before you hit send.**

100% on-device · Zero data leaves your browser · Free · Forever

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Install on Chrome Web Store](https://img.shields.io/badge/Install-CWS%20v0.3.0-4285F4?logo=google-chrome&logoColor=white)](https://chromewebstore.google.com/detail/aegisgate-lens/lkioinepjpjfdhiggaomoafnhagfcjip)
[![Firefox Add-on](https://img.shields.io/badge/Install-AMO%20(coming%20soon)-FF7139?logo=firefox&logoColor=white)](#installation)
[![Version](https://img.shields.io/badge/version-v0.3.0-brightgreen.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.3.0)
[![Tests](https://img.shields.io/badge/tests-508%2F508-brightgreen.svg)](#test-coverage)
[![ML](https://img.shields.io/badge/ML-pure%20JS%20(CharCNN--BiLSTM)-9cf.svg)](#ml-threat-detector)
[![Perf](https://img.shields.io/badge/ML%20inference-~5--50ms%20(Chrome%20est.)-blue.svg)](#performance)
[![Privacy](https://img.shields.io/badge/privacy-12%20non--negotiables-success.svg)](./docs/SECURITY.md)
[![Patterns](https://img.shields.io/badge/patterns-151%20regex%20%2B%20ML-9cf.svg)](#)
[![Providers](https://img.shields.io/badge/providers-10-blue.svg)](#supported-ai-providers)
[![Chrome 116+](https://img.shields.io/badge/chrome-116%2B-yellow.svg)](https://developer.chrome.com/docs/extensions/mv3)
[![Firefox 142+](https://img.shields.io/badge/firefox-142%2B-FF7139?logo=firefox&logoColor=white)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
[![Zero npm](https://img.shields.io/badge/dependencies-zero-success.svg)](./docs/NO-EXTERNAL-DEPS.md)
[![CSP](https://img.shields.io/badge/CSP-script--src%20'self'-success.svg)](#security)
[![CodeQL](https://github.com/aegisgatesecurity/aegisgate-lens/actions/workflows/security.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/actions/workflows/security.yml)
[![Security Policy](https://img.shields.io/badge/security-RFC%209116-blue.svg)](./SECURITY.md)

[Install](#installation) · [How It Works](#how-it-works) · [ML Detector](#ml-threat-detector) · [Detection](#what-it-detects) · [Privacy](./docs/SECURITY.md) · [Architecture](./docs/ARCHITECTURE-v0.1.3.md) · [Releases](https://github.com/aegisgatesecurity/aegisgate-lens/releases)

</div>

> **We follow [GitHub's recommended security practices](https://securitylab.github.com/resources/five-easy-steps-to-secure-your-open-source-project/) for open source projects.** CodeQL scanning · Secret scanning with push protection · Dependabot alerts & security updates · Protected branches · RFC 9116 security policy · [Report a vulnerability →](./SECURITY.md)

---

> **🛡️ Using AegisGate at work?** [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform) is our server-side gateway — 153 detection patterns, MCP/A2A/ACP protection, 15+ compliance frameworks, and cryptographic attestation. For the 95% of users without enterprise protections, Lens is here. [Explore Platform →](https://github.com/aegisgatesecurity/aegisgate-platform)

---

## What's New in v0.3.0

- **🧠 ML Threat Detector** — Char CNN-BiLSTM with Attention, running in pure JavaScript. No WASM, no ONNX Runtime, no external dependencies. Detects adversarial prompt injections (instruction override, roleplay injection, obfuscated commands) in ~5-50ms.
- **🔍 DeepSeek + Meta AI** — Two new AI providers with live-verified DOM selectors (10 providers total).
- **📦 6x smaller** — Extension reduced from 25MB (WASM) to 4.2MB (pure JS).
- **🔒 Stricter CSP** — `script-src 'self'` only. No `wasm-unsafe-eval`, no `eval()`, no `Function()`.
- **✅ 504 tests** — 492 unit + 12 ML perf/stress tests. All passing.

## Why AegisGate Lens?

Every AI conversation is a potential data leak. A prompt containing an API key, a social security number, or a database credential gets sent in plain text to a third-party LLM — and you can never take it back.

Lens is the browser extension that catches it **before you hit send**.

- **100% on-device.** No prompt text, no URLs, no page content ever leaves your browser. Zero telemetry by default.
- **151 regex patterns + ML.** Sub-millisecond regex detection plus ~5-50ms ML inference for adversarial prompt injection.
- **10 AI providers.** ChatGPT, Claude, Gemini, Copilot, DuckDuckGo, Perplexity, Mistral, Grok, DeepSeek, Meta AI.
- **Fail-visible.** Every detection is shown to you — you decide to cancel, redact, or proceed.
- **Free. Forever.** Apache 2.0, no account required, no upsell gate.

## Detection Flow

```mermaid
flowchart LR
    User["👤 You type a prompt"] -->|"Keystroke<br/>(debounced 250ms)"| Lens["🛡️ Lens<br/>Content Script"]
    Lens -->|"Regex facets<br/>(sync, ~0.3ms)"| Regex{"151 regex<br/>patterns"}
    Lens -->|"ML facet<br/>(async, ~5-50ms)"| ML["🧠 Char CNN-BiLSTM"]

    Regex -->|"PII detected"| PII["🔒 PII<br/>(55 patterns)"]
    Regex -->|"Secret detected"| Secret["🔑 Secrets<br/>(41 patterns)"]
    Regex -->|"XSS detected"| XSS["💉 XSS<br/>(12 patterns)"]
    Regex -->|"Compliance risk"| Comp["📋 Compliance<br/>(43 patterns)"]
    ML -->|"Adversarial detected"| Adv["⚠️ ML Adversarial<br/>(score ≥ 0.5)"]
    ML -->|"Suspicious"| Sus["🟡 ML Suspicious<br/>(0.3 < score < 0.5)"]

    PII & Secret & XSS & Comp & Adv & Sus --> Decision{"Any<br/>findings?"}
    Decision -->|"Yes"| Banner["⚠️ Banner<br/>Cancel · Redact · Dismiss"]
    Decision -->|"No"| Pass["✅ Pass-through"]

    style Lens fill:#1e40af,stroke:#3b82f6,color:#fff
    style ML fill:#7c3aed,stroke:#8b5cf6,color:#fff
    style Banner fill:#dc2626,stroke:#ef4444,color:#fff
    style Pass fill:#16a34a,stroke:#22c55e,color:#fff
```

## ML Threat Detector

v0.3.0 adds a **Char CNN-BiLSTM with Attention** model that detects adversarial prompt injections — the kind of attacks that regex can't catch (paraphrased instructions, roleplay injection, obfuscated commands).

| Property | Value |
|----------|-------|
| Architecture | Char CNN-BiLSTM with Attention |
| Parameters | 1,589,378 (1.58M) |
| Input | Character-level, max 128 chars |
| Output | Sigmoid score [0, 1] |
| Threshold | 0.5 (adversarial), 0.3 (suspicious) |
| Weight format | float16, gzip+base64 JSON (~3.7MB) |
| Inference | Pure JavaScript (no WASM, no ONNX) |
| CSP requirement | `script-src 'self'` only |

The ML detector runs **asynchronously** alongside the regex facets. Regex detections appear immediately (~0.3ms); ML detections update the banner when ready (~5-50ms in Chrome). This gives defense-in-depth: regex catches known patterns, ML catches paraphrased and obfuscated variants.

**ML evaluation results (Node.js; Chrome expected ~10x faster):**

| Metric | Value |
|--------|-------|
| Adversarial detection rate | 100% (10/10 prompt injections) |
| Benign pass-through rate | 81.8% (9/11; 2 FPs on creative writing) |
| Score separation | 0.82 (adversarial avg 0.988 vs benign avg 0.171) |
| Score determinism | 100% (20/20 identical calls) |

See [docs/MODEL-CARD.md](./docs/MODEL-CARD.md) for full evaluation data.

## Security Posture

| Metric | Value |
|--------|-------|
| Prompt data sent to servers | **0 bytes** (all on-device) |
| External dependencies | **0** (no npm, no node_modules) |
| WASM binaries | **0** (removed in v0.3.0, pure JS instead) |
| Telemetry by default | **Off** (opt-in FP reporting sends hashes only) |
| Content Security Policy | **MV3 strict** (`script-src 'self'`; no inline, no remote, no eval, no wasm-unsafe-eval) |
| Commit signing | **Ed25519** on all commits |
| Vulnerability disclosure | **RFC 9116** (security@aegisgatesecurity.io) |

## What It Detects

Lens runs **5 detection facets** — 4 regex (synchronous) + 1 ML (asynchronous) — on every keystroke (debounced 250ms).

| Facet | What it catches | Example | Patterns | Latency |
|-------|----------------|---------|----------|----------|
| **PII** | Email, phone, SSN, credit card (Luhn-validated), DOB, address, driver's license, passport, tax ID, bank account, IP address | `john.doe@example.com`, `4111-1111-1111-1111` | 55 | ~0.3ms |
| **Secrets** | API keys (AWS, GitHub, OpenAI, Stripe, Slack), OAuth tokens, RSA private keys, database credentials | `ghp_abc123...`, `AKIA...`, `-----BEGIN RSA PRIVATE KEY-----` | 41 | ~0.3ms |
| **XSS** | Cross-site scripting payloads | `<script>alert(1)</script>` | 12 | ~0.3ms |
| **Compliance** | OWASP LLM Top 10, MITRE ATLAS, EU AI Act, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA | "patient SSN:", "credit card:" | 43 | ~0.3ms |
| **ML Threat** | Adversarial prompt injection (instruction override, roleplay, obfuscated commands) | "Ignore all previous instructions..." | 1 model | ~5-50ms |
| **Total** | — | — | **151 regex + 1 ML** | — |

## How Lens Compares

| Capability | Lens | Browser-native warnings | Enterprise DLP |
|------------|------|------------------------|----------------|
| PII detection (55 patterns) | ✅ | ❌ | ✅ |
| Secret detection (41 patterns) | ✅ | ❌ | ✅ |
| XSS detection (12 patterns) | ✅ | ❌ | ⚠️ Web-only |
| Compliance risk flagging (43 patterns) | ✅ | ❌ | ⚠️ Limited |
| ML adversarial detection | ✅ | ❌ | ⚠️ Rare |
| Works on 10 AI providers | ✅ | ❌ | ⚠️ Requires proxy |
| 100% on-device, zero telemetry | ✅ | ✅ | ❌ Cloud-based |
| Zero dependencies, no WASM | ✅ | ✅ | ❌ Requires agent |
| Free (Apache 2.0) | ✅ | ✅ | ❌ Paid license |
| Fail-visible (user sees every detection) | ✅ | ✅ | ❌ Silent block |

## Performance

| Metric | v0.3.0 | v0.2.0 |
|--------|--------|--------|
| Regex detection (p99) | **<1ms** | <1ms |
| ML inference (p50, Chrome est.) | **~5-50ms** | n/a |
| ML inference (p50, Node.js) | **~420ms** | n/a |
| Model load time | **~120ms** | n/a |
| Extension size | **4.2MB** | ~2MB |
| FPR (regex, WildChat) | **2.31%** | 2.31% |
| ML adversarial detection | **100%** (10/10) | n/a |
| ML benign pass-through | **81.8%** (9/11) | n/a |

**Source**: [docs/MODEL-CARD.md](./docs/MODEL-CARD.md) — detection metrics and evaluation data

## Supported AI Providers

| Provider | Hosts |
|---------|-------|
| ChatGPT | chat.openai.com, chatgpt.com |
| Claude | claude.ai |
| Gemini | gemini.google.com |
| Microsoft Copilot | copilot.microsoft.com, copilot.cloud.microsoft |
| DuckDuckGo (Duck.ai) | duck.ai |
| Perplexity | perplexity.ai, www.perplexity.ai |
| Mistral Le Chat | chat.mistral.ai, le-chat.mistral.ai |
| Grok | grok.com, www.grok.com |
| **DeepSeek** | chat.deepseek.com |
| **Meta AI** | meta.ai |

## How It Works

1. **Content script** is injected into each supported AI provider page (per the MV3 manifest)
2. **On every keystroke** (debounced 250ms), the prompt value is read from the textarea
3. **4 regex facets** run synchronously: PII (55), Secrets (41), XSS (12), Compliance (43) = 151 patterns
4. **1 ML facet** runs asynchronously: Char CNN-BiLSTM detects adversarial prompt injection
5. **PostProcess** filters false positives: Luhn validation for credit cards, 4-4-4 CC pattern rejection, ID-label context check
6. **Banner shows** with severity color (critical = red, high = orange, medium = yellow, low = blue)
7. **User chooses**: Cancel / Edit & Redact / Send Anyway / Dismiss for 24h
8. **Dismissal** is stored in `chrome.storage.local` for 24h

## Installation

### Chrome Web Store (recommended)

1. Visit the [Chrome Web Store listing](https://chromewebstore.google.com/detail/aegisgate-lens/lkioinepjpjfdhiggaomoafnhagfcjip)
2. Click **Add to Chrome**
3. Click the AegisGate Lens icon in your toolbar to verify it's active

### Firefox Add-ons (AMO)

**Coming soon.** Lens v0.3.0+ supports Firefox 128+ via Manifest V3.

1. Visit the [Firefox Add-ons listing](https://addons.mozilla.org/) (link will be added when published)
2. Click **Add to Firefox**
3. Click the AegisGate Lens icon in your toolbar to verify it's active

### From source (development / testing)

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-lens.git
cd aegisgate-lens
# No npm install needed — zero external dependencies
```

**Load in Chrome:**
1. Navigate to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `aegisgate-lens` directory

**Load in Firefox:**
1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `manifest.json` from the `aegisgate-lens` directory

## Test Coverage

| Suite | Count | Status |
|-------|-------|--------|
| Node unit tests (`node:test`) | 493 | ✅ all pass |
| E2e manifest validation | 25 | ✅ all pass |
| ML perf/stress tests | 12 | ✅ all pass |
| Go unit tests (`go test`) | 3 | ✅ all pass |
| Headless smoke in real Chrome (via CDP) | 16 | ✅ all pass |
| Platform FPR test (6,500 WildChat prompts) | 1 | ✅ 2.31% FPR |
| **Total** | **508** | ✅ |

## Privacy: The 12 Non-Negotiables

AegisGate Lens **never** sends or stores:

1. ❌ Prompt text (input or output)
2. ❌ URLs
3. ❌ Page content
4. ❌ Personal identifiers (PII is rewritten in your browser, never sent)
5. ❌ Account credentials
6. ❌ Browser fingerprinting
7. ❌ Cross-site tracking
8. ❌ AI provider metadata
9. ❌ Keystroke timing
10. ❌ Mouse movement
11. ❌ Session identifiers
12. ❌ IP addresses (when self-hosted)

The only opt-in path is **false-positive reporting**: when you click "Submit & Dismiss" on a banner, Lens sends **hashed metadata only** (detection category, pattern ID, domain hash) — no prompt text, no URLs, no page content. You can dismiss without reporting (no data sent).

See [docs/SECURITY.md](./docs/SECURITY.md) for the full privacy policy and security model.

## Security

- **Apache 2.0** license (inference code; model weights included but not open source)
- **Zero external dependencies** (no npm, no node_modules, no bundled libraries)
- **Zero WASM** (removed in v0.3.0; pure JS inference)
- **MV3 strict CSP** (`script-src 'self'`; no inline scripts, no remote code, no eval, no wasm-unsafe-eval)
- **Ed25519 commit signing** on all commits
- **RFC 9116** vulnerability disclosure (contact `security@aegisgatesecurity.io`)

See [docs/SECURITY.md](./docs/SECURITY.md) for the full security model and [docs/NO-EXTERNAL-DEPS.md](./docs/NO-EXTERNAL-DEPS.md) for the dependency policy.

## For Enterprise Teams

AegisGate Lens is the consumer-facing layer. The same team builds [AegisGate Platform™](https://github.com/aegisgatesecurity/aegisgate-platform) — the server-side gateway with central policy, team-wide analytics, MCP/A2A/ACP/RESPONSE protection, the Trust Framework, MITRE ATLAS enforcement, OWASP LLM Top-10, the EU AI Act Compliance Module, and SIEM export.

| Use case | Recommendation |
|----------|----------------|
| Individual developers, security researchers, journalists, privacy-conscious users | **Lens alone** (free) |
| Teams of 2–10 who need a shared detection policy | **Lens + Platform Starter** ($29/mo) |
| Enterprises needing SIEM, compliance modules, central policy | **Platform Professional or Enterprise** (custom) |

## Roadmap

- **v0.3.1**: Firefox AMO publication, welcome page aesthetic update
- **v0.4.0**: Public benchmark dataset
- **v0.5.0**: Third-party security audit (Cure53 / Trail of Bits / NCC Group)

## Community & Support

- **X/Twitter**: [https://x.com/aegisgate](https://x.com/aegisgate)
- **Mastodon**: [https://mastodon.social/@aegisgate](https://mastodon.social/@aegisgate)
- **Email**: [support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io)

## License

Apache 2.0. See [LICENSE](./LICENSE) for the full text. Model weights are included in the extension package but are not open source.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io) · [𝕏 @aegisgate](https://x.com/aegisgate) · [🐘 @aegisgate@mastodon.social](https://mastodon.social/@aegisgate)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>