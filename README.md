<div align="center">

# 🛡️ AegisGate Lens

**Privacy-first browser extension that warns you before you hit send.**

100% on-device · Zero data leaves your browser · Free · Forever

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Install on Chrome Web Store](https://img.shields.io/badge/Install-CWS%20v0.1.4-4285F4?logo=google-chrome&logoColor=white)](https://chromewebstore.google.com/detail/aegisgate-lens/lkioinepjpjfdhiggaomoafnhagfcjip)
[![Version](https://img.shields.io/badge/version-v0.1.4-brightgreen.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.1.4)
[![Tests](https://img.shields.io/badge/tests-734%2F734-brightgreen.svg)](#)
[![FPR](https://img.shields.io/badge/FPR-2.31%25%20on%206%2C500%20WildChat-success.svg)](#detection-performance)
[![Perf](https://img.shields.io/badge/p99%3C2ms%20(typical)-blue.svg)](#detection-performance)
[![Privacy](https://img.shields.io/badge/privacy-12%20non--negotiables-success.svg)](./docs/SECURITY.md)
[![Patterns](https://img.shields.io/badge/patterns-151%20regex%20(4%20facets)-blue.svg)](#)
[![Chrome 116+](https://img.shields.io/badge/chrome-116%2B-yellow.svg)](https://developer.chrome.com/docs/extensions/mv3)
[![Zero npm](https://img.shields.io/badge/dependencies-zero-success.svg)](./docs/SECURITY.md)

[Install](#installation) · [How It Works](#how-it-works) · [Detection](#what-it-detects) · [Privacy](./docs/SECURITY.md) · [Architecture](./docs/ARCHITECTURE-v0.1.3.md) · [Releases](https://github.com/aegisgatesecurity/aegisgate-lens/releases)

</div>

---

> **🛡️ Using AegisGate at work?** [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform) is our server-side gateway — 153 detection patterns, MCP/A2A/ACP protection, 15+ compliance frameworks, and cryptographic attestation. For the 95% of users without enterprise protections, Lens is here. [Explore Platform →](https://github.com/aegisgatesecurity/aegisgate-platform)

---

## Why AegisGate Lens?

Every AI conversation is a potential data leak. A prompt containing an API key, a social security number, or a database credential gets sent in plain text to a third-party LLM — and you can never take it back.

Lens is the browser extension that catches it **before you hit send**.

- **100% on-device.** No prompt text, no URLs, no page content ever leaves your browser. Zero telemetry by default.
- **151 regex patterns, zero ML.** Sub-millisecond detection. No model to download, no inference lag, no black box.
- **8 AI providers.** ChatGPT, Claude, Gemini, Copilot, DuckDuckGo, Perplexity, Mistral, Grok.
- **Fail-visible.** Every detection is shown to you — you decide to cancel, redact, or proceed.
- **Free. Forever.** Apache 2.0, no account required, no upsell gate.

## Detection Flow

```mermaid
flowchart LR
    User["👤 You type a prompt"] -->|"Keystroke<br/>(debounced 250ms)"| Lens["🛡️ Lens<br/>Content Script"]
    Lens -->|"Scan 4 facets<br/>in parallel"| Scan{"151 regex<br/>patterns"}

    Scan -->|"PII detected"| PII["🔒 PII<br/>(55 patterns)"]
    Scan -->|"Secret detected"| Secret["🔑 Secrets<br/>(41 patterns)"]
    Scan -->|"XSS detected"| XSS["💉 XSS<br/>(12 patterns)"]
    Scan -->|"Compliance risk"| Comp["📋 Compliance<br/>(43 patterns)"]

    PII & Secret & XSS & Comp -->|"PostProcess<br/>Luhn + context"| Decision{"Any<br/>findings?"}

    Decision -->|"Yes"| Banner["⚠️ Banner<br/>Cancel · Redact · Dismiss"]
    Decision -->|"No"| Pass["✅ Pass-through"]

    Banner -->|"Cancel"| Stop["🛑 Don't send"]
    Banner -->|"Redact"| Redacted["📝 Masked prompt"]
    Banner -->|"Dismiss 24h"| Send["➡️ Send anyway"]
    Pass --> Send2["➡️ Send to AI"]

    style Lens fill:#1e40af,stroke:#3b82f6,color:#fff
    style Banner fill:#dc2626,stroke:#ef4444,color:#fff
    style Pass fill:#16a34a,stroke:#22c55e,color:#fff
```

## Security Posture

| Metric | Value |
|--------|-------|
| Prompt data sent to servers | **0 bytes** (all on-device) |
| External dependencies | **0** (no npm, no node_modules) |
| Telemetry by default | **Off** (opt-in FP reporting sends hashes only) |
| Content Security Policy | **MV3 strict** (no inline scripts, no remote code, no eval) |
| Commit signing | **Ed25519** on all commits |
| Vulnerability disclosure | **RFC 9116** (security@aegisgatesecurity.io) |

## What It Detects

Lens runs **4 detection facets** in parallel on every keystroke (debounced 250ms). Each facet uses hand-curated regex patterns. **No ML model, no inference latency, no model loading.**

| Facet | What it catches | Example | Patterns |
|-------|----------------|---------|----------|
| **PII** | Email, phone, SSN, credit card (Luhn-validated), DOB, address, driver's license, passport, tax ID, bank account, IP address | `john.doe@example.com`, `4111-1111-1111-1111` | 55 |
| **Secrets** | API keys (AWS, GitHub, OpenAI, Stripe, Slack), OAuth tokens, RSA private keys, database credentials | `ghp_abc123...`, `AKIA...`, `-----BEGIN RSA PRIVATE KEY-----` | 41 |
| **XSS** | Cross-site scripting payloads | `<script>alert(1)</script>` | 12 |
| **Compliance** | OWASP LLM Top 10 (5/10), MITRE ATLAS, EU AI Act, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA | "patient SSN:", "credit card:" | 43 |
| **Total** | — | — | **151** |

**Roadmap (v0.2.0)**: 2 more facets (Toxicity, Prompt-Injection) + TinyML model for ambiguous cases. See [docs/ARCHITECTURE-v0.1.3.md](./docs/ARCHITECTURE-v0.1.3.md) for the full architecture.

## How Lens Compares

| Capability | Lens | Browser-native warnings | Enterprise DLP |
|------------|------|------------------------|----------------|
| PII detection (55 patterns) | ✅ | ❌ | ✅ |
| Secret detection (41 patterns) | ✅ | ❌ | ✅ |
| XSS detection (12 patterns) | ✅ | ❌ | ⚠️ Web-only |
| Compliance risk flagging (43 patterns) | ✅ | ❌ | ⚠️ Limited |
| Works on 8 AI providers | ✅ | ❌ | ⚠️ Requires proxy |
| 100% on-device, zero telemetry | ✅ | ✅ | ❌ Cloud-based |
| Zero dependencies | ✅ | ✅ | ❌ Requires agent |
| Free (Apache 2.0) | ✅ | ✅ | ❌ Paid license |
| Fail-visible (user sees every detection) | ✅ | ✅ | ❌ Silent block |

## Performance

| Metric | v0.1.3 | v0.1.0-beta baseline |
|--------|--------|---------------------|
| FPR (WildChat, 6,500 prompts) | **2.31%** (150 FPs) | 12.49% (812 FPs) |
| FPR (per-pattern must-not-trigger, 119 entries) | **0/119** (100% clean) | n/a |
| Detection latency (avg) | **0.34 ms** | n/a |
| Detection latency (p99) | **1 ms** | 0.847 ms (claimed) |
| Throughput | **5,348 prompts/sec** | 6,474 prompts/sec (claimed) |
| FPR reduction | **5.1×** | (baseline) |

**Source**: [docs/MODEL-CARD.md](./docs/MODEL-CARD.md) — detection metrics and evaluation data

## Why Regex (not ML)?

- **Privacy**: regex is auditable. A model is a black box.
- **Size**: 151 patterns = ~55KB. A TinyML model would add 1–2MB.
- **Latency**: regex detects in **<1ms** (typical 0.3–0.5ms). A model would need 50–100ms.
- **Determinism**: same result every time. A model can drift.
- **FPR**: 2.31% on 6,500 WildChat prompts — comparable to or better than ML approaches.

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

## How It Works

1. **Content script** is injected into each supported AI provider page (per the MV3 manifest)
2. **On every keystroke** (debounced 250ms), the prompt value is read from the textarea
3. **4 regex facets** run in parallel: PII (55), Secrets (41), XSS (12), Compliance (43) = 151 patterns
4. **PostProcess** filters false positives: Luhn validation for credit cards, 4-4-4 CC pattern rejection, ID-label context check
5. **Banner shows** with severity color (critical = red, high = orange, medium = yellow, low = blue)
6. **User chooses**: Cancel / Edit & Redact / Send Anyway / Dismiss for 24h
7. **Dismissal** is stored in `chrome.storage.session` (or `chrome.storage.local` fallback) for 24h

## Installation

### From Chrome Web Store (recommended)

1. Visit the [Chrome Web Store listing](https://chromewebstore.google.com/detail/aegisgate-lens/lkioinepjpjfdhiggaomoafnhagfcjip)
2. Click **Add to Chrome**
3. Click the AegisGate Lens icon in your toolbar to verify it's active

### From source (development)

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-lens.git
cd aegisgate-lens
# No npm install needed — zero external dependencies
```

## Test Coverage

| Suite | Count | Status |
|-------|-------|--------|
| Node unit tests (`node:test`) | 431 | ✅ all pass |
| Go unit tests (`go test`) | 3 | ✅ all pass |
| Headless smoke in real Chrome (via CDP) | 16 | ✅ all pass |
| Platform FPR test (6,500 WildChat prompts) | 1 | ✅ 2.31% FPR |
| **Total** | **450** | ✅ |

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

- **Apache 2.0** license
- **Zero external dependencies** (no npm, no node_modules, no bundled libraries)
- **MV3 strict CSP** (no inline scripts, no remote code, no eval)
- **Ed25519 commit signing** on all commits
- **RFC 9116** vulnerability disclosure (contact `security@aegisgatesecurity.io`)
- **No model bundles** in v0.1.3 (regex-only, so no bundle signing needed)

See [docs/SECURITY.md](./docs/SECURITY.md) for the full security model.

## For Enterprise Teams

AegisGate Lens is the consumer-facing layer. The same team builds [AegisGate Platform™](https://github.com/aegisgatesecurity/aegisgate-platform) — the server-side gateway with central policy, team-wide analytics, MCP/A2A/ACP/RESPONSE protection, the Trust Framework, MITRE ATLAS enforcement, OWASP LLM Top-10, the EU AI Act Compliance Module, and SIEM export.

| Use case | Recommendation |
|----------|----------------|
| Individual developers, security researchers, journalists, privacy-conscious users | **Lens alone** (free) |
| Teams of 2–10 who need a shared detection policy | **Lens + Platform Starter** ($29/mo) |
| Enterprises needing SIEM, compliance modules, central policy | **Platform Professional or Enterprise** (custom) |

## Roadmap (v0.2.0)

- **2 missing detection facets**: Toxicity + Prompt-Injection
- **TinyML model** (1–2MB transformer) for ambiguous cases
- **Firefox/Edge support**
- **Public benchmark dataset release**
- **Third-party security audit** (Cure53 / Trail of Bits / NCC Group)

## License

Apache 2.0. See [LICENSE](./LICENSE) for the full text.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>