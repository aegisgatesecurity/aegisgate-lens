# 🛡️ AegisGate Lens

### Privacy-first browser extension that warns you **before you hit send** when your AI prompt contains PII, secrets, XSS payloads, or compliance risks.

**100% on-device. Zero prompt content ever leaves your browser. Free. Forever.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.1.3-orange.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/blob/v0.1.3/CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-497%2F497%20%2B%203%2F3%20%2B%2016%2F16%20%2B%20128%2F128-brightgreen.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/blob/v0.1.3/docs/FACTS.md)
[![FPR](https://img.shields.io/badge/FPR-2.31%25%20on%206%2C500%20WildChat-success.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/blob/v0.1.3/docs/METRICS-v0.1.2.md)
[![Privacy](https://img.shields.io/badge/privacy-12%20non--negotiables-success.svg)](./docs/SECURITY.md)
[![Patterns](https://img.shields.io/badge/patterns-132%20regex%20(4%20facets)-blue.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/blob/v0.1.3/docs/FACTS.md)
[![Chrome 116+](https://img.shields.io/badge/chrome-116%2B-yellow.svg)](https://developer.chrome.com/docs/extensions/mv3)
[![Zero npm](https://img.shields.io/badge/dependencies-zero-success.svg)](./docs/SECURITY.md)

[Install](#installation) · [How It Works](#how-it-works) · [Detection](#what-it-detects) · [Privacy](./docs/SECURITY.md) · [Architecture](./docs/ARCHITECTURE-v0.1.0-BETA.md) · [Releases](https://github.com/aegisgatesecurity/aegisgate-lens/releases)

> **Canonical facts**: All numbers in this README come from [docs/FACTS.md](./docs/FACTS.md). If you change a number, update FACTS.md FIRST, then propagate to this README and the marketing site (aegisgatesecurity.io/lens/).

---

## What It Does

AegisGate Lens is a Manifest V3 Chrome extension that watches what you type into **8 major AI chat tools** — ChatGPT, Claude, Gemini, Microsoft Copilot, DuckDuckGo, Perplexity, Mistral, and Grok — and shows a top-of-screen banner **before you send the prompt** if sensitive content is detected.

When you click the banner, you can:
- **Cancel** — don't send the prompt
- **Edit & Redact** — Lens shows the rewritten prompt with sensitive values masked
- **Send Anyway** — proceed at your own risk
- **Dismiss for 24 hours** — if you're sure the detection is a false positive

All detection happens **in your browser**. No prompt text, no URLs, no page content, no account, no telemetry by default.

---

## What It Detects

Lens runs **4 detection facets** in parallel on every keystroke (debounced 250ms). Each facet uses hand-curated regex patterns. **No ML model, no inference latency, no model loading.**

| Facet | What it catches | Example | Patterns |
|-------|----------------|---------|----------|
| **PII** | Email, phone, SSN, credit card (Luhn-validated), DOB, address, driver's license, passport, tax ID, bank account, IP address | `john.doe@example.com`, `4111-1111-1111-1111` | 55 |
| **Secrets** | API keys (AWS, GitHub, OpenAI, Stripe, Slack), OAuth tokens, RSA private keys, database credentials | `ghp_abc123...`, `AKIA...`, `-----BEGIN RSA PRIVATE KEY-----` | 41 |
| **XSS** | Cross-site scripting payloads | `<script>alert(1)</script>` | 12 |
| **Compliance** | OWASP LLM Top 10 (5/10 implemented), MITRE ATLAS, EU AI Act, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA | "patient SSN:", "credit card:" | 24 |
| **Total** | — | — | **132** |

**Roadmap (v0.2.0)**: 2 more facets (Toxicity, Prompt-Injection) + TinyML model for ambiguous cases. See [FACTS.md](./docs/FACTS.md) section 8.

---

## Why Regex (not ML)?

v0.1.3 is intentionally regex-only. The rationale:

- **Privacy**: regex is auditable. A model is a black box.
- **Size**: regex is 132 patterns = ~50KB. A TinyML model would add 1-2MB.
- **Latency**: regex detects in **<1ms** (typical 0.3-0.5ms). A model would need 50-100ms.
- **Determinism**: regex produces the same result every time. A model can drift.
- **No training data**: regex patterns are hand-curated. No need for a training corpus.
- **FPR**: with the v0.1.4 postProcess tightening, FPR on 6,500 WildChat prompts is **2.31%** (150 false positives) — comparable to or better than ML approaches.

---

## Performance

| Metric | v0.1.3 | v0.1.0-beta baseline |
|--------|--------|---------------------|
| FPR (WildChat, 6,500 prompts) | **2.31%** (150 FPs) | 12.49% (812 FPs) |
| FPR (per-pattern must-not-trigger, 119 entries) | **0/119** (100% clean) | n/a |
| Detection latency (avg) | **0.34 ms** | n/a |
| Detection latency (p99) | **1 ms** | 0.847 ms (claimed) |
| Throughput | **5,348 prompts/sec** | 6,474 prompts/sec (claimed) |
| FPR reduction | **5.1×** | (baseline) |

**Source**: [docs/METRICS-v0.1.2.md](./docs/METRICS-v0.1.2.md) — the canonical metrics doc.

---

## Supported AI Providers

AegisGate Lens works on **8 AI providers** (with 13 host entries for the various subdomains and www variants):

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

**Source**: [src/util/selectors.js](./src/util/selectors.js) (the runtime source of truth).

---

## How It Works

1. **Content script** is injected into each supported AI provider page (per the MV3 manifest)
2. **On every keystroke** (debounced 250ms), the prompt value is read from the textarea
3. **4 regex facets** run in parallel: PII (55 patterns), Secrets (41), XSS (12), Compliance (24) = 132 patterns
4. **PostProcess** filters false positives:
   - Luhn validation for credit cards
   - 4-4-4 CC pattern rejection (a phone regex was matching credit card digit runs)
   - ID-label context check for ID-shaped patterns (requires "ID:", "passport", etc. prefix)
5. **Banner shows** with severity color (critical = red, high = orange, medium = yellow, low = blue)
6. **User chooses**: Cancel / Edit & Redact / Send Anyway / Dismiss for 24h
7. **Dismissal** is stored in `chrome.storage.session` (or `chrome.storage.local` fallback) for 24h

See [docs/ARCHITECTURE-v0.1.0-BETA.md](./docs/ARCHITECTURE-v0.1.0-BETA.md) for the full architecture.

---

## Installation

### From Chrome Web Store (recommended)

1. Visit the [Chrome Web Store listing](https://chromewebstore.google.com/category/extensions/ai)
2. Click **Add to Chrome**
3. Click the AegisGate Lens icon in your toolbar to verify it's active

### From source (development)

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-lens.git
cd aegisgate-lens
# No npm install needed — zero external dependencies
```

The Chrome extension `.zip` is built by the CI workflow in [tools/build-lens-extension/](../consolidated/aegisgate-platform/tools/build-lens-extension/) (in the platform monorepo).

---

## Test Coverage

| Suite | Count | Status |
|-------|-------|--------|
| Node unit tests (`node:test`) | 431 | ✅ all pass |
| Go unit tests (`go test`) | 3 | ✅ all pass |
| Headless smoke in real Chrome (via CDP) | 16 | ✅ all pass |
| Platform FPR test (6,500 WildChat prompts) | 1 | ✅ 2.31% FPR |
| **Total** | **450** | ✅ |

```bash
# Run all tests locally
node --test test/unit/*.test.mjs           # 431 Node tests
cd tools/headless-smoke/flow && go test ./...   # 3 Go tests
./test/headless-smoke/headless-smoke-bin \  # 16 smoke tests
  --dist test/headless-smoke/dist \
  --output smoke-report.json
```

See [docs/METRICS-v0.1.2.md](./docs/METRICS-v0.1.2.md) for the full test analysis and FPR breakdown.

---

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

The only opt-in path is **false-positive reporting**: when you click "Submit & Dismiss" on a banner. Then Lens sends **hashed metadata only** (detection category, pattern ID, domain hash) — no prompt text, no URLs, no page content. You can dismiss without reporting (no data sent).

See [docs/SECURITY.md](./docs/SECURITY.md) for the full privacy policy and security model.

---

## Security

- **Apache 2.0** license
- **Zero external dependencies** (no npm, no node_modules, no bundled libraries)
- **MV3 strict CSP** (no inline scripts, no remote code, no eval)
- **Ed25519 commit signing** on all commits
- **RFC 9116** vulnerability disclosure (contact `security@aegisgatesecurity.io`)
- **No model bundles** in v0.1.3 (regex-only, so no bundle signing needed)

See [docs/SECURITY.md](./docs/SECURITY.md) for the full security model.

---

## For Enterprise Teams

AegisGate Lens is the consumer-facing layer. The same team builds [AegisGate Platform™](https://aegisgatesecurity.io/?utm_source=lens-readme) — the server-side gateway with central policy, team-wide analytics, MCP/A2A/ACP/RESPONSE protection, the Trust Framework, MITRE ATLAS enforcement, OWASP LLM Top-10, the EU AI Act Compliance Module, and SIEM export.

| Use case | Recommendation |
|----------|----------------|
| Individual developers, security researchers, journalists, privacy-conscious users | **Lens alone** (free) |
| Teams of 2-10 who need a shared detection policy | **Lens + Platform Starter** ($29/mo) |
| Enterprises needing SIEM, compliance modules, central policy | **Platform Professional or Enterprise** (custom) |

---

## Roadmap (v0.2.0)

Planned for v0.2.0 (timeline TBD, after CWS approval of v0.1.2):

- **2 missing detection facets**: Toxicity + Prompt-Injection
- **TinyML model** (1-2MB transformer) for ambiguous cases (would reduce FPR further)
- **Firefox/Edge support**
- **Public benchmark dataset release**
- **Third-party security audit** (Cure53 / Trail of Bits / NCC Group)
- **Marketing site refresh** (aegisgatesecurity.io/lens/)
- **Lighthouse CI integration**

See [docs/FACTS.md](./docs/FACTS.md) section 8 for the full roadmap.

---

## License

Apache 2.0. See [LICENSE](./LICENSE) for the full text.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The standing rules (108 lessons learned) are in [docs/AEGISGATE-LENS-STANDING-RULES-2026-06-29.md](./.plans/AEGISGATE-LENS-STANDING-RULES-2026-06-29.md).

---

## Contact

- **Privacy questions**: privacy@aegisgatesecurity.io
- **Security disclosures**: security@aegisgatesecurity.io (per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116))
- **General questions**: [Lens GitHub Discussions](https://github.com/aegisgatesecurity/aegisgate-lens/discussions)
- **Marketing site**: [aegisgatesecurity.io/lens](https://aegisgatesecurity.io/lens/)

---

**Built with privacy by the [AegisGate Security](https://aegisgatesecurity.io) team.**

> All numbers in this README are sourced from [docs/FACTS.md](./docs/FACTS.md). If a number changes, update FACTS.md FIRST, then propagate here and to the marketing site.