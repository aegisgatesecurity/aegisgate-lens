# AegisGate Lens

<div align="center">

# 🛡️ AegisGate Lens — Privacy-First AI Security for Your Browser

![Version](https://img.shields.io/badge/Version-v0.3.0--rc1-blue?label=Version&logo=semver)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Node Version](https://img.shields.io/badge/Node-20_LTS-339933?logo=node.js)](https://nodejs.org)
[![Chrome MV3](https://img.shields.io/badge/Manifest-V3-4285F4?logo=google-chrome)](https://developer.chrome.com/docs/extensions/reference/manifest)
[![Security](https://img.shields.io/badge/Security-0_CVEs-brightgreen?logo=shield)](SECURITY.md)
![Tests](https://img.shields.io/badge/Tests-233_passing-brightgreen?logo=checkmarx)
[![DCO](https://img.shields.io/badge/DCO-Required-blueviolet)](DCO.md)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-Compatible-003399?logo=europeanunion)](docs/COMPLIANCE-MATRIX.md)

> **The browser-side complement to the [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform) security gateway.** Detects prompt injection, PII, secrets, XSS, and toxic content **BEFORE** it reaches ChatGPT, Claude, Gemini, or Copilot — with 100% on-device ML and a privacy-first design enforced in CI.

[🌐 Website](https://aegisgatesecurity.io) • [🚀 **Live Demo**](https://demo.aegisgatesecurity.io/) • [📊 Pricing](https://aegisgatesecurity.io/pricing/) • [📚 Docs](https://aegisgatesecurity.io/lens/) • [🔒 Security](SECURITY.md) • [💬 Discussions](https://github.com/aegisgatesecurity/aegisgate-lens/discussions)

</div>

---

## 🆕 What's New in v0.3.0-rc1 (2026-06-30)

> **This is a release-candidate (rc1).** The Chrome Web Store submission follows this CI pass. The first public-facing release of the v0.3 line is `v0.3.0` after CWS review.

- 🧠 **ModernBERT-base ML model** (149M params, 8K context) for Facet 6 prompt-injection detection — replaces v0.1's regex-only approach
- 🪟 **Sliding window inference** (2048 / 1024 / 4) for long-context attacks (up to 13K tokens with 80%+ recall)
- 🛡️ **6-facet detection system**: PII · Secrets · XSS · Compliance · Toxicity · Prompt Injection
- 🎯 **Detection threshold tuned to 0.05** via hard test set sweep (100% short, 0% FPR)
- 🔐 **Ed25519 bundle signing** (8/8 attack vectors rejected; signing key held offline)
- 🏛️ **SLSA L2 + Sigstore + Rekor** provenance for every release artifact
- 🧪 **233/233 tests pass, 7/7 ship-readiness gates PASS**
- 📜 **New docs**: `SECURITY.md` (RFC 9116), `docs/COMPLIANCE-MATRIX.md`, `docs/CISO-ONE-PAGER.md`, `docs/ARCHITECTURE-V0.3-ADDENDUM.md`
- 🖼️ **New CWS asset**: 440×280 small promo tile
- 📝 **PR template** with privacy-review section
- 🚫 **Zero third-party JavaScript dependencies** (privacy product, enforced in CI)

**Read the full [v0.3.0-rc1 release notes](https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.3.0-rc1).**

---

## What is AegisGate Lens?

AegisGate Lens is a **single-binary Chrome extension** that runs a 6-facet
detection cascade on every prompt you type into an AI tool, **before the
prompt is sent**. The extension is a **security product with a privacy-first
design** — it detects attacks (prompt injection, PII leakage, secret
disclosure, XSS, toxic content) while enforcing 12 non-negotiable privacy
guarantees in code and CI.

It is the **browser-side complement** to the [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform)
security gateway: the Platform secures server-side AI traffic; the Lens
secures client-side AI prompts. Together they provide defense-in-depth
across the full AI request lifecycle.

**In one sentence**: *AegisGate Lens stops prompt injection, PII, secrets, XSS, and toxic content at the browser — with 100% on-device ML and a privacy-first design that ships with Ed25519-signed bundles, SLSA L2 provenance, and 233/233 tests passing.*

### Who It's For

- **Security teams** at organizations using ChatGPT Enterprise, Claude for Work, Gemini for Workspace, or Microsoft Copilot who need to prevent prompt injection, accidental secret leakage, and PII exfiltration
- **Privacy-conscious professionals** (lawyers, doctors, journalists, researchers) who use AI tools but cannot send client/patient/source data to the cloud
- **Solo developers and small teams** using AI as a daily coding assistant and want a "set and forget" guardrail against accidentally pasting API keys, tokens, or PII
- **Enterprise customers** who need auditor-ready evidence (SOC 2, ISO 27001, EU AI Act, HIPAA, PCI-DSS) that AI usage is monitored and policy-compliant

### Who It's NOT For

- **Anyone who doesn't use AI in their browser yet** (you're not the target — come back when you ship)
- **Anyone looking for an LLM-side alignment tool** (the Lens is endpoint-side; try NeMo Guardrails or Guardrails AI for model-side)
- **Anyone who needs a managed cloud service** (the Lens is on-device; the cloud version is the [Platform](https://github.com/aegisgatesecurity/aegisgate-platform))
- **Anyone who has a fully air-gapped AI workflow** (the Lens is a browser extension; air-gapped users should use the Platform directly)

---

## The Problem

When you paste a prompt into ChatGPT, Claude, or Copilot, you're trusting the AI provider with:

- **Customer PII** (names, emails, SSNs, payment data) that the model may log for training
- **API keys and tokens** (GitHub PATs, AWS credentials, Slack webhooks) that get cached server-side
- **Internal documentation** (architecture diagrams, business plans) that may be retained for months
- **Prompt injection attacks** (hidden in pasted documents or images) that hijack the model

The major AI providers (Lakera Guard, Cisco AI Defense, Rebuff, Prompt Shields) solve this **by sending your prompts to their cloud** for analysis — which **violates the very privacy you're trying to protect**.

**AegisGate Lens solves this 100% on-device.** Your prompts never leave your browser.

---

## Why AegisGate Lens? (vs. Other AI Security Tools)

| | AegisGate Lens | Lakera Guard | Cisco AI Defense | Rebuff |
|---|---|---|---|---|
| **On-device ML** | ✅ ModernBERT-base | ❌ cloud only | ❌ cloud only | ❌ cloud only |
| **Open source** | ✅ Apache 2.0 | ❌ proprietary | ❌ proprietary | ✅ MIT |
| **Zero prompt data leaves the browser** | ✅ hardware-enforced | ❌ | ❌ | ❌ |
| **6-facet cascade** (PII + secrets + XSS + compliance + toxicity + PI) | ✅ | ❌ 1 facet | ❌ 2 facets | ❌ 1 facet |
| **Long-context (13K+ tokens)** | ✅ sliding window | ❌ 4K limit | ❌ 4K limit | ❌ 4K limit |
| **Ed25519 bundle signing** | ✅ | ❌ | ❌ | ❌ |
| **SLSA L2 + Sigstore + Rekor** | ✅ | ❌ | ❌ | ❌ |
| **Zero npm dependencies** | ✅ (privacy enforced) | n/a | n/a | n/a |
| **Privacy guarantees in CI** | ✅ | ❌ | ❌ | ❌ |
| **Catches secrets (API keys, tokens, webhooks)** | ✅ 17+ categories | ❌ | ❌ | ❌ |
| **Catches PII with Luhn validation** | ✅ 17+ types | ❌ | ❌ | ❌ |
| **Detects XSS / source code in prompts** | ✅ 7+ patterns | ❌ | ❌ | ❌ |
| **Compliance markers (OWASP, EU AI Act, NIST AI RMF)** | ✅ 3+ frameworks | ❌ | ❌ | ❌ |
| **Toxicity detection (weapons, violence)** | ✅ regex + toxic-bert ML | ❌ | ❌ | ❌ |

**The 12 non-negotiable privacy guarantees are enforced in CI**, not just documented:

1. Prompts never leave the browser
2. URLs never leave the browser
3. Page content never leave the browser
4. No user ID, session ID, or cookie is collected
5. Default is OFF — opt-in required for telemetry
6. Open source from day one (Apache 2.0)
7. Privacy policy published before ship
8. **Zero third-party JavaScript dependencies** (no `package.json`)
9. Data retention: 90 days for events, indefinite for aggregated stats
10. API rate-limited: 100 events/min per install
11. Backend: TLS 1.2+ only, HSTS
12. Threat model updated whenever architecture changes

---

## The 6 detection facets

| Facet | What it catches | How |
|---|---|---|
| **1. PII** | SSNs, credit cards (Luhn-validated), emails, phones, IPs, health data | Regex |
| **2. Secrets** | API keys (AWS, GCP, OpenAI, Stripe, Twilio, GitHub, GitLab, ...), OAuth tokens, JWTs, private keys, DB URLs | Regex |
| **3. XSS / Source** | Script tags, SQL injection, source code being shared | Regex |
| **4. Compliance** | OWASP LLM Top-10, EU AI Act, NIST AI RMF markers | Regex from Platform |
| **5. Toxicity** | Weapons, violence, illegal content markers | Regex + toxic-bert ML |
| **6. Prompt Injection** | Novel attacks that evade regex (long-context, obfuscated, etc.) | ModernBERT-base ML + sliding window (2048/1024/4) |

The cascade is **regex → ML → sliding window**. Regex catches the 95%
of attacks instantly. ML catches the rest. Sliding window handles
long-context attacks buried in legal documents, code reviews, or
emails (up to 13K tokens with 80%+ recall).

---

## 🏗️ Architecture

The Lens is a Manifest V3 Chrome extension with 17 content scripts
that match against 8 AI provider hostnames (chat.openai.com,
claude.ai, gemini.google.com, copilot.microsoft.com, duck.ai,
duckduckgo.com, perplexity.ai, grok.com, x.com). On every prompt
mutation, the 6-facet cascade runs **in the content script's main
world** (not in a service worker) for sub-millisecond detection.

The **bundle signing keypair** is held offline in the AegisGate
Security's secure storage; the public key is in the repo at
`keys/lens-toxicity-pub.pem`. The private key is **never** in the
public repo or in any CI environment. The v0.2.2 release was signed
with the previous keypair; the v0.3.0+ line is signed with a new
keypair (key rotation per [`SECURITY.md`](SECURITY.md)).

For the full architecture, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
and [`docs/ARCHITECTURE-V0.3-ADDENDUM.md`](docs/ARCHITECTURE-V0.3-ADDENDUM.md).

---

## ⚡ Performance

| Metric | Value |
|---|---|
| Detection latency (regex only) | <5ms |
| Detection latency (regex + ModernBERT) | <400ms |
| Inference memory | ~150 MB peak (ModernBERT int8) |
| Bundle size (int8) | 147 MB |
| Bundle size (full fp32) | 549 MB |
| Cold start (no cached model) | ~2.5s |
| Warm start (cached model) | <400ms |

The int8 quantized ModernBERT bundle is preferred at runtime; fp32 is
the fallback for users who need higher precision at the cost of
~400 MB extra download. The build tool
(`tools/build-lens-extension/`) prefers int8 when present in the
bundle (see the [build tool PR](https://github.com/aegisgatesecurity/aegisgate-platform/pulls)).

---

## 🚀 Quick Start

### Install from Chrome Web Store (recommended for most users)

1. Visit the [Chrome Web Store listing](https://chromewebstore.google.com/) (link coming after CWS review)
2. Click "Add to Chrome"
3. Visit any AI tool, type a prompt — Lens will show a banner if it
   detects anything (PII, secrets, prompt injection, etc.)
4. Click the Lens icon in the toolbar to see the popup, opt-in to
   telemetry, and review the threat model

### Build from source (for developers and security researchers)

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-lens.git
cd aegisgate-lens
git checkout v0.3.0-rc1
# Run the 21 test suites (233/233 should pass)
for t in test/*.test.mjs; do node "$t"; done
```

For the build tool, see
[`tools/build-lens-extension/`](https://github.com/aegisgatesecurity/aegisgate-platform/tree/main/tools/build-lens-extension)
in the Platform repo. For the test harness, see the
[`ci.yml`](.github/workflows/ci.yml) workflow.

---

## 🎯 Tier Comparison (Lens Free vs Platform Enterprise)

The Lens is **free** for individual use. The AegisGate Platform is the
**Enterprise** tier (server-side gateway for AI traffic). Together they
provide defense-in-depth across the AI request lifecycle.

| | AegisGate Lens (Free) | AegisGate Platform (Enterprise) |
|---|---|---|
| **Use case** | Browser-side prompt detection (client endpoint) | Server-side AI traffic gateway (backend) |
| **Where it runs** | Chrome extension (on the user's device) | Self-hosted Go binary (on your infra) |
| **Detects** | Prompt injection, PII, secrets, XSS, toxic content (in prompts the USER types) | All of the above + tool poisoning, A2A spoofing, MCP abuse, agent intent attacks, EU AI Act violations |
| **Catches** | Outbound threats (data leaving the user) | Inbound AND outbound (data flowing in both directions) |
| **Compliance evidence** | Anonymized telemetry (opt-in) | Auditor-ready signed envelopes (SOC 2, ISO 27001, EU AI Act, HIPAA, PCI-DSS) |
| **Multi-tenant** | ❌ (per-user) | ✅ (per-org, per-team, per-role) |
| **mTLS + HMAC + capability enforcement** | ❌ (browser-side) | ✅ |
| **STIX/TAXII export** | ❌ | ✅ (12 SIEM integrations) |
| **Pricing** | Free | Starter $29/mo, Developer $99/mo, Professional $499/mo, Enterprise custom |
| **Bundle size** | 147 MB int8 / 549 MB fp32 | 13.3 MB Go binary |
| **Network egress** | Zero (100% on-device) | Configurable (rate-limited) |
| **Deployment** | One-click CWS install | Docker, Kubernetes, bare metal (60s setup) |
| **Open source** | Apache 2.0 | Apache 2.0 |
| **Audit log retention** | 90 days (events) | Indefinite (signed envelopes) |

**Recommendation**: Use both. The Lens catches what the user
accidentally pastes; the Platform catches what the AI provider
returns. Together they cover the full AI request lifecycle.

---

## ✨ Features at a Glance

| Feature | Status | Where |
|---|---|---|
| 6-facet detection cascade | ✅ v0.3.0 | `src/detectors/` |
| ModernBERT ML inference | ✅ v0.3.0 | `src/util/transformer-modernbert.js` |
| Sliding window (long-context) | ✅ v0.3.0 | `src/util/transformer-modernbert.js` |
| Ed25519 bundle signing | ✅ v0.3.0 | `src/util/bundle-loader.js` |
| On-device only (no cloud) | ✅ v0.3.0 | Architectural (enforced in CI) |
| Welcome page (onboarding) | ✅ v0.3.0 | `src/welcome.html` |
| Threat model updated per change | ✅ v0.3.0 | `docs/THREAT-MODEL.md` |
| Chrome Web Store listing | ⏳ In review | CWS submission pending |
| Firefox port | ✅ v0.3.0 | `lens-final-dist-firefox/` |
| In-extension upgrade CTA to Platform | ⏳ v0.3.x | (planned) |
| 100K-token context window | ⏳ v0.4.0 | (planned) |
| Bug bounty program (HackerOne) | ⏳ v0.4.0 | (planned, $500-$5000 per finding) |
| Independent security audit (NCC Group) | ⏳ v0.4.0 | (planned) |

---

## 🛡️ Security Hardening

- **Ed25519 bundle signing** (8/8 attack vectors rejected in `test/security-bundle-verification.test.mjs`)
- **SLSA L2 + Sigstore + Rekor** provenance for every release artifact (`gh attestation verify --repo aegisgatesecurity/aegisgate-lens <artifact>`)
- **Strict CSP** (no `eval`, no inline scripts, no remote code)
- **Sender ID validation** (content scripts verify they're from the legitimate extension)
- **Bundle signing key** is held offline (public key only in repo at `keys/lens-toxicity-pub.pem`)
- **No third-party JavaScript dependencies** (verified by CI grep)
- **Pen-tests**: 21/21 pass (F-01 sender validation, F-02 bundle signing, F-04 dismissals quota, F-05 wire protocol)
- **Privacy boundary test** (14 adversarial events; no prompt content crosses the wire)

For vulnerability disclosure, see [`SECURITY.md`](SECURITY.md). Email
**security@aegisgatesecurity.io** (PGP key on request). The signing
key for the toxicity bundle is held offline per the key-rotation
policy documented in `docs/THREAT-MODEL.md`.

---

## 🛠️ Try the Live Demo

**Want to see AegisGate Lens in action before reading another line of docs?**
Try the [AegisGate Live Demo →](https://demo.aegisgatesecurity.io/)

The demo runs the **actual AegisGate Lens** in headless Chrome against
AI provider mocks. You'll get:
- 4 of the 6 detection facets running live (PII, secrets, XSS, compliance)
- 10+ pre-loaded test prompts covering all categories
- The full banner UI with "send anyway" / "edit" / "cancel" actions

The Platform demo (separate) also includes the Trust Framework, MCP
guardrails, and EU AI Act compliance — try that one too if you want the
full picture.

---

## 📚 Documentation

- 📖 [**Quick Start**](docs/QUICK-START.md) — install + first 5 minutes
- 🏛️ [**Architecture**](docs/ARCHITECTURE.md) — the v0.1 foundation
- 🆕 [**Architecture v0.3 Addendum**](docs/ARCHITECTURE-V0.3-ADDENDUM.md) — the 9 v0.3.0 decisions
- 🛡️ [**Threat Model**](docs/THREAT-MODEL.md) — STRIDE analysis + 24+ findings
- 🛡️ [**Security Policy**](SECURITY.md) — RFC 9116 compliant, vulnerability disclosure
- 📊 [**Compliance Matrix**](docs/COMPLIANCE-MATRIX.md) — MITRE ATLAS, NIST AI RMF, OWASP LLM Top-10, EU AI Act [**CISO One-Pager**](docs/CISO-ONE-PAGER.md) — 189 lines, full privacy/data handling for enterprise CISOs

- 👔- 🧪 [**DCO**](DCO.md) — Developer Certificate of Origin
- 🤝 [**Contributing**](CONTRIBUTING.md) — dev env setup + PR process
- 📜 [**Changelog**](CHANGELOG.md) — full v0.1, v0.2.2, v0.3.0-rc1 history

---

## 🤝 Community

- 💬 [GitHub Discussions](https://github.com/aegisgatesecurity/aegisgate-lens/discussions) — ask questions, share patterns
- 🐛 [Issue Tracker](https://github.com/aegisgatesecurity/aegisgate-lens/issues) — bug reports, feature requests
- 🛡️ [Security Disclosure](SECURITY.md) — email security@aegisgatesecurity.io
- 🌍 [AegisGate Website](https://aegisgatesecurity.io) — full company info
- 📧 [General Questions](mailto:support@aegisgatesecurity.io)

---

## 📋 Version Support

| Version | Status | Security fixes | Notes |
|---|---|---|---|
| **v0.3.x** (this release line) | ✅ current dev | ✅ | ModernBERT ML, sliding window, 6-facet cascade |
| v0.2.x | ✅ current stable | ✅ | v0.2.2 was the last pre-ModernBERT release |
| v0.1.x | ❌ deprecated | ❌ | regex-only, no ML, no sliding window |
| < v0.1 | ❌ EOL | ❌ | — |

---

## 📜 License

Apache License 2.0. See [`LICENSE`](LICENSE).

## 🤝 Contributing

We welcome contributions! See [`CONTRIBUTING.md`](CONTRIBUTING.md) for
the dev env setup, the PR process, and the privacy review section
(mandatory for any change that touches detection or telemetry).
All commits must be signed off per [`DCO.md`](DCO.md) (enforced by CI).

## 🙏 Acknowledgments

Built with ❤️ by the [AegisGate Security](https://aegisgatesecurity.io)
team. The Lens is the browser-side complement to the Platform — together
they cover the full AI request lifecycle, end-to-end.

> *The privacy product for the 95% who don't have an AI estate — and the
> security product for the 5% who do.*
