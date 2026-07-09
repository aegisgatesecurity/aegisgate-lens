<div align="center">

# 🛡️ AegisGate Lens

### Privacy-first browser extension that warns you **before you hit send** when your AI prompt contains PII, secrets, or compliance risks.

**100% on-device. Zero prompt content ever leaves your browser. Free. Forever.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.1.0--beta-orange.svg)](https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/lens-v0.1.0-beta)
[![Tests](https://img.shields.io/badge/tests-325%2F325%20passing-brightgreen.svg)](https://github.com/aegisgatesecurity/aegisgate-lens)
[![Privacy](https://img.shields.io/badge/privacy-zero--egress-success.svg)](./docs/PRIVACY-POLICY.md)
[![Build](https://img.shields.io/badge/build-SLSA%20L2-blueviolet.svg)](./SECURITY.md)
[![No npm](https://img.shields.io/badge/dependencies-zero-success.svg)](./docs/NO-EXTERNAL-DEPS.md)
[![Chrome 116+](https://img.shields.io/badge/chrome-116%2B-yellow.svg)](https://developer.chrome.com/docs/extensions/mv3)

[Install](#installation) · [How It Works](#how-it-works) · [Compare](#how-lens-compares) · [Privacy](./docs/PRIVACY-POLICY.md) · [Security](./SECURITY.md) · [Releases](https://github.com/aegisgatesecurity/aegisgate-lens/releases)

</div>

---

## What It Does

AegisGate Lens is a Manifest V3 Chrome extension that watches what you type into **8 major AI chat tools** — ChatGPT, Claude, Gemini, Microsoft Copilot, Perplexity, Duck.ai, Grok, and Mistral — and shows a top-of-screen banner before you send the prompt, if sensitive content is detected.

- 🛑 **PII** (SSN, email, phone, credit card, address, passport, IBAN, Aadhaar, NHS, SIN, TFN, CPF, BIP39 seed, crypto wallets, digital payment handles, …)
- 🔑 **Secrets** (AWS, GitHub PAT, GCP, Stripe, OpenAI, JWT, PEM private keys, …)
- 🧨 **Source / XSS** (script tags, event handlers, javascript: URLs, SVG with onload, mutation XSS, polyglot, …)
- ⚖️ **Compliance** (OWASP LLM Top 10, MITRE ATLAS, EU AI Act, ANP, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA, …)

The detector is **4 regex facets, 120 patterns, sub-1ms latency** — no network calls, no ML, no prompt content logged.

## Benchmark Results (v0.1.0-beta, locked 2026-07-08)

| Metric | Value | Source |
|---|---|---|
| **In-target recall** (high-risk PII) | **98.99%** | 5,870 of 5,930 high-risk PII records across 5 public corpora |
| **Mixed records recall** (PII + low-risk PII) | **99.73%** | 39,285 of 39,391 mixed records |
| **FPR on real user prompts** | **7.40%** | 2,221 of 30,000 OASST1 + ultrachat prompts |
| **PII facet precision** | **76.51%** | When the detector fires, 77% of the time it's real PII |
| **Latency p50** | 0.156ms | Per-keystroke detection |
| **Latency p99** | **0.847ms** | 60× better than the 50ms target |
| **Unit tests** | **328/328 passing** | 10 .mjs test files in `test/unit/` |
| **Headless smoke** | **6/6 PASS** | Real Chromium 149 in `test/headless-smoke/` |
| **Patterns** | **120 total** | 54 PII + 41 Secrets + 12 XSS + 24 Compliance |
| **Providers** | **8** | chatgpt, claude, gemini, copilot, perplexity, duck_ai, grok, mistral |
| **Build size** | 1.13 MB | `lens-0.1.0-lens-sr.zip` |

**Tested against** 60,000 PII records (5 public corpora) and 30,000 real user prompts (OASST1 + ultrachat). No adversarial attacks or model-card evaluation in this release — those are the v0.2.0 work.

## How It Works

```
User types in AI provider input field
        ↓
  Debounced 300ms scan
        ↓
  4-facet regex dispatcher (PII / Secrets / XSS / Compliance)
        ↓
  Banner shows: "N sensitive items detected"
  with category, severity, masked value
  + Cancel send / Edit & redact / Send anyway actions
```

**Zero network egress.** The content script never calls `fetch`, `sendMessage` with prompt data, or any external service. Telemetry is **opt-in, off by default, and domain-hashed** ([see PRIVACY-POLICY.md](./docs/PRIVACY-POLICY.md)).

The 8 supported providers are matched via `hostname`. When a page loads, the content script attaches to the input field and starts scanning per-keystroke. When a detection fires, a brand-matched banner is rendered at the top of the page (`position: fixed; top: 0`) with three actions.

## How Lens Compares

| Capability | AegisGate Lens | Lakera Guard | Microsoft Prompt Shields | Cisco AI Defense |
|---|---|---|---|---|
| **Pricing** | **Free, forever** | $50/seat/mo | Free for Azure customers | Custom enterprise |
| **Architecture** | 100% on-device | Cloud-side | Cloud-side | Cloud-side |
| **Sees prompt content** | ❌ Never | ✅ Yes | ✅ Yes | ✅ Yes |
| **Network round-trip** | ❌ None | ✅ Required | ✅ Required | ✅ Required |
| **Latency (per keystroke)** | **0.85ms p99** | 50–200ms | 100–300ms | 50–150ms |
| **Detection type** | Regex (120 patterns) | ML + heuristics | ML | ML + rules |
| **OWASP LLM Top 10 coverage** | 6/10 | 10/10 | 10/10 | 9/10 |
| **MITRE ATLAS coverage** | 15 techniques | Unknown | 8 techniques | 12 techniques |
| **EU AI Act coverage** | 4 articles | Yes | Yes | Partial |
| **Open source** | ✅ Apache 2.0 | ❌ | ❌ | ❌ |
| **SLSA L2 build** | ✅ | ❌ | ✅ | ✅ |
| **Privacy moat** | Cannot see prompts | Sees prompts | Sees prompts | Sees prompts |
| **Cost to serve per user** | $0 | Variable | Variable | Variable |

**The core differentiator:** we are the only tool where the privacy guarantee is **enforced by what we cannot do**, not what we promise. No server, no logs, no prompt content ever crosses a wire. For SOC 2 / HIPAA / GDPR / EU AI Act compliance, that architectural fact matters.

## Why AegisGate Lens With Chrome (or Firefox, or Safari, etc.)?

Chrome 130+ has a built-in **Sensitive Content Detection** feature that works well for a single user on Google Search. AegisGate Lens is designed to be a **complement** to that (not a replacement), adding value on three dimensions: more detection patterns, more provider coverage, and full auditability. Here's how the two compare:

| Concern | Chrome's built-in | AegisGate Lens |
|---|---|---|
| **Where detection runs** | Inside Chrome's native UI, but the rules are defined by Google | Inside our open-source extension code, auditable by anyone |
| **Who sees the data** | Google (rule matches are logged to chrome://components) | Nobody — no telemetry, no logs, no sync |
| **Which providers it covers** | Only the browser's built-in input surfaces (Google Search, AI experiments) | 8 of the top consumer AI chat tools (chatgpt.com, claude.ai, gemini.google.com, copilot.microsoft.com, perplexity.ai, duck.ai, grok.com, chat.mistral.ai) |
| **What it detects** | Credit cards, mostly | 120 patterns across 4 facets: PII, Secrets, XSS / source-code risks, Compliance (OWASP / MITRE ATLAS / EU AI Act / NIST CSF / ISO 27001 / CCPA / LGPD / PIPEDA / POPIA) |
| **False positives** | Some — the banner shows a generic alert, no remediation guidance | Tuned to 7.40% FPR on 30,000 real user prompts; banner explains the category, severity, and mask; offers Cancel / Edit manually / Send anyway / False positive |
| **Customization** | None — Google's rules are fixed | Open source. You (or your security team) can read every regex. |
| **Auditability** | Closed-source native code | Apache 2.0; threat model published at [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md); 328 unit tests, 6 headless smoke tests, 100K-prompt benchmark |
| **Compliance posture** | "Trust us" — Google does not publish a threat model or privacy policy for this feature | "Verify us" — 9.5/10 threat-model score; CC-BY-4.0 threat model; SOC 2 / HIPAA / GDPR / EU AI Act / OWASP LLM Top 10 / MITRE ATLAS / NIST CSF / ISO 27001 mapped in `docs/THREAT-MODEL.md` |
| **Pricing** | Free (bundled with Chrome) | Free, forever (Apache 2.0, no telemetry, no "Pro" tier, no "Enterprise" upsell on the Lens itself) |
| **Platform integration** | None | AegisGate Platform (server-side enforcement, automated redaction, custom patterns, SSO) when your team is ready. The Lens is the TOFU; the Platform is the BOFU. |

**The short version:** Chrome's built-in is great for a single user. AegisGate Lens is for the 95% of AI users who don't fit that profile — people who use multiple AI tools, paste regulated or proprietary content, need to defend their configuration to a security review, and want zero-telemetry warnings before they hit send. It's a complement, not a replacement.

## Installation

1. **Chrome Web Store:** submission is **pending**. We are completing the CWS review process and expect the extension to be publicly available within 1–3 business days of submission. *(This line is a placeholder during the v0.1.0-beta pre-launch window; remove once the listing is live.)*
2. **Manual install (developer / power-user):** download the latest release: `lens-0.1.0-lens-sr.zip` from the [Releases page](https://github.com/aegisgatesecurity/aegisgate-lens/releases)
3. Open `chrome://extensions/` in Chrome 116+
4. Enable **Developer mode** (top right)
5. Click **Load unpacked** and select the extracted folder
6. Navigate to any supported AI chat tool and start typing

For source builds, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security & Privacy

- **Privacy policy:** [docs/PRIVACY-POLICY.md](./docs/PRIVACY-POLICY.md) — the 12 non-negotiables
- **Security policy:** [SECURITY.md](./SECURITY.md) — how to report vulnerabilities
- **Threat model:** [docs/THREAT-MODEL.md](./docs/THREAT-MODEL.md) — STRIDE-based, 9.5/10
- **No external dependencies:** [docs/NO-EXTERNAL-DEPS.md](./docs/NO-EXTERNAL-DEPS.md) — zero npm, zero node_modules
- **Build provenance:** SLSA L2 + Ed25519 bundle signing + Sigstore + Rekor

## Pricing

**AegisGate Lens is free. Forever. No "Teams" tier, no "Business" tier.**

It is the **top of the funnel (TOFU)** for the paid AegisGate Platform (the server-side enterprise gateway, $29–$499+/mo). When your team needs server-side enforcement, custom patterns, audit logging, or SSO, you upgrade to Platform — but the Lens is always free for individuals and small teams.

See the [in-product CTA](#how-it-works) or visit [aegisgatesecurity.io/platform](https://aegisgatesecurity.io/platform) for pricing details.

## Roadmap

- **v0.1.0-beta** (this release) — 4-facet regex, 8 providers, Chrome 116+
- **v0.2.0-beta** (Q3 2026) — TinyML for context-aware FPR reduction (target: <2% FPR), Firefox/Edge support
- **v0.3.0+** (Q4 2026+) — Custom user patterns, export detection history, whitelist/blacklist per provider

## License

Copyright © 2024-2026 AegisGate Security, LLC. Apache 2.0. See [LICENSE](./LICENSE).

For commercial support, enterprise deployment, or to report a vulnerability, see [SECURITY.md](./SECURITY.md).


---

<div align="center">

**AegisGate Security, LLC** — [aegisgatesecurity.io](https://aegisgatesecurity.io)  
Built with 🖤 by security professionals, for security professionals.

</div>
