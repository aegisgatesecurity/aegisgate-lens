# AegisGate Lens

> **Privacy-first browser extension that warns you in real time — before you hit send — when your prompt to ChatGPT, Claude, Gemini, Copilot, Perplexity, Duck.ai, Grok, or Mistral contains PII, secrets, source-code risks, or compliance-relevant language.**

**Version:** v0.1.0-beta
**License:** Apache 2.0
**Pricing:** **Free. Forever. No accounts, no telemetry by default, no prompt content ever leaves your device.**

---

## What It Does

AegisGate Lens runs entirely in your browser. It watches what you type into 8 major AI chat tools and, when it detects sensitive content, shows a top-of-screen banner before you send the prompt.

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
| **Unit tests** | **325/325 passing** | 11 .mjs test files in `test/unit/` |
| **Patterns** | **120 total** | 54 PII + 41 Secrets + 12 XSS + 24 Compliance |
| **Providers** | **8** | chatgpt, claude, gemini, copilot, perplexity, duck_ai, grok, mistral |
| **Build size** | 1.13 MB | `lens-0.1.0-lens-sr.zip` |

**Benchmark methodology:** 100K-record public corpus (5 PII sources, 3 benign sources, all license-clean: CC-BY-4.0 / MIT / Apache-2.0). See `test/benchmarks/BENCHMARK-PLAN.md` for the full Methodology C specification. The 5,930 "in-target" records are PII records whose categories the detector was designed to catch (SSN, email, phone, credit card, passport, driver's license, IBAN, etc.). The 30,000 "benign" records are real user prompts from OASST1 and ultrachat. Numbers are honest: 99% recall on records the detector targets, 7.40% FPR on real prompts.

## Privacy Architecture

The Lens is the only AI security tool that **cannot see your prompt even if it wanted to**. The detection runs in your browser via JavaScript regex. No prompt content, no value, no category text is sent to AegisGate servers.

**What the Lens does NOT do:**
- See your prompt content (only pattern matches)
- Track which AI you use, when, or how often
- Log your conversations
- Phone home with your data
- Require an account

**What the Lens DOES do:**
- Run 4 regex facets on every keystroke (sub-1ms p99)
- Show a banner when it detects sensitive content
- Let you Cancel, Edit & Redact, or Send Anyway
- Work offline (no network required)

**Opt-in telemetry (off by default):** If you choose to share false-positive reports, only metadata is sent: hashed domain + category + severity + action. No values, no prompt text.

## Providers (8)

- [ChatGPT](https://chatgpt.com) and [chat.openai.com](https://chat.openai.com)
- [Claude](https://claude.ai)
- [Gemini](https://gemini.google.com)
- [Microsoft Copilot](https://copilot.microsoft.com)
- [Perplexity](https://perplexity.ai)
- [Duck.ai](https://duck.ai)
- [Grok](https://grok.com)
- [Mistral Le Chat](https://chat.mistral.ai)

## Detection Facets

| Facet | Patterns | Severity levels |
|---|---|---|
| **PII** | 54 | SSN, email, phone, credit card, DOB, address, passport, driver's license, IBAN, Aadhaar, NHS, TFN, SIN, CPF, international passports (UK/EU/CA/AU/DE/FR/ES/IT/JP), national IDs, crypto wallets (BTC/ETH/BNB/LTC/SOL), digital payment (PayPal/Stripe/Venmo/CashApp), residence permits, visas |
| **Secrets** | 41 | AWS, GitHub PAT, GCP, Azure, JWT, Stripe, Slack, OpenAI, Anthropic, CI tokens, cloud tokens, OAuth, PEM, API keys, DB connections |
| **Source/XSS** | 12 | `<script>`, event handlers, `javascript:` URLs, `data:text/html`, SVG with onload, DOM clobbering, mutation XSS, polyglot |
| **Compliance** | 24 | OWASP LLM Top 10 (LLM01/04/08/09/10), MITRE ATLAS, EU AI Act (Art 5/15), ANP, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA, toxicity reference |

## Security Posture

13 STRIDE findings in the threat model: 11 resolved, 1 residual (F-12 telemetry metadata), 1 accepted (F-07 public bundle by design). Combined trust score 9.5/10.

- **Ed25519 bundle signing**
- **SLSA L2 release provenance**
- **Strict CSP** — no `eval()`, no `new Function()`, no `setTimeout(string, ...)`, no inline event handlers
- **F-01 sender-ID validation** in the service worker (rejects messages from foreign extensions)
- **No npm / no node_modules** — single-binary extension, vendored deps only
- **Apache 2.0** license

See `docs/THREAT-MODEL.md` and `plans/AEGISGATE-LENS-THREAT-MODEL.md` for the full threat model.

## Installation

### From Chrome Web Store
*(link coming — submission in progress)*

### From source (developer mode)
1. Clone the repo
2. Open `chrome://extensions/` in Chrome 116+
3. Enable Developer Mode (top right)
4. Click "Load unpacked"
5. Select `/path/to/aegisgate-lens/src/`
6. Visit any of the 8 supported providers and start typing

## Testing

```bash
# Unit tests
cd aegisgate-lens
node --test test/unit/*.test.mjs
# Expected: tests 310, pass 310, fail 0

# Benchmark (private corpus, gitignored)
cd test/benchmarks/corpus
node scripts/bench-v3.js
# Expected: in-target recall ~99%, FPR ~7.4%
```

## Redaction Behavior

When the user clicks **"Edit & redact"** in the banner, the Lens replaces each detected value in the input with `[REDACTED:<category>]` (e.g., `[REDACTED:pii_ssn]`, `[REDACTED:pii_email]`). The replacement is local — the prompt is rewritten in the input field and a synthetic `input` event is dispatched so the provider's framework (React, Vue, etc.) sees the change.

The redaction is **client-side and deterministic**: it uses the same detection events that triggered the banner, processed in reverse index order so positions don't shift. If the input has changed since the banner was shown (the user typed more), the algorithm falls back to a string-replace fallback. If the value can't be found, the field is left alone (the user can edit manually).

Verified: 10/10 dedicated redact tests passing, including a real-world prompt (DOB + phone + email) where all three values are correctly redacted.

## Architecture

```
Browser (Chrome 116+)
├── src/
│   ├── manifest.json           # MV3, no "world": "MAIN"
│   ├── background.js           # SW, F-01 sender-ID, dynamic injection
│   ├── content.js              # Content orchestrator
│   ├── detectors/
│   │   └── regex/
│   │       ├── pii.js          # 54 patterns (4-facet ship state)
│   │       ├── secrets.js      # 41 patterns
│   │       ├── source_xss.js   # 12 patterns
│   │       └── compliance.js   # 24 patterns
│   ├── util/
│   │   ├── banner-ui.js        # PNG logo + Platform CTA + documentElement anchor
│   │   ├── selectors.js        # 8 providers, no rogue entries
│   │   ├── prompt-detect.js    # MutationObserver + 300ms debounce
│   │   ├── logger.js           # Console wrapper with error handling
│   │   └── banner.css          # Brand-matched styles
│   ├── privacy/
│   │   ├── schema.js           # Category definitions
│   │   └── domain_hash.js      # One-way hash for telemetry
│   ├── icons/                  # icon-16/32/48/128.png + logo.png
│   ├── popup/                  # Extension popup with Platform CTA
│   └── welcome/                # First-install welcome page
└── build/                      # Copy of src/ for Chrome load
```

## Pricing (the only place in the world this is true)

**AegisGate Lens is free. Forever.**

| Tier | Price | What it is |
|---|---|---|
| **AegisGate Lens** | **Free** | This extension. No account, no telemetry, no prompt content leaves. |
| AegisGate Platform — Community | Free | Self-hosted single-instance, 6 frameworks |
| AegisGate Platform — Starter | $29/mo | MCP guardrails, basic HTTP scanning |
| AegisGate Platform — Developer | $79/mo | All 5 pillars, AI Proxy, mTLS |
| AegisGate Platform — Professional | $499/mo or $99/seat at 10+ | + HIPAA/PCI/SOC 2/EU AI Act, CISO Digest |
| AegisGate Platform — Enterprise | Custom | + ISO 27001/NIST AI RMF, HSM, FedRAMP, on-prem, CVE-for-AI publishing |

The Lens is the **top of the funnel** for the Platform. The Lens is a public good; the money is in the Platform. See [aegisgatesecurity.io/platform](https://aegisgatesecurity.io/platform) for details.

## Roadmap

### v0.1.0-beta (shipped 2026-07-08) — YOU ARE HERE
- 4-facet regex detector, 120 patterns
- 8 providers, all verified
- Privacy-first architecture, zero prompt content egress
- 99% recall / 7.4% FPR on 100K benchmark
- Sub-1ms detection latency
- 325/325 unit tests passing
- Ed25519 signed, SLSA L2, strict CSP

### v0.2.0-beta (planned, 2-3 weeks)
- TinyML model (DistilBERT-tiny, INT8 quantized) for context-aware FPR reduction
- Target: 99% recall, <2% FPR
- Firefox + Edge support (1:1 port from Chrome, since Edge is Chromium-based)
- Adversarial red-team test set (~500 records)

### v0.3.0+ (future)
- Safari support
- Custom user-defined patterns
- On-device threat intelligence feed (opt-in)
- Zero-knowledge proof for detection telemetry

## Repository

- **Source code:** `src/` (12 files, 9,945 lines)
- **Tests:** `test/unit/` (9 .mjs files, 325 tests)
- **Benchmark:** `test/benchmarks/` (private, gitignored)
- **Docs:** `docs/` and `plans/` (AegisGate Lens architecture, threat model, standing rules)

## Standing Rules

This project follows 100+ standing rules codified from 32+ days of painful lessons. See `plans/AEGISGATE-LENS-STANDING-RULES-2026-06-29.md`. The key rules:

- No npm dependencies
- No server-side components (kills privacy moat)
- Strict CSP (no eval, no inline event handlers)
- Verifiable builds (Ed25519 signed, SLSA L2)
- All test claims must be reproducible

## License

Apache 2.0. See [LICENSE](LICENSE).

Copyright 2024-2026 AegisGate Security.
