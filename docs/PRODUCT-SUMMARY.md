# AegisGate Lens — Product Summary

**Version**: v0.3.1
**Last updated**: 2026-08-17
**Audience**: External readers who want a definitive description of
what AegisGate Lens is and isn't.

## What is AegisGate Lens?

AegisGate Lens is a **free, privacy-first Chrome extension** that
detects sensitive content — PII, credentials, XSS payloads,
compliance-relevant language, and adversarial prompt injections —
in real time as you type into consumer AI chat tools. When a match
fires, a banner appears at the top of the page with the category,
severity, and your options (Cancel / Edit & Redact / Send Anyway /
False Positive).

Lens runs **100% in your browser**. Your prompt never leaves your
device. There is no server round-trip, no remote ML inference,
no prompt content logged anywhere, no accounts, no telemetry by
default.

## What it catches

Lens scans your prompt across five detection facets — four regex
(synchronous, ~0.3ms) and one ML (asynchronous, ~5-50ms in Chrome):

1. **Personal data** (69 patterns) — government-issued IDs, contact
   information, financial account numbers, and biometric identifiers.
   Coverage includes the US, EU, UK, Canada, Australia, Brazil, and
   India. Structural validation: Luhn for cards, IBAN mod-97, BIP39
   wordlist for seed phrases.
2. **Credentials and tokens** (41 patterns) — access keys for cloud
   infrastructure, source-control platforms, payment services,
   team-messaging tools, and email-delivery providers, plus OAuth
   and JWT tokens and PEM private keys.
3. **Source-code risks** (12 patterns) — script injection, event
   handler abuse, dangerous URL schemes, mutation XSS patterns,
   and SVG-based payloads.
4. **Compliance-relevant language** (43 patterns) — references to
   frameworks that an enterprise security team needs to flag for
   review: the OWASP LLM Top 10 risk categories, MITRE ATLAS
   adversary techniques, articles of the EU AI Act, and parallel
   frameworks for Brazil, the UK, and other jurisdictions.
5. **ML adversarial detection** (1 model) — a Char CNN-BiLSTM with
   Attention (1.58M parameters) that detects prompt injection
   attacks including instruction override, roleplay injection, and
   obfuscated commands. Pure JavaScript inference, no WASM, no
   remote server. Runs asynchronously ~5-50ms after the regex
   detection, providing defense-in-depth.

**Total: 155 regex patterns + 1 ML model.**

## How it works

1. You type into a supported AI chat tool.
2. After a 250 ms debounce, the content script runs the four-facet
   regex detector (synchronous, ~0.3ms).
3. Simultaneously, the ML detector runs asynchronously (~5-50ms).
4. If a match fires, a brand-matched banner appears at the top of
   the page showing the category, severity, and a masked value
   (e.g., "SSN: 123-…6789" or "ML: adversarial prompt detected").
5. You choose: Cancel send / Edit & Redact / Send Anyway / This is
   a false positive.
6. Nothing leaves your browser.

## Where it works

Lens supports 10 consumer AI chat tools (10 host patterns in the
manifest):

- ChatGPT (chat.openai.com, chatgpt.com)
- Claude (claude.ai)
- Gemini (gemini.google.com)
- Microsoft Copilot (copilot.microsoft.com, copilot.cloud.microsoft)
- Perplexity (perplexity.ai, www.perplexity.ai)
- Mistral (chat.mistral.ai, le-chat.mistral.ai)
- DuckDuckGo AI (duck.ai)
- Grok (grok.com, www.grok.com)
- **DeepSeek (chat.deepseek.com)** — *new in v0.3.0*
- **Meta AI (meta.ai)** — *new in v0.3.0*

## What it does NOT do

- **No prompt text on wire.** Architectural: there is no `fetch()`
  call to any origin in the content script.
- **No server round-trip** for detection. Both regex and ML run
  in-browser.
- **No ML inference on a remote server.** The model weights are
  bundled in the extension package; inference runs in JavaScript.
- **No prompt content logged anywhere.** The schema forbids it
  in the service worker payload.
- **No URLs or page content sent.** The opt-in FP report is
  domain-hashed (SHA-256 truncated to 16 hex chars) and
  category-only.
- **No accounts, no sign-in, no email capture.**
- **No analytics SDK, no cookies, no fingerprinting.**
- **No A/B testing, no crash reporting, no remote config.**
- **No npm dependencies.** Zero third-party runtime code. The
  build tool is a Go program in a separate monorepo.
- **No WASM binaries.** Removed in v0.3.0. Pure JS inference.

## What's new in v0.3.0

- **ML threat detector** — Char CNN-BiLSTM with Attention, pure JS
  inference, detects adversarial prompt injections (instruction
  override, roleplay injection, obfuscated commands). 100%
  adversarial detection rate on v0.3.0 test set.
- **DeepSeek + Meta AI** — two new AI provider integrations (10 total).
- **6× smaller extension** — reduced from 25MB (WASM) to 4.2MB (pure JS).
- **Stricter CSP** — `script-src 'self'` only, no `wasm-unsafe-eval`.
- **504 tests** — 492 unit + 12 ML perf/stress.
- **Lazy model loading** — 3.7MB model weights loaded on first
  `classify()` call, not on page load.

## For enterprise teams

AegisGate Lens is the consumer-facing layer. The same team builds
[AegisGate Platform](https://aegisgatesecurity.io/) — the
server-side enterprise gateway that adds central policy management,
team-wide analytics, MCP/A2A/ACP/RESPONSE protection, the Trust
Framework, MITRE ATLAS enforcement, OWASP LLM Top-10, the EU AI
Act Compliance Module, and SIEM export.

| Use case | Recommendation |
|---|---|
| Individual developers, security researchers, journalists, privacy-conscious users | **Lens alone** (free) |
| Teams of 2-10 who need a shared detection policy | **Lens + Platform Starter** ($29/mo) |
| Enterprises needing SIEM, compliance modules, central policy | **Platform Professional or Enterprise** (custom) |

## Where to go next

- **Install**: see the [README](../README.md) for the Chrome Web Store
  link
- **Source code**: <https://github.com/aegisgatesecurity/aegisgate-lens>
- **Privacy policy**: `docs/PRIVACY-POLICY.md`
- **Security model**: `docs/THREAT-MODEL.md`
- **ML model card**: `docs/MODEL-CARD.md`
- **Architecture**: `docs/ARCHITECTURE-v0.1.3.md`
- **Bundle API**: `docs/API.md`
- **A11Y audit**: `docs/A11Y-AUDIT-v0.1.3.md`
- **Comparison vs Platform**: see the marketing site
  (`aegisgatesecurity.io/lens/compare/`)