# AegisGate Lens — Product Summary

**Version**: v0.1.3
**Last updated**: 2026-07-10
**Audience**: External readers who want a definitive description of
what AegisGate Lens is and isn't. For the Chrome Web Store
submission copy (which has a 16,000-char dashboard field), see
`.plans/AEGISGATE-LENS-CHROME-STORE-LISTING.md`.

## What is AegisGate Lens?

AegisGate Lens is a **free, privacy-first Chrome extension** that
detects sensitive content — PII, credentials, XSS payloads, and
compliance-relevant language — in real time as you type into
consumer AI chat tools. When a match fires, a banner appears at
the top of the page with the category, severity, and your options
(Cancel / Edit & Redact / Send Anyway / False Positive).

Lens runs **100% in your browser**. Your prompt never leaves your
device. There is no server round-trip, no ML inference on a remote
machine, no prompt content logged anywhere, no accounts, no
telemetry by default.

## What it catches

Lens scans your prompt across four categories of risk:

1. **Personal data** — government-issued IDs, contact information,
   financial account numbers, and biometric identifiers. Coverage
   includes the US, EU, UK, Canada, Australia, Brazil, and India.
   Structural validation: Luhn for cards, IBAN mod-97, BIP39
   wordlist for seed phrases.
2. **Credentials and tokens** — access keys for cloud
   infrastructure, source-control platforms, payment services,
   team-messaging tools, and email-delivery providers, plus OAuth
   and JWT tokens and PEM private keys.
3. **Source-code risks** — script injection, event handler abuse,
   dangerous URL schemes, mutation XSS patterns, and SVG-based
   payloads. These are the patterns that would cause an AI tool to
   echo malicious content back to a user.
4. **Compliance-relevant language** — references to frameworks
   that an enterprise security team needs to flag for review:
   the OWASP LLM Top 10 risk categories, MITRE ATLAS adversary
   techniques, articles of the EU AI Act, and parallel frameworks
   for Brazil, the UK, and other jurisdictions. The detector is
   conservative — it flags for human review, it does not adjudicate.

## How it works

1. You type into a supported AI chat tool.
2. After a 250 ms debounce, the content script runs the four-facet
   regex detector.
3. If a match fires, a brand-matched banner appears at the top of
   the page showing the category, severity, and a masked value
   (e.g., "SSN: 123-…6789").
4. You choose: Cancel send / Edit & Redact / Send Anyway / This is
   a false positive.
5. Nothing leaves your browser.

## Where it works

Lens supports 8 consumer AI chat tools (8 host patterns in the
manifest, 1 localhost fallback for the smoke test):

- ChatGPT (chat.openai.com, chatgpt.com)
- Claude (claude.ai)
- Gemini (gemini.google.com)
- Microsoft Copilot (copilot.microsoft.com, copilot.cloud.microsoft)
- Perplexity (perplexity.ai, www.perplexity.ai)
- Mistral (chat.mistral.ai, le-chat.mistral.ai)
- DuckDuckGo AI (duck.ai)
- Grok (grok.com, www.grok.com)

## What it does NOT do

- **No prompt text on wire.** Architectural: there is no `fetch()`
  call to any origin in the content script.
- **No server round-trip** for detection. Detection is in-browser.
- **No ML inference on a remote server.** The detector is
  100% regex.
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

## What's new in v0.1.3

- **405 Node unit tests** + **3 Go unit tests** + **16/16
  headless smoke** in real Chromium 150 (previously 326 + 0 + 6)
- **131 regex patterns** across the 4 facets (previously 120)
- **A11Y audit** completed: 32 findings addressed, WCAG 2.1 AA
  compliance for all static surfaces
- **Lighthouse-style CI integration** for the headless smoke
- **Responsive icon set** for the in-page banner
- **Dismiss flow** end-to-end tested (PII → banner → click
  dismiss → verify hidden → re-type → verify no banner)

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
- **Architecture**: `docs/ARCHITECTURE-v0.1.3.md`
- **Bundle API**: `docs/API.md`
- **A11Y audit**: `docs/A11Y-AUDIT-v0.1.3.md`
- **Comparison vs Platform**: see the marketing site
  (`aegisgatesecurity.io/lens/compare/`)
