# AegisGate Lens — FACTS

**Version**: 0.1.3 (v0.1.3 branch at 122608c, on origin — 28 v0.1.4 commits on this branch)
**Last updated**: 2026-07-13 (28 v0.1.4 commits: prior session's polish + this session's Bug #4 chain)
**Status**: Shipped to CWS (re-submitted 2026-07-10, awaiting review; expected 2026-07-13)
**Audience**: Maintainers, contributors, marketing copy writers, and anyone writing about AegisGate Lens

---

## Purpose

This document is the **single source of truth** for all verifiable claims about AegisGate Lens. The Hugo homepage (`/lens/`), the GitHub README.md, the GitHub repo description, the CWS listing, and any other marketing or documentation surface **MUST** use the numbers in this document.

If a number changes (e.g., a new version adds a new pattern), update this file FIRST, then propagate to all surfaces.

---

## 1. Version

- **Current version**: v0.1.3
- **Manifest version**: 0.1.0 (the manifest.json `version` field is the CWS-required semver, which is the MAJOR.MINOR of the marketing version. v0.1.3 is the third iteration of v0.1.0)
- **Branch**: v0.1.3
- **Latest commit**: 122608c (LOCAL ONLY, NOT pushed — CWS review pending)

---

## 2. AI Provider Support

AegisGate Lens protects **8 AI providers**:

| ID | Name | Hosts |
|----|------|-------|
| chatgpt | ChatGPT | chat.openai.com, chatgpt.com |
| claude | Claude | claude.ai |
| gemini | Gemini | gemini.google.com |
| copilot | Microsoft Copilot | copilot.microsoft.com, copilot.cloud.microsoft |
| perplexity | Perplexity | perplexity.ai, www.perplexity.ai |
| duck_ai | DuckDuckGo (Duck.ai) | duck.ai |
| grok | Grok | grok.com, www.grok.com |
| mistral | Mistral Le Chat | chat.mistral.ai, le-chat.mistral.ai |

Total: **8 providers** across 13 host entries (some providers have www variants and main + subdomain variants).

**Source of truth**: `src/util/selectors.js` (the `PROVIDERS` object that the content script uses to identify providers at runtime). The `manifest.json` `content_scripts.matches` array must match this list.

---

## 3. Detection Facets

AegisGate Lens ships with **4 active detection facets**. 2 more facets (Toxicity, Prompt-Injection) are reserved in the schema for v0.2.0.

| Facet | Categories | Patterns | Description |
|-------|-----------|----------|-------------|
| PII | 54 | 55 | Email, phone, SSN, credit card, DOB, address, DL, passport, tax ID, bank account, IP |
| Secrets | 41 | 41 | API keys (AWS, GitHub, OpenAI, Stripe, Slack), OAuth tokens, RSA private keys |
| XSS | 11 | 12 | Cross-site scripting payloads |
| Compliance | 29 | 24 | OWASP LLM Top 10 (5/10), MITRE ATLAS, EU AI Act, NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA |
| **Total** | **135 categories** | **132 patterns** | — |

**Notes**:
- The pattern count is the number of `re: /.../` entries in the regex files
- The category count is the number of entries in the schema's facet arrays
- 2 more facets (toxicity, prompt-injection) are planned for v0.2.0

**Source of truth**:
- Patterns: `src/detectors/regex/*.js` (count the `re: /` entries)
- Categories: `src/privacy/schema.js` (count the entries in each facet array)

---

## 4. Test Coverage

- **Node unit tests**: 500/500 PASS (Lesson #119: default `--test-isolation=process`)
- **Go unit tests**: 3/3 PASS
- **Headless smoke tests**: 16/16 PASS (in real Chrome 150, via CDP)
- **Headless mini-smoke tests**: 128/128 PASS (extended flows: per-host routing, dismiss flow, F-7 e2e)
- **Smoke stability (Lesson #113)**: 5/5 runs 16/16, gate=true, ec=0
- **Platform FPR test**: 2.31% on 6,500 WildChat prompts (better than the 2.43% v0.1.2 baseline)
- **Total automated tests**: 500 (Node) + 3 (Go) + 16 (smoke) + 128 (mini-smoke) = 647

**Source of truth**: `docs/METRICS-v0.1.2.md` (the metrics doc) and the GitHub Actions CI workflow output.

---

## 5. Detection Performance

- **FPR (WildChat, 6,500 prompts)**: **2.31%** (150 false positives)
- **FPR (v0.1.0-beta baseline)**: 12.49% (812/6500)
- **FPR (v0.1.2 baseline)**: 2.43% (158/6500)
- **FPR reduction (v0.1.0-beta → v0.1.3)**: **5.1×**
- **FPR must-not-trigger (per-pattern corpus, 119 entries)**: 0/119 (100% clean)
- **Detection latency (avg)**: 0.34 ms
- **Detection latency (p50)**: 0 ms
- **Detection latency (p95)**: 1 ms
- **Detection latency (p99)**: 1 ms
- **Detection latency (p99.9)**: 9 ms (with warmup)
- **Throughput**: 5,348 prompts/sec

**Source of truth**: `docs/METRICS-v0.1.2.md` (the canonical metrics doc).

---

## 6. Privacy and Security

- **12 Privacy Non-Negotiables**: No prompt text, no URLs, no page content, no personal identifiers, no account credentials, no browser fingerprinting, no cross-site tracking, no AI provider metadata, no keystroke timing, no mouse movement, no session identifiers, no IP addresses (when self-hosted)
- **Detection**: 100% on-device (no network calls for default detection)
- **Opt-in telemetry**: Hashed metadata only (detection category, pattern ID, domain hash). No prompt text. No URLs. No page content.
- **License**: Apache 2.0
- **Zero external dependencies**: No npm, no node_modules, no bundled libraries
- **Content Security Policy (CSP)**: Strict MV3 CSP (no inline scripts, no remote code, no eval)
- **Commit signing**: Ed25519 SSH keys on all commits
- **Vulnerability disclosure**: RFC 9116 compliant, contact `security@aegisgatesecurity.io`

---

## 7. Repository

- **GitHub**: `aegisgatesecurity/aegisgate-lens`
- **Branch (locked)**: v0.1.3
- **main (locked)**: cb6412b (revert of v0.1.3 #32; frozen for CWS review)
- **CWS submission**: `lens-0.1.0-lens-sr.zip` (SHA-256 25c62b96...)
- **CWS Item ID**: emolejlnnnhcdeinpgcjdlldnmgfjmde
- **CWS status**: v0.1.2 re-submitted 2026-07-10, awaiting review (24-72h window; expected approval 2026-07-13). Verify at CWS Developer Dashboard with Item ID emolejlnnnhcdeinpgcjdlldnmgfjmde.

---

## 8. Roadmap (v0.2.0)

The next major release (v0.2.0) will add:

1. **2 missing detection facets**: Toxicity + Prompt-Injection
2. **TinyML model** (1-2MB transformer) for ambiguous cases
3. **Firefox/Edge support**
4. **Public benchmark dataset release**
5. **Third-party security audit** (Cure53 / Trail of Bits / NCC Group)
6. **Marketing site refresh** (aegisgatesecurity.io/lens/)
7. **Lighthouse CI integration**

---

## 9. Quick Reference Card

**Performance baseline (v0.1.4)**: p50=0.08ms (500 chars), p99=0.36ms (2000 chars), p99=1.37ms (10k chars). Benchmark at `tools/bench/run-benchmark.js`. See `test/benchmarks/results/v0.1.4-baseline.json`.



Use this card for quick copy/paste into other surfaces:

```
AegisGate Lens v0.1.4
- 8 AI providers (ChatGPT, Claude, Gemini, Copilot, DuckDuckGo, Perplexity, Mistral, Grok)
- 132 regex patterns across 4 detection facets (PII=55, secrets=41, XSS=12, compliance=24)
- 500/500 Node tests + 3/3 Go tests + 16/16 headless smoke in real Chrome (5/5 runs, Lesson #113)
- 2.31% FPR on 6,500 WildChat prompts (5.1x better than v0.1.0-beta baseline)
- Sub-millisecond detection (avg 0.34ms; p99 0.36ms for 2000 chars, p99 1.37ms for 10k chars)
- 100% on-device, zero network egress by default
- 12 privacy non-negotiables, Apache 2.0, zero external dependencies
- $0 (free, forever)
```

v0.1.4 features (28 v0.1.4 commits on v0.1.3 branch):
- "🛡️ Lens active" indicator on every AI chat (click → opens popup, Bug #4)
- Hide indicator toggle (G1)
- "Not PII" dismiss button (G5)
- Pause 1h / 1d buttons (G2)
- 8th provider mock (Perplexity fix)
- Mini-smoke 128-test binary (per-host routing, dismiss flow)
- Lightweight shell linter (12 checks, no npm)
- 3-job split in smoke.yml CI
- Performance baseline benchmark (p50/p99/p99.9)
- v0.2.0 prep docs (Firefox/Edge, ML kept out per Lesson #99)

---

## How to update this file

1. **Change a number**: update the relevant section, update the "Last updated" date, and propagate to all surfaces (homepage, README, CWS listing, etc.)
2. **Add a new fact**: add a new section, update the Quick Reference Card if applicable
3. **Remove a fact**: don't — the marketing surfaces may still reference it. Mark as deprecated instead.

## Surfaces that must stay in sync with this file

| Surface | Path | Update method |
|---------|------|---------------|
| Hugo homepage | `websites/aegisgate-site/content/lens/_index.md` | Manual edit |
| Hugo compare | `websites/aegisgate-site/content/lens/compare.md` | Manual edit |
| Hugo architecture | `websites/aegisgate-site/content/lens/architecture.md` | Manual edit |
| Hugo changelog | `websites/aegisgate-site/content/lens/changelog.md` | Manual edit |
| Hugo privacy | `websites/aegisgate-site/content/lens/privacy.md` | Manual edit |
| Hugo security | `websites/aegisgate-site/content/lens/security.md` | Manual edit |
| GitHub README | `aegisgate-lens/README.md` | Manual edit |
| GitHub repo description | GitHub repo Settings → About | Manual edit |
| CWS listing | `.plans/AEGISGATE-LENS-CHROME-STORE-LISTING.md` | Manual edit |
| Chrome Web Store | CWS Developer Dashboard | Manual edit (copy/paste) |

**Future improvement (v0.2.0)**: automate the sync via a build-time template (e.g., Hugo template that reads from a JSON file generated from this doc).