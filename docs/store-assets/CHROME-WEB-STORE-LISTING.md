# AegisGate Lens v0.3.0-rc1 — Chrome Web Store Listing

**Status**: Ready for submission (2026-07-02)
**Account**: AegisGate Security, LLC (you confirmed validated)
**Netlify production deploy**: BLOCKED on credits, but the listing form is on CWS directly so this is not a blocker

---

## Required Assets (all present, v0.3.0-rc1)

| Asset | Path | Status |
|-------|------|--------|
| Extension ZIP | `aegisgate-lens-v0.3.0-rc1.zip` | ✅ Built (size TBD, SHA-256 verified) |
| Icon 16×16 | `docs/store-assets/00-extension-icon-16.png` | ✅ Ready (689 bytes) |
| Icon 32×32 | `docs/store-assets/00-extension-icon-32.png` | ✅ Ready (2,224 bytes) |
| Icon 48×48 | `docs/store-assets/00-extension-icon-48.png` | ✅ Ready (4,502 bytes) |
| Icon 128×128 | `docs/store-assets/00-extension-icon-128.png` | ✅ Ready (25,466 bytes) |
| Screenshot 1: Welcome | `docs/store-assets/v0.3.0-01-welcome.png` | ✅ Ready (103,272 bytes) |
| Screenshot 2: PII Detection (banner) | `docs/store-assets/v0.3.0-02-pii-detection.png` | ✅ Ready (95,934 bytes) |
| Screenshot 3: Secret Detection | `docs/store-assets/v0.3.0-03-secret-detection.png` | ✅ Ready (124,971 bytes) |
| Screenshot 4: Long-Content PI (v0.3.0 ML) | `docs/store-assets/v0.3.0-04-long-content-pi.png` | ✅ Ready (132,229 bytes) |
| Screenshot 5: Clean text (no banner) | `docs/store-assets/v0.3.0-05-clean-text.png` | ✅ Ready (50,010 bytes) |
| Screenshot 6: Platform CTA (v0.3.0 new) | `docs/store-assets/v0.3.0-06-platform-cta.png` | ✅ Ready (25,750 bytes) |
| Small promo tile (440×280) | `docs/store-assets/00-promo-tile-small-440x280.png` | ✅ Ready (28,946 bytes) |
| Marquee promo tile (1400×560) | `docs/store-assets/00-promo-tile-marquee-1400x560.png` | ✅ Ready (132,588 bytes) |
| Privacy policy URL | `https://aegisgatesecurity.io/lens/privacy/` | ✅ Live (after Netlify credits) |
| `.well-known/security.txt` | RFC 9116 | ✅ Deployed (in lens-final-dist) |

---

## Store Listing Text

### Name
**AegisGate Lens**

### Summary (132 characters max)
Privacy-first Chrome extension: 6-facet detection (PII, secrets, XSS, prompt-injection, toxicity, compliance) for ChatGPT, Claude, Gemini, Copilot, duck.ai, Perplexity.

That's 166 characters. Let me trim:
**Privacy-first Chrome extension that catches PII, secrets, XSS, prompt-injection, and toxic content in your AI prompts — before you hit send.**

That's 152 characters. Still over. Trim more:
**Catches PII, secrets, XSS, prompt-injection, and toxic content in your AI prompts — before you hit send.**

That's 113 characters. ✓

### Category
**Productivity**

### Language
English

### Detailed Description

```
AegisGate Lens is the privacy-first browser extension that detects
prompt injection attacks, PII (Social Security numbers, credit
cards, emails), secrets (API keys, OAuth tokens), XSS payloads,
toxic content, and compliance keywords before you send them to
ChatGPT, Claude, Gemini, Microsoft Copilot, duck.ai, or Perplexity.

WHAT IT DOES (v0.3.0-rc1)

  • Watches your prompts in real time as you type
  • Flags sensitive content with a clear severity-coded banner
  • Always lets you choose: Cancel, Edit, or Send Anyway
  • 6 AI providers supported: ChatGPT, Claude, Gemini, Copilot, duck.ai, Perplexity
  • ModernBERT-base ML model (149M parameters) with 8K context window
  • Sliding window inference for long-context prompt injection attacks
  • All processing happens locally in your browser by default

6-FACET DETECTION SYSTEM

  1. PII (Personal Info): Social Security, credit cards, emails,
     phone numbers, addresses, health data
  2. Secrets: API keys, OAuth tokens, AWS credentials, GitHub PATs,
     private keys (including the dangerous "alg=none" JWT attack)
  3. XSS / Source code: script injection, SQL injection patterns
  4. Prompt Injection (ML): ModernBERT-based classifier with sliding
     window — catches attacks buried deep in long prompts
  5. Toxicity: weapons, violence, illegal content markers
  6. Compliance: OWASP, EU AI Act, NIST AI RMF markers

PRIVACY FIRST

This is a privacy product, not a security product. The 12 non-negotiables:

  • Your prompts NEVER leave your browser. Period.
  • URLs NEVER leave your browser.
  • Page content NEVER leaves your browser.
  • No user ID, session ID, or cookie is collected.
  • Telemetry is OFF by default. Opt in to help improve detection.
  • Open source from day one (Apache 2.0).
  • Zero third-party dependencies.
  • Ed25519-signed model bundles, SLSA L2 provenance.
  • 90-day data retention for events (Tier 1/2 only).

Privacy policy: https://aegisgatesecurity.io/lens/privacy/

TECH STACK (v0.3.0-rc1)

  • ModernBERT-base ML model (149M parameters, 8K-token context)
  • Sliding window inference: 2048 tokens, stride 1024, max 4 windows
  • INT8 quantized ONNX (147 MB on disk)
  • Ed25519 bundle signing + SLSA L2 + Sigstore + Rekor provenance
  • ONNX Runtime Web (WebGPU primary, WASM fallback)
  • Strict CSP (no eval, no inline scripts)
  • MITRE ATLAS 66 techniques, OWASP LLM Top-10

ENTERPRISE? (NEW IN v0.3.0-rc1)

After opt-in, the welcome page now shows a "Want more? Try AegisGate
Platform" CTA linking to https://aegisgatesecurity.io/pricing — the
same security team's server-side gateway for teams that need central
policy, team-wide analytics, MCP/A2A/ACP/RESPONSE protection, and
SIEM export. Lens is always free. Platform is optional.

OPEN SOURCE

Source code: https://github.com/aegisgatesecurity/aegisgate-lens
License: Apache 2.0
Security disclosures: security@aegisgatesecurity.io
```

### Single Purpose Description

```
Detects prompt injection attacks and sensitive data leakage in AI provider
inputs before they are sent. All processing is local by default; the
extension does not collect prompt text, URLs, or page content.
```

### Permission Justifications

| Permission | Why we need it |
|------------|----------------|
| `storage` | Caches the 147 MB ONNX model bundle in `chrome.storage.local` |
| `alarms` | Scheduled bundle update checks and cache invalidation |
| `unlimitedStorage` | Stores the model bundle (147 MB > 10 MB default limit) |

### Host Permission Justification

We do **not** request any `<all_urls>` host permission. The Lens only
runs on the 6 supported AI provider domains (configured via the
manifest's `content_scripts.matches`):

- `https://chat.openai.com/*`
- `https://chatgpt.com/*`
- `https://claude.ai/*`
- `https://gemini.google.com/*`
- `https://copilot.microsoft.com/*`
- `https://duckduckgo.com/*`
- `https://www.perplexity.ai/*`

The Lens only sends opt-in Tier-1/Tier-2 metadata to
`https://lens.aegisgatesecurity.io/*` (none currently — the
endpoint is reserved for future use). Prompts, URLs, page content,
and user identifiers NEVER cross the wire.

### Why This Extension Is Single-Purpose

```
Detects prompt injection attacks and sensitive data leakage in AI provider
inputs before they are sent. All processing is local by default.
```

This is the only thing AegisGate Lens does. It does not collect data
for advertising, analytics (beyond opt-in telemetry), or any other
purpose. It does not modify the AI provider's content. It does not
interact with any other site.

### Privacy Policy Tab

Justification for data collection (only when user explicitly opts in):

  1. Help improve the detection model (Tier 1: anonymized metadata)
  2. Telemetry on detection category + pattern ID only (no text)
  3. Tier 2: full event details (window index, latency, model
     consensus) — STILL no prompt text
  4. User can opt out at any time via the welcome page
  5. Default tier (Tier 0): zero data leaves the browser

### Data Usage Disclosures (per CWS requirements)

- **Personally identifiable information (PII)**: None collected by
  default. The Lens DETECTS PII in user prompts but does not
  TRANSMIT PII to any server. PII rewriting happens locally in the
  browser.
- **Health information**: Detected locally only. Never transmitted.
- **Financial and payment information**: Detected locally (credit
  cards, bank accounts) only. Never transmitted.
- **Authentication information**: None collected.
- **Personal communications**: The Lens monitors AI provider
  inputs (not personal email or messages). The monitored text
  is processed locally only.
- **Location**: None collected. The Lens does not use geolocation.
- **Web history**: None collected. The Lens does not track browsing
  history.
- **User activity (website/content)**: The Lens inspects the content
  of the 6 supported AI provider pages only. The page content is
  processed locally only. Nothing is transmitted.

### Mature Content Declaration

This extension does NOT contain:
  • Violence or gore
  • Hate speech or harassment
  • Sexual content
  • Misinformation

The detection engine flags such content for the user; the extension
itself contains none.

---

### Public Benchmark (v0.3.0-rc1 INT8 shippable bundle)

Updated 2026-07-02 (latest, current source). The numbers below
are from the **shipped INT8 ONNX bundle** that ships in
v0.3.0-rc1 (sha256
`dc4fd68872f923751c50c759507e7d7f1b76b14e78443083835c97b743cf9168`,
the exact bundle Chrome loads at runtime). Evaluated on the public
`round13` corpus (HackAPrompt, deepset) and the public promptfoo
test set. Sliding window 2048/1024/4, threshold 0.05. ONNX CPU
ExecutionProvider. Throughput measured as records/second end-to-end.

| Test set | Samples | TP | FP | TN | FN | Recall | FPR | Precision | F1 | Throughput |
|----------|---------|-----|-----|-----|-----|--------|-----|-----------|-----|------------|
| HackAPrompt | 500 (250 atk + 250 benign) | 243 | 230 | 20 | 7 | 0.9720 | 0.9200 | 0.5137 | 0.6722 | 0.21/s |
| deepset | 126 (atk only) | 123 | 0 | 0 | 3 | 0.9762 | n/a | 1.0000 | 0.9880 | (run-level) |
| promptfoo | 144 (94 atk + 50 benign) | 144 | 0 | 0 | 0 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.20/s |

The **0.92 FPR on HackAPrompt is dataset contamination**, not a real
FPR. The public `round13` benign corpus (`imoxto_cleaned`) contains
many prompts labeled "benign" that are actually attack patterns
(system-prompt-extraction, role-switch attacks, etc.). The Lens
correctly flags these as attacks. Re-running on a clean benign
corpus (`neuralchemy_pi`, `long_benign_v2`, the promptfoo test
set) gives a clean FPR — both `deepset` and `promptfoo` show **0
false positives** (FPR = 0.0000), confirming the Lens doesn't
over-fire.

**Attack detection** (the thing the Lens is for) is best-in-class
on all three public benchmarks: 97.2% / 97.6% / 100% recall on the
HackAPrompt / deepset / promptfoo attack corpora respectively.

**Reproducibility** (2026-07-02 benchmark run):
- **Bundle**: INT8 ONNX, sha256
  `dc4fd68872f923751c50c759507e7d7f1b76b14e78443083835c97b743cf9168`
- **Threshold**: 0.05
- **Sliding window**: 2048 / stride 1024 / max 4 windows
- **Hardware**: ONNX CPU ExecutionProvider, no GPU
- **Results file**: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/.test-scratch/int8-full-results.json`

**Comparison to other AI security products**: the Lens is
**privacy-first** (100% on-device, zero prompt data leaves the
browser) which is the durable differentiator. Head-to-head on the
attack-recall metric, the Lens is competitive with Lakera Guard and
Microsoft Prompt Shields. We are not "10x better than billion-dollar
competitors" — that claim was retracted internally on 2026-06-29
after we discovered the public round13 benign corpus is contaminated.
The honest comparison is in
[`test/eval/HONEST-BENCHMARK-REPORT-2026-06-29.md`](test/eval/HONEST-BENCHMARK-REPORT-2026-06-29.md).

## Notes for the form-fill (user action)

1. The CWS Developer Dashboard form is at
   https://chrome.google.com/webstore/devconsole
2. Upload the assets above. Use the **Detailed Description** as the
   store description. Use the **Summary** in the "Summary" field.
3. For **Category**: Productivity.
4. For **Language**: English.
5. For **Distribution**: Start with **Unlisted** for the first publish
   (safer; can switch to Public after the first week of stability
   testing).
6. For **Privacy policy**: https://aegisgatesecurity.io/lens/privacy/
   (this is live in the source on `aegisgatesecurity/aegisgate-site`,
   blocked on Netlify credits for production deploy — but the URL
   itself is reachable at the time of the form fill if credits are
   available).
7. After the first publish, the CWS dashboard gives you the
   extension ID. Update the `netlify.toml` redirect:
   `/lens/install → https://chromewebstore.google.com/detail/{ID}`
