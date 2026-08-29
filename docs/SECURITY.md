# AegisGate Lens — Security Policy

**Version**: v0.3.2
**Last updated**: 2026-08-17
**Contact**: `security@aegisgatesecurity.io` (PGP key below)
**Disclosure timeline**: We acknowledge within 3 business days,
triage within 7, and aim to fix critical issues within 30 days.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x (current) | ✅ Active |
| 0.2.x | ⚠️ Security fixes only |
| 0.1.x | ❌ Replaced by 0.2.x |
| 0.0.x | ❌ Never released publicly |

We do not backport security fixes to unsupported versions. Please
upgrade to the latest 0.3.x release.

## How to report a vulnerability

**Email**: `security@aegisgatesecurity.io`
**X/Twitter**: [https://x.com/aegisgate](https://x.com/aegisgate)
**Mastodon**: [https://mastodon.social/@aegisgate](https://mastodon.social/@aegisgate)
**PGP key**: see `aegisgatesecurity.io/.well-known/security.txt`
  (per RFC 9116)
**Subject line prefix**: `[Lens Security]`

Please include:
- A clear description of the vulnerability
- Steps to reproduce (or a working PoC)
- The Lens version affected
- The expected impact

**Do not** file a public GitHub issue for security vulnerabilities.
We will work with you on coordinated disclosure.

## Threat model

See `docs/THREAT-MODEL.md` for the formal STRIDE-based threat model.
Summary:

- **In scope**: prompt content, banner UX, opt-in telemetry,
  ML inference pipeline
- **Out of scope**: the AI provider websites themselves
  (Lens is a passive observer, not a Man-in-the-Middle)
- **Threat actors**: malicious AI providers (e.g., a compromised
  ChatGPT that exfiltrates user prompts), malicious browser
  extensions (Lens uses sender-id validation to reject
  messages from foreign extensions), network attackers
  (Lens has no network requests in the default config)

## Security posture (v0.3.0)

- **Manifest V3** with strict CSP (`script-src 'self'; object-src 'self'`)
- **Zero npm dependencies** (per `CONTRIBUTING.md` rule)
- **Zero WASM binaries** (removed in v0.3.0; pure JS inference)
- **No `eval()`, no `Function()`, no `wasm-unsafe-eval`, no inline event handlers**
- **ML inference is pure JavaScript** — no onnxruntime, no WASM,
  no external runtime. Model weights are float16 JSON loaded via
  `fetch(chrome.runtime.getURL())` and decompressed with the
  browser's built-in `DecompressionStream`.
- **Sender-id validation** in the service worker (F-01)
- **Domain hashing** (F-12) for opt-in telemetry
- **Schema-validated** service worker payloads
- **SLSA L2** build provenance (build is in the Platform
  build pipeline, signed with Ed25519)
- **No remote code** of any kind
- **Lazy model loading** — 3.7MB model weights are not fetched
  until the first `classify()` call; no network request on page load

## ML security considerations

The ML threat detector (Char CNN-BiLSTM with Attention) introduces
new attack surfaces that did not exist in the regex-only v0.2.0:

1. **Model extraction**: The model weights are bundled in the
   extension package. A sophisticated attacker could extract the
   weights from the ZIP and reconstruct the model. This is
   acceptable because (a) the model is a binary classifier with
   limited adversarial value, and (b) the model does not learn
   from user input — it is a fixed, pre-trained model.
2. **Adversarial evasion**: An attacker who knows the model
   architecture could craft inputs that evade detection. This is
   mitigated by the dual detection system (regex + ML) — evading
   both requires different techniques.
3. **Model poisoning**: Not applicable — the model is bundled at
   build time and cannot be updated remotely. There is no model
   update mechanism.
4. **Side-channel timing**: The ML inference takes a measurable
   amount of time (~5-50ms in Chrome). A malicious page script
   could potentially infer whether ML detection triggered by
   measuring timing. This is acceptable because the banner is
   already visible to the user — there is no secret to protect
   from timing.

## A11Y security

See `docs/A11Y-AUDIT-v0.1.3.md`. The A11Y audit also covers
security-adjacent concerns like focus management (which prevents
clickjacking-style attacks via the banner UI).

## Compliance

- **SOC 2**: out of scope (Lens is consumer-only; Platform is SOC 2)
- **HIPAA**: applicable in spirit (no PHI handling, but the
  privacy posture is HIPAA-compatible)
- **GDPR**: applicable (no personal data collection by default)
- **EU AI Act**: out of scope for the consumer Lens; the
  AegisGate Platform has the EU AI Act Compliance Module

## Security history

- **2026-08-05**: v0.3.0 — ML threat detector added (pure JS,
  no WASM). DeepSeek and Meta AI providers added. WASM/ONNX
  removed. CSP simplified to `script-src 'self'` only.
  Lazy model loading implemented. 504 tests.
- **2026-07-09**: v0.2.0 — 11 F-findings fixed.
- **2026-07-05**: 5 CI infrastructure fixes shipped.
- **2026-07-05**: A11Y audit (32 findings addressed).
- **2026-06-28**: v0.2 ML cascade burned down (no remote
  model inference — architectural privacy improvement).
- **Earlier**: see `git log` for the full history.

## Bug bounty

We do not currently have a paid bug bounty program. We do credit
researchers in the release notes (with permission) and ship a
reproduction test case as a regression guard.

## See also

- `docs/THREAT-MODEL.md` — the formal STRIDE threat model
- `docs/A11Y-AUDIT-v0.1.3.md` — accessibility audit
  (includes focus management, the prime clickjacking vector)
- `docs/MODEL-CARD.md` — ML model card (architecture, evaluation,
  limitations, ethical considerations)
- `docs/NO-EXTERNAL-DEPS.md` — the zero-dependency policy
- `CONTRIBUTING.md` — the no-npm rule (privacy guarantee)
- `aegisgatesecurity.io/.well-known/security.txt` — RFC 9116