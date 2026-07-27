# AegisGate Lens — Security Policy

**Version**: v0.1.3
**Last updated**: 2026-07-10
**Contact**: `security@aegisgatesecurity.io` (PGP key below)
**Disclosure timeline**: We acknowledge within 3 business days,
triage within 7, and aim to fix critical issues within 30 days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (current) | ✅ Active |
| 0.1.0-beta (CWS submission) | ❌ Replaced by 0.1.1 |
| 0.0.x (pre-release) | ❌ Never released publicly |
| 0.2.x (planned) | N/A — not yet released |

We do not backport security fixes to unsupported versions. Please
upgrade to the latest 0.1.x release.

## How to report a vulnerability

**Email**: `security@aegisgatesecurity.io`
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

- **In scope**: prompt content, banner UX, opt-in telemetry
- **Out of scope**: the AI provider websites themselves
  (Lens is a passive observer, not a Man-in-the-Middle)
- **Threat actors**: malicious AI providers (e.g., a compromised
  ChatGPT that exfiltrates user prompts), malicious browser
  extensions (Lens uses sender-id validation to reject
  messages from foreign extensions), network attackers
  (Lens has no network requests in the default config)

## Security posture (v0.1.3)

- **Manifest V3** with strict CSP (`script-src 'self'`)
- **Zero npm dependencies** (per `CONTRIBUTING.md` rule)
- **No `eval()`, no `Function()`, no inline event handlers**
- **Sender-id validation** in the service worker (F-01)
- **Domain hashing** (F-12) for opt-in telemetry
- **Schema-validated** service worker payloads
- **SLSA L2** build provenance (build is in the Platform
  build pipeline, signed with Ed25519)
- **No remote code** of any kind

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

- **2026-07-09**: 11 F-findings fixed (see `docs/CHANGELOG.md`)
- **2026-07-05**: 5 CI infrastructure fixes shipped
- **2026-07-05**: A11Y audit (32 findings addressed)
- **2026-06-28**: v0.2 ML cascade burned down (no remote
  model inference — architectural privacy improvement)
- **Earlier**: see `git log` for the full history

## Bug bounty

We do not currently have a paid bug bounty program. We do credit
researchers in the release notes (with permission) and ship a
reproduction test case as a regression guard.

## See also

- `docs/THREAT-MODEL.md` — the formal STRIDE threat model
- `docs/A11Y-AUDIT-v0.1.3.md` — accessibility audit
  (includes focus management, the prime clickjacking vector)
- `CONTRIBUTING.md` — the no-npm rule (privacy guarantee)
- `aegisgatesecurity.io/.well-known/security.txt` — RFC 9116
