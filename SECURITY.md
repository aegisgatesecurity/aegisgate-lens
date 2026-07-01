# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | ✅ (current dev)   |
| 0.2.x   | ✅ (current stable) |
| 0.1.x   | ❌ (deprecated)    |
| < 0.1   | ❌                 |

The latest `0.3.x` and `0.2.x` minor versions receive security fixes. The 0.1.x line is no longer maintained.


The AegisGate Lens team takes the security of the Lens extension seriously. This document explains how to report security vulnerabilities, what we commit to in our response, and what security properties the Lens is designed to provide.

---

## Reporting a Vulnerability

**Please DO NOT open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available gives attackers a roadmap to exploit users.

### How to report

**Email**: `security@aegisgatesecurity.io`

**Subject line**: `Lens Security: <short description>`

**What to include**:
- Description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- Affected versions (Lens version, Chrome version, OS)
- Your assessment of impact (data leak, code execution, etc.)
- Your name and how you'd like to be credited (optional)

### What to expect

- **Initial response**: within 24 hours (typically much faster)
- **Triage report**: within 72 hours, including severity assessment
- **Fix timeline**: Critical (CVSS ≥ 9.0) within 7 days, High (7.0-8.9) within 30 days, Medium (4.0-6.9) within 90 days
- **Disclosure**: We coordinate public disclosure with the reporter. Default 90 days from acknowledgment.
- **Credit**: Reporters are credited in our security acknowledgments unless they prefer anonymity.

---

## Security Properties of AegisGate Lens

### Privacy by design (the 12 non-negotiables)

The Lens is a privacy product. The following are **non-negotiable** design constraints — any violation pauses the build:

1. The Lens never sends prompt content to any server. Period.
2. The Lens never sends URLs to any server. Period.
3. The Lens never sends page content to any server. Period.
4. The Lens never collects a user ID, session ID, or cookie. Period.
5. The Lens's default is OFF. The user must explicitly opt in to telemetry.
6. The Lens is open source from day one. Apache 2.0.
7. The Lens's privacy policy is published before the Lens ships.
8. The Lens's third-party dependencies are audited. (There are none.)
9. The Lens's data retention is 90 days for events, indefinite for aggregated stats.
10. The Lens's API is rate-limited. 100 events/min per installation, 10K/min server.
11. The Lens's backend is TLS-only. HTTP is rejected. HSTS is enabled.
12. The Lens's threat model is updated whenever the architecture changes.

### Technical security properties (verified)

- **Strict CSP**: `script-src 'self'; object-src 'self'` — no `eval()`, no inline scripts, no remote code.
- **Minimal permissions**: Only `storage` and `alarms` (2 of ~40 available Chrome permissions).
- **Minimal host access**: Only `lens.aegisgatesecurity.io/*` (not `*://*`).
- **Sender ID validation (F-01)**: Content scripts validate that messages come from the legitimate extension ID via `chrome.runtime.sender.id`. Foreign senders are rejected.
- **Bundle signing (F-02)**: All ONNX model bundles are Ed25519-signed. Tampered bundles fail signature verification and are not loaded. The signing key is rotated quarterly (see `KEY_ROTATION_POLICY.md`).
- **Dismissals quota (F-04)**: User-dismissed banner entries are capped at 1000 entries with 1-day TTL, preventing storage-exhaustion attacks.
- **Wire protocol integrity (F-05)**: All telemetry events are validated against a JSON schema. Out-of-schema events are dropped at the client before any network call.
- **No third-party JavaScript dependencies** (Standing Rule §1.1): Zero supply chain attack surface for a privacy product. Verified by CI.
- **SLSA L2 + Sigstore**: Every release artifact has signed provenance via `actions/attest-build-provenance@v3` + `softprops/action-gh-release@v2`.

### Threat model

The Lens addresses 15 documented findings in the threat model (10 RESOLVED, 1 PARTIAL F-15, 1 closed F-14, 3 accepted). See `docs/THREAT-MODEL.md` for the full analysis.

Known partial limitations (documented in the threat model):
- **F-15** (PARTIAL): Bundle signature verification covers ONNX models. Extension code (JavaScript) is verified via GitHub Actions provenance instead.
- **F-14** (closed): RLO Unicode bidi attack vector was addressed in Day 25 v9 retraining; catch rate is 100% on canonical corpus.
- **F-01, F-02, F-04, F-05** (RESOLVED): Sender validation, bundle signing, dismissals quota, and wire protocol integrity are all verified by 21/21 passing pen-tests.

### Bounty program (status)

A public bug bounty program (HackerOne or Bugcrowd) is planned for **post-launch** (per Day 28 sprint plan, see `plans/AEGISGATE-LENS-V03-DAY-5-PHASE-4-BUNDLE-HARDENING-2026-06-30.md`).

For pre-launch disclosures, we offer **acknowledgment in the security credits** (this page, updated quarterly).

---

## Security acknowledgments

We thank the following researchers for responsibly disclosed vulnerabilities (none at present).

_This page was last updated 2026-06-30. The next quarterly review is scheduled for 2026-09-30._

---

## Related documents

- [Privacy Policy](PRIVACY-POLICY.md)
- [v0.2 Addendum to Privacy Policy](PRIVACY-POLICY-V02-ADDENDUM.md)
- [Threat Model](THREAT-MODEL.md)
- [Standing Rules](../plans/AEGISGATE-LENS-STANDING-RULES-2026-06-29.md)
- [v0.2 Architecture](../plans/AEGISGATE-LENS-V02-ARCHITECTURE.md)
- [Ship Readiness Gate](../plans/AEGISGATE-LENS-V02-SHIP-READINESS-GATE.md)

## Contact

- **Security email**: security@aegisgatesecurity.io
- **Support email**: support@aegisgatesecurity.io (general questions, not for security reports)
- **Privacy email**: privacy@aegisgatesecurity.io (privacy-specific concerns)

AegisGate Security, LLC — founded 2026
