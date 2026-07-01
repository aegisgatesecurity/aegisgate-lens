# AegisGate Lens — Privacy & Data Handling (CISO One-Pager)

**Audience**: CISOs, GRC leads, Privacy officers, Procurement teams
**Last updated**: 2026-06-30
**Status**: v0.2.0-rc1 (pre-CWS-submission)

---

## TL;DR

AegisGate Lens is a **privacy-first browser extension** that protects the 95% of organizations that don't have AI estates. It runs in the user's browser, sees only what's needed to detect sensitive data leakage, and **never sends prompt content to any server**. The product is open source (Apache 2.0), has **zero third-party JavaScript dependencies**, and is engineered to be auditable end-to-end.

**If you have 5 minutes**: read the 12 non-negotiables below.
**If you have 30 minutes**: also read the Privacy Policy (`docs/PRIVACY-POLICY.md`) and the v0.2 addendum.
**If you have 2 hours**: also read the Threat Model (`docs/THREAT-MODEL.md`) and the Compliance Matrix (`docs/COMPLIANCE-MATRIX.md`).

---

## The 12 non-negotiables

These are the design constraints, not nice-to-haves. Any violation pauses the build.

1. **The Lens never sends prompt content to any server. Period.**
2. **The Lens never sends URLs to any server. Period.**
3. **The Lens never sends page content to any server. Period.**
4. **The Lens never collects a user ID, session ID, or cookie. Period.**
5. **The Lens's default is OFF. The user must explicitly opt in to telemetry.**
6. **The Lens is open source from day one. Apache 2.0.**
7. **The Lens's privacy policy is published before the Lens ships.**
8. **The Lens's third-party dependencies are audited. (There are none.)**
9. **The Lens's data retention is 90 days for events, indefinite for aggregated stats.**
10. **The Lens's API is rate-limited. 100 events/min per installation, 10K/min server.**
11. **The Lens's backend is TLS-only. HTTP is rejected. HSTS is enabled.**
12. **The Lens's threat model is updated whenever the architecture changes.**

---

## What data the Lens sees

| Data type | When seen | Where it goes |
|---|---|---|
| **User prompt text** | Always (it's what we detect) | **Stays in browser.** Never sent. |
| **AI provider URL** (e.g., chat.openai.com) | Always (host match required) | **Stays in browser.** Never sent. |
| **Page DOM** (excluding prompt) | When scanning for page-load injection attacks | **Stays in browser.** Never sent. |
| **Detection events** (when user dismisses, allows, or edits) | Only after opt-in | Sent to `lens.aegisgatesecurity.io` as anonymized metadata |
| **Anonymized metadata** (category, severity, action) | Only after opt-in | Sent with 90-day retention |

---

## What the opt-in telemetry looks like (and doesn't look like)

When the user opts in to telemetry, the **only** fields in each event are:
- `domain_hash` (16-hex SHA-256 prefix of the AI provider hostname)
- `category` (enum: `pii_email`, `pii_phone`, `secret_api_key`, `prompt_injection`, etc.)
- `severity` (enum: `low`, `medium`, `high`, `critical`)
- `user_action` (enum: `send_anyway`, `edit`, `cancel`, `dismiss`)
- `timestamp` (ISO 8601 UTC)
- `model_version` (the Lens version, not the AI provider's model)
- `language` (IETF tag, e.g., `en-US`)
- `extension_id` (for anti-abuse, hashed)
- `confidence` (0-1 float)

**Explicitly NOT collected**:
- ❌ Prompt content
- ❌ URLs (only hashed domain)
- ❌ Page content
- ❌ User ID, session ID, cookies
- ❌ Free-text fields
- ❌ Geolocation
- ❌ Fingerprinting data

**Verified**: The Privacy Boundary Test (`tools/test_privacy_boundary.py`) loads the actual API client code, mocks fetch with capture, sends 14 adversarial events containing sensitive PII/secrets, and verifies NO prompt content reaches any field. 14/14 tests pass.

---

## Compliance certifications

| Framework | Coverage | Document |
|---|---|---|
| **GDPR Art. 15-22** (right to access, deletion, etc.) | ✅ Full | `docs/PRIVACY-POLICY.md` §9 (30-day deletion SLA) |
| **CCPA/CPRA** (right to know, delete) | ✅ Full | `docs/PRIVACY-POLICY.md` §2.2 |
| **LGPD** (Brazil) | ✅ Full | Same as GDPR (we have no user IDs to look up) |
| **PIPEDA** (Canada) | ✅ Full | Same as GDPR |
| **APPI** (Japan) | ✅ Full | Same as GDPR |
| **PIPA** (South Korea) | ✅ Full | Same as GDPR |
| **MITRE ATLAS** | ✅ 7/10 (3 are out of scope) | `docs/COMPLIANCE-MATRIX.md` §1 |
| **NIST AI RMF 1.0** | ✅ GOVERN, MAP, MEASURE, MANAGE all supported | `docs/COMPLIANCE-MATRIX.md` §2 |
| **OWASP LLM Top-10 (2025)** | ✅ 5 fully, ⚠️ 4 partial, ❌ 1 out-of-scope | `docs/COMPLIANCE-MATRIX.md` §3 |
| **EU AI Act** (selected) | ✅ Art. 9, 14, 15 | `docs/COMPLIANCE-MATRIX.md` §4 |

**Not certified (yet)**:
- SOC 2 Type II — post-launch (planned Q3 2026)
- ISO 27001 — post-launch (planned Q4 2026)
- HIPAA BAA — available on Enterprise tier
- FedRAMP — available on Enterprise tier

---

## Threat model highlights

The threat model (`docs/THREAT-MODEL.md`) documents 15 findings:

- **10 RESOLVED**: F-01 (sender ID), F-02 (bundle signing), F-04 (dismissals quota), F-05 (wire protocol), F-06 (CSP), F-08 (CORS), F-10 (rate limit), F-12 (data retention), F-13 (TLS), F-14 (RLO Unicode)
- **1 PARTIAL**: F-15 (bundle signing covers ONNX models; JS code verified via GitHub Actions provenance)
- **1 CLOSED**: F-14 (RLO bidi attack vector addressed in v9 retraining)
- **3 ACCEPTED**: Documented limitations in the threat model (e.g., LLM04 training-time poisoning is out of scope; we protect end-user prompt, not model training data)

---

## Technical security properties (verified by CI)

- **Strict CSP**: `script-src 'self'; object-src 'self'` — no `eval()`, no inline scripts, no remote code.
- **Minimal permissions**: Only `storage` and `alarms` (2 of ~40 available Chrome permissions).
- **Minimal host access**: Only `lens.aegisgatesecurity.io/*` (not `*://*`).
- **Bundle signing**: All ONNX model bundles are Ed25519-signed. 8/8 attack vectors rejected in pen-tests.
- **Zero third-party JavaScript dependencies**: Privacy product, zero supply chain attack surface. CI fails the build if `package.json` or `node_modules/` exists.
- **SLSA L2 + Sigstore + Rekor + GitHub Attestations**: Every release artifact has signed provenance.

---

## 6-facet detection system

The Lens runs a cascade of 6 detection facets on every prompt the user types:

| Facet | What it detects | How |
|---|---|---|
| 1. PII | SSN, credit cards, emails, phones, IPs, health data | Regex + Luhn validation (16/16 tests pass) |
| 2. Secrets | API keys, OAuth tokens, AWS creds, JWTs, private keys | Regex with framework-specific patterns (17/17 tests pass) |
| 3. XSS | Script tags, SQL injection, source code being shared | Regex (7/7 tests pass) |
| 4. Compliance | OWASP, EU AI Act, NIST AI RMF markers | Regex from Platform library (3/3 tests pass) |
| 5. Toxicity | Weapons, violence, illegal content markers | Regex + toxic-bert ML (96.94% recall, 0% FPR) |
| 6. Prompt Injection | Novel attacks | ModernBERT ML + sliding window (100% short-context, 80% long-context) |

---

## Detection metrics (canonical)

- **Total tests**: 233/233 pass (0 fail)
- **PII recall**: 100% (16/16 facet tests + 6400+ corpus tests)
- **Secret recall**: 100% (17/17 facet tests)
- **XSS recall**: 100% (7/7 facet tests)
- **Compliance recall**: 100% (3/3 facet tests)
- **Toxicity recall**: 96.94% (ML)
- **PI short-context recall**: 100% (200/200)
- **PI long-context recall**: 80% (sliding window)
- **FPR (clean benign)**: 0% across all facets
- **Pen-tests**: 21/21 pass (F-01, F-02, F-04, F-05)

The canonical metrics file: `models/release-candidates/ship_readiness_metrics.json`

---

## Bug bounty and disclosure

- **Security email**: security@aegisgatesecurity.io
- **Response time**: 24 hours initial, 72 hours triage
- **Critical fix**: 7 days, High fix: 30 days, Medium fix: 90 days
- **Disclosure window**: 90 days default
- **Public bounty program**: planned for Q3 2026 (post-launch)

---

## Why this is different

Other AI security products (Lakera Guard, Cisco AI Defense, Rebuff, Prompt Shields) typically:
- Require sending prompt content to a cloud service for analysis
- Charge $50-500/seat/month for the basic tier
- Don't open-source their detection logic
- Have 2-5% false positive rates

AegisGate Lens:
- Runs **entirely in the browser** (no prompt content ever leaves)
- **Free** for the browser extension (revenue is on the Platform side, via enterprise)
- **Open source** (Apache 2.0) — every detection rule is auditable
- 0% false positive rate on canonical corpus (lower than competitors)

---

## Where to go next

- **Privacy Policy**: `docs/PRIVACY-POLICY.md` (and `docs/PRIVACY-POLICY-V02-ADDENDUM.md` for v0.2-specific addenda)
- **Threat Model**: `docs/THREAT-MODEL.md`
- **Compliance Matrix**: `docs/COMPLIANCE-MATRIX.md`
- **Source code**: github.com/aegisgatesecurity/lens (after public launch)
- **Contact**: privacy@aegisgatesecurity.io (privacy) or security@aegisgatesecurity.io (security)

---

_AegisGate Security, LLC — founded 2026. AegisGate Lens is a product of AegisGate Security, LLC._
