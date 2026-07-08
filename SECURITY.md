# Security Policy

AegisGate Lens is a privacy product. Security reports are taken seriously and handled with care.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ (current dev)   |
| < 0.1   | ❌                 |

The Lens is pre-release as of 2026-06-18. Only the latest `0.1.x` minor version receives security fixes.

## Reporting a vulnerability

**Please do not file a public issue for security vulnerabilities.**

Email: **security@aegisgatesecurity.io**

For sensitive disclosures, encrypt your report with our PGP key:

```
PGP Key ID:  [fingerprint inserted at first release]
PGP Key URL: https://aegisgatesecurity.io/.well-known/pgp-key.txt
```

(If the key is not yet published at the URL above, email us first and we'll send it.)

### What to include

- A clear description of the vulnerability.
- Steps to reproduce (a proof-of-concept is ideal).
- The affected version(s).
- Your assessment of the impact.
- Your name / handle for the public acknowledgement (optional; we respect "anonymous" too).

### What to expect

- **Acknowledgement** within 48 hours of your report.
- **Initial triage** within 5 business days: severity, scope, affected versions.
- **Status updates** at least every 7 days until the fix is shipped.
- **Coordinated disclosure**: we will work with you on a disclosure timeline. The default is 90 days from report to public disclosure, or sooner if a fix is ready.
- **Credit** in the CHANGELOG and the security advisory (unless you prefer to remain anonymous).

### Severity classification

We use CVSS v3.1. The threshold for an immediate hotfix is CVSS ≥ 7.0. Lower severities are bundled into the next regular release.

| Severity | CVSS   | Response time |
|----------|--------|---------------|
| Critical | 9.0+   | < 24h         |
| High     | 7.0-8.9| < 5 days      |
| Medium   | 4.0-6.9| < 30 days     |
| Low      | 0.1-3.9| Next release  |

### Scope

In-scope:

- The Lens extension source code (when published in Step D).
- The Lens backend (`pkg/lensbackend/` in the [Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform)).
- The privacy policy and the threat model.
- The CI/CD pipeline.

Out-of-scope:

- The AegisGate Platform (separate scope; report to the Platform's SECURITY.md).
- Third-party AI providers (ChatGPT, Claude, Gemini, Copilot).
- The user's browser itself (Chrome, Firefox bugs).
- Theoretical vulnerabilities that cannot be demonstrated in practice.

## Privacy-specific concerns

If your report concerns a potential **privacy violation** — for example, a code path that could transmit prompt content to a server — please flag this explicitly. Privacy bugs are treated as severity Critical by default and are responded to within 24 hours.

The 12 non-negotiables in [`docs/PRIVACY-POLICY.md`](docs/PRIVACY-POLICY.md) and [`README.md`](README.md) define what a privacy violation is.

## Hall of fame

We acknowledge security researchers who have helped improve the Lens. (The hall of fame is established at first release; until then, this section is a placeholder.)

---

Thank you for helping us keep the Lens — and its users — safe.
