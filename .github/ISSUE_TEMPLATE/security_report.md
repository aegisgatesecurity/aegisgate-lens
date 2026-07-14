---
name: 🔒 Security report
about: Report a security issue with AegisGate Lens (PRIVATE until triaged)
title: "[SECURITY] "
labels: ["security", "needs-triage", "private"]
---

> **🔒 IMPORTANT**: Do NOT file a public GitHub issue for security vulnerabilities.
> Email **security@aegisgatesecurity.io** instead. See [SECURITY.md](../SECURITY.md) for our full disclosure policy.

## Summary

A short, non-sensitive description of the issue. (Do NOT include the actual exploit, payload, or PII.)

## Affected component

- [ ] Content script (the part that runs on chatgpt.com / claude.ai / etc.)
- [ ] Background service worker (background.js)
- [ ] Popup (popup.html / popup.js)
- [ ] Bundle / build pipeline (tools/ci/)
- [ ] CI / GitHub workflows (.github/workflows/)
- [ ] Linter (tools/lint.sh)
- [ ] Other (please specify)

## Severity (your estimate)

- [ ] Critical (remote code execution, data exfiltration, persistent XSS)
- [ ] High (privilege escalation, content script bypass, XSS via prompt)
- [ ] Medium (FPR regression, FNR regression, minor security gate violation)
- [ ] Low (cosmetic, documentation, hardening opportunity)

## Discovery context

- [ ] Found while using Lens in production
- [ ] Found while reviewing the code
- [ ] Found while writing a tool that interacts with Lens
- [ ] Reported by a security scanner (please specify which)
- [ ] Other (please describe)

## Disclosure timeline

- [ ] I have not disclosed this publicly
- [ ] I have disclosed this to a third party (please specify)
- [ ] I have a coordinated disclosure timeline in mind (please specify)

## Contact

How can we reach you? (PGP key, Signal handle, email, etc.)
