# AegisGate Lens

> **Privacy-first browser extension that protects the 95%.**
> Detect sensitive data before it leaves your browser.
> No prompt content ever crosses the wire. Open source from day one.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-v0.3.0--rc1-green.svg)]()
[![Open Source](https://img.shields.io/badge/Open%20Source-Day%20One-green.svg)]()
[![No npm](https://img.shields.io/badge/Dependencies-Go%20Stdlib%20Only-orange.svg)](docs/NO-EXTERNAL-DEPS.md)

AegisGate Lens is a Manifest V3 Chrome extension (with Firefox support planned) that observes prompts being typed into AI providers — ChatGPT, Claude, Gemini, Copilot — and warns the user **before they send** when sensitive data is detected. It is the privacy product for the 95% of organizations that don't have an AI estate, and the distribution channel for [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform).

The tagline: **"Secure every AI interaction — in your browser, in your data center, in your AI agents."**

---

## What's new in v0.3.0

- **ModernBERT-base ML model** (149M params) replaces v0.1's regex-only approach. Detects novel prompt injection attacks.
- **Sliding window inference** with parameters 2048/1024/4: handles long-context attacks (up to 13K tokens) with 80%+ recall.
- **Detection threshold tuned to 0.05** via hard-test-set sweep.
- **6-facet detection system**: PII, Secrets, XSS, Compliance, Toxicity (ML), Prompt Injection (ML).
- **233/233 tests pass, 7/7 ship-readiness gates PASS** (PII, Secrets, XSS, Compliance, Toxicity, PI short, PI long).
- **Zero third-party JavaScript dependencies** (privacy product; zero supply chain attack surface).
- **Ed25519 bundle signing** for all ONNX model bundles (8/8 attack vectors rejected).
- **SLSA L2 + Sigstore + Rekor** provenance for every release artifact.
- **Privacy boundary test** in CI: verifies no prompt content crosses the wire (14/14 adversarial events blocked).

For the full v0.3.0 changelog, see [`CHANGELOG.md`](CHANGELOG.md).



- **In your browser** → AegisGate Lens (this repo).
- **In your data center** → [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform).
- **In your AI agents** → AegisGate Agent Guard (planned, Year 2).

---

## Privacy First

AegisGate Lens is a privacy product, not a security product. The commitments below are non-negotiable, enforceable in code, and audited in CI. The full Privacy Policy is published at <https://aegisgatesecurity.io/lens/privacy>; the source is at [`docs/PRIVACY-POLICY.md`](docs/PRIVACY-POLICY.md) (with a working draft at `plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md` in the Platform monorepo).

The 12 non-negotiables (any violation pauses the build):

1. **The Lens never sends prompt content to any server.** Period. Even for debugging.
2. **The Lens never sends URLs to any server.** Period. The `domain_hash` is computed locally.
3. **The Lens never sends page content to any server.** Period.
4. **The Lens never collects a user ID, session ID, or cookie.** Period.
5. **The Lens's default is OFF.** The user must explicitly opt in to telemetry.
6. **The Lens is open source from day one.** Apache 2.0.
7. **The Lens's privacy policy is published before the Lens ships.**
8. **The Lens's third-party dependencies are audited.** (See below — there are none.)
9. **The Lens's data retention is 90 days for events, indefinite for aggregated stats.**
10. **The Lens's API is rate-limited.** 100 events/min per installation, 10K/min server.
11. **The Lens's backend is TLS-only.** HTTP is rejected. HSTS is enabled.
12. **The Lens's threat model is updated whenever the architecture changes.**

See [`docs/PRIVACY-POLICY.md`](docs/PRIVACY-POLICY.md) and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the full commitments and the STRIDE analysis.

---

## Architecture (v0.3.0)

```
┌─────────────────────────────────────────────────────────────┐
│  Browser (Chrome / Firefox)                                  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  content.ts  │  │ service-     │  │   popup.ts   │      │
│  │  (DOM watch) │◀▶│ worker.ts    │◀▶│  (UI / opt-  │      │
│  │              │  │ (router,     │  │   in toggle) │      │
│  │              │  │  state, q)   │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│                  Anonymized metadata only                    │
│                  (9 fields, no PII)                         │
└────────────────────────────┼────────────────────────────────┘
                             │ TLS 1.2+ only
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  AegisGate Lens Backend (Go)                                 │
│                                                              │
│  POST /api/v1/lens/telemetry    ← event ingest              │
│  GET  /api/v1/lens/check       ← known-threat lookup        │
│  GET  /api/v1/lens/stats        ← aggregate counts           │
│  GET  /api/v1/lens/healthz     ← liveness                   │
│                                                              │
│  Server-side domain_hash recomputation (TLS SNI check)       │
│  Rate limit: 100/min/installation, 10K/min/server            │
│  Retention: 90d events, 24h send_anyway, 24h IP geo         │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  pkg/ioc.Store (AegisGate Platform)                          │
│                                                              │
│  Shared with AegisGate Gateway via the existing gossip       │
│  protocol. IOCs originated by the Lens improve the          │
│  Gateway's detection rules.                                 │
└─────────────────────────────────────────────────────────────┘
```

The full architecture is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (pointer to the canonical document in the Platform monorepo).

---

## No External Dependencies

**This repository has zero third-party JavaScript dependencies.** No `npm install`, no `node_modules`, no `package.json`, no `package-lock.json`, no `actions/setup-node` in any CI workflow, no vendored `tsc.js`, no esbuild, no webpack, no Jest, no ESLint, no Prettier.

The build is a **Go program** that lives in the AegisGate Platform monorepo at [`tools/build-lens-extension/`](https://github.com/aegisgatesecurity/aegisgate-platform/tree/main/tools/build-lens-extension). The Platform's CI builds the extension; the Lens repo is the source files and assets.

Why? The Lens is a privacy product. Every third-party package is a potential supply-chain attack vector. The convenience of `transformers.js` and `onnxruntime-web` is not on the table. The whole company ships one way: a single binary from source, with as close to zero external imports as physically possible.

The constraint, in full: [`docs/NO-EXTERNAL-DEPS.md`](docs/NO-EXTERNAL-DEPS.md).

---

## Current Status: v0.1 pre-build

We are in **Phase 0+1** of the build sequence. The Privacy Policy has been drafted (in the Platform monorepo) and is awaiting legal review. The Lens backend (`pkg/lensbackend/` in the Platform monorepo) has been built and tested. The Lens extension itself has not yet been written — that is Step D in the build sequence, scheduled to start after this repo's bootstrap is complete.

See the [Roadmap](docs/ROADMAP.md) for the Quarter-by-Quarter plan and the [Lens Architecture document](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/plans/AEGISGATE-LENS-ARCHITECTURE-v1.md) for the design.

---

## Repository Layout

```
aegisgate-lens/
├── LICENSE                   Apache 2.0
├── README.md                 this file
├── CONTRIBUTING.md           contribution rules (incl. the "no npm" rule)
├── SECURITY.md               vulnerability disclosure
├── CODE_OF_CONDUCT.md        community standards
├── CHANGELOG.md              version history
├── .gitignore                ignored files
├── .github/
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
├── src/                      TypeScript source files (empty in v0.1-pre-build; populated in Step D)
├── test/                     Test cases for the detector (empty in v0.1-pre-build)
└── docs/
    ├── ARCHITECTURE.md       pointer to the canonical architecture doc
    ├── THREAT-MODEL.md       pointer to the canonical threat model
    ├── PRIVACY-POLICY.md     pointer to the published privacy policy
    ├── NO-EXTERNAL-DEPS.md   the no-deps constraint, explained
    └── ROADMAP.md            pointer to the canonical roadmap
```

The TypeScript source files will be added in Step D. The build, CI, and release pipeline is **not** in this repo — it lives in the Platform monorepo at [`tools/build-lens-extension/`](https://github.com/aegisgatesecurity/aegisgate-platform/tree/main/tools/build-lens-extension). This is intentional; see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the rationale.

---

## How to Get Involved

We welcome bug reports, feature requests, and (eventually) pull requests.

- **Bug reports and feature requests:** open an issue using the templates in `.github/ISSUE_TEMPLATE/`.
- **Security disclosures:** see [`SECURITY.md`](SECURITY.md). Email `security@aegisgatesecurity.io` for anything that should not be public.
- **Code contributions:** see [`CONTRIBUTING.md`](CONTRIBUTING.md). The "no npm" rule is a hard contribution gate; please read it before opening a PR.

We are a small, founder-led open-source project. Response times may be longer than commercial offerings. Please be patient and kind.

---

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

Copyright 2026 AegisGate Security, LLC.

---

## Related Repositories

- [aegisgatesecurity/aegisgate-platform](https://github.com/aegisgatesecurity/aegisgate-platform) — the AegisGate Platform (Gateway, MCP server, IOC library, etc.). The Lens's backend lives in the Platform monorepo at `pkg/lensbackend/`.
- [aegisgatesecurity/aegisgate-site](https://github.com/aegisgatesecurity/aegisgate-site) — the marketing website.
- [aegisgatesecurity/aegisgate-demo](https://github.com/aegisgatesecurity/aegisgate-demo) — the live demo environment.
- [aegisgatesecurity/aegisgate-admin](https://github.com/aegisgatesecurity/aegisgate-admin) — the admin portal.

---

## Contact

- **General:** open an issue.
- **Security:** `security@aegisgatesecurity.io` (PGP key in [`SECURITY.md`](SECURITY.md)).
- **Privacy:** `privacy@aegisgatesecurity.io`.
- **Media / partnerships:** `hello@aegisgatesecurity.io`.
