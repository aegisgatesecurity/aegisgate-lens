# Changelog

All notable changes to AegisGate Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository bootstrap (LICENSE, README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG, .gitignore).
- Issue templates: `bug_report.md`, `feature_request.md`.
- Documentation stubs: `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, `docs/PRIVACY-POLICY.md`, `docs/NO-EXTERNAL-DEPS.md`, `docs/ROADMAP.md`.
- `src/` and `test/` placeholders with READMEs explaining what will live there.

### Not yet implemented
The following are planned for the v0.1 release (Phase 1 of the Roadmap) and are tracked in the [Platform monorepo's roadmap](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/plans/AEGISGATE-LENS-ROADMAP.md):
- TypeScript source files in `src/`.
- Test cases in `test/`.
- The build tool (a Go program in the Platform monorepo at `tools/build-lens-extension/`) is not yet committed.

## [v0.3.0-rc1] - 2026-06-30

### Added
- **ModernBERT-base ML model** (149M params) replaces v0.2.2's regex-only approach.
- **Sliding window inference** with parameters 2048/1024/4 (long-context attacks).
- **6-facet detection system**: PII, Secrets, XSS, Compliance, Toxicity, PI.
- **Detection threshold tuned to 0.05** via hard-test-set sweep.
- **Ed25519 bundle signing** for all ONNX model bundles.
- **SLSA L2 + Sigstore + Rekor** provenance for every release artifact.
- **Zero third-party JavaScript dependencies** (privacy product).
- **Privacy boundary test** in CI: 14/14 adversarial events blocked.
- **233/233 tests pass, 7/7 ship-readiness gates PASS**.
- New docs: SECURITY.md, COMPLIANCE-MATRIX.md, CISO-ONE-PAGER.md.
- New CWS asset: 440x280 small promo tile.
- PR template, dev env setup section in CONTRIBUTING.md.
- v0.3.0 addenda in ARCHITECTURE.md and THREAT-MODEL.md.

### Fixed (5 ship-blocker bugs in bundle signing/parsing/loading)
1. findHeaderStart walked to wrong { (added findRootOpenBrace with depth tracking)
2. findKeyForBundle now accepts both signing_public_key and signing_pub_key_b64
3. parseBundle JSON.parse'd plain text files (now branches on extension)
4. Syntax error in dist bundle-loader.js (missing ? in ternary)
5. createSession loaded FP32 even when int8 present (now prefers int8)

### Changed
- Detection threshold: 0.50 → 0.05
- Long-context attack detection: 80%+ (with sliding window)
- Bundle size: 147 MB int8 + 549 MB full
- License: kept Apache 2.0

## [v0.2.2] - 2026-06-22 (historical, added retroactively)

### Added (note: this entry was missing from the v0.1 CHANGELOG; added here for completeness)
- 3-tier on-device cascade (regex → ML → sliding window)
- Day 17: wordplay corpus closes F-11 (60/60 PAIR bypass rate → 0/60)
- Day 18: threat model F-13 closed (SLSA L2)
- Day 19-20: CodeQL config suppresses 4 known false positives
- F-10/F-11 closed (PAIR bypass 0/60, security 9.5/10)
- Bundle signature verification (Ed25519)
- Sender ID validation (F-01)
- Strict CSP (no eval, no unsafe-inline)
- 6 GitHub Actions workflows (ci.yml, security.yml, lens-tests.yml, etc.)
- Pair adversarial testing (PAIR bypass rate 5% → 2% → 0%)

### Changed
- Privacy architecture: 12 non-negotiables documented and enforced
- Threat model: STRIDE analysis covering 3 trust boundaries
- CodeQL config: now in `.github/codeql/codeql-config.yml`

### Notes
- This release was tagged `lens-v0.2.2` (PGP-signed by security@aegisgatesecurity.io) on 2026-06-22
- Superseded by v0.3.0-rc1 (adds ModernBERT ML, sliding window, 6-facet cascade)

## [0.0.0] - 2026-06-18

### Added
- Repository created at <https://github.com/aegisgatesecurity/aegisgate-lens>.
- Bootstrap files (this CHANGELOG and the others in the [Unreleased] section above).
- Apache 2.0 LICENSE.
- CI enforcement: the Platform monorepo's CI rejects any `package.json`, `node_modules/`, `package-lock.json`, or `yarn.lock` if they appear in this repo or in any PR.

[Unreleased]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/HEAD
