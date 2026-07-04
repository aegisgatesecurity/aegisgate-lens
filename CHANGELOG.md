# Changelog

All notable changes to AegisGate Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial project structure (v0.1.0-beta) — see
  [`docs/ARCHITECTURE-v0.1.0-BETA.md`](docs/ARCHITECTURE-v0.1.0-BETA.md)
  for the binding architectural specification.

## [0.1.0-beta] — 2026-07-04

### Added
- **First public release of AegisGate Lens.** A clean-whiteboard rebuild
  of the product with all 6 detection facets, the tiered ML architecture
  (regex + ModernBERT-base + Longformer-base), the SPA MutationObserver
  pattern, and the privacy-first non-negotiables from the legal doc.
- `docs/ARCHITECTURE-v0.1.0-BETA.md` — the binding architectural spec.
- `LICENSE` (Apache 2.0), `README.md`, `CHANGELOG.md`, `.gitignore`.

### Notes
- v0.1.0-beta is the **first** public version of the new build. It
  supersedes the never-published internal iterations; the changelog
  starts here on purpose. There is no migration path from prior
  internal versions because none were released to the public.
- The 12 non-negotiables (no content/URL/page-content leaves the
  browser, opt-in by default, Apache 2.0 OSS, no external runtime
  dependencies, etc.) are documented in the architecture doc and
  enforced in the build.

[Unreleased]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.1.0-beta
