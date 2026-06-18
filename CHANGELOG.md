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

## [0.0.0] - 2026-06-18

### Added
- Repository created at <https://github.com/aegisgatesecurity/aegisgate-lens>.
- Bootstrap files (this CHANGELOG and the others in the [Unreleased] section above).
- Apache 2.0 LICENSE.
- CI enforcement: the Platform monorepo's CI rejects any `package.json`, `node_modules/`, `package-lock.json`, or `yarn.lock` if they appear in this repo or in any PR.

[Unreleased]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/HEAD
