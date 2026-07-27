<!-- AegisGate Lens — Pull Request Template -->

## What changed?

A clear, concise description of the change.

## Why?

The problem this PR solves. Link to the relevant issue, doc, or commit.

## How to test

Steps for a reviewer to verify the change. For UI changes, include screenshots.

## Test coverage

- [ ] Unit tests pass (`node --test test/unit/*.test.mjs test/e2e/*.test.mjs`)
- [ ] Go tests pass (`cd tools/headless-smoke/flow && go test ./...`)
- [ ] v0.1.3 smoke passes (1x, 16 tests)
- [ ] mini smoke passes (1x, 128 tests) — if changed any of: selectors.js, mock.go, devtools.go, main.go
- [ ] Linter passes (`bash tools/lint.sh`) — 12/12 checks
- [ ] F-7 e2e passes — 20/20 tests
- [ ] Bundle rebuilt (`python3 tools/ci/build-bundle.py`) — if changed any of: src/

## Risk assessment

- [ ] Low risk (docs, linter, internal tooling)
- [ ] Medium risk (changes a single detector or one UX feature)
- [ ] High risk (changes the content script, manifest, or bundle injection)

## Privacy implications

Lens is privacy-first: NO prompt content ever leaves your browser. Does this PR:
- [ ] Preserve this (no change)
- [ ] Add a feature that needs opt-in user consent (describe)
- [ ] Change the bundle in a way that affects user trust (describe)

## Backout plan

If this PR breaks something in production, how do we roll it back?
- [ ] Revert the commit (no data loss)
- [ ] Revert + publish a hotfix (if user-visible)
- [ ] Other (describe)

## Related work

- [ ] Closes issue #
- [ ] Related PR #
- [ ] Implements part of the project roadmap (see CHANGELOG.md)
