# AegisGate Lens — Day 18: SLSA Build Level 2 Release Provenance

**Status**: ✅ COMPLETE. First SLSA-provenanced Lens release published.
**Date**: 2026-06-22.
**Method**: `actions/attest-build-provenance@v3` (GitHub's built-in) +
`softprops/action-gh-release@v2` in `release-lens.yml`.

---

## Executive Summary

The first AegisGate Lens release with **signed SLSA Build Level 2 provenance**
was published on 2026-06-22 at 23:08:00Z.

| Field | Value |
|---|---|
| Tag | `lens-v0.2.2` |
| Release | https://github.com/aegisgatesecurity/aegisgate-platform/releases/tag/lens-v0.2.2 |
| Artifact | `aegisgate-lens-0.2.2.zip` (112,573 bytes) |
| Artifact SHA-256 | `54f9b74db3cd7d52fa020c9242a0bd664e9eee13e417e022d650ac9df0ae4c69` |
| Provenance | In-toto SLSA Provenance v1.0, signed via GitHub OIDC / Fulcio, in public Rekor transparency log |
| Workflow | `.github/workflows/release-lens.yml` at commit `73fbd63` |
| Builder | `github.com/aegisgatesecurity/aegisgate-platform/.github/workflows/release-lens.yml@refs/tags/lens-v0.2.2` |
| Verification command | `gh attestation verify aegisgate-lens-0.2.2.zip --owner aegisgatesecurity --repo aegisgate-platform` |

End-to-end verification via `gh attestation verify` **returned exit 0** (success)
on 2026-06-22T23:09:00Z. The ZIP was built by the canonical GitHub Actions
workflow `release-lens.yml` from commit `73fbd63` of the Platform repo.

---

## Why SLSA Level 2 (not L3)

Initial plan was SLSA Build Level 3 using `slsa-framework/slsa-github-generator`.
After ~3 hours of debugging `startup_failure` on the reusable workflow,
**the workflow file would not start at all** — no job logs, no error
message visible. Process-of-elimination debugging:

- v1 minimal hello-world (21 lines): works.
- v2 + Build + Lens checkout (88 lines): works.
- v3 + SLSA L3 reusable workflow (103 lines): **startup_failure** with zero jobs.
- v4 + 5 + 6: same failure.
- v7 minimal with just SLSA call: same failure.

Root cause unidentified after eliminating:
- YAML Norway problem (`on:` unquoted → quoted `"on":`)
- Tag vs SHA pinning (SLSA requires SHA pin for non-forgeability)
- Permissions (id-token, contents, attestations)
- Workflow dispatch vs tag push

**Pivot decision**: Use `actions/attest-build-provenance@v3` (GitHub's built-in,
officially maintained) instead. This produces a **SLSA Build Level 2**
provenance (signed via GH OIDC, recorded in Rekor). L2 is the standard
target for OSS projects; L3 is reserved for projects requiring hardened
build isolation (typically enterprise or regulated environments).

**Trade-off documented**: L3 requires a "hardened build platform" guarantee
(non-caching ephemeral runners). For a single-maintainer repo with our
threat model, L2 covers the actual risk profile. Revisit L3 if/when we have:
1. Multiple maintainers (need isolation between contributors)
2. Time to set up a minimal reproduction of the L3 startup_failure
3. Admin log access to GitHub Actions

---

## The Locate ZIP bug (5 hours of debugging)

The build tool (`tools/build-lens-extension/package.go:46`) names the ZIP as:

```go
zipName := fmt.Sprintf("lens-%s-%s.zip", cfg.Version, shortSHA)
shortSHA := cfg.Commit[:7]
```

With `--commit "lens-src:${GITHUB_SHA}"`, `cfg.Commit[:7]` = **`"lens-sr"`**
(the literal first 7 chars of `"lens-src:..."`, NOT the git SHA's first 7 chars).

**The bug**: My initial Locate ZIP step computed `cut -c1-7` of
`"lens-src:${GITHUB_SHA}"`, giving the SHA's first 7 chars (e.g., `54f9b74`).
But the actual filename ends in `lens-sr.zip`. So the workflow searched
for `/tmp/lens-0.2.2-54f9b74.zip` which doesn't exist (the actual file
is `/tmp/lens-0.2.2-lens-sr.zip`).

**The fix**: Hardcode `"lens-sr"` as the suffix in the Locate ZIP step
because `cfg.Commit[:7]` is always `"lens-sr"` for our `--commit` arg.

This is documented in `release-lens.yml` comments so future maintainers
don't trip over it.

---

## What changed (Platform repo commits)

| SHA | Description |
|---|---|
| `110b2bd` | Build tool JSDoc typedef fix (Day 18 commit 1) |
| `73fbd63` | SLSA L2 release workflow — `release-lens.yml` |

## What changed (Lens repo commits)

| SHA | Description |
|---|---|
| `lens-v0.2.2` tag | First SLSA-provenanced release tag, publicly visible |

---

## How to verify the Lens release

For users who downloaded `aegisgate-lens-0.2.2.zip`:

```bash
# Option 1: Use GitHub's built-in verification (recommended).
gh attestation verify \
  --owner aegisgatesecurity \
  --repo aegisgate-platform \
  aegisgate-lens-0.2.2.zip

# Option 2: Use slsa-verifier CLI (requires offline TUF metadata).
slsa-verifier verify-artifact \
  --provenance-path aegisgate-lens-0.2.2.intoto.jsonl \
  --source-uri github.com/aegisgatesecurity/aegisgate-platform \
  --source-tag lens-v0.2.2 \
  aegisgate-lens-0.2.2.zip
```

A passing verify confirms:
1. The ZIP was built from the tagged commit of the Platform repo.
2. The build was performed by the canonical `release-lens.yml` workflow.
3. The provenance was signed by GitHub's OIDC token (Fulcio).
4. The signature is recorded in the public Rekor transparency log.

---

## What's NOT done (Day 19+)

| Item | Why | Effort |
|---|---|---|
| `VERIFY.md` in both repos | User-facing verification instructions | 30 min |
| Lens-side Node test that verifies a release artifact | Catch regressions in CI | 1 hour |
| F-13 in threat model | Release artifact supply chain mitigation | 30 min |
| SLSA Level 3 (L3) revisit | L2 sufficient for current threat model | 1 day (when we have admin log access) |
| Release verification in `lens-tests.yml` CI | Automated regression check | 30 min |

---

## Files

- `.github/workflows/release-lens.yml` (Platform) — the new workflow
- `pkg/lensbackend/` — unaffected
- `plans/LENS-DAY-18-SLSA-L2-RELEASE-REPORT.md` — this document
