# AegisGate Lens — Runbook

**Audience**: AegisGate Security, LLC (the 1-person maintainer)
**Purpose**: What to do when something breaks. Read this before debugging.

Last updated: 2026-07-12 (Lens v0.1.4)

---

## Triage priorities (in order)

1. **Critical security issue** (XSS, RCE, data exfiltration) — email `security@aegisgatesecurity.io` and patch within 24 hours
2. **Lens breaks on a specific provider** (e.g., chatgpt.com crashes) — patch within 72 hours
3. **FPR spike** (Lens warns on benign content) — patch within 1 week
4. **FNR spike** (Lens misses a clear PII) — patch within 1 week
5. **UI/UX bug** (banner doesn't show, dismiss doesn't work) — patch within 2 weeks
6. **Documentation/typo** — fix opportunistically

---

## Emergency: How to disable Lens on a specific host

If Lens is causing a critical issue on a specific AI provider, you can disable it **without pushing a new release** by adding a host block to the manifest's `content_scripts.matches` array. This requires pushing a new CWS version (24-72 hour review).

**Quicker fix**: ask the affected user to disable Lens via the popup:
- Open Lens popup
- Uncheck "Enable on this site" (or equivalent — see `src/popup/popup.html`)

**Fastest fix (for known-good site)**: add the kill switch (see Gap 11 below).

---

## When the bundle is stale and F-7 fails

The F-7 e2e test enforces: `test/headless-smoke/bundle.js` must be built AFTER the most recent `src/` change. If you see this fail in CI:

```bash
cd aegisgate-lens
python3 tools/ci/build-bundle.py
git add test/headless-smoke/bundle.js
git commit -m "fix: rebuild bundle"
```

This is a 30-second fix. CI will pass on the next run.

---

## When the smoke test fails in CI

The smoke test runs the bundle in a real Chromium browser. Common failure modes:

### "navigate failed: CDP timeout waiting for Page.navigate"
- **Cause**: Chromium is busy or the test page didn't load
- **Fix**: Re-run the CI job (most failures are flaky on first run)
- **If persistent**: check if any provider changed their DOM (selectors.js would need updating)

### "expected >=1 detection, got 0"
- **Cause**: A regex pattern no longer matches the test text
- **Fix**: Check if the provider changed their DOM (input/textarea selector)
- **Or**: Check if the regex was tightened too much (over-fitting)

### "__lensPromptDetect not set"
- **Cause**: Content script didn't attach to the page
- **Fix**: Check that the manifest's `content_scripts.matches` includes the test page's URL
- **Or**: Check that the test page is HTTPS (Chrome requires HTTPS for content scripts)

---

## When a user reports a false positive (FPR)

1. Ask the user for the **structure** of the text, not the content (privacy!)
2. Reproduce locally with a synthetic version of the text
3. If a regex is matching too broadly, tighten it in `src/detectors/regex/*.js`
4. Add a regression test in `test/unit/`
5. Re-run the smoke (verify no FNR regression)

---

## When a user reports a false negative (FNR)

1. Ask for the structure, not the content
2. Reproduce locally
3. Check if there's a regex that should match — if so, fix it
4. If there's no regex, consider adding one (132 patterns now, room to grow)
5. Add a regression test

---

## When CI fails on a PR

1. Check the GitHub Actions log (link in the PR comments)
2. Identify which job failed (smoke, mini-smoke, lint, security)
3. For smoke: see "When the smoke test fails" above
4. For lint: run `bash tools/lint.sh` locally to see the failure
5. For security: check the Trivy scan output for the specific CVE

---

## How to roll back a CWS submission

1. Go to https://chrome.google.com/webstore/devconsole/
2. Find the AegisGate Lens listing (item ID: `emolejlnnnhcdeinpgcjdlldnmgfjmde`)
3. Click "Cancel" on the pending submission (if under review)
4. Or: publish a hotfix version (build, zip, submit, publish)

**Warning**: CWS rollbacks are slow (24-72 hours). For critical issues, ask users to disable Lens via the popup.

---

## How to cut a new release

1. Update `CHANGELOG.md` with the new version's entry
2. Bump `version` in `src/manifest.json` (semver)
3. Update `docs/FACTS.md` to reflect the new version
4. Commit + push the release branch
5. Merge to `main` (after CWS approval)
6. Tag the release: `git tag -s v0.1.5 -m "v0.1.5: <summary>"`
7. Push the tag: `git push origin v0.1.5`
8. Create a GitHub Release from the tag (web UI)
9. Submit the new zip to CWS: `python3 tools/ci/build-bundle.py && zip -r lens-X.Y.Z-lens-sr.zip ...`
10. Update the CWS listing text per the v0.1.4 LESSONS learned

---

## The `__lensDisabled` kill switch

If a critical bug ships to production and you need to disable Lens immediately:

1. Push a v0.1.5 with the kill switch:
   - Add `globalThis.__lensDisabled = true` at the top of `src/content.js`
   - The content script checks this flag and bails out if set
2. Users update to v0.1.5 and Lens is disabled
3. Roll out the real fix in v0.1.6

**Why this matters**: between "discover critical bug" and "CWS approves new version", users could lose 24-72 hours of productivity. The kill switch lets you respond in 24 hours.

---

## Emergency contact

- **Security issues**: `security@aegisgatesecurity.io`
- **CWS dashboard**: https://chrome.google.com/webstore/devconsole/
- **GitHub**: https://github.com/aegisgatesecurity/aegisgate-lens
- **GitHub Actions**: https://github.com/aegisgatesecurity/aegisgate-lens/actions

---

## See also

- [SECURITY.md](SECURITY.md) — security disclosure policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [CHANGELOG.md](CHANGELOG.md) — what changed
- [docs/FACTS.md](docs/FACTS.md) — single source of truth for verifiable claims
- [docs/V0.1.4-HOUSEKEEPING-ANALYSIS-2026-07-12.md](docs/V0.1.4-HOUSEKEEPING-ANALYSIS-2026-07-12.md) — pre-merge checklist
- [docs/V0.1.4-BLIND-SPOT-ANALYSIS-2026-07-12.md](docs/V0.1.4-BLIND-SPOT-ANALYSIS-2026-07-12.md) — what's missing

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
