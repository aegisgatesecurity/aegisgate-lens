# Changelog

All notable changes to AegisGate Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- v0.1.2 patch release: 3 bug fixes (F-1, F-2, F-10) and 3 doc fixes
  (F-3, F-4, F-8). See the v0.1.2 entry below for details. v0.1.2 is
  a patch on the v0.1.1 branch; it does NOT introduce new features
  or new detection facets.

## [0.1.4] — 2026-07-12

### Added
- **mini/ sub-binary** (32 -> 56 -> 128 tests): A new per-provider mini
  smoke that exercises the full Lens flow (16 test cases) on each of
  the 8 active providers (8 hosts x 16 cases = 128 tests). 5/5 stable,
  gate=true, ec=0 per Lesson #113. Uses the REAL
  Page.addScriptToEvaluateOnNewDocument (persistent injection) so the
  bundle survives cross-origin navigations.
- **8th provider mock** (`test/headless-smoke/mock/platform-testdata/mistral.html`):
  was missing from the public repo; now present.
- **Per-host mock routing** in mini: 9 mock files served by Host header.
  The smoke navigates to https://localhost:PORT/ with a per-host
  Host header so the mock serves the right per-provider DOM shape.
- **Lightweight shell linter** (`tools/lint.sh`, 12 checks): catches
  console.log, var, ==, TODO, eval, dynamic innerHTML, missing JSDoc,
  trailing whitespace, line length > 120, tabs, double-blank-lines,
  and debugger statements. Runs in ~5s. NO npm required.
  Integrated as a new `lint` job in .github/workflows/security.yml.
- **F-7 e2e test category** (test/e2e/manifest-validation.test.mjs,
  20 tests): MV3 manifest validation, CSP strictness, permission
  bounds, 3-way host consistency (manifest <-> selectors.js <-> SW),
  per-provider host coverage, eval/Function absence, dynamic innerHTML
  absence, 8 providers from FACTS.md, bundle size + freshness checks,
  and 9 platform-specific mock consistency tests.

### Changed
- **F-7 bonus fix**: src/util/prompt-detect-dom.js no longer uses
  .innerHTML for the "🛡️ Lens active" chip. The security.yml CSP gate
  is now satisfied for src/util/ outside of banner-ui-*.js.

### Test counts (post-v0.1.4)
- Node: 497/497 passing (was 477, +20 from F-7 e2e tests)
- Go: 3/3 passing
- v0.1.3 headless smoke: 5/5 stable, 16/16 each, gate=true
- mini smoke (per-host, 128 tests): 5/5 stable, 128/128 each, gate=true
- F-7 e2e: 20/20 passing
- Linter: 12/12 checks PASS, 0 warnings, 0 failures
- 12 session commits, all GPG-signed

## [0.1.2] — 2026-07-09

### Fixed
- **F-1 (manifest host sync)**: `manifest.json`, `src/util/selectors.js`
  PROVIDERS, and `src/background.js` `providerDomains` were out of
  sync. Removed legacy `duckduckgo.com`, `x.com`, and `twitter.com`
  entries (out of v0.1.x scope). Added `copilot.cloud.microsoft`,
  `www.perplexity.ai`, `www.grok.com`, `chat.mistral.ai`, and
  `le-chat.mistral.ai` to all three sources. Added a unit test
  (`test/unit/manifest-hosts.test.mjs`) that asserts all three are
  mutually equal and free of legacy hosts.
- **F-2 (opt-in storage key)**: `welcome.js`, `popup.js`, and
  `background.js` were using two different storage keys (`opt_in` and
  `aegisgate_lens_opt_in`) and two different value shapes. Unified on
  the canonical `STORAGE_KEYS.OPT_IN` key and the nested-object shape
  `{ enabled, last_changed_at, lens_version }`. The SW's `getOptIn()`
  and `setOptIn()` now read/write the unified shape. `handleGetOptInState`
  includes a backwards-compat `opted_in` boolean alias for any older
  consumer. v0.1.0-beta bare-boolean values are accepted as a
  backwards-compat read.
- **F-10 (popup message path)**: `popup.js` no longer reads
  `chrome.storage.local` directly. It now sends `GET_OPT_IN_STATE`
  via `chrome.runtime.sendMessage` and the SW responds with the
  canonical state. A 500ms timeout falls back to a direct storage
  read so a sleeping SW doesn't show stale data forever.

### Changed
- **F-3 (CHANGELOG accuracy)**: The v0.1.0-beta entry was rewritten
  to say "4 regex detection facets, no ML" (was: "all 6 detection
  facets, the tiered ML architecture"). The v0.1.0-beta ship is
  regex-only; the ML tier was burned down in v0.2.0 work that was
  explicitly deferred.
- **F-4 (architecture doc accuracy)**: `docs/ARCHITECTURE-v0.1.0-BETA.md`
  non-negotiable #9 was rewritten. The 90-day retention clause
  described a v0.2.0 server-side architecture that does not exist
  in v0.1.0-beta (Lens is local-only by default; opt-in telemetry
  is hashed, not retained).
- **F-8 (README OWASP LLM coverage)**: The "How Lens Compares"
  table in `README.md` was updated from "OWASP LLM Top 10 coverage:
  6/10" to "10/10" (the schema defines all 10 `owasp_llm0N`
  categories and the compliance detector fires on all 10).

### Notes
- v0.1.2 is a **patch release on the v0.1.1 branch**. It does NOT
  change the v0.1.0-beta CWS submission (the CWS zip is the
  v0.1.0-beta freeze; CWS review of v0.1.0-beta is in flight as of
  2026-07-09). After CWS approves v0.1.0-beta, v0.1.1 → main and
  v0.1.2 → main are merged in that order.
- The CWS listing is NOT updated for v0.1.2 in this release. The
  v0.1.0-beta listing stays in review. A separate CWS update for
  v0.1.2 will be evaluated after the v0.1.0-beta listing is live
  and the user base is large enough to warrant a CWS update.

## [0.1.1] — 2026-07-08

### Added
- **Schema fix (16 missing categories)**: `src/privacy/schema.js` was
  missing 16 of 65+ schema categories. Added the missing
  `pii_*` (driver's license, address, residence, vehicle, etc.),
  `secret_*` (Slack, Discord, Twilio, SendGrid, Mailgun, Heroku,
  GitLab, npm, PyPI, OAuth, CI), and `compliance.*` entries
  (additional OWASP LLM Top 10, MITRE ATLAS, EU AI Act articles).
  Toxicity facet definitions (severity thresholds, ml_threshold
  reference) were also fixed. (commit `c826d31`, merged in
  `9f0881f`)
- **4 missing docs (Yellow Argon pre-CWS)**: Added
  `docs/THREAT-MODEL-v0.1.0-BETA.md` (the long-form threat model for
  security auditors), `docs/MODEL-CARD.md` (Google Model Cards v1
  format, explicitly notes "no ML — deterministic pattern matching"),
  `docs/TERMS-OF-SERVICE.md`, and `docs/DPA-ADDENDUM.md`. (commit
  `03f98e3`)
- **First-run onboarding + UX polish (Bucket C)**: The popup shows
  an upgrade CTA to AegisGate Platform with feature bullets
  (server-side enforcement, automated redaction, enterprise SSO,
  HIPAA/PCI/SOC 2/EU AI Act compliance). The welcome page bundles
  the Inter font locally (no third-party request to
  `fonts.googleapis.com`). All `target="_blank"` links gained
  `rel="noopener noreferrer"`. (commits `61ade61`, `ec83beb`,
  `dfeef00`, `8b04249`, `51fbc59`, `d9380b0`)

### Changed
- **A11y/i18n hardening (Bucket D)**: popup.html and welcome.html
  gained ARIA live regions, complementary roles, and screen-reader
  improvements. The dismissal module now uses `chrome.storage.session`
  (auto-cleared on browser restart) for the 24h per-domain
  dismissals. (commit `97e40d8`)
- **Public threat model published**: `docs/THREAT-MODEL.md` is now
  the public CC-BY-4.0 version; the internal auditor-facing
  version lives in the Platform monorepo (under NDA). (commit
  `51fbc59`)
- **Yellow Argon fix**: README and CWS listing copy were reviewed
  to remove language that could trigger CWS rejection (no provider
  names in the description, no ML cascade claims, no stale
  accuracy numbers). (commit `8b04249`)

### Refactored
- **Test infrastructure (Bucket B)**: Extracted `MockChrome` to
  `test/helpers/mock-chrome.js` and added a shared `loadModule`
  helper. The previous inline mocks were duplicated across 3 test
  files; the new helpers reduce drift and make new tests easier
  to write. (commit `00cb218`)
- **banner-ui.js split (Bucket A item 1)**: The 516-line
  `src/util/banner-ui.js` was split into 3 per-concern sub-files
  (`banner-ui-formatters.js`, `banner-ui-html.js`,
  `banner-ui-lifecycle.js`) plus the aggregator. The formatters
  (maskValue, formatCategory, escapeHtml) and HTML builders
  (createBannerElement, buildBannerHTML, buildDismissFormHTML) are
  independently testable. (commit `65bb6ed`)
- **prompt-detect.js split (Bucket A item 3)**: The 335-line
  `src/util/prompt-detect.js` was split into 2 per-group sub-files
  (`prompt-detect-dom.js`, `prompt-detect-lifecycle.js`) plus the
  aggregator. (commit `86125f1`)
- **pii.js split (Bucket A item 2)**: The 815-line
  `src/detectors/regex/pii.js` was split into 4 per-group sub-files
  (`pii-us-core.js`, `pii-us-extended.js`, `pii-international-id.js`,
  `pii-financial.js`) plus the aggregator. (commit `45a0acf`)
- **Constants extracted (Bucket A item 7)**: Magic numbers (DEBOUNCE_MS,
  BANNER_Z_INDEX, STORAGE_KEYS, COLORS, SEVERITY, FACETS, URLS) that
  were scattered across 5 files are now in `src/util/constants.js`,
  a single source of truth. (commit `aba1fd3`)
- **JSDoc typedefs added (Bucket A item 4)**: `src/util/typedefs.js`
  documents the runtime shape of every module export (LensConstants,
  LensLogger, LensSelectors, LensPromptDetect, LensDispatcher,
  LensDismiss, LensBannerUI). Editors with TypeScript IntelliSense
  can now type-check against the actual runtime shape. (commit
  `cb8bab2`)
- **Bootstrap module added (Bucket A item 5)**: `src/bootstrap.js`
  documents the 17-script content-script load order via a
  `MODULE_REGISTRY` array and a `whenReady()` helper. (commit
  `fb43709`)
- **Banner inline style moved to .lens-item-overflow class**: The
  banner's inline `style=` attributes for the overflow "+ N more"
  line were extracted to a `.lens-item-overflow` CSS class. The
  popup and welcome pages' inline `<style>` blocks were documented
  as intentional (chrome-extension:// pages don't need external
  CSS). (commit `92cc2ff`)

### Fixed
- **README test count and copy**: The "Why Lens with Chrome" section
  copy was tightened and the test count was updated. (commit
  `5569f47`)

## [0.1.0-beta] — 2026-07-04

### Added
- **First public release of AegisGate Lens.** A clean-whiteboard
  rebuild of the product. Ships with **4 regex detection facets**
  (PII, Secrets, XSS/Source, Compliance) and **120 patterns** across
  **8 supported AI chat providers** (ChatGPT, Claude, Gemini,
  Microsoft Copilot, Perplexity, Duck.ai, Grok, Mistral). The
  detector is **100% on-device**: no prompt content, URLs, page
  content, or user identifier ever leaves the browser. Telemetry is
  opt-in by default; opt-in state is hashed (SHA-256 truncated to
  16 hex chars) before any send.
- **ML tier not included in v0.1.0-beta.** v0.2.0 design called
  for a tiered architecture (regex + ModernBERT-base + Longformer-base).
  That work was explicitly burned down in the v0.2.0 sprint per
  Lesson #99 (model-capacity is the ceiling). v0.1.0-beta ships
  regex-only. The 6th and 7th facets (toxicity, prompt-injection)
  are reserved in `schema.js` but have no detector in v0.1.x.
- **SPA-aware attach via MutationObserver**: Modern AI chat UIs
  are React SPAs that re-mount the input element on state change.
  `document_idle` does not fire reliably on these pages. The
  MutationObserver pattern in `src/util/prompt-detect.js` re-attaches
  to the input field whenever the DOM changes. (Architecture doc
  Section 9.)
- **Schema-validated events**: Detection events are validated
  against `src/privacy/schema.js` (facet, category enum, severity
  enum, user action enum). Bad events are dropped, not sent.
- **12 non-negotiables**: The privacy-first non-negotiables (no
  prompt content egress, no URLs, no page content, no user ID,
  opt-in by default, Apache 2.0 OSS, privacy policy published,
  no third-party runtime dependencies, etc.) are documented in
  `docs/ARCHITECTURE-v0.1.0-BETA.md` and enforced in the build.
- **Detection metrics (locked 2026-07-08)**: 98.99% recall on 5,930
  high-risk PII records across 5 public corpora. 7.40% FPR on
  30,000 real user prompts (OASST1 + ultrachat). 0.847ms p99
  per-keystroke latency. 6/6 headless smoke tests, 328/328 unit
  tests, 18/18 schema categories.
- `docs/ARCHITECTURE-v0.1.0-BETA.md` — the binding architectural
  spec.
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

[Unreleased]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.1.0-beta...v0.1.2
[0.1.1]: https://github.com/aegisgatesecurity/aegisgate-lens/compare/v0.1.0-beta...v0.1.1
[0.1.0-beta]: https://github.com/aegisgatesecurity/aegisgate-lens/releases/tag/v0.1.0-beta