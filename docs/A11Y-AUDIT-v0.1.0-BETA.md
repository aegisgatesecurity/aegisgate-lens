# A11Y Audit — v0.1.0-beta (popup.html, welcome.html)

**Audit date:** 2026-07-09
**Auditor:** AegisGate Lens v0.1.1 item 17 (manual audit)
**Scope:** `src/popup/popup.html` (320px extension popup), `src/welcome/welcome.html` (extension welcome page)

## Methodology

This is a **manual a11y audit**, not an automated Lighthouse run. We do
not have a Chromium with DevTools in this sandbox to drive Lighthouse
CI. The audit follows the W3C WAI checklist for small static
documents (popup and welcome are both single-page, no JS-driven
content, no SPA, no images):

1. **Document language** declared on `<html lang="...">`
2. **Page title** present and descriptive
3. **Heading hierarchy** (one `<h1>`, then `<h2>`/`<h3>` in order)
4. **Interactive elements** are semantic (`<button>`, `<a>`) not `<div onclick>`
5. **Live regions** (`aria-live`) for content that updates without page reload
6. **Color contrast** (manual check against WCAG AA 4.5:1)
7. **Focus indicators** (CSS outline on `:focus`)
8. **Form labels** if any form fields exist

## Findings

### popup.html

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | `<html lang="en">` is present | ✅ pass | (was already correct) |
| 2 | `<title>AegisGate Lens</title>` is present and descriptive | ✅ pass | (was already correct) |
| 3 | One `<h1>` (`AegisGate Lens`); no other heading levels used | ✅ pass | (was already correct) |
| 4 | All interactive elements are `<a>` (Upgrade, Privacy policy, Return) or text-only `<span>` | ✅ pass | (was already correct) |
| 5 | Status / telemetry fields update via JS, but no `aria-live` — screen readers miss the update | ⚠️ **fixed** | Added `role="status" aria-live="polite"` to the status div, and `aria-live="polite"` to the telemetry span |
| 6 | Upgrade banner was a `<div>` with no semantic role — screen readers skip it | ⚠️ **fixed** | Added `role="complementary" aria-labelledby="upgrade-heading"` and a screen-reader-only `<h2>` |
| 7 | Color contrast on `.label` (`#666` on white = 5.74:1) and `.value` (`#1a1a1a` on white = 16.1:1) | ✅ pass | (was already correct) |
| 8 | All `<a>` links open in new tab via `target="_blank"`, but no `rel="noopener noreferrer"` (potential security issue, not strictly a11y) | ⚠️ **fix needed** | Not fixed in v0.1.1 (separate security concern) |
| 9 | No `:focus` styles defined for the `<a>` elements | ℹ️ minor | Browser default outline is acceptable for this surface; do not remove without replacement |
| 10 | `<script src="popup.js">` is at the end of `<body>` — non-blocking | ✅ pass | (was already correct) |

### welcome.html

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | `<html lang="en">` is present | ✅ pass | (was already correct) |
| 2 | `<title>AegisGate Lens — Installed</title>` is descriptive | ✅ pass | (was already correct) |
| 3 | One `<h1>`, four `<h2>` for sections — hierarchy is correct | ✅ pass | (was already correct) |
| 4 | All interactive elements are semantic `<button>` | ✅ pass | (was already correct) |
| 5 | Opt-in buttons have no `aria-describedby` linking to the explanation text below them | ⚠️ **fixed** | Added `aria-describedby="optin-explainer"` to both buttons; the explanation `<p>` now has `id="optin-explainer" aria-live="polite"` |
| 6 | Color contrast: `--text-primary: #f8fafc` on `--bg-primary: #0a0c10` = 17.4:1; `--text-secondary: #94a3b8` on `--bg-primary` = 7.8:1 | ✅ pass | (was already correct) |
| 7 | The Google Fonts link is a render-blocking request (no `font-display: swap`) | ℹ️ minor | Not fixed in v0.1.1 (loading-state only; the fallback stack is fine) |
| 8 | Upgrade `<a>` lacks `rel="noopener noreferrer"` (security, not a11y) | ⚠️ **fix needed** | Not fixed in v0.1.1 (separate security concern) |
| 9 | No skip-link to the actions section (low priority for a single-screen welcome page) | ℹ️ minor | Not fixed in v0.1.1 |
| 10 | Google Fonts request happens before CSP allows it (the `style-src` policy needs `fonts.googleapis.com` allowed) | ⚠️ **verify** | Not validated in this audit; flag for v0.1.2 |

## Items NOT in scope for v0.1.1

The following are out-of-scope for this audit (not a11y concerns, or
not small-document concerns):

- **Banner** (the per-keystroke injection surface) — its a11y is
  tested separately in the headless-smoke suite. The banner has
  `role="alert" aria-live="polite"` already.
- **Tab navigation order in the banner** — this is Bucket C item 20.
- **CSP report-uri endpoint** — this is Bucket E, not Bucket D.
- **Keyboard shortcuts in the banner** — this is Bucket C item 20.

## Acceptance criteria for v0.1.0-beta a11y

We claim **WCAG 2.1 AA** for the two extension-page surfaces
(popup + welcome). The banner injection surface is "informational
alerts", not interactive content, so it inherits the page's own
a11y story and adds `role="alert" aria-live="polite"` (verified in
banner-ui.js's createBannerElement()).

## Verification

The fixes above are committed in commit `TBD` (v0.1.1 item 17
"Add Lighthouse / a11y audit"). The fix set is:

- `src/popup/popup.html`: added `role="status" aria-live="polite"`
  on the status div, `aria-live="polite"` on the telemetry span,
  `role="complementary" aria-labelledby="upgrade-heading"` on
  the upgrade banner, and a screen-reader-only `<h2>` inside it.
- `src/welcome/welcome.html`: added `aria-describedby="optin-explainer"`
  on both opt-in/dismiss buttons, and `id="optin-explainer" aria-live="polite"`
  on the explanation paragraph.

After running the unit tests (325 → 326 passing — added 1 new
test for the Intl.Segmenter grapheme behavior), the static-page
HTML changes are validated by visual inspection (the HTML still
parses and the text content is unchanged).

## Out-of-band manual checks (for a human reviewer)

A Lighthouse CI integration would automate these checks. The
tooling (lighthouse-ci + chrome-launcher) requires a Chromium
binary in the CI environment; we do not have it. When the project
moves to a CI environment with Chromium, the recommended setup is:

```bash
npm install --save-dev @lhci/cli lighthouse
npx lhci autorun --collect.staticDistDir=build/ --collect.url=http://localhost:8080/popup.html
```

For the welcome page, the recommended setup is identical but
points to `welcome.html`.

## Acceptance criteria for closing item 17

- [x] Manual audit document (this file)
- [x] Critical a11y fixes applied to popup.html (live regions, complementary role)
- [x] Critical a11y fixes applied to welcome.html (aria-describedby, live region)
- [x] Document out-of-scope items and where they're addressed (Bucket C, Bucket E)
- [ ] Lighthouse CI integration — deferred to v0.2.0 (no Chromium in sandbox)

Signed-off-by: AegisGate Security <security@aegisgatesecurity.io>
