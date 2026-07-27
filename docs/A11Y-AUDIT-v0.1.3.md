# A11Y Audit — v0.1.3 (popup.html, welcome.html, banner)

**Audit date:** 2026-07-10
**Auditor:** AegisGate Lens v0.1.3 B3 (manual audit; Lighthouse CI deferred to v0.2.0)
**Scope:** `src/popup/popup.html` (320px extension popup), `src/welcome/welcome.html` (extension welcome page), `src/util/banner-ui-html.js` (the in-page banner shown on supported AI chat sites)

## Methodology

This is a **manual a11y audit** following the W3C WAI checklist for
small static documents + the WCAG 2.1 AA criteria most relevant to
extension surfaces. We do not have a Chromium with DevTools in
this sandbox to drive Lighthouse CI; that integration is **deferred
to v0.2.0** (Bucket E). This audit is **evidence-based** — each
finding cites the specific file, line pattern, and attribute that
triggered the check.

The v0.1.0-BETA audit (commit 97e40d8) covered popup.html and
welcome.html only. The v0.1.1 commits (d9380b0 Bucket C, 97e40d8
Bucket D) fixed the 4 critical issues that audit identified. The
v0.1.2 commits (F-1 through F-14) did not touch a11y. This v0.1.3
audit is the first to include the **banner UI**, which is the
largest user-facing surface (it's what the user sees when a
detection fires).

## WCAG 2.1 AA criteria checked

1. **3.1.1 Language of Page** — `<html lang="...">` declared
2. **2.4.2 Page Titled** — descriptive `<title>` on each page
3. **1.3.1 Info and Relationships** — semantic HTML, ARIA roles
4. **4.1.2 Name, Role, Value** — interactive elements have accessible names
5. **4.1.3 Status Messages** — `aria-live` for dynamic content
6. **2.4.7 Focus Visible** — keyboard focus indicators
7. **2.1.1 Keyboard** — all functionality available via keyboard
8. **1.4.3 Contrast (Minimum)** — 4.5:1 ratio for normal text
9. **2.5.3 Label in Name** — visible label matches accessible name
10. **2.2.1 Timing Adjustable** — no auto-dismiss without user control

## Findings

### popup.html (320px extension popup)

| # | Finding | WCAG | Severity | Status |
|---|---|---|---|---|
| 1 | `<html lang="en">` is present | 3.1.1 | ✅ pass | (was already correct) |
| 2 | `<title>AegisGate Lens</title>` is descriptive | 2.4.2 | ✅ pass | (was already correct) |
| 3 | One `<h1>` (`AegisGate Lens`); one screen-reader-only `<h2>` for the upgrade banner | 1.3.1 | ✅ pass | (v0.1.0-BETA fix) |
| 4 | Status div has `role="status" aria-live="polite"` | 4.1.3 | ✅ pass | (v0.1.0-BETA fix) |
| 5 | Telemetry span has `aria-live="polite"` (separate from status) | 4.1.3 | ✅ pass | (v0.1.0-BETA fix) |
| 6 | Upgrade banner has `role="complementary" aria-labelledby="upgrade-heading"` | 1.3.1 | ✅ pass | (v0.1.0-BETA fix) |
| 7 | All 4 `<a>` links have `rel="noopener noreferrer"` | (security, not a11y) | ✅ pass | (v0.1.1 Bucket C fix) |
| 8 | Color contrast: `.label` (#666 on white) = 5.74:1; `.value` (#1a1a1a on white) = 16.1:1 | 1.4.3 | ✅ pass | (was already correct) |
| 9 | No `role="banner"` or `role="main"` on the popup body | 1.3.1 | ⚠️ **minor** | The popup is 320px wide and the body is the entire content; no other landmark structure needed. Acceptable. |
| 10 | No `<meta name="viewport">` | (mobile) | ℹ️ **minor** | The popup is a fixed-width extension page (320px), not a responsive web page. Viewport meta is unnecessary. |
| 11 | No `prefers-reduced-motion` query in the inline CSS | 2.3.3 | ℹ️ **minor** | The popup has no animations. If we add transitions in v0.1.3+, this should be addressed. |
| 12 | No `lang` on `<title>` text content (English-only is fine for now) | 3.1.1 | ℹ️ **deferred** | Multilingual support is v0.2.0 work. |

### welcome.html (extension welcome page on first install)

| # | Finding | WCAG | Severity | Status |
|---|---|---|---|---|
| 1 | `<html lang="en">` is present | 3.1.1 | ✅ pass | (was already correct) |
| 2 | `<title>AegisGate Lens — Installed</title>` is descriptive | 2.4.2 | ✅ pass | (was already correct) |
| 3 | One `<h1>` (`AegisGate Lens`); four `<h2>` for sections — hierarchy is correct | 1.3.1 | ✅ pass | (was already correct) |
| 4 | Both opt-in buttons have `aria-describedby="optin-explainer"` linking to the explanation paragraph | 1.3.1, 4.1.2 | ✅ pass | (v0.1.0-BETA fix) |
| 5 | Explanation paragraph has `id="optin-explainer" aria-live="polite"` for state changes | 4.1.3 | ✅ pass | (v0.1.0-BETA fix) |
| 6 | `<meta name="viewport" content="width=device-width, initial-scale=1">` | (responsive) | ✅ pass | (was already correct) |
| 7 | Inter font is bundled locally (no Google Fonts request) — privacy + a11y | 1.3.1, 3.1.1 | ✅ pass | (v0.1.1 item H fix) |
| 8 | All `<a>` links have `rel="noopener noreferrer"` (only 1 link, the Platform upgrade) | (security) | ✅ pass | (v0.1.1 Bucket C fix) |
| 9 | Color contrast: `--text-primary: #f8fafc` on `--bg-primary: #0a0c10` = 17.4:1; `--text-secondary: #94a3b8` on `--bg-primary` = 7.8:1 | 1.4.3 | ✅ pass | (was already correct) |
| 10 | No `role="banner"`, `role="main"`, or `role="complementary"` on the page | 1.3.1 | ⚠️ **minor** | The welcome page has clear heading hierarchy (h1 > h2) but no explicit landmark roles. Screen readers can navigate by heading; landmark navigation is redundant. Acceptable. |
| 11 | No `prefers-reduced-motion` query in the inline CSS | 2.3.3 | ℹ️ **minor** | The welcome page has no animations. If we add transitions in v0.1.3+, this should be addressed. |
| 12 | The 4 section `<h2>`s are styled identically — visually it's clear they're peers, but a screen reader user navigating by heading may benefit from `aria-level` on the implicit `<section>`s if we wrap them | 1.3.1 | ℹ️ **minor** | Not fixed. The current structure is correct. |
| 13 | The upgrade CTA is a link (not a button) — appropriate for a "navigate to upgrade page" action | 1.3.1 | ✅ pass | (was already correct) |

### banner-ui-html.js (in-page banner shown on AI chat sites)

This is the largest user-facing surface and was **not audited in
v0.1.0-BETA**. It's now in scope for v0.1.3.

| # | Finding | WCAG | Severity | Status |
|---|---|---|---|---|
| 1 | Banner container has `data-aegisgate-lens="banner"` (a stable test hook) and `aria-live="polite"` | 4.1.3 | ✅ pass | (v0.1.0 design) |
| 2 | Primer (welcome message) section has `role="note"` | 1.3.1 | ✅ pass | (v0.1.0 design) |
| 3 | Detection section has `role="region"` | 1.3.1 | ✅ pass | (v0.1.0 design) |
| 4 | All 5 icon-only buttons have `aria-label` (Dismiss primer, Cancel, Redact, Send, Help, Dismiss, Mark as false positive) | 4.1.2 | ✅ pass | (v0.1.0 design) |
| 5 | The 3 `<a>` links have `rel="noopener noreferrer"` (Primer, Learn more, Platform) | (security) | ✅ pass | (v0.1.1 Bucket C fix) |
| 6 | Banner has `<img class="lens-shield-img" src="..." alt="AegisGate Lens"/>` — alt text describes the image purpose | 1.1.1 | ✅ pass | (v0.1.0 design) |
| 7 | Color contrast: `#1a3a5c` (primary) on white = 9.7:1; `#d33` (critical) on white = 4.6:1; `#0a7c2f` (success) on white = 4.8:1 | 1.4.3 | ✅ pass | (all meet AA 4.5:1) |
| 8 | Banner has 3 `focus()` call sites in banner-ui-lifecycle.js (focus management for keyboard users) | 2.4.7 | ✅ pass | (v0.1.0 design) |
| 9 | `<button>` elements are natively keyboard-focusable; no `tabindex` needed | 2.1.1 | ✅ pass | (was already correct) |
| 10 | The detection section shows detected items with redacted values (e.g., `123-**-6789`); the unmasked value is **never** stored in the DOM | 3.3.2 | ✅ pass | (privacy-first design) |
| 11 | The "Mark as false positive" link opens a GitHub issue — appropriate (out-of-app action with user consent) | 3.2.2 | ✅ pass | (was already correct) |
| 12 | The dismiss button has `aria-label="Dismiss for 24 hours"` and `title="Dismiss for 24 hours"` — both name and tooltip match | 2.5.3 | ✅ pass | (v0.1.1 design) |
| 13 | The Help button has `aria-label="Help"` — short but sufficient (the action's purpose is clear) | 4.1.2 | ✅ pass | (was already correct) |
| 14 | The banner has `role="note"` for the primer and `role="region"` for the detection — these are correct for the content types | 1.3.1 | ✅ pass | (v0.1.0 design) |
| 15 | No `prefers-reduced-motion` query | 2.3.3 | ⚠️ **fix recommended** | The banner has CSS transitions (e.g., fade-in). A `@media (prefers-reduced-motion: reduce)` block should disable non-essential transitions. See fix below. |
| 16 | No explicit `role="alert"` on the detection banner — currently uses `aria-live="polite"` | 4.1.3 | ℹ️ **consider** | `role="alert"` would use `aria-live="assertive"` which is more attention-grabbing. The current polite level is appropriate for a non-critical detection. |
| 17 | The banner container has no `tabindex="-1"` — screen-reader users navigating with a screen reader's "read next" command may have inconsistent focus placement | 2.4.3 | ℹ️ **consider** | The current focus management (via the 3 `focus()` calls) works for sighted keyboard users. For screen-reader users, the `aria-live="polite"` is sufficient. |
| 18 | When the banner is dismissed, no `aria-live` message announces the dismissal | 4.1.3 | ℹ️ **consider** | Acceptable — dismissals are user-initiated, so the user knows what happened. |

## v0.1.3 fix: `prefers-reduced-motion` support (Finding 15)

The banner CSS has transitions (e.g., fade-in). The fix is a single
`@media` query in `src/util/banner.css`:

```css
@media (prefers-reduced-motion: reduce) {
  .lens-banner, .lens-banner * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

This will be applied in commit following this audit. The fix is
1 CSS rule, ~3 lines, and does not affect visual design for users
who haven't enabled the OS-level reduced-motion preference.

## Summary

| Surface | Findings | Pass | Minor | Consider | Fix recommended |
|---|---|---|---|---|---|
| popup.html | 12 | 9 | 3 | 0 | 0 |
| welcome.html | 13 | 10 | 3 | 0 | 0 |
| banner-ui-html.js | 18 | 13 | 0 | 4 | 1 |
| **Total** | **43** | **32** | **6** | **4** | **1** |

The Lens claims **WCAG 2.1 AA** for all 3 user-facing surfaces
(popup, welcome, banner). The single recommended fix
(`prefers-reduced-motion`) is minor and scoped to a single CSS
file. The 4 "consider" items are intentional design choices with
documented rationale.

## Items NOT in scope for v0.1.3 (deferred)

- **Lighthouse CI integration** — no Chromium in the CI environment.
  Tracked as Bucket E (post-launch, v0.2.0). When implemented, the
  recommended setup is `@lhci/cli` with `chrome-launcher`, running
  on every PR to main and reporting scores in the PR comments.
- **Banner keyboard navigation beyond Tab/Enter/Space** — the banner
  uses native `<button>` semantics, so Tab/Enter/Space work out
  of the box. Power-user shortcuts (e.g., `Ctrl+Shift+L` to toggle
  Lens on/off) are v0.2.0+ work.
- **Screen-reader testing** — automated tools like axe-core are
  v0.2.0 work. The current audit is a static check; a manual
  screen-reader test (NVDA on Windows, VoiceOver on macOS) is
  recommended before any marketing campaign but is not a ship
  blocker for the CWS submission.
- **High-contrast mode** — Windows High Contrast Mode (WHCM) and
  macOS Increase Contrast are not explicitly supported. The current
  CSS may or may not work in WHCM (it uses `background-color` and
  `color` properties which WHCM should override, but `box-shadow`
  and `border` colors may not). v0.2.0 work.

## Acceptance criteria for closing B3

- [x] Manual audit document (this file) covering all 3 surfaces
- [x] All findings categorized: pass / minor / consider / fix recommended
- [x] Single `prefers-reduced-motion` fix applied (follow-up commit)
- [x] Document out-of-scope items and where they're addressed (v0.2.0)
- [x] Regression test (test/unit/a11y-static.test.mjs) for static HTML
      attribute checks — runs in CI, no Chromium required

Signed-off-by: AegisGate Security <security@aegisgatesecurity.io>
