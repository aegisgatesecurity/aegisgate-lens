# AegisGate Lens v0.1.0-beta — Banner Design Spec (Step 3f input)

**Date**: 2026-07-04 16:10 UTC
**Status**: Pre-implementation design spec
**Author**: this AI, informed by the existing corporate site at
`/home/chaos/Desktop/AegisGate/websites/aegisgate-site/`

## Context

The AegisGate Lens extension's warning banner is the user's
**first and only contact** with the privacy product. The banner
must:

1. **Catch attention** without being alarming
2. **Mirror the corporate site** so users recognize the brand
3. **Show what was found** without showing the full value (e.g.
   "4111…1111" not "4111-1111-1111-1111")
4. **Let the user decide** — send anyway, redact, or cancel
5. **Be honest** about privacy — "we never sent your prompt to
   any server"

## Brand assets extracted from the corporate site

From `themes/aegisgate/assets/css/main.css`:

```css
--bg-primary: #0a0c10;        /* Deep midnight black-blue */
--bg-secondary: #11141d;      /* Subtle lift for cards */
--bg-tertiary: #1a1f2e;       /* Elevated surfaces */
--primary: #38bdf8;           /* Sophisticated Cyan */
--secondary: #10b981;         /* Emerald for success */
--accent: #f43f5e;            /* Rose for critical */
--text-primary: #f8fafc;      /* Clean white-grey */
--text-secondary: #94a3b8;    /* Muted slate */
--text-muted: #64748b;        /* Deep slate */
--border-color: rgba(51, 65, 85, 0.5);
--glass-bg: rgba(17, 20, 29, 0.7);
--radius-sm: 6px;
--radius-md: 12px;
```

From the existing alert styles:

```css
.alert { padding: 1rem 1.5rem; border-radius: 6px;
         border-left: 4px solid; }
.alert-info    { bg rgba(0, 173, 216, 0.1);  border var(--primary); }
.alert-warning { bg rgba(255, 189, 46, 0.1);  border #ffbd2e; }
.alert-danger  { bg rgba(249, 117, 131, 0.1); border var(--accent); }
.alert-success { bg rgba(35, 134, 54, 0.1);  border var(--secondary); }
```

The site already uses the same `var(--primary)` cyan for the
Lens "Install from Chrome Web Store" callout. The banner should
match that exact palette so users recognize it.

## Logo / header

The corporate logo is a metallic shield with the "AG" monogram
and "AEGISGATE SECURITY" wordmark. For the banner header we
will use:

- A small inline SVG version of the shield (or a CSS-drawn
  approximation: triangle + padlock outline + cyan accent)
- The wordmark "AegisGate Lens" (shorter than "AegisGate
  Security" to distinguish the product)
- A small "(?) help" link in the top-right that opens the
  welcome page in a new tab (or shows inline help)

## Severity → color mapping (matches site)

| Severity | Color | Rationale |
|---|---|---|
| critical | `--accent` rose (#f43f5e) | SSO tokens, credit cards, PEM keys, passports — danger |
| high | `#ffbd2e` amber | SSN, bank accounts, OAuth tokens, prompt injection — caution |
| medium | `--primary` cyan (#38bdf8) | Email, phone, IP, EU AI Act — informational |
| low | `--text-muted` slate | IP-only, EU AI Act robustness — low priority |

We borrow the site's exact colors and add `#ffbd2e` amber for
"high" (not in the site's CSS but in line with the warning
palette).

## Layout (4 sections, top to bottom)

```
┌──────────────────────────────────────────────────────────────┐
│ [🛡️ AegisGate Lens] 3 sensitive items detected   [×]  [?] │ <- header
├──────────────────────────────────────────────────────────────┤
│  ● Credit card number  [CRITICAL]   match: 4111…1111        │
│  ● Email address      [MEDIUM]     match: j***@e****.com   │
│  ● AWS access key     [CRITICAL]   match: AKIA…MPLE         │
├──────────────────────────────────────────────────────────────┤
│  These items are visible to the AI provider when you send.   │
│  AegisGate Lens never sends your prompt to any server.      │
├──────────────────────────────────────────────────────────────┤
│  [Cancel send]  [Edit & redact]  [Send anyway]              │
└──────────────────────────────────────────────────────────────┘
```

### Section details

**Header** (24px tall, dark glass background):
- Left: shield SVG (16x16) + "AegisGate Lens" wordmark (12px, weight 600)
- Center: "{N} sensitive item(s) detected" (the count, with plural)
- Right: help link "(?)" (12px, cyan) + close "×" (14px, muted)

**Detection list** (one row per unique category, max 8 visible
with scroll):
- 4px colored left border (severity color)
- Category name (12px, primary text)
- Severity pill (10px, severity color bg, dark text)
- "match: " + masked value (12px, muted)
- "—" (12px, muted)
- Privacy note for sensitive categories (e.g. "your credit
  card number is shown masked because we don't echo secrets")

**Privacy footer** (12px, secondary text):
- Two sentences: one about what the AI provider will see, one
  about Lens's privacy posture

**Action row** (3 buttons + 1 dismiss):
- "Cancel send" (secondary, default styling)
- "Edit & redact" (primary, cyan) — auto-replaces detected values
  with `[REDACTED]`
- "Send anyway" (ghost, no border, just text) — opt-in, also
  records the dismiss for 24 hours

## Behavior

### Trigger

The banner appears when the user:
- Types into the prompt input and a detection fires
- Presses Enter (or clicks send) with detections present
- Pastes content that contains detections

### Dismissal

- "Cancel send" closes the banner; the input keeps its text
- "×" in the header closes the banner for 24 hours (same
  domain + same category). After 24h, the warning reappears.
- "Send anyway" closes the banner and submits the prompt
- "Edit & redact" replaces each detected value with `[REDACTED]`
  in the input, closes the banner, and lets the user review

### Auto-close

If the user clears the input (or changes the prompt such that
no detections remain), the banner fades out after 300ms.

### Position

The banner is inserted as a sibling of the input element,
immediately above the input (so it pushes the input down
slightly when it appears). It is NOT a floating tooltip — it
must not cover the AI provider's UI.

## Implementation constraints

- **No external CSS** — all styles are inline in the JS module
  (or as a sibling CSS file loaded by the content script)
- **No external fonts** — use the system font stack
  (`-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
  Helvetica, Arial, sans-serif`) so we don't trigger a font
  download in the page
- **No external images** — the shield icon is an inline SVG
- **No shadow DOM** — we attach the banner to the regular DOM
  tree; we tag it with `data-aegisgate-lens="banner"` so the
  page's CSS doesn't affect it (and we apply our own CSS with
  higher specificity via `!important` on critical rules)
- **z-index: 2147483647** — the maximum 32-bit signed integer
  z-index, so the banner always sits on top of any page UI

## Privacy posture (in the banner copy)

- The footer text "AegisGate Lens never sends your prompt to
  any server" must be present on every banner
- A "Learn more" link points to `lens.aegisgatesecurity.io/privacy`
  (or the GitHub README in the local-only case)
- The "match: " value is masked: show first 4 and last 4
  characters only, with `…` in between

## Accessibility

- The banner has `role="alert"` and `aria-live="polite"` so
  screen readers announce the warning
- The action buttons have `aria-label` attributes
- The dismiss "×" is keyboard-accessible (tab + Enter)
- Color is not the only severity signal — there's also a
  text label ([CRITICAL], [HIGH], etc.)

## What this spec does NOT cover

- The detection itself (Step 3e: detectors/index.js, the
  6-facet dispatcher)
- The ML facets (Step 3h: toxicity + prompt-injection)
- The welcome page (separate, in 3a)
- The popup (Step 3j: threat-intel badge)
- The build tool (Step 3k)

## Sign-off

This spec is the input to Step 3f. The user has approved the
brand integration. The implementation will:

1. Add `src/util/banner-ui.js` with the full banner module
2. Add `src/assets/banner.css` with the brand-matched styles
3. Update `content.js` to call `banner-ui.show()` and
   `banner-ui.hide()` instead of the placeholder `confirm()`
4. Add `src/assets/banner.css` to `web_accessible_resources`
   in the manifest so the content script can load it
5. Verify in headless Chrome + real browser

The user will sign off after 3e is complete; 3f can begin
immediately after.
