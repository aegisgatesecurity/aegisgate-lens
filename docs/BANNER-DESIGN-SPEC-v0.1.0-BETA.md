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

## User decisions (2026-07-04 16:25)

1. **Color mapping**: approved as critical=rose / high=amber /
   medium=cyan / low=slate (the site's exact palette)
2. **Action button order**: approved as
   Cancel / Edit & redact / Send anyway (left to right)
3. **Match masking**: approved as first 4 + `…` + last 4
   (e.g. `4111…1111`) for most types; emails get
   `j***@e****.com` style
4. **"Learn more" link**: points to the **GitHub README**
   (`github.com/aegisgatesecurity/aegisgate-lens#readme`).
   The corporate site doesn't have public-ready docs yet
5. **Dismissal flow**: the elaborate opt-in flow (see below)
6. **Order of work**: 3e (dispatcher) first, then 3f (banner),
   then 3g, 3h, 3i, 3j, 3k in order

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

## Dismissal flow (with opt-in threat-intel reporting)

The user's directive (2026-07-04): the "false positive" dismissal
IS the opt-in mechanism for the threat-intel (TI) engine. Privacy
is the default; the user opts in by choosing to submit a sanitized
FP report. This is consistent with the 12 non-negotiables in the
legal doc and the Tier 0 / Tier 1 / Tier 2 model in the
corporate privacy page.

### Flow

When the user clicks **"This is a false positive"** (a link
below the detection list, in muted text), the banner expands
inline to show the dismiss form:

```
┌──────────────────────────────────────────────────────────────┐
│ [🛡️ AegisGate Lens] 1 sensitive item detected       [×]  [?] │
├──────────────────────────────────────────────────────────────┤
│  ● Credit card number  [CRITICAL]   match: 4111…1111        │
├──────────────────────────────────────────────────────────────┤
│  Tell us why this is a false positive (helps us improve):   │
│                                                              │
│  ☐ This is test/fake data                                   │
│  ☐ This is my own data (I know what I'm doing)              │
│  ☐ This is for a legitimate use case I trust                │
│                                                              │
│  [Submit & dismiss]  [Just dismiss (private)]  [Cancel]     │
└──────────────────────────────────────────────────────────────┘
```

### Two dismiss paths

1. **"Submit & dismiss"** — the user opts in to sending ONE
   anonymous, sanitized FP report. This is the only time Lens
   sends any data unless the user has also separately enabled
   Tier 1 telemetry in settings.

2. **"Just dismiss (private)"** — the dismissal is local-only.
   No data is sent. The detection is suppressed for 24h on the
   same domain.

### What "Submit & dismiss" sends (one-time, sanitized, opt-in)

```json
{
  "domain_hash": "abc123...",          // SHA-256 prefix of hostname
  "category": "pii_credit_card",
  "pattern_id": "visa_v1",
  "reason": "test_data" | "own_data" | "legitimate",
  "ml_score": 0.34,                    // only if ML was used
  "threshold": 0.85,                   // only if ML was used
  "model_version": "0.1.0+regex-v1",
  "lens_version": "0.1.0-beta",
  "timestamp": 1234567890
}
```

**The prompt content is NEVER sent.** No URLs, no page content,
no user identifier. The report is bucketed by `domain_hash` so
AegisGate can count FPs by AI provider without knowing which
provider it is.

### Where the data goes

The Lens client sends this to the existing Platform backend
endpoint at `POST /lens/telemetry/fp-report` (new endpoint, to
be added in 3g when we wire the SW → backend channel). The
backend aggregates the reports and feeds the TI engine's
FP-reduction model. The user can see all reports they have
sent in the Lens popup (3j).

### Dismissal scope

- Same exact detection: `category + pattern_id` (NOT the full
  match text — only the pattern fingerprint)
- Same domain: `domain_hash`
- 24 hours (then the warning reappears)

### State machine

```
[detection fires]
      ↓
[banner shown]
      ↓
[user clicks "This is a false positive"]
      ↓
[dismiss form shown inline]
      ↓
   ┌──┴──┐
   ↓     ↓
[Submit  [Just
 &       dismiss
 dismiss] (private)]
   ↓     ↓
[FP      [local
 report  storage
 sent]   only]
   ↓     ↓
   └──┬──┘
      ↓
[banner closes]
      ↓
[24h suppression on domain+pattern]
```

### Why this is a good opt-in model

1. **No friction**: the user opts in at the moment of value
   (their false positive is going away)
2. **Transparent**: the form is open about what is sent
3. **Reversible**: the user can clear all FP reports in the
   popup
4. **Narrow**: only the specific pattern + reason is sent
5. **Bounded**: the user can never accidentally enable
   broad telemetry by clicking "Submit & dismiss"

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
