# AegisGate Lens - Dismiss Banner Feature Spec

**Status**: Draft  
**Version**: v0.1.0  
**Author**: AegisGate Security  
**Last Updated**: 2026-06-21  

## 1. Overview

The Dismiss Banner feature allows users to mark a Lens warning as a
"false positive" so it doesn't reappear for the same prompt on the
same domain. This is a UX safety net for the ~0.3% FPR inherent in
any ML-based detection system.

## 2. Goals

- **Reduce user friction** for the legitimate FPR cases (every false
  positive that bothers a user is a churn risk)
- **Improve the model** by collecting (anonymized) dismissal data
  that can be used for retraining
- **Maintain user trust** by being fully transparent about what
  happens when they click "Dismiss"
- **Respect user privacy** by never sending prompt content with
  dismissals

## 3. UX Design

### Current Banner (before this feature)

```
┌────────────────────────────────────────────────────────┐
│ 🛡️ AegisGate Lens: 1 sensitive item detected         │
│                                                         │
│ • Credit card number (critical) — match: "4111…1111"  │
│                                                         │
│ [Cancel] [Edit] [Send anyway]                    [×]  │
└────────────────────────────────────────────────────────┘
```

### New Banner (with dismiss option)

```
┌────────────────────────────────────────────────────────┐
│ 🛡️ AegisGate Lens: 1 sensitive item detected         │
│                                                         │
│ • Credit card number (critical) — match: "4111…1111"  │
│                                                         │
│ This is a false positive                              │
│ [Tell us why ▼]  [Cancel] [Edit] [Send anyway]  [×]  │
└────────────────────────────────────────────────────────┘
```

When user clicks "This is a false positive", expand to show:

```
┌────────────────────────────────────────────────────────┐
│ 🛡️ AegisGate Lens: 1 sensitive item detected         │
│                                                         │
│ • Credit card number (critical) — match: "4111…1111"  │
│                                                         │
│ Why is this a false positive?                         │
│ ☐ This is test/fake data                              │
│ ☐ This is my own data (I know what I'm doing)         │
│ ☐ This is for a legitimate use case I trust           │
│ ☐ Other (please describe)                             │
│ [Submit and dismiss] [Just dismiss]                   │
└────────────────────────────────────────────────────────┘
```

## 4. Behavior

### Dismissal Scope

A dismissal applies to:
- **Same exact detection** (same category + similar pattern)
- **Same domain** (host hash)
- **For 24 hours**

After 24 hours, the warning will reappear. This prevents a user
from permanently suppressing a real detection by accident.

### "Just dismiss" vs "Submit and dismiss"

- **"Just dismiss"**: Suppresses locally only, no telemetry
- **"Submit and dismiss"**: Sends an anonymous FP report to
  improve the model. Telemetry is opt-in (off by default for
  privacy).

## 5. Data Model

### Local Storage (chrome.storage.local)

```javascript
{
  "dismissals": {
    "domain_hash_abc123": {
      "category_pattern_key": {
        "dismissed_at": 1234567890,
        "expires_at": 1234654290,
        "reason": "test_data" | "own_data" | "legitimate" | null
      }
    }
  }
}
```

The `category_pattern_key` is a hash of `category + first 100 chars
of the match`. We don't store the full match to keep storage small.

### Anonymous Telemetry (opt-in)

If the user has opted into anonymous telemetry:

```json
{
  "domain_hash": "abc123...",
  "category": "pii_credit_card",
  "reason": "test_data",
  "ml_score": 0.34,
  "threshold": 0.85,
  "model_version": "0.1.0+regex-v1+ml-5way-v1",
  "lens_version": "0.1.0",
  "timestamp": 1234567890
}
```

**The prompt content is NEVER sent.** Only metadata.

## 6. Implementation Plan

### Phase 1 (this session)
- [ ] Add "This is a false positive" button to banner
- [ ] Add dismiss form with reason checkboxes
- [ ] Add local storage of dismissals
- [ ] Check dismissals before showing banner
- [ ] Add telemetry for opt-in users

### Phase 2 (next session)
- [ ] Add FP report to model retraining pipeline
- [ ] Improve model based on collected FPs
- [ ] Add banner "Last dismissed 2 hours ago" indicator

## 7. Privacy Considerations

- **No prompt content is ever sent** - the FP report contains only
  category, score, domain hash, and optional reason
- **Domain hash is one-way** - we can count FPs by domain but
  cannot identify the domain
- **Opt-in only** - the user must explicitly enable telemetry in
  the welcome page
- **24-hour expiration** - dismissals don't last forever
- **User can clear at any time** via the popup or extension settings

## 8. Accessibility

- All buttons are keyboard-navigable
- Reason checkboxes use native `<input type="checkbox">` for screen reader support
- Focus is trapped in the expanded dismiss form
- Escape key closes the dismiss form

## 9. Success Metrics

- **FP dismissal rate**: 50%+ of FPs should be dismissed (not
  re-shown within 24h)
- **User satisfaction**: <2% of users disable the extension
- **Telemetry opt-in rate**: 5-10% of users (privacy-respecting)
- **No regression in TPR**: dismissals should NOT make the
  model miss real attacks (this is enforced by 24h expiration)

## 10. Open Questions

1. Should the dismiss reason be required? (current: optional)
2. Should the banner show "last dismissed 2 hours ago" inline?
3. Should we add a "report to AegisGate" option for malware-style
   attacks? (separate from false positive)

## 11. Files to Modify

```
src/
├── content.js (banner UI + dismiss flow)
├── storage.js (dismissal storage API)
├── api/client.js (telemetry endpoint)
├── welcome.html (mention dismiss feature)
└── popup.html (add "manage dismissals" link)

plans/
├── LENS-DISMISS-BANNER-SPEC.md (this file)
└── LENS-PRIVACY-IMPACT.md (add section)
```

## 12. Testing Plan

1. Test dismiss flow on real chatgpt.com
2. Verify dismissal persists across page reloads
3. Verify dismissal expires after 24h (mock clock)
4. Verify different categories don't get same dismissal
5. Verify no telemetry sent for users who haven't opted in
6. Test keyboard navigation
7. Test screen reader announcements
