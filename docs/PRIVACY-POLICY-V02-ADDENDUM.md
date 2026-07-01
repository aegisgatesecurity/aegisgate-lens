# AegisGate Lens v0.2.0 — Privacy Policy Addendum

**Date**: 2026-06-29
**Status**: v0.2.0-specific clarifications
**Source of truth**: https://aegisgatesecurity.io/lens/privacy (this addendum is a working doc)

This addendum is the v0.2.0-specific elaboration of the 12 non-negotiables in
[PRIVACY-POLICY.md](PRIVACY-POLICY.md). It documents:

- The machine learning model in v0.2.0
- Detection tuning parameters and what they mean for privacy
- The data integrity findings from v0.2.0 testing
- How v0.2.0 maintains the non-negotiables

The 12 non-negotiables themselves are unchanged. What follows is **how** v0.2.0
upholds them in practice.

---

## v0.2.0 — Model Card Summary

**Model**: ModernBERT-base (149M parameters)
**Architecture**: Bidirectional transformer, 22 layers, 768 hidden dim
**Context window**: 8,192 tokens
**Training data**: Mixed corpus of v0.1 (rounds 7-8) + v0.2 augmented data
  - v0.1 corpora: `corpora/v7/round7_*.jsonl`, `corpora/v8/round8_*.jsonl`
  - v0.2 corpora: `corpora/r8_augmented_train.jsonl`, `corpora/r8_holdout_long_context*.jsonl`
**Inference**: ONNX runtime, WebGPU primary + WASM fallback
**Sliding window**: 2048 tokens, stride 1024, max 4 windows per document
**Detection threshold**: P(attack) >= 0.05 → flagged as attack
**Aggregation**: max-pool across windows (conservative — flag if any window scores high)

**Why this matters for privacy**: All inference runs on-device. The model is
~150 MB quantized (q4f16), downloaded once after first detection event.
The model never sees prompts that don't exist on the user's machine.

---

## Non-Negotiable #1: The Lens never sends prompt content to any server

### How v0.2.0 enforces this

The telemetry event payload (verified in `src/api/client.js` line 175-189) contains
ONLY the following fields:

```json
{
  "lens_event_version": 1,
  "domain_hash": "abc123...",
  "facet": 6,
  "category": "pii_ssn",
  "severity": "critical",
  "user_action": "send_anyway",
  "timestamp": 1719676800,
  "model_version": "0.2.0+modernbert-v1",
  "lens_version": "0.2.0",
  "confidence": 0.998
}
```

**No `text`, no `match`, no `snippet`, no prompt content, no URL, no page content.**

This was verified by source review of `src/api/client.js` lines 175-189 in
2026-06-29 testing (see `test/eval/chrome120-comprehensive-report.md`).

### What does cross the wire

- `domain_hash`: SHA-256 prefix (16 hex chars) of the AI provider hostname
  (e.g., `chat.openai.com` → `8c6c5fb0d0f5f4a3`). Not the full URL.
- `category`: enum string (e.g., `pii_ssn`, `jwt_none`, `prompt_injection_ml`).
  No detected text.
- `severity`: enum string (`low`, `medium`, `high`, `critical`).
- `facet`: integer 1-6 indicating which of the 6 detection facets fired.
- `user_action`: enum string (`send_anyway`, `edit`, `cancel`, `dismiss`).
  Tells us what the user chose to do after the warning.
- `timestamp`: Unix seconds.
- `model_version`, `lens_version`: version strings for telemetry correlation.
- `confidence`: float 0-1.

### What does NOT cross the wire

- ❌ The prompt text (whatever the user typed into ChatGPT/Claude/Gemini)
- ❌ The AI response (whatever the model replied)
- ❌ The page URL (only the SHA-256 of the hostname)
- ❌ Any user-identifiable information (no user ID, no session ID, no cookie)
- ❌ Any page content beyond the hostname hash
- ❌ Any clipboard content, file uploads, screenshots, etc.

---

## Non-Negotiable #5: The Lens's default is OFF

### How v0.2.0 enforces this

Telemetry opt-in is **explicit** and **off by default**.

`src/storage.js` line 22: `const KEY_OPT_IN = 'lens.optIn.enabled'`

`getOptIn()` returns `false` unless the user has explicitly set this key to
`true`. There is no default-on opt-in path. Even the FP telemetry card
(`maybeShowFPOptInCard`) is opt-in only.

### What users see

- First install: detection works, telemetry is OFF.
- User sees an FP dismissal card (after 1st FP dismissal): "Help improve Lens
  detection? Send anonymized metadata only." → "Opt in" or "Not now"
- If "Not now": no further prompts. Telemetry stays off.
- If "Opt in": user can later opt out via popup or welcome page.

### What does NOT happen

- ❌ No automatic opt-in after N uses
- ❌ No opt-in via implicit consent
- ❌ No "first install counts as opt-in"
- ❌ No opt-in bundled with another permission grant

---

## Non-Negotiable #10: The Lens's API is rate-limited

### How v0.2.0 enforces this

Two layers of rate limiting:

**Client-side** (`src/api/client.js`):
- `eventsPerMinute = 100` (default)
- Implemented in `_checkRateLimit()` (line 80-87)
- Throws on rate limit (rate-limited events are silently dropped)

**Server-side** (in Platform monorepo's `pkg/lensbackend/ratelimit.go`):
- Per-installation: 100/min
- Global: 10K/min
- Returns 429 on overflow

**Verified**: F-05 pen-test in `test/pen-tests/f01-f05-bash.sh` — 7 wire protocol
attack vectors all rejected by backend.

---

## v0.2.0 Data Integrity Findings

### Corpus fix (2026-06-29)

During v0.2.0 testing, we discovered that `corpora/r7_long_benign_train.jsonl`
contained 197 records labeled as "benign" that actually contained prompt
injection text. This was a labeling error inherited from v0.1's
`long_context_v7.jsonl` corpus (per the v0.2 nuclear burndown post-mortem).

**Fix applied**: `test/eval/r7_long_benign_train_fixed.jsonl` reclassifies
these 197 records as attacks with audit fields (`original_label`,
`fix_applied`, `fix_reason`, `fix_timestamp`).

**Privacy impact**: None. The fix is in our test/training data, not in
user-facing data. The Lens's runtime detection is unchanged.

**User-facing impact**: More accurate long-context detection. The 197
previously-mislabeled records are now correctly flagged as attacks.

### Threshold tuning (2026-06-29)

The detection threshold was lowered from 0.50 to 0.05 based on hard test set
sweep. This was a deliberate data-driven decision documented in
`test/eval/threshold-sweep-hard-results.md`.

**Result**:
- Short-attack recall: 100% (unchanged)
- Long-context attack recall: 80-85% (was 34-41%)
- Benign FPR: 0% (unchanged)
- F1: 0.94 (was 0.74)

**Privacy impact**: NONE. Lowering the threshold does NOT cause more data
to be sent. It only causes the Lens to FLAG more potential attacks (which
the user can still send with "Send Anyway"). Telemetry is opt-in and
unchanged.

---

## Where to report v0.2.0-specific privacy concerns

If you believe v0.2.0 has violated any of the 12 non-negotiables, please
email `privacy@aegisgatesecurity.io` and reference "Lens v0.2.0" in the
subject line. We treat privacy bugs as severity Critical and respond
within 24 hours.

See [`SECURITY.md`](../SECURITY.md) for the full disclosure process (will
be added in v0.2.0 final release).

---

## Changelog for this addendum

- **2026-06-29**: Initial draft. Documents v0.2.0 model card, telemetry
  payload verification, and data integrity findings.
- Pending: Founder legal review. Will be merged into main PRIVACY-POLICY.md
  after legal approval.

---

## v0.3 Telemetry Opt-In (Restored from v0.1)

Per the 12 non-negotiables (especially #4: "The Lens never collects a user ID, session ID, or cookie" and #5: "The Lens's default is OFF"), AegisGate Lens v0.3 reintroduces telemetry opt-in from v0.1 with v0.3 enhancements.

### Two-tier opt-in design

| Tier | Default | What it sends | Use case |
|---|---|---|---|
| **Detect-only** | ON | Nothing | Maximum privacy, no telemetry |
| **Tier 1** (anonymized metadata) | OFF | 9 fields: domain_hash (16 hex), category, severity, user_action, timestamp, model_version, lens_version, confidence | Helps AegisGate improve detection |
| **Tier 2** (full event details) | OFF | 14 fields (Tier 1 + 5 TI extensions): attack_keywords_hash, attack_pattern_id, model_consensus, similar_attack_count_30d, bundle_signature | Threat Intelligence aggregation |

### What is NEVER sent (verified by code review)

- ❌ **Prompt text** — the actual content the user typed or pasted
- ❌ **URLs** — only `domain_hash` (first 16 hex chars of SHA-256)
- ❌ **Page content** — only category, not the page
- ❌ **User IDs / session IDs / cookies** — explicitly forbidden by non-negotiable #4
- ❌ **File uploads / clipboard / screenshots** — never accessed by Lens

### Tier 1 event schema (9 fields)

```json
{
  "lens_event_version": 1,
  "domain_hash": "abc123def4567890",
  "category": "pii_ssn",
  "severity": "critical",
  "user_action": "send_anyway",
  "timestamp": 1719676800,
  "model_version": "0.3.0+modernbert-v3",
  "lens_version": "0.3.0",
  "confidence": 0.98
}
```

### Tier 2 additional fields (5 fields)

```json
{
  "attack_keywords_hash": "sha256_of_tokenized_keywords",
  "attack_pattern_id": "DAN-jailbreak-v1",
  "model_consensus": 0.95,
  "similar_attack_count_30d": 3,
  "bundle_signature": "aKzukcm1ElgBZDMlG7IROw12CyjPHfkuKv+Bj8I70+c="
}
```

These are still **metadata only**. No prompt text, no URLs, no page content.

### Rate limiting

- **Client-side**: 100 events/min per installation (Privacy Policy §10.2)
- **Server-side**: 10K events/min globally (defense in depth)
- **Local buffer**: 200 events max (oldest evicted)
- **Background flush**: every 5 minutes

### User controls

- Opt-in via welcome page (`welcome.html`) on first install
- Opt-out anytime via popup or by re-opening welcome page
- All local buffer cleared on opt-out

### Implementation

- `src/util/opt-in.js` — opt-in state management (Tier 1, Tier 2, v0.1 compat)
- `src/util/telemetry-queue.js` — local buffer, rate limit, background flush
- `lens-final-dist/welcome.html` — opt-in UI with 3 choices + privacy details
- `lens-final-dist/welcome.js` — opt-in button handlers
- Tests: `test/opt-in.test.mjs` (11 tests), `test/telemetry-queue.test.mjs` (9 tests)

### Threat Intelligence feedback loop

Tier 2 events feed an AegisGate Security TI platform:
1. User pastes prompt containing new attack pattern
2. Lens detects (Tier 1: sends category)
3. Lens detects via Tier 2 model consensus (sends attack_keywords_hash)
4. Backend aggregates: which patterns appear most across user base?
5. AegisGate publishes anonymized TI feeds to enterprise customers (separate TI product)
6. AegisGate uses aggregated data to inform model retraining priorities

This creates a feedback loop: more Lens installs → better threat visibility → better detection → better Lens. The user benefits from being part of a larger safety network while maintaining privacy.

