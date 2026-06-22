# AegisGate Lens — Day 2 Schema v1 Contract

**Status**: v1 cut-over landed in commit `d0f8bdf` (2026-06-22).
**Test mirror**: `test/schema.test.mjs` (21 assertions, all green).
**Browser code**: `src/privacy/schema.js`.
**Backend mirror** (when built): `pkg/lensbackend/validation.go` (TODO).

---

## Purpose

This document is the **source of truth** for the LensEvent wire format. Any change to the field set, field types, or field constraints requires:

1. An update to this document.
2. An update to `src/privacy/schema.js` (the browser-side validator).
3. An update to `test/schema.test.mjs` (the executable mirror).
4. An update to the backend Go validator when one is built.

All four must land in the same commit. The CI gate (not yet built) will assert the test count matches the field count declared here.

---

## The §v1 contract

### Required fields (9)

> **Day 3 update**: every event-construction site in `src/content.js`
> and `src/service-worker.js` now sets `lens_event_version: NS.privacy.schema.SCHEMA_VERSION`
> (i.e. `1`). The value is read from the canonical export, never
> hardcoded, so a future version bump changes one constant in one
> place. See `test/event-construction.test.mjs` for the executable
> verification.

| Field | Type | Constraint | Notes |
|---|---|---|---|
| `lens_event_version` | integer | `=== 1` | New in v1. Day 2 cut-over rejects versionless events. |
| `domain_hash` | string | exactly 16 lowercase hex chars | SHA-256 of the AI provider hostname, truncated. Privacy-preserving per-installation identifier. |
| `category` | enum | one of 6 values (see below) | The kind of sensitive data detected. |
| `severity` | enum | one of 5 values (see below) | How risky the detection is. |
| `user_action` | enum | one of 4 values (see below) | What the user did after seeing the warning. |
| `timestamp` | integer | positive, within ±24h of client clock | Unix seconds (not millis). |
| `model_version` | string | non-empty, contains `"+"` | e.g., `"0.2.2+regex-v1"`. The `+` separates extension version from detector version. |
| `lens_version` | string | non-empty | e.g., `"0.2.2"`. |
| `confidence` | number | finite, in `[0.0, 1.0]` | Detector's confidence score. |

### Optional fields (2)

| Field | Type | Constraint | Notes |
|---|---|---|---|
| `id` | string | any non-empty | Client-side UUID for deduplication. Server marks this `Required: false`. |
| `fp_reason` | string | non-empty, ≤200 chars, no URL-shaped values | Free-text reason the user gave when dismissing a false positive. Set by the in-banner false-positive form. Allowed only on `user_action === 'dismiss_false_positive'` events; ignored on others. The validator enforces length and URL-shape; the constructor site is expected to enforce the `user_action` gate. |

### Enums

**Categories** (`category`):
- `pii_email`
- `pii_phone`
- `pii_ssn`
- `pii_credit_card`
- `secret_api_key`
- `source_code`
- `health_check` (Day 3 addition: synthetic category for the "Send test event" diagnostic in the popup; not produced by detectors)

**Severities** (`severity`):
- `info`
- `low`
- `medium`
- `high`
- `critical`

**User actions** (`user_action`):
- `send_anyway`
- `edit`
- `cancel`
- `dismiss`
- `dismiss_false_positive` (Day 3 addition: set by `sendFPTelemetry` in `src/content.js` when the user dismisses a detection as a false positive; gated by `fpTelemetryEnabled` opt-in flag in `chrome.storage.local`)

### Privacy guardrails (enforced via allowlist)

The validator enforces a **schema-is-an-allowlist** policy: any field NOT in the union of `{required fields} ∪ {id}` is rejected with `unknown field: <name>`. This is the browser-side mirror of the backend's `DisallowUnknownFields`.

**Specifically rejected fields (the ones a developer might be tempted to add):**

- `prompt_text` — prompt content is NEVER transmitted.
- `url` — page URLs are NEVER transmitted.
- `page_content` — page text is NEVER transmitted.
- `user_id`, `install_id`, `device_id` — no per-user identifiers.
- `ip_address` — derived server-side from TCP, never sent by client.
- `match_substring` — the exact matched text (e.g., the email address) is NEVER transmitted.
- `provider` — derivable from `domain_hash` server-side.
- `referer`, `user_agent` — derived from HTTP headers server-side.

If you find yourself wanting to add a field to the schema, **stop and re-read** `legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md` §4 (the non-negotiables).

### Schema versioning

- `lens_event_version` is a positive integer.
- v1 accepts `[1]` and rejects all others (including the versionless v0).
- A future v2 would be a breaking change: new fields, new enums, or new constraints. v2 would also need to support all v1 fields for at least one release cycle (per the standard AegisGate "two-version acceptance window" used elsewhere in the platform).

### Normalized output field order

The `validate()` function returns the normalized event with this exact key order (for stable hashing, JSON signature verification, and reproducibility):

```
lens_event_version
domain_hash
category
severity
user_action
timestamp
model_version
lens_version
confidence
id            (only if present in input)
```

This is asserted by the test `normalized event preserves field order (for stable hashing)`.

---

## Decision log

### Why `lens_event_version: 1` and not `2` (per the plan wording)?

The 30-day plan referred to the schema as "lens_event_version: 2" because the *plan* was iterating to its Day-2 deliverable. The *schema* itself was previously versionless (v0). The Day-2 cut-over introduces the first versioned schema, which is v1 by convention. Future v2 will be a real breaking change. This decision is documented so future maintainers don't think v1 was skipped.

### Why `domain_hash` and not `anonymous_token` (rotating monthly UUID)?

The plan considered a rotating monthly UUID for per-installation correlation. We rejected that approach because:

1. `domain_hash` already provides per-installation correlation (16 hex chars of SHA-256 of the hostname).
2. A rotating UUID is a *stronger* identifier (more bits, longer-lived correlation) than the domain hash, with no privacy benefit.
3. The hash is deterministic and stateless — no storage required, no rotation schedule to maintain.

`domain_hash` wins on both privacy and simplicity. This is documented at line 79-86 of the original 30-day plan.

### Why `id` (UUID) as optional?

UUIDs are useful for client-side deduplication and server-side idempotency, but they add 16 bytes per event and give the server a per-event correlation handle. By making `id` optional and tagging it `Required: false` on the server, we let the client include one if it wants (cheap dedup) without forcing it (smaller, more private events).

### Why is `timestamp` in seconds, not milliseconds?

Smaller wire size (4 bytes vs 8), and the ±24h tolerance means second-resolution is plenty for "is this event from the recent past?" filtering. The Go side can convert as needed.

### Why is `model_version` required to contain `+`?

The `+` separator distinguishes the extension version from the detector version, e.g., `"0.2.2+regex-v1"` means "Lens 0.2.2 with regex detector v1". This becomes important when we ship a v2 detector or when we hot-swap detectors mid-flight.

---

## Migration notes

### v0 → v1 (Day 2)

- **Breaking**: any client sending versionless events will be silently dropped (they fail client-side `validate()` and never hit the wire).
- **Migration path**: clients update `src/privacy/schema.js`'s `REQUIRED_FIELDS` to include `lens_event_version`, then set `lens_event_version: 1` on every event constructed.
- **Detection**: the mock backend in `test/mock-backend.mjs` logs `version=${event.lens_event_version}` on every accept, so a developer can grep `version=undefined` to find stragglers.

### Future breaking changes (v2, v3, ...)

Each version bump requires:
1. Add the new version to `ACCEPTED_SCHEMA_VERSIONS` (with the previous version, during the deprecation window).
2. Update `SCHEMA_VERSION` to the latest.
3. Update `REQUIRED_FIELDS` / `VALID_*` / field constraints.
4. Update `test/schema.test.mjs` to cover the new fields and the multi-version acceptance.
5. Bump `lens_event_version` on every event constructed in `src/content.js`, `src/service-worker.js`, and the popup.
6. Bump the backend Go struct's JSON tags in the same commit.
7. Update this document.

---

## What this document does NOT cover

- The **detection** logic (regex + ML cascade) — that's in `src/detectors/` and `plans/AEGISGATE-LENS-30-DAY-PLAN.md`.
- The **telemetry flow** (event → service-worker → backend) — that's `src/service-worker.js` and `test/telemetry.smoke.mjs`.
- The **local audit log** (1000-entry cap, never sent to backend) — that's `src/storage.js`.
- The **opt-in state** (per-device, synced boolean + timestamps) — that's `src/storage.js`.
- The **user-facing UI** (popup, banner, welcome page) — that's `src/popup.html`, `src/content.js`, `src/welcome.html`.
