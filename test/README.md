# test/

Two test layers live here. They are intentionally separate:

1. **Detector fixtures** (JSON) — used by the Go test harness in the
   Platform monorepo (`tools/test-extension/`) to verify that the
   in-browser regex/ML detectors flag the right things.
2. **Telemetry test harness** (Node, no dependencies) — used to verify
   that the Lens's telemetry path (validate → sendEvent → backend)
   behaves correctly end-to-end. Added on Day 2 of the 30-day plan.

## Layer 1: Detector fixtures

```
test/
├── pii_email.json
├── pii_phone.json
├── pii_ssn.json
├── pii_credit_card.json
├── false_positives.json
└── ...
```

Each file is a JSON array of `{input, expected_match, expected_category, expected_severity}` records. The `input` is the synthetic prompt text (redacted, never real PII), and the Go test harness checks that the detector's output matches `expected_*`.

**No real PII in the test cases.** All test inputs use synthetic data: `user@example.com`, `555-01-0123`, `4111-1111-1111-1111` (the canonical Stripe test card), `AKIAIOSFODNN7EXAMPLE` (the AWS documentation example key), etc. See `docs/PRIVACY-POLICY.md` for the data-handling commitments.

## Layer 2: Telemetry test harness (Day 2)

```
test/
├── README.md                          <- this file
├── schema.test.mjs                    <- schema validator unit tests (Day 2)
├── telemetry.smoke.mjs                <- APIClient + mock backend smoke test (Day 2)
├── event-construction.test.mjs        <- content.js event sites produce v1 (Day 3)
├── integration.test.mjs               <- full chain: content.js -> SW -> APIClient
│                                          -> JSONL (Day 4)
├── fp-opt-in.test.mjs                 <- in-banner "Help improve detection"
│                                          opt-in prompt UI behavior (Day 5)
├── security-sender-validation.test.mjs <- service worker rejects foreign senders
│                                          (Day 8 / F-01)
├── security-bundle-verification.test.mjs <- Ed25519 bundle signature check
│                                          (Day 8 / F-02)
├── dismissals-pruning.test.mjs        <- chrome.storage.local dismissals cap
│                                          + expiry pruning (Day 9 / F-04)
├── mock-backend.mjs                   <- local HTTP server that captures telemetry
├── fixtures/
│   └── valid-event.json               <- canonical LensEvent for tests
└── mock-output/                       <- JSONL stream written by mock-backend.mjs
    └── events.jsonl                   <- gitignored
```

> **Why no `package.json`?** The AegisGate Lens ships as plain JavaScript
> with no build step and no runtime dependencies. The repo's `.gitignore`
> deliberately excludes `package.json`, `package-lock.json`, and
> `node_modules/`. The Node-based test harness uses **only Node built-ins**
> (`node:assert`, `node:http`, `node:fs`, `node:vm`, `node:url`) so no
> `npm install` is required. Just run the `.mjs` files with Node 20+.

### Running the tests

From the repo root (`lens-repo-bootstrap/`):

```bash
# Run all Node tests (9 suites).
node test/schema.test.mjs && \
node test/telemetry.smoke.mjs && \
node test/event-construction.test.mjs && \
node test/integration.test.mjs && \
node test/fp-opt-in.test.mjs && \
node test/security-sender-validation.test.mjs && \
node test/security-bundle-verification.test.mjs && \
node test/dismissals-pruning.test.mjs

# Or run them individually:
node test/schema.test.mjs
node test/telemetry.smoke.mjs
node test/event-construction.test.mjs
node test/integration.test.mjs
node test/fp-opt-in.test.mjs
node test/security-sender-validation.test.mjs
node test/security-bundle-verification.test.mjs
node test/dismissals-pruning.test.mjs

# Start the mock backend in one terminal and watch events in another.
node test/mock-backend.mjs
node tools/lens-cli/telemetry-tail.mjs --follow
```

### What `npm test` verifies

**`schema.test.mjs`** — 21 assertions on `src/privacy/schema.js`:
- Valid event passes.
- `lens_event_version: 1` is required.
- Legacy `lens_event_version: 0` is rejected.
- Future `lens_event_version: 2` is rejected.
- Each of the 8 other required fields is checked for presence.
- `prompt_text` and `url` are rejected as unknown fields (privacy guardrail).
- Invalid category / severity / user_action enum values are rejected.
- Domain-hash length and case are validated.
- Timestamp must be within ±24h of the client clock.
- Confidence must be in [0, 1].
- Non-object input is rejected.
- Field order in the normalized event is stable.

**`telemetry.smoke.mjs`** — 13 end-to-end assertions on the telemetry path:
- `/healthz` round-trips through the APIClient.
- A valid event reaches the mock backend (full path: validate → sendEvent → fetch → JSONL).
- A forbidden field is rejected by `validate()` (privacy guardrail).
- A versionless event is rejected by `validate()` (Day 2 cut-over).
- `sendEvent` propagates validation errors as throws.
- The 100/min rate limit accepts exactly 100 events and silently drops the rest.
- `http://production-style` URLs are rejected at construction.
- `https://` URLs are allowed at construction.
- `http://127.0.0.1` (localhost) is allowed.
- `http://example.com` is rejected (not localhost).
- Missing bearer token is rejected at construction.
- Invalid baseUrl is rejected at construction.
- The JSONL output contains every accepted event (one per line).

### Adding new tests

Schema tests live in `schema.test.mjs`. Each test is a top-level `await test(name, fn)` call. The runner prints `PASS`/`FAIL` per assertion and exits non-zero if any fail.

Smoke tests live in `telemetry.smoke.mjs`. The smoke test boots its own mock backend on a random free port; you do not need to start `mock-backend.mjs` manually to run the smoke test.

**`event-construction.test.mjs`** — 8 regression assertions on the production event-construction sites in `src/content.js` and `src/service-worker.js`:
- `ContentScript.prototype.recordAction` stamps `lens_event_version: 1` and the event passes `validate()`.
- All 4 user-action enum values (`send_anyway`, `edit`, `cancel`, `dismiss`) produce a valid event.
- Zero detections sends zero events.
- `ContentScript.prototype.sendFPTelemetry` stamps `lens_event_version: 1`, omits `fp_reason` when empty, and respects the `fpTelemetryEnabled` opt-in flag.
- `service-worker.js handleTestEvent` produces a valid v1 event.

**`integration.test.mjs`** — 7 end-to-end assertions wiring `src/content.js` + `src/service-worker.js` + `src/api/client.js` + `src/privacy/schema.js` together through a stubbed `chrome.runtime.sendMessage` bridge and the mock backend:
- A v1 detection round-trips: content.js → service-worker → JSONL, with all 9 required fields intact.
- A versionless event is silently dropped (Day 2 cut-over holds across the full chain, not just at validate()).
- An event with `prompt_text` is silently dropped (privacy guardrail holds across the full chain).
- The 100/min rate limit accepts exactly 100 events and drops the rest through the full chain (verifies the service-worker APIClient cache stays valid).
- An opted-out user triggers zero backend traffic AND zero local audit entries.
- Multiple detections from one user action produce multiple events.
- A fresh detection chain produces a v1 event in the JSONL.

**`fp-opt-in.test.mjs`** — 8 assertions on the in-banner "Help improve detection" opt-in prompt (Day 5):
- The card appears on the first FP dismissal when neither flag is set.
- The card body contains the privacy guarantee ("anonymous metadata", "no prompt text", "no URLs", "off by default").
- Clicking "Allow" sets `fpTelemetryEnabled = true` AND `fpOptInPromptSeen = true`, and hides the banner.
- Clicking "Not now" sets only `fpOptInPromptSeen = true`, and hides the banner.
- A second FP dismissal after "Allow" does NOT show the card.
- A second FP dismissal after "Not now" does NOT show the card.
- A user with `fpTelemetryEnabled = true` (opted in via the popup) does NOT see the card.
- `dismissAsFalsePositive` still emits the `dismiss_false_positive` telemetry event with `lens_event_version: 1` even when the card shows.

**`security-sender-validation.test.mjs`** — 9 assertions that the service worker's `chrome.runtime.onMessage` listener rejects any sender whose `id` does not match our own extension (Day 8 / F-01 fix):
- OWN_ID is set on chrome.runtime.
- Own-extension message reaches the handler.
- Foreign extension `lens.telemetry` is rejected.
- Foreign extension `lens.opt_in` is rejected (the most dangerous attack: turning telemetry on without user consent).
- Foreign extension `lens.stats` is rejected.
- `sender.id === undefined` is rejected.
- `sender.id === ''` is rejected.
- Case-bypass is rejected (case-sensitive comparison).
- Malformed message (no `type`) from a foreign sender is rejected.

**`security-bundle-verification.test.mjs`** — 9 assertions that the Ed25519 bundle signature verification in `src/util/bundle-loader.js` actually works (Day 8 / F-02 evidence):
- Valid signed bundle parses successfully.
- Flipping one byte in the payload fails signature verification.
- Flipping one byte in the signature fails verification.
- Removing the magic value fails (header not found).
- Changing the magic value fails.
- Truncating the bundle (last byte removed) fails.
- Appending an extra byte fails signature verification.
- Bundle header contains expected fields.
- `reconstructModels` produces a usable model list.

The fixture is the real `lens_ml_build/aegisgate-lens-v0.1.1.bundle` (8.7 MB, 41 model files). The verification IS wired — this test is the executable proof.

**`dismissals-pruning.test.mjs`** — 8 assertions on the chrome.storage.local dismissals cap (Day 9 / F-04 fix):
- `DISMISSAL_MAX_ENTRIES === 1000` (sanity).
- 100 expired entries + 1 new → only 1 entry remains.
- 50 expired + 50 live + 1 new → 51 entries (pruned correctly).
- 1000 (cap) valid + 1 new → exactly 1000 entries (oldest dropped).
- 500 expired + 500 live + 1 new → 501 entries (pruning keeps live entries).
- New entry has correct shape (`dismissed_at`, `expires_at`, `reason`).
- Domain hash prefix preserved in the storage key (regression).
- 100,000 pre-existing entries bounded to ≤1000 after a single `storeDismissal` call (worst-case F-04 attack).

### `tools/lens-cli/telemetry-tail.mjs`

A read-only viewer for the JSONL stream emitted by the mock backend. Prints one line per event with severity color, category, user action, confidence, and domain hash. Useful for "is the detector firing the way I expect?" debugging without having to instrument the browser.

It is read-only and never sends telemetry. See `tools/lens-cli/telemetry-tail.mjs` for usage.

## Privacy guarantees for these tests

The schema validator's allowlist enforcement (`unknown field: prompt_text` is rejected) is the privacy contract for telemetry. Any future field added to the event MUST be added to `REQUIRED_FIELDS` or `id` in `src/privacy/schema.js` AND to the backend Go struct's JSON tags — otherwise it will be rejected client-side before it ever hits the wire.

The tests in this directory do not exercise prompt content, URLs, or page content. They exercise metadata only. If you find yourself wanting to add a test that does, **stop and re-read `legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md` §4**.
