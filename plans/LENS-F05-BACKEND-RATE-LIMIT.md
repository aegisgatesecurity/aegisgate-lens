# AegisGate Lens — Backend Rate-Limit Documentation (F-05)

**Status**: Reference document — links the Lens threat model to the
Platform backend implementation.
**Severity**: CVSS 5.5 (Medium). **Day 10**: RESOLVED.

---

## Purpose

This document bridges the threat model entry for F-05 in
`plans/LENS-THREAT-MODEL.md` to the actual implementation in the
Platform monorepo. If you are reviewing the Lens threat model and
want to verify F-05's "RESOLVED" status, read this page first.

---

## The threat (one-paragraph recap)

A botnet that obtains valid Lens bearer tokens (by installing the
extension or via XSS in any page the victim visits) can send
unlimited telemetry events to the Lens backend. The Lens extension
enforces a 100 events/minute rate limit per installation client-side,
but a custom client (or one with a stolen bearer token) bypasses
that. The backend MUST enforce rate limiting independently.

---

## Implementation (Platform monorepo)

Repository: `/home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform`

**File**: `pkg/lensbackend/ratelimit.go` (173 lines)

Key design choices:

- **Per-installation rate limit**: 100 events/minute, keyed by
  `HMAC-SHA-256(domain_hash, server_hmac_key)`. The HMAC prevents
  one installation from enumerating other installations' rate-limit
  buckets by guessing domain hashes.
- **Global rate limit**: 10,000 events/minute server-wide,
  configurable via `LENS_RATE_LIMIT_PER_MIN` env var (default 10000).
- **Wraps the Platform's existing rate limiter**:
  `upstream/aegisgate/pkg/resilience/ratelimit` (vendored in the
  monorepo via go.mod replace). This avoids reimplementing token-bucket
  logic in stdlib.
- **HTTP 429 on rate-limit failure** with `Retry-After: 60` header
  and JSON error body `{"error":"rate_limit_exceeded","reason":"..."}`.

**Test**: `pkg/lensbackend/server_test.go::TestRateLimiter` verifies:

1. Exactly 100 events accepted from a single installation.
2. The 101st request is rejected.
3. A second installation is unaffected by the first's quota
   exhaustion (per-installation isolation).

---

## Cross-repo verification (Day 10)

Ran `go test ./pkg/lensbackend/...` in the Platform repo on 2026-06-22.
All 30+ tests pass (TestRateLimiter, TestHandlers_HandleTelemetry_*,
TestServer_NewServer_*, TestServerRequiresBearerToken,
TestServerEmptyTokenReturns503, etc.).

The Lens repo's `test/wire-protocol.test.mjs` (10 assertions) drives
`src/api/client.js` against a captured fetch and verifies the
Lens-side wire protocol matches the Platform's expectations:

- `POST /api/v1/lens/telemetry` with `Authorization: Bearer <token>`
  and `Content-Type: application/json`.
- `GET /api/v1/lens/check?domain=<host>` with `Authorization: Bearer`.
- `GET /api/v1/lens/stats` with `Authorization: Bearer`.
- `GET /api/v1/lens/healthz` (no auth).
- 4xx responses surface as thrown `Error` with HTTP status code in
  the message.
- Lens-side rate limit mirrors the Platform's `TestRateLimiter`
  invariant (100 accepted, 101st dropped) without ever calling
  fetch() for the dropped event.

This dual-side verification means future drift in the Platform's
wire protocol is caught on the extension side before release.

---

## How to reproduce the verification

From `aegisgate-platform/`:

```bash
go test ./pkg/lensbackend/... -run 'TestRateLimiter|TestHandlers|TestServer' -v
```

From `lens-repo-bootstrap/`:

```bash
node test/wire-protocol.test.mjs
```

---

## Change log

- **Day 9 (2026-06-22)**: Initially filed as a handoff document
  under the name `LENS-BACKEND-RATE-LIMIT-ISSUE.md`. Pre-Days-8
  inspection had not verified the Platform repo's contents.
- **Day 10 (2026-06-22)**: After Platform Admin access was granted
  and the Platform repo was inspected, the implementation was found
  to already exist. This document was rewritten from "issue to file"
  to "documentation of what exists". The original issue body is
  preserved in git history for reference if a future regression is
  found and the rate limit needs to be re-implemented.

## Contact

Lens maintainer: `security@aegisgatesecurity.io` (sensitive follow-up).
Platform monorepo: `pkg/lensbackend/` is owned by the Platform team.
