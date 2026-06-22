# AegisGate Lens — Backend IP Rate-Limit Handoff

**Status**: Day 9 deliverable for F-05 in `plans/LENS-THREAT-MODEL.md`.
**Owner**: Platform monorepo (Lens backend in `pkg/lensbackend/`).
**Severity**: CVSS 5.5 (Medium).

---

## Purpose

This document is a **handoff** for filing an issue in the
`aegisgatesecurity/aegisgate-platform` monorepo (Lens backend Go code).
The Lens extension itself cannot fix this; the fix must land in the
backend Go service.

If you have write access to the Platform monorepo, copy the contents
of this file into a new GitHub issue and tag it with the labels
`lens`, `security`, `backend`, `rate-limit`.

---

## Title

`[Lens backend] Add IP-based rate limit to /api/v1/lens/telemetry`

## Body

### Threat context

See `plans/LENS-THREAT-MODEL.md` finding **F-05** in the
`lens-repo-bootstrap` repo.

**Attack vector**: A botnet that obtains valid bearer tokens (by
installing the Lens extension and extracting the token from
`chrome.storage.local`, or via XSS in any page the victim visits)
can send unlimited telemetry events. The current client-side rate
limit (100/min/installation) only protects against a single
installation. With 10,000 IPs and 10,000 tokens, the botnet can
send 100,000,000 events/hour to the backend.

**Why the extension can't fully fix this**: The client-side rate
limit lives on the `APIClient` instance inside the content
script's service worker. An attacker controlling the bearer
token bypasses the extension entirely and talks to the backend
directly.

### Proposed fix

Three layers of rate limiting, applied in order at the Go HTTP
handler in `pkg/lensbackend/`:

1. **IP-based rate limit**: 1000 events/hour per source IP across
   ALL bearer tokens. Stored in Redis or in-memory LRU. Drops the
   attack surface by ~10,000x for a small botnet.

2. **Bearer-token-per-IP rate limit**: 100 events/min per
   (token, IP) tuple. Mirrors the client-side limit but
   enforced server-side so a custom client can't bypass it.

3. **Anomaly detection**: If any installation sends >10x its
   historical median event rate over a 1-hour window, log a
   `[ANOMALY]` event with the token, IP, and event count, and
   return `429 Too Many Requests` until the rate normalizes.

### Suggested implementation

In `pkg/lensbackend/telemetry.go`:

```go
func (h *Handler) PostTelemetry(w http.ResponseWriter, r *http.Request) {
    ip := clientIP(r)  // X-Forwarded-For aware
    token := bearerToken(r)

    // Layer 1: IP rate limit.
    if !h.ipLimiter.Allow(ip, 1000, time.Hour) {
        http.Error(w, "ip rate limit exceeded", http.StatusTooManyRequests)
        return
    }

    // Layer 2: per-(token, IP) rate limit.
    if !h.tokenIPLimiter.Allow(token+":"+ip, 100, time.Minute) {
        http.Error(w, "token+ip rate limit exceeded", http.StatusTooManyRequests)
        return
    }

    // Existing event validation.
    var event lens.Event
    if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
        http.Error(w, "invalid JSON", http.StatusBadRequest)
        return
    }
    if !event.Validate() {
        http.Error(w, "schema validation failed", http.StatusBadRequest)
        return
    }

    // Layer 3: anomaly detection.
    if h.anomalyDetector.IsAnomalous(token, event) {
        log.Warnf("anomalous event rate from token=%s ip=%s", token, ip)
        http.Error(w, "anomalous rate", http.StatusTooManyRequests)
        return
    }

    // Persist.
    if err := h.store.Insert(event); err != nil {
        http.Error(w, "store failed", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusAccepted)
}
```

Use `golang.org/x/time/rate` for the rate limiters (already a
common dep). Use `github.com/go-redis/redis` for the IP limiter
storage if running multi-instance.

### Acceptance criteria

1. Backend rejects requests from a single IP exceeding 1000/hour
   with HTTP 429.
2. Backend rejects requests from a single (token, IP) tuple
   exceeding 100/minute with HTTP 429.
3. Anomaly detection logs a `[ANOMALY]` line for installations
   exceeding 10x historical median.
4. The tests in `lens-repo-bootstrap/test/integration.test.mjs`
   (which exercise the wire protocol from the extension side) all
   still pass — none should be affected by server-side rate
   limits since they send <100 events/minute per test.

### Out of scope

- Per-domain rate limiting (would require resolving the
  `domain_hash` server-side).
- Cross-IP rate limiting per bearer token (would require token
  fingerprinting that doesn't compromise user privacy).
- Backend availability / DDoS at the network layer (handled by
  Cloudflare / load balancer, not the application).

---

## Contact

Day 9 owner: AegisGate Lens maintainer
(`security@aegisgatesecurity.io` for sensitive follow-up).

Cross-reference: `lens-repo-bootstrap` commit `61c47f7` (Day 8
sender-id validation) closes F-01 in the same threat model;
this issue closes F-05.
