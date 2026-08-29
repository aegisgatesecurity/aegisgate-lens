# AegisGate Lens v0.3.2 — Threat Model

**Status:** v0.3.2 (all findings triaged against the shipped product; 11 resolved, 1 residual, 1 accepted, 1 partial)
**Date:** 2026-08-17
**Audience:** Chrome Web Store reviewers, enterprise security buyers, third-party auditors, end users with security questions
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

This is the **public, Lens-specific** threat model. A more detailed version with additional test references and mitigation history is available to enterprise customers under NDA.

## Purpose

This document catalogs the threats the AegisGate Lens extension
itself faces. It is **distinct from the MITRE ATLAS / OWASP
mapping** (which catalogs the threats the Lens *detects* in user
prompts). Both are needed; do not confuse them.

The goal: enumerate realistic attack vectors, document the
current mitigation, and call out residual risk so a CWS reviewer,
an enterprise buyer, or a security auditor can independently
verify the posture.

## Scope

**In-scope:**

- The Lens extension source code in `src/` (~7,200 lines of
  vanilla JS / CSS / HTML, no npm dependencies, no node_modules).
- The service worker (`src/background.js`).
- The 8 content-script injection paths (one per supported AI
  provider plus the on-page indicator).
- `chrome.storage.session` (dismissal data, opt-in state).
- The wire protocol between content script and service worker
  (`src/api/messages.js`).
- The `chrome-extension://` origin and its `web_accessible_resources`.
- The Ed25519 bundle signing chain
  (`tools/build-lens-extension/main.go`).

**Out-of-scope (covered elsewhere):**

- The detection logic itself — see
  `docs/MITRE-ATLAS-OWASP-MAPPING.md` (or, in the CWS listing,
  the "What it catches" section).
- The Lens backend (Go) — part of the AegisGate Platform
  (separate repo). Not shipped as part of the Lens extension.
- The browser's extension sandbox — owned by Chrome.
- Third-party AI providers (ChatGPT, Claude, Gemini, etc.) —
  they have their own threat models. The Lens does not trust
  them; see F-03 below.

## Trust boundaries

Three trust boundaries are in scope:

1. **The Chrome extension ↔ the page DOM.** The content script
   runs in the same JavaScript context as the AI provider's page.
   The page is partially attacker-controlled (any input the user
   pastes, any content the AI tool renders, any third-party
   script the provider loads).
2. **The Chrome extension ↔ the service worker.** The content
   script sends messages to the service worker via
   `chrome.runtime.sendMessage`. The service worker runs in a
   separate JavaScript context but shares the
   `chrome.runtime.id`.
3. **The Chrome extension ↔ the network.** The extension has NO
   network calls by default. Opt-in telemetry sends one
   `fetch()` to the AegisGate backend per dismissed-and-submitted
   false-positive. The endpoint URL is hardcoded in
   `src/api/messages.js` and validated before send.

## Score

| Dimension | Score | What it means |
|---|---|---|
| **Engineering posture** (code, tests, build) | 9.7/10 | All known engineering threats are mitigated. The 0.3 deduction is for the residual adversarial-robustness gap (F-15 partial). |
| **Trust posture** (distribution, supply chain, ops) | 9.0/10 | SLSA L2 + Ed25519 + Sigstore + Rekor + Trivy. The 1.0 deduction is for "not yet independently audited by a third party." |
| **Combined** | **9.5/10** | Weighted by exposure (engineering threats are reachable by every user; trust threats are reachable only at install / update). |

## Findings (STRIDE)

Status legend: **RESOLVED** (mitigated and verified), **CLOSED**
(mitigated in a prior version but not re-verified for v0.1.0-beta
because the underlying vector was removed by architectural change),
**RESIDUAL** (known to exist; defense-in-depth remains; not a
fixable gap), **ACCEPTED** (deliberate trade-off, not a defect),
**PARTIAL** (mitigated for the majority of cases; remaining cases
documented in the finding).

### F-01: Service worker accepts `chrome.runtime.onMessage` from any sender
- **STRIDE:** S, I, D, E
- **Severity:** Medium (6.5/10)
- **Status:** **RESOLVED**
- **Mitigation:** `src/background.js` validates the `sender.id`
  matches `chrome.runtime.id` of the running extension. Messages
  from any other extension are rejected with a console.warn
  and an early return. Validated by 12 unit tests in
  `test/unit/sw-messages.test.mjs` (`sw: onMessage REJECTS
  messages from foreign extensions`).
- **Verified:** unit tests + CI (`F-01 sender-id check` in
  `.github/workflows/security.yml` fails the build if a
  contributor removes the check).

### F-02: Bundle signing verification
- **STRIDE:** T
- **Severity:** Medium-High (5.0-7.5/10)
- **Status:** **RESOLVED**
- **Mitigation:** `tools/build-lens-extension/main.go` produces
  an Ed25519 signature over the bundled CRX. The signature is
  published alongside the .crx on the GitHub release.
  Verification at install time is delegated to the OS
  (ChromeOS / macOS / Windows code-signing).
- **Verified:** `F-02 bundle signature verification` in CI.

### F-03: Content script accepts input from attacker-controlled DOM
- **STRIDE:** T, E
- **Severity:** N/A (intended behavior)
- **Status:** **ACCEPTED**
- **Mitigation:** The content script reads from the input field
  via `selectors.getInputValue(state.input)`. This is a
  *required* read — the whole point of the Lens is to see the
  prompt. The lens does NOT trust the DOM in any other way: it
  does not write to it except via the `Edit manually` action,
  which uses the React-native `value` setter to avoid React's
  synthetic-event bypass.
- **Why accepted:** the prompt IS the threat model input. We
  cannot defend against the user pasting their own PII; that's
  the entire problem statement.
- **Verified:** 325+ unit tests cover the input-read path
  (including the React-bypass technique).

### F-04: `chrome.storage` is unbounded for `dismissals`
- **STRIDE:** D
- **Severity:** Low (3.5/10)
- **Status:** **RESOLVED** (in v0.1.1)
- **Mitigation:** v0.1.0-beta used `chrome.storage.local`. v0.1.1
  migrated to `chrome.storage.session` (auto-cleared on browser
  restart) per item 25. The 24h TTL is enforced by
  `dismiss.js`'s `gc()` function, which runs on every read and
  removes entries past their `expires_at`. Together: defense
  in depth.
- **Verified:** unit tests cover the `gc()` logic and the
  session-storage migration.

### F-06: Manifest CSP is strict but doesn't cover content scripts
- **STRIDE:** T, E
- **Severity:** Low (2.0/10)
- **Status:** **RESOLVED**
- **Mitigation:** `manifest.json` declares
  `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self'" }`.
  The CI's CSP gate (`CSP gate` job in security.yml) grep-fails
  any future `eval(`, `Function(`, `innerHTML`, or
  `document.write` in the source.
- **Verified:** CI grep gate.

### F-07: `web_accessible_resources` exposes bundles to AI provider pages
- **STRIDE:** I
- **Severity:** N/A (accepted)
- **Status:** **ACCEPTED**
- **Mitigation:** The WAR exposes `util/banner.css` and the
  icon PNGs. These are static assets that the banner injects
  into the page. They contain no JS, no PII, no token. The
  `chrome-extension://` origin is sandboxed; even if a hostile
  page could read the bundle, the bundle is a CSS file (a
  stylesheet) and an icon (an image). The trade-off: exposing
  them is the only way the banner can render on a third-party
  page (otherwise the page's CSP would block the `link` tag).
- **Why accepted:** static CSS / PNGs have no executable
  attack surface.

### F-08: No sender-id validation on `chrome.runtime.sendMessage` from content script
- **STRIDE:** S
- **Severity:** Same as F-01
- **Status:** **RESOLVED** (via F-01)
- **Mitigation:** Same as F-01 — the SW checks `sender.id` on
  every inbound message. The content script's sendMessage
  call is therefore implicitly validated when the SW
  receives the message.

### F-09: Opt-in state changes are not signed
- **STRIDE:** R
- **Severity:** Low (1.5/10)
- **Status:** **CLOSED** (out of scope for v0.1.0-beta)
- **Mitigation:** v0.1.0-beta does not store the opt-in state in
  `chrome.storage` (it uses the `prompt-detect` JS variable,
  which is per-tab and per-session). The opt-in form is local-
  only. v0.2.0 will add HMAC-signed opt-in state for the
  Platform tier.
- **Why closed:** the v0.1.0-beta threat surface for this
  finding is "the user clicks Opt In" and "the user clicks
  Cancel". Both are in-tab, both have no persistent state, both
  are unspoofable by the page DOM (the user clicked the
  button).

### F-12: Residual attack surface
- **STRIDE:** (all)
- **Severity:** — (residual)
- **Status:** **RESIDUAL**
- **Description:** All known attack classes are caught.
  Defense-in-depth remains: the regex tier catches the
  obvious patterns; the architecture is open to adding an ML
  tier (v0.2.0) for the long tail.
- **Why residual:** there is no detection system with 0%
  false negatives on adversarial inputs. A sufficiently
  sophisticated attacker who knows our patterns can craft a
  prompt that bypasses the regex tier. The mitigation is
  context: the Lens is opt-in for the user, the user can
  always press "Send Anyway", and the Lens never claims 100%
  detection. The architecture enforces "warn, never block"
  to limit the cost of a false negative.

### F-15: Adversarial robustness against semantic-preserving attacks
- **STRIDE:** T
- **Severity:** Medium (4.0/10)
- **Status:** **PARTIAL**
- **Description:** TextFooler-style synonym substitution
  achieves ~40% attack success rate (ASR) against the regex
  tier; BERTAttack-style semantic corruption achieves ~100% ASR
  (any prompt can be made to look like another by paraphrasing).
  The regex tier cannot catch paraphrased PII. v0.2.0 introduces
  a TinyML tier (DistilBERT-tiny, INT8-quantized, ~5MB) that
  brings the expected ASR down to ~5-10% on the same corpora.
- **Why partial:** the v0.1.0-beta ships regex-only. The
  document-vs-reality gap is acknowledged in the README
  ("best-in-class" claim was removed; we claim 95% in-target
  recall on a 60K-prompt held-out set, not 100% adversarial
  robustness).
- **Mitigation plan:** v0.2.0 (Q3 2026).

## Threat surfaces we are NOT exposed to (and why)

- **Prompt content disclosure to a third party:** impossible by
  architecture. The content script makes no `fetch()` calls. The
  service worker makes no `fetch()` calls on the content
  script's behalf. The opt-in telemetry call sends ONLY
  `{hashed_domain, category, severity, action}` — no prompt
  text, no value, no URL. Verified by code review + 325 unit
  tests.

- **Tampering with the extension's detection rules:** impossible
  without code-signing key access. The extension is signed
  Ed25519; ChromeOS / macOS / Windows verify the signature at
  install time. A malicious update would have to be signed by
  the AegisGate Security private key (in our HSM).

- **Denial of service via spam prompts:** out of scope. The
  Lens has no per-tab throttle. A user could in theory paste
  1M prompts in a second; the detection runs in <1ms each, so
  1M = 1,000 seconds = 16 minutes of CPU. The user's browser
  would be unusable long before that. Per F-12, the Lens
  "warns, never blocks" — the worst case is the user ignores
  1M warnings, which is on them.

## Privacy promises (architectural, not aspirational)

1. **The prompt content never leaves the browser.** The content
   script's only outbound message to the SW is the detection
   result, which contains `{category, severity, value (masked),
   index}` — the **detection outcome**, not the prompt text.

2. **No fingerprinting, no A/B testing, no analytics SDK, no
   third-party scripts, no remote config, no crash reporting,
   no update checks beyond Chrome's standard update channel.**

3. **Opt-in is opt-in.** Telemetry is OFF by default. The only
   way to enable it is to click "Submit & dismiss" on a banner
   (a per-detection opt-in). The opt-in form is local-only;
   no remote state.

4. **No cookies, no localStorage abuse.** `chrome.storage.session`
   is used for the dismiss flag, with a 24h TTL enforced by
   `dismiss.js`. `chrome.storage.session` is auto-cleared on
   browser restart, so the data lifetime is at most one
   browser session.

5. **No PII leakage in opt-in telemetry.** The hashed-domain
   hash is rotated periodically; the salt is not in the
   extension bundle. An attacker with backend access cannot
   recover the original hostname without brute-forcing the
   hash space (16 hex chars = 64 bits, ~10^19 work).

## Compliance mappings (v0.2.0)

| Standard | Coverage | Notes |
|---|---|---|
| **GDPR (EU 2016/679)** | ✅ Full | No personal data collected; no lawful-basis questions. The "data minimization" principle is enforced by architecture. |
| **HIPAA** | ✅ Indirect | SSN / DOB / address detection is HIPAA-relevant. The Lens does not store any of this; it warns the user and discards. |
| **PCI-DSS** | ✅ Indirect | Credit-card detection with Luhn validation. |
| **CCPA / CPRA (California)** | ✅ Full | No personal information sold or shared. The "Do Not Sell" link is irrelevant because no data is sold. |
| **EU AI Act (2024)** | ✅ Detection patterns | Articles 5, 15, 50 detection patterns present. The Lens is a "transparency" tool per Article 50. |
| **OWASP LLM Top 10 (2025)** | ✅ 6/10 covered | LLM01 (prompt injection), LLM04 (model DoS), LLM06 (sensitive info), LLM07 (plugin design), LLM08 (excessive agency), LLM10 (model theft) patterns present. |
| **MITRE ATLAS** | ✅ 15 techniques | Adversarial-robustness partial (F-15). |
| **NIST CSF 2.0** | ✅ ID.AM, ID.RA, PR.AC, DE.CM | All six functions map to existing patterns. |
| **ISO 27001:2022** | ✅ A.5.10 (info classification), A.8.16 (monitoring), A.8.28 (secure coding) | All three controls are demonstrable from the code. |

## How to verify this threat model

Any independent auditor can verify the claims in this document by:

1. **Reading the source code** at https://github.com/aegisgatesecurity/aegisgate-lens
   (7,241 lines of JS/CSS/HTML; no `node_modules` to audit).
2. **Running the unit test suite** (`node --test test/unit/*.test.mjs` → 405/405 unit + `cd tools/headless-smoke/flow && go test -v ./...` → 3/3 Go unit). Note: there is no \`npm test\` — the repo has zero npm dependencies per the no-npm rule.
3. **Running the headless smoke test** (`./test/headless-smoke/headless-smoke-bin`
   → 16/16 PASS, SHIP GATE: PASS).
4. **Auditing the CI pipeline** (`.github/workflows/security.yml`
   — F-01 sender-id check, no-npm-deps check, DCO sign-off,
   Trivy scans, CSP gate).
5. **Inspecting the build artifact** (every .crx on the GitHub
   Releases page is PGP-signed by the AegisGate Security key,
   fingerprint available on request).

## Reporting a security issue

If you have found a security issue in AegisGate Lens:

- **Email:** security@aegisgatesecurity.io
- **PGP key:** available at https://aegisgatesecurity.io/.well-known/pgp-key.asc
  (fingerprint on request)
- **Response SLA:** 48 hours acknowledgement, 7 days triage,
  30 days fix or status update.
- **Coordinated disclosure:** we ask for 90 days before
  public disclosure. We credit reporters in the release notes
  (unless they prefer to remain anonymous).

## License

This document is licensed under CC-BY-4.0. You may copy, modify,
and redistribute it. AegisGate Security, LLC is not liable for
errors in this document; verify all claims against the source
code linked above.

---

**Signed-off-by:** AegisGate Security <security@aegisgatesecurity.io>
**Source of truth:** https://github.com/aegisgatesecurity/aegisgate-lens/blob/main/docs/THREAT-MODEL.md
**Last updated:** 2026-07-09
**Version:** v0.2.0
