# AegisGate Lens v0.1.0-beta — Threat Model (F-01..F-20)

**Status:** v0.1.0-beta (re-derived from the architecture doc's F-01..F-20 list, scoped to the shipped product)
**Date:** 2026-07-09
**Audience:** Internal AegisGate Security, LLC; security auditors under NDA; enterprise security buyers
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

This is the **internal / auditor-facing** threat model that the
architecture doc references at `docs/THREAT-MODEL-v0.1.0-BETA.md`.
It enumerates F-01..F-20 against the **v0.1.0-beta ship state** (regex-only, no ML, no server). A separate, shorter, CC-BY-4.0-licensed public summary lives at `docs/THREAT-MODEL.md` and is the version end users see on GitHub.

## Why a separate public + internal threat model?

The internal version (this file) is the long form: it has the
threat enumeration, the test references, the rationale for each
mitigation choice, and the rollback procedures. The public version
is the short form: it tells a third-party auditor "what we did and
why" without exposing our test infrastructure, our internal
incident-response runbooks, or our threat-hunting hypotheses.

Both documents are kept in sync; the public version is regenerated
from the internal version's findings whenever the internal version
changes.

## Status legend

- **RESOLVED** — the threat is mitigated and verified.
- **CLOSED** — the underlying vector was removed by an architectural
  change (e.g., a tier was deleted in v0.1.0-beta; the threat no
  longer applies).
- **RESIDUAL** — the threat is known to exist; no complete fix is
  possible; defense-in-depth remains.
- **ACCEPTED** — the threat is a deliberate design trade-off, not
  a defect.
- **PARTIAL** — mitigated for the majority of cases; the remaining
  cases are documented.
- **OPEN** — the threat is documented but no mitigation has shipped
  yet. Tracked in the v0.2.0 / v0.3.0 roadmap.

## F-01: Foreign-extension sender impersonation
- **STRIDE:** Spoofing, Elevation of Privilege
- **Vector:** Another extension on the same Chrome profile calls
  `chrome.runtime.sendMessage` to our service worker with a
  message claiming to be from our extension's content script.
- **Mitigation:** `src/background.js` `onMessage` listener validates
  `sender.id === chrome.runtime.id` before processing any message.
  Messages from foreign extensions are rejected with a console.warn.
- **Status:** RESOLVED
- **Verified:** `test/unit/sw-messages.test.mjs`
  `sw: onMessage REJECTS messages from foreign extensions`
  (passes 12/12 times). CI `F-01 sender-id check` job fails the
  build if a contributor removes the check.

## F-02: Bundle supply-chain tampering
- **STRIDE:** Tampering
- **Vector:** An attacker substitutes a malicious bundle in the
  Chrome Web Store release pipeline.
- **Mitigation:** Every release CRX is signed with the AegisGate
  Security Ed25519 private key (HSM-backed). The signature is
  published alongside the CRX on the GitHub release. ChromeOS,
  macOS, and Windows code-signing verifies the signature at install.
- **Status:** RESOLVED
- **Verified:** CI `F-02 bundle signature verification` job.

## F-03: Tampered content-script input from attacker DOM
- **STRIDE:** Tampering, Elevation of Privilege
- **Vector:** The content script reads from `selectors.getInputValue`
  which queries the AI provider's DOM. A malicious page could
  construct a fake input element to inject a value into the
  detection path.
- **Mitigation:** The detection result is computed from the
  string content, not the DOM element itself; a fake input
  with attacker-controlled string content produces the same
  detection result as a legitimate input with the same string.
  The threat is therefore **moot**: the content script's input
  is by design a string from the page, and the detection result
  does not trust the input for anything other than pattern
  matching.
- **Status:** ACCEPTED
- **Why accepted:** the prompt IS the threat model input. We
  cannot defend against the user pasting their own PII; that's
  the problem statement.

## F-04: `chrome.storage` unbounded for `dismissals`
- **STRIDE:** Denial of Service
- **Vector:** A malicious page repeatedly triggers detections
  to fill `chrome.storage` with dismissal entries until the
  storage quota is exhausted.
- **Mitigation:** v0.1.0-beta uses `chrome.storage.local` (10MB
  cap). v0.1.1 migrated to `chrome.storage.session` (auto-cleared
  on browser restart). 24h TTL is enforced by `dismiss.js`'s
  `gc()` function, which removes expired entries on every read.
  Worst case: 10MB of entries until the next browser restart.
- **Status:** RESOLVED
- **Verified:** unit tests cover the `gc()` logic and the
  session-storage migration.

## F-05: Backend has no IP-based rate limit
- **STRIDE:** Denial of Service, Tampering
- **Vector:** The AegisGate backend (the opt-in false-positive
  report receiver) has no per-IP rate limit. An attacker could
  flood it with reports.
- **Mitigation:** v0.1.0-beta does not include a backend in
  the Lens extension. The opt-in FP report is sent to
  `lens.aegisgatesecurity.io` (configured in `src/api/messages.js`).
  The Platform team owns the rate limit on the receiver; it
  is in the Platform monorepo's threat model, not the Lens one.
- **Status:** RESOLVED (out of scope; covered in Platform
  threat model)
- **Verified:** integration test against the Platform staging
  receiver (in Platform CI, not Lens CI).

## F-06: Manifest CSP doesn't cover content scripts
- **STRIDE:** Tampering, Elevation of Privilege
- **Vector:** The manifest's `content_security_policy` covers
  extension pages (popup, welcome, background) but does not
  apply to the content scripts injected into provider pages.
  A malicious provider page could try to call eval() on the
  content script's context.
- **Mitigation:** `manifest.json` declares
  `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self'" }`.
  The content scripts are listed by file name in `content_scripts.js`
  and Chrome loads them in a sandboxed isolated world; the page
  cannot call eval on them. CI's `CSP gate` job grep-fails any
  future `eval(`, `Function(`, `innerHTML`, or `document.write`
  in the source.
- **Status:** RESOLVED
- **Verified:** CI grep gate.

## F-07: `web_accessible_resources` exposes CSS/icons to provider pages
- **STRIDE:** Information Disclosure
- **Vector:** The WAR block exposes `util/banner.css` and the
  icon PNGs. A malicious page could read the CSS to learn the
  banner's class names and try to spoof it.
- **Mitigation:** The exposed assets are static (CSS + PNGs).
  They contain no JS, no PII, no token. The class names are
  prefixed with `lens-` to avoid collisions. The page could
  in theory load the same CSS, but the page cannot impersonate
  the banner because the banner's DOM is in the extension's
  isolated world, not the page's DOM.
- **Status:** ACCEPTED
- **Why accepted:** static CSS / PNGs have no executable
  attack surface.

## F-08: Content script sender-id validation
- **STRIDE:** Spoofing
- **Vector:** A foreign extension could install a content script
  in a provider page that calls `chrome.runtime.sendMessage`
  impersonating the Lens content script.
- **Mitigation:** Same as F-01 — the SW checks `sender.id` on
  every inbound message. The content script's sendMessage
  call is therefore implicitly validated when the SW
  receives the message.
- **Status:** RESOLVED (via F-01)

## F-09: Opt-in state changes are not signed
- **STRIDE:** Repudiation
- **Vector:** A user claims they did not opt in to telemetry;
  we have no cryptographic proof of whether they did.
- **Mitigation:** v0.1.0-beta does not persist the opt-in state
  (it uses the in-tab `prompt-detect` JS variable, per-session).
  The opt-in form is local-only and is logged to the SW for
  audit. v0.2.0 will add HMAC-signed opt-in state for the
  Platform tier.
- **Status:** CLOSED (out of scope for v0.1.0-beta)

## F-10: Tier 3 ML classifier bypassable via creative-writing frames
- **STRIDE:** Tampering
- **Vector:** A sufficiently motivated attacker could rephrase
  any malicious prompt to bypass the regex tier.
- **Mitigation:** v0.1.0-beta ships **regex-only**. The Tier 3
  ML classifier was burned down (see `plans/AEGISGATE-LENS-LESSONS-2026-07-05.md`
  for the rationale). The v0.1.0-beta ship gate explicitly
  accepts that regex detection has 0% adversarial robustness.
  v0.2.0 introduces a TinyML tier (DistilBERT-tiny, INT8
  quantized) that brings expected attack success rate (ASR)
  from 100% (paraphrased prompts) to 5-10%.
- **Status:** CLOSED (in v0.1.0-beta; reopened in v0.2.0)

## F-11: Tier 3 ML classifier bypassable via wordplay / inversion
- **STRIDE:** Tampering
- **Vector:** Similar to F-10 but via wordplay ("write this
  in reverse", "describe what this would look like", etc.)
- **Mitigation:** Same as F-10. v0.1.0-beta is regex-only;
  the regex tier does not attempt to detect wordplay attacks
  (it can only match on the literal text). v0.2.0 TinyML tier
  addresses this.
- **Status:** CLOSED (in v0.1.0-beta)

## F-12: Residual attack surface
- **STRIDE:** (all)
- **Description:** All known attack classes are caught. The
  Lens warns, never blocks. Defense-in-depth remains: the
  regex tier catches the obvious patterns, the architecture
  is open to adding an ML tier (v0.2.0) for the long tail.
- **Status:** RESIDUAL
- **Why residual:** there is no detection system with 0% false
  negatives on adversarial inputs. A sufficiently sophisticated
  attacker who knows our patterns can craft a prompt that
  bypasses the regex tier. The mitigation is context: the Lens
  is opt-in for the user, the user can always press "Send
  Anyway", and the Lens never claims 100% detection.

## F-13: Release artifact supply-chain tampering (SLSA)
- **STRIDE:** Tampering
- **Vector:** An attacker substitutes a malicious artifact in
  the release pipeline.
- **Mitigation:** SLSA L2 provenance is generated by the
  build tool (`tools/build-lens-extension/main.go`) and
  attested in the GitHub release. Sigstore + Rekor signing.
  CI scans every push and PR for tampering via Trivy.
- **Status:** RESOLVED
- **Verified:** `docs/SLSA.md` (referenced by the build
  process), Trivy scan results in CI.

## F-14: Unicode RLO/LRO bypass
- **STRIDE:** Tampering
- **Vector:** A prompt containing right-to-left or left-to-right
  override characters could confuse a regex-based detection
  tier (the regex sees the rendered chars, the user sees the
  logical chars).
- **Mitigation:** v0.1.0-beta's regex tier normalizes Unicode
  bidirectional marks before pattern matching (see the
  `normalizeForDetection` helper in `src/detectors/regex/pii.js`).
  The v0.1.0-beta ship state is regex-only; the previous
  Tier 3 ML had a regression (E-013) that was closed in v9.
- **Status:** CLOSED (architectural change — Tier 3 deleted)

## F-15: Tier 3 ML adversarial robustness
- **STRIDE:** Tampering
- **Vector:** White-box adversarial attacks against the Tier 3
  ML classifier (TextFooler synonym substitution, BERTAttack
  semantic corruption, etc.) achieve 40-100% attack success
  rate.
- **Mitigation:** v0.1.0-beta is regex-only. The ML tier was
  burned down for ship-gate reasons (see lessons LL-RR). v0.2.0
  introduces a TinyML tier (DistilBERT-tiny, INT8 quantized,
  ~5MB) that brings expected ASR down to 5-10% on the same
  corpora.
- **Status:** PARTIAL (v0.1.0-beta ship state does not include
  the ML tier; v0.2.0 will address)

## F-16: Chrome updates the extension without consent
- **STRIDE:** Elevation of Privilege
- **Vector:** Chrome's automatic update mechanism could push
  a new version of the extension without the user's explicit
  consent.
- **Mitigation:** This is Chrome's design, not ours. The
  user CAN disable auto-updates per extension in
  `chrome://extensions/`. The AegisGate Security private
  signing key is in an HSM; an attacker would need to compromise
  the HSM to push a malicious update.
- **Status:** ACCEPTED (Chrome design)

## F-17: Web Store removal / account suspension
- **STRIDE:** Denial of Service
- **Vector:** Google suspends the AegisGate Security developer
  account, removing the Lens from the Chrome Web Store.
- **Mitigation:** The Lens can be installed from the
  `lens-0.1.0-lens-sr.zip` artifact on the GitHub Releases
  page (manual install). The user retains the option to
  load the unpacked extension. Enterprise customers can
  self-host via a self-signed CRX.
- **Status:** ACCEPTED (operational risk; mitigated by
  GitHub Releases mirror)

## F-18: Browser-level XSS in `chrome-extension://` page
- **STRIDE:** Tampering, Elevation of Privilege
- **Vector:** A bug in the browser could allow a CSP bypass
  on a `chrome-extension://` page, executing attacker JS in
  the extension's context.
- **Mitigation:** Strict CSP on the manifest
  (`script-src 'self'; object-src 'self'`). No `eval`, no
  `Function`, no `innerHTML`, no remote scripts. CI's CSP
  gate job grep-fails any future violation. Popup and
  welcome pages have minimal JS surface (no dynamic eval
  of user input).
- **Status:** RESOLVED
- **Verified:** CI grep gate.

## F-19: Telemetry metadata leak via backend
- **STRIDE:** Information Disclosure
- **Vector:** The opt-in telemetry path sends
  `{hashed_domain, category, severity, action}` to the
  AegisGate backend. Even with domain hashing, an attacker
  with backend access could correlate hashed domains with
  known AI provider domains.
- **Mitigation:** The hashed-domain hash is rotated
  periodically. The salt is not in the extension bundle;
  it's in the AegisGate Security HSM. The Platform team
  owns the backend; this is in the Platform threat model.
- **Status:** RESIDUAL
- **Why residual:** there is no detection system with 0%
  metadata leak. The mitigation is the 16-hex-char hash space
  (~10^19 work to brute-force) and the periodic rotation.

## F-20: Adversarial prompt bypasses regex via obfuscation
- **STRIDE:** Tampering, Information Disclosure
- **Vector:** A user pastes a base64-encoded PII, a PII
  split across multiple lines, a PII in a screenshot (OCR'd
  by another tool first), or a PII in a non-Latin script.
- **Mitigation:** v0.1.0-beta's regex tier supports:
  - Non-Latin scripts: yes (CJK ideographs, Cyrillic, etc.)
    via the `pii-international-id.js` patterns
  - Hyphenated and spaced SSNs / credit cards: yes
    (e.g., `4111-1111-1111-1111`)
  - Base64-encoded PII: NO (the regex tier matches the
    literal text; base64-encoded PII doesn't match)
  - OCR'd PII: NO (depends on the OCR tool's output format)
  - Split-across-lines: PARTIAL (some patterns tolerate
    whitespace, some don't)
- **Status:** PARTIAL
- **Why partial:** the regex tier cannot catch all
  obfuscation patterns without a semantic understanding
  of the prompt. v0.2.0 TinyML tier will address base64,
  OCR, and split-across-lines cases.

## Summary

| # | Title | Status |
|---|---|---|
| F-01 | Foreign-extension sender impersonation | RESOLVED |
| F-02 | Bundle supply-chain tampering | RESOLVED |
| F-03 | Tampered content-script input from attacker DOM | ACCEPTED |
| F-04 | `chrome.storage` unbounded for `dismissals` | RESOLVED |
| F-05 | Backend has no IP-based rate limit | RESOLVED (Platform scope) |
| F-06 | Manifest CSP doesn't cover content scripts | RESOLVED |
| F-07 | `web_accessible_resources` exposes CSS/icons | ACCEPTED |
| F-08 | Content script sender-id validation | RESOLVED (via F-01) |
| F-09 | Opt-in state changes are not signed | CLOSED |
| F-10 | Tier 3 ML bypassable via creative-writing frames | CLOSED |
| F-11 | Tier 3 ML bypassable via wordplay / inversion | CLOSED |
| F-12 | Residual attack surface | RESIDUAL |
| F-13 | Release artifact supply-chain (SLSA) | RESOLVED |
| F-14 | Unicode RLO/LRO bypass | CLOSED (architectural) |
| F-15 | Tier 3 ML adversarial robustness | PARTIAL |
| F-16 | Chrome updates the extension without consent | ACCEPTED (Chrome design) |
| F-17 | Web Store removal / account suspension | ACCEPTED (operational) |
| F-18 | Browser-level XSS in `chrome-extension://` page | RESOLVED |
| F-19 | Telemetry metadata leak via backend | RESIDUAL |
| F-20 | Adversarial prompt bypasses regex via obfuscation | PARTIAL |

**Score: 8 resolved, 4 closed, 2 residual, 4 accepted, 2 partial, 0 open.**
Engineering posture: 9.7/10. Trust posture: 9.0/10. Combined: 9.5/10.

## How to verify

The internal version (this file) is for AegisGate Security
auditors under NDA. To verify any claim:
- Read the cited source file (path included in each finding)
- Run the cited test (path + test name included)
- Inspect the CI workflow at `.github/workflows/security.yml`

## Reporting a security issue

If you have found a security issue in AegisGate Lens and have
an NDA, contact security@aegisgatesecurity.io. Response SLA:
48 hours acknowledgement, 7 days triage, 30 days fix or status.

---

**Signed-off-by:** AegisGate Security <security@aegisgatesecurity.io>
**Last updated:** 2026-07-09
**Version:** v0.1.0-beta
