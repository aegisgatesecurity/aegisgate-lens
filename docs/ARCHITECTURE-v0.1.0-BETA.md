# AegisGate Lens v0.1.0-beta — Architecture

> **Status**: DRAFT for sign-off (2026-07-04). No code yet.
> **Audience**: Implementer (this AI), reviewer (founder), future contributors.
> **License**: Apache 2.0.

## 0. What this document is

The binding architectural specification for AegisGate Lens v0.1.0-beta.
It replaces all prior Lens versions (v0.1, v0.2, v0.3.0-rc1, v0.3.0-rc2)
and exists to ensure the new build is auditable, deliverable, and aligned
with the product vision.

**Read first**: `plans/AEGISGATE-LENS-PIVOT-2026-06-18.md`,
`plans/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md`.

## 1. The vision (one paragraph)

AegisGate Lens is a privacy-first browser extension that protects
individuals and small teams (the 95% of AI users without enterprise
protection) from accidentally exposing sensitive data to consumer AI
tools and from being prompt-injected via pasted content. The Lens is
the top of the funnel; the AegisGate Gateway is the bottom. Both
products share threat intel. Both serve different buyers. The Lens
generates the data that makes the Gateway smarter.

## 2. The 12 non-negotiables (from the Legal & Developer Constraints)

1. No prompt content ever leaves the browser — even for debugging.
2. No URLs ever leave the browser — domain is hashed locally.
3. No page content ever leaves the browser.
4. No user ID, session ID, or cookie is ever collected.
5. The Lens's default is OFF. Telemetry requires explicit opt-in.
6. Apache 2.0 OSS from day one. Code, threat model, architecture public.
7. Privacy policy published before ship to Chrome Web Store.
8. Zero runtime external dependencies. No `package.json`, no `node_modules`.
9. **Local-only by default; opt-in telemetry is hashed, not retained.** The v0.1.0-beta Lens does not retain any event data on a server. Detection runs 100% in the browser. If the user opts in to false-positive reporting (the only opt-in path in v0.1.0-beta), the report payload is domain-hashed (SHA-256 truncated to 16 hex chars) and category-only; no prompt text, URL, page content, or user identifier is sent. The on-device chrome.storage.local cap is MAX_EVENTS_RING (1000) + MAX_USER_ACTIONS (100); the per-dismissal 24h TTL caps the dismiss map. A server-side retention policy (90 days events, indefinite aggregated stats) is described in the v0.2.0 design but is NOT shipped in v0.1.x. The v0.1.0-beta Lens is offline-capable.
10. API rate-limited: 100 events/min per installation, 10K/min per backend.
11. Backend TLS-only (1.2+). HSTS enabled. HTTP rejected.
12. Threat model updated whenever architecture changes.

## 3. The 6 detection facets

Each prompt is evaluated by all 6 facets in parallel. Results are
aggregated into a single event with a per-facet discriminator.

| # | Facet | Tool | Always-on? | Bundle size |
|---|---|---|---|---|
| 1 | PII | Regex + Luhn | Yes | 0 KB (built-in) |
| 2 | Secrets | Regex (Platform port) | Yes | 0 KB (built-in) |
| 3 | Source / XSS | Regex (Platform port) | Yes | 0 KB (built-in) |
| 4 | Compliance (OWASP, ATLAS, EU AI Act, ANP, CU) | Regex (Platform port) | Yes | 0 KB (built-in) |
| 5 | Toxicity | Regex (always) + toxic-bert (ML, lazy) | Regex always; ML when uncertain | 110 MB lazy |
| 6 | Prompt injection | ModernBERT-base (lazy) | When text >= 20 chars | 134 MB lazy |

## 4. The tiered ML architecture (v0.3 lineage)

```
Tier 0 (always-on, 0 MB):    Regex facets 1-4 + 5-regex
Tier 1 (default-on, lazy):   ModernBERT-base, 8K ctx, q4f16 ONNX, 147 MB
Tier 2 (lazy, on-demand):    Longformer-base, 4K ctx, q4f16 ONNX, 150 MB
                             Triggered only when text > 8K chars AND
                             attack-related keywords detected by regex
```

**Why tiers**: ~100% of benign prompts are < 8K chars. ~100% of
long-context attacks are > 24K chars. The long-context problem is
real (lawyers pasting contracts, journalists pasting research) and
Tier 1 alone misses it. Tier 2 is the helper, not a replacement.

**Loading rules**:
- Tier 1: lazy-loaded on first prompt requiring ML.
- Tier 2: lazy-loaded only when both conditions hit.
- Both bundles Ed25519-signed, SHA-256 manifest verified at load.
- Both cached in `chrome.storage.local` with `unlimitedStorage` perm.
- NEVER `await import()` from a content script. All ML loads happen
  in the service worker. Content scripts post text to the SW via
  `chrome.runtime.sendMessage`; SW returns the detection result.

## 5. WebGPU vs WASM execution provider

Detected at runtime in the SW. WebGPU preferred when available
(shader-f16 + adapter present). WASM fallback (single-thread).
The choice is surfaced in the popup for transparency.

## 6. The file structure

```
aegisgate-lens/
|-- LICENSE                          (Apache 2.0)
|-- README.md
|-- CHANGELOG.md
|-- .gitignore                       (comprehensive; blocks dist, vendor,
|                                     node_modules, ml models, *.zip, *.crx)
|-- manifest.json                    (declarative content_scripts, NO scripting,
|                                     SW NOT a module, unlimitedStorage, alarms)
|
|-- src/
|   |-- background.js                (service worker; not a module; owns
|   |                                 storage; fetches to backend; lazy-loads
|   |                                 ML bundles; threat-intel poll every 6h)
|   |-- content.js                   (full 6-facet dispatcher; MutationObserver
|   |                                 for SPA prompt-area detection; runs at
|   |                                 document_idle; posts events to SW)
|   |
|   |-- detectors/
|   |   |-- index.js                 (the real dispatcher -- not a skeleton)
|   |   |-- luhn.js                  (credit-card Luhn validation)
|   |   |-- regex/
|   |   |   |-- pii.js               (Facet 1: SSN, email, phone, etc.)
|   |   |   |-- secrets.js           (Facet 2: API keys, RSA, tokens)
|   |   |   |-- source_xss.js        (Facet 3: source code leaks, XSS)
|   |   |   `-- compliance.js        (Facet 4: OWASP/ATLAS/EU AI Act/ANP/CU)
|   |   `-- ml/
|   |       |-- toxicity.js          (Facet 5: regex + toxic-bert lazy)
|   |       |-- prompt_injection.js  (Facet 6: ModernBERT-base lazy)
|   |       |-- long_context.js      (Tier 2: Longformer-base lazy, on-demand)
|   |       |-- ep-detect.js         (WebGPU vs WASM detection)
|   |       `-- bundle-loader.js     (Ed25519 verify, SHA-256 manifest, cache)
|   |
|   |-- privacy/
|   |   |-- schema.js                (event validator; 65 categories; facet
|   |   |                             discriminator; required fields)
|   |   `-- domain_hash.js           (SHA-256 with crypto.subtle feature-detect)
|   |
|   |-- api/
|   |   |-- messages.js              (message type constants:
|   |   |                             LENS_ANALYZE_TEXT, LENS_REPORT_DETECTION,
|   |   |                             LENS_OPT_IN, LENS_GET_STATE, etc.)
|   |   `-- client.js                (the SW's fetch() to backend with
|   |                                 sender.id validation, rate limit)
|   |
|   |-- util/
|   |   |-- logger.js                (console.error/warn wrapper; NEVER
|   |   |                             silently swallows err)
|   |   |-- banner-ui.js             (pure DOM banner; send/redact/cancel)
|   |   |-- prompt-detect.js         (MutationObserver; attaches to prompt
|   |   |                             textarea for 10 providers)
|   |   |-- selectors.js             (selector list: ChatGPT, Claude, Gemini,
|   |   |                             Copilot, Grok, Perplexity, DuckDuckGo,
|   |   |                             X, duck.ai)
|   |   |-- opt-in.js                (localStorage opt-in flag, sticky)
|   |   `-- storage.js               (chrome.storage.local wrapper, owned by SW)
|   |
|   |-- welcome/
|   |   |-- welcome.html             (first-install welcome page)
|   |   `-- welcome.js
|   |
|   |-- popup/
|   |   |-- popup.html               (browser action popup)
|   |   `-- popup.js
|   |
|   `-- icons/
|       |-- icon-16.png
|       |-- icon-32.png
|       |-- icon-48.png
|       `-- icon-128.png
|
|-- tools/
|   `-- build/
|       |-- main.go                  (Go build tool; stdlib only; cp + zip +
|       |                             SHA256SUMS; output lens-v0.1.0-beta.zip)
|       `-- README.md
|
|-- test/
|   |-- unit/
|   |   |-- regex-pii.test.mjs       (node:test; no Jest/Mocha)
|   |   |-- regex-secrets.test.mjs
|   |   |-- regex-source-xss.test.mjs
|   |   |-- regex-compliance.test.mjs
|   |   |-- schema.test.mjs
|   |   |-- domain-hash.test.mjs
|   |   |-- banner-ui.test.mjs
|   |   |-- prompt-detect.test.mjs
|   |   |-- opt-in.test.mjs
|   |   `-- facet_gap_analysis.js    (the 44-test verifier; rewritten clean)
|   |
|   `-- e2e/
|       |-- main.go                  (Go E2E; uses vendored chromedp dep;
|       |                             rewritten from scratch, NOT a fix of
|       |                             the old Go test extension)
|       `-- mock-ai-page.html        (served by the test binary)
|
`-- docs/
    |-- ARCHITECTURE-v0.1.0-BETA.md  (this file)
    |-- THREAT-MODEL-v0.1.0-BETA.md  (re-derived from F-01..F-20)
    |-- MODEL-CARD.md                (Google Model Cards format)
    |-- PRIVACY-POLICY.md
    |-- TERMS-OF-SERVICE.md
    |-- DPA-ADDENDUM.md
    |-- NO-EXTERNAL-DEPS.md
    `-- CONTRIBUTING.md
```

## 7. The manifest (sketch -- final in Phase 3)

```json
{
  "manifest_version": 3,
  "name": "AegisGate Lens",
  "version": "0.1.0-beta",
  "description": "Privacy-first browser extension that detects prompt injection, PII, secrets, and toxicity before they reach AI tools. No prompt content ever leaves your browser. Apache 2.0.",
  "permissions": ["storage", "alarms", "unlimitedStorage"],
  "host_permissions": ["https://lens.aegisgatesecurity.io/*"],
  "background": { "service_worker": "src/background.js" },
  "content_scripts": [{
    "matches": [
      "https://chat.openai.com/*", "https://chatgpt.com/*",
      "https://claude.ai/*", "https://gemini.google.com/*",
      "https://copilot.microsoft.com/*", "https://duck.ai/*",
      "https://duckduckgo.com/*", "https://perplexity.ai/*",
      "https://grok.com/*", "https://x.com/*"
    ],
    "js": ["src/content.js"],
    "run_at": "document_idle",
    "all_frames": false
  }],
  "action": { "default_popup": "src/popup/popup.html" },
  "icons": { "16": "src/icons/icon-16.png", "32": "src/icons/icon-32.png",
             "48": "src/icons/icon-48.png", "128": "src/icons/icon-128.png" },
  "web_accessible_resources": [{
    "resources": ["src/welcome/welcome.html", "src/icons/*"],
    "matches": ["<all_urls>"]
  }],
  "content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
  },
  "minimum_chrome_version": "116"
}
```

Key points: NO `scripting` permission. NO `"type": "module"` on the
SW. NO `chrome.scripting.registerContentScripts()`. NO
`chrome.userScripts`. Just the official, declarative mechanism.

## 8. Content script to service worker transport

```
content.js  ---chrome.runtime.sendMessage--->  background.js
            <---response (detection result)---
```

The SW is the only component that does `fetch()` to the backend.
Content scripts have `host_permissions` for the backend hostname
but don't use them directly -- that routing lives in the SW. This
keeps the trust boundary clean: all network I/O is auditable in
one place (the SW).

The `onMessage` listener validates `sender.id === chrome.runtime.id`
to reject foreign senders (per threat model F-01). Every dispatched
message logs the type and the (local-hashed) sender, never the content.

## 9. SPA prompt-area detection (MutationObserver)

Modern React SPAs (ChatGPT, Claude, Gemini, Copilot, Grok, Perplexity,
DuckDuckGo, X) never reliably fire `document_idle` for the prompt
textarea. The content script uses a MutationObserver pattern:

```
new MutationObserver(records => {
  for (const r of records) {
    for (const n of r.addedNodes) {
      if (n.nodeType !== 1) continue;
      const el = n.matches?.(SELECTORS.prompt)
        ? n
        : n.querySelector?.(SELECTORS.prompt);
      if (el && !el.__lens_attached) attachPromptListeners(el);
    }
  }
});
```

`run_at: document_idle` is kept (matches the v0.1 baseline the audit
preserved as a working starting point). The MutationObserver handles
the post-load React render that bypasses `document_idle`.

## 10. The test strategy (no CDP bypass)

Two layers, both required:

**Unit tests** (`test/unit/`): Node.js `node:test` (built-in, no
Jest, no Mocha). Tests the regex chain, the schema, the domain hash,
the banner UI (in jsdom or similar built-in), the prompt detector
(mocks MutationObserver). No browser needed.

**E2E tests** (`test/e2e/`): Go binary using the vendored chromedp
dep. Loads the unpacked dist in a real Chrome via the DevTools
Protocol. Navigates to `test/e2e/mock-ai-page.html` (served by the
test binary). Types a test prompt. Asserts the banner element appears.
Asserts `performance.getEntriesByType('resource')` includes
chrome-extension:// entries (proves real content_scripts injection,
not a CDP bypass). Asserts no `console.error` was logged.

**Forbidden** for content_scripts tests: `Page.addScriptToEvaluateOnNewDocument`.
That was the bypass mechanism that faked the 180/180 result. If we
see this in any test, it is a bug, not a feature.

## 11. The build strategy

`tools/build/main.go` is a single Go file (stdlib only -- `archive/zip`,
`crypto/sha256`, `encoding/hex`, `flag`, `fmt`, `io`, `os`, `path/filepath`).
It:
1. Reads the manifest version.
2. Copies the manifest, icons, popup, welcome, and resources to `lens-v0.1.0-beta/`.
3. Zips to `lens-v0.1.0-beta.zip`.
4. Writes `lens-v0.1.0-beta/SHA256SUMS`.

No `go.mod`, no external Go modules. The `chromedp` dep used by
the E2E tests is in the Platform monorepo, not in this repo (this
repo consumes the vendored copy).

## 12. The threat model summary

The full threat model is in `docs/THREAT-MODEL-v0.1.0-BETA.md`
(re-derived from F-01..F-20). Summary:

- **F-01 sender-id validation** -- implemented in `background.js`
  `onMessage` listener.
- **F-02 bundle signing** -- Ed25519 + SHA-256 manifest in
  `detectors/ml/bundle-loader.js`. Reject on mismatch.
- **F-03 content script on attacker DOM** -- by design. Detectors
  are read-only.
- **F-04 dismissals pruning** -- implemented in `util/storage.js`
  (the SW's `chrome.storage.local` wrapper).
- **F-05 backend rate limit** -- inherited from Platform's
  `pkg/lensbackend/ratelimit.go`; client-side 100/min/installation
  re-enforced in `background.js`.
- **F-06 CSP** -- `script-src 'self' 'wasm-unsafe-eval'`; no
  `eval`, `Function`, `innerHTML`, `document.write` in
  the source (enforced by `test/unit/security-csp.test.mjs`).
- **F-07 web-accessible bundles** -- accepted trade-off; documented
  in the Privacy Policy.
- **F-08 sender-id (same as F-01)**.
- **F-09 opt-in state** -- `last_changed_at` and `lens_version`
  recorded alongside the flag.
- **F-10..F-20** -- ML robustness, fingerprinting, FP poisoning,
  threat-intel timing, bundle update push. Mitigations documented
  in the threat model doc.

## 13. The privacy posture (the public-facing summary)

- The Lens reads the content of the prompt textarea only. It does
  not read other page content.
- The Lens hashes the page domain (SHA-256, truncated to 16 hex
  chars) locally. The hash never leaves the browser except as
  part of an opt-in telemetry event.
- The Lens never sends prompt content, URLs, page content, user
  IDs, session IDs, or cookies to any server.
- Telemetry is opt-in. The default is OFF. The opt-out is sticky.
- All backend traffic is TLS 1.2+. HTTP is rejected.
- Data retention: 90 days for events, indefinite for aggregated stats.

## 14. The CWS posture (the Chrome Web Store submission)

- CWS listing will be rebuilt fresh (per user decision; old assets
  were from a broken build).
- Required disclosures: data collection (metadata only, opt-in),
  permission justifications, privacy policy URL, accurate screenshots.
- Single-purpose: protect users from prompt injection and PII leaks.
- No `key` field required (no OAuth).

## 15. Sign-off

This document is binding for the v0.1.0-beta implementation. Any
deviation requires a new architecture-version and explicit re-approval.

When approved, the implementer proceeds to Phase 2 (scaffold) and
Phase 3 (incremental build with real-browser verification at each step).

---

*End of v0.1.0-beta Architecture Document.*
