# AegisGate Lens v0.1.0-beta — Step 3d verification record

**Date**: 2026-07-04 15:55 UTC
**Step**: Phase 3 / Step 3d (SPA prompt detector with MutationObserver)

## What was tested

Per the architecture doc Section 9 and the Phase 3 plan, Step 3d
delivers the SPA-aware prompt detector:
- `util/selectors.js` — selector table for 10 AI providers
- `util/prompt-detect.js` — attaches to the prompt input via
  MutationObserver (survives React re-mounts)
- `content.js` — wires up the prompt detector with onDetect and
  onSendIntercept callbacks (banner UI is 3f, dispatcher is 3e)

## Files added

| File | Lines | Purpose |
|---|---|---|
| `src/util/selectors.js` | 244 | 10 provider configs (chatgpt, claude, gemini, copilot, perplexity, duckduckgo, duck.ai, grok, mistral, huggingchat), each with input/send/container selectors, submit method, and contentEditable flag |
| `src/util/prompt-detect.js` | 320 | SPA-aware prompt detector: identifyProvider, findInput, MutationObserver-based re-attach, debounced input listener, send-button intercept, Enter-key intercept, onDetect/onSendIntercept callbacks |
| `test/unit/selectors-prompt-detect.test.mjs` | 316 | 16 tests with a minimal DOM mock (no jsdom dep) |

## Files modified

- `src/content.js` — now wires up the prompt detector with
  `onDetect` and `onSendIntercept` callbacks. The banner UI
  (3f) will replace the placeholder `confirm()` with proper
  buttons. The 6-facet dispatcher (3e) will replace the
  PII-only `detectPrompt()`.
- `manifest.json` — content_scripts.js now has 9 entries:
  logger, luhn, pii, secrets, xss, compliance, selectors,
  prompt-detect, content

## Test results

```
=== facet_gap_analysis.js ===
78/78 PASS (100%)

=== node:test 6 test files ===
luhn.test.mjs:                     17/17
regex-pii.test.mjs:                37/37
regex-secrets.test.mjs:            27/27
regex-source-xss.test.mjs:         18/18
regex-compliance.test.mjs:         26/26
selectors-prompt-detect.test.mjs:  16/16

TOTAL:                            219/219 tests passing across 7 suites
```

## What the test suite covers

The 16 selectors+prompt-detect tests verify:

1. **Provider config**: 10 providers, each with all required
   fields (id, name, hosts, inputSelector, sendSelector,
   containerSelector, submitMethod, isContentEditable)
2. **Provider identification**:
   - chat.openai.com → chatgpt
   - claude.ai → claude
   - gemini.google.com → gemini
   - duck.ai → duck_ai
   - x.com → grok
   - www.perplexity.ai → perplexity (subdomain match)
   - CHAT.OPENAI.COM → chatgpt (case-insensitive)
   - example.com → null (no match)
3. **Prompt detector lifecycle**:
   - init() identifies provider and attaches
   - getState() returns expected fields
   - shutdown() is idempotent
   - detectPrompt() delegates to pii.js
   - init() returns false when no provider matches

## The mock-DOM strategy

To avoid a 100KB+ jsdom dependency, the tests use a minimal
DOM mock implemented in ~50 lines (MockElement, MockDocument,
matchSelector). This covers the selector-matching logic and
the prompt-detect lifecycle without requiring a real browser.

The mock is intentionally simple — it supports tag, #id, .class,
[attr=val], and [attr*="val"] selectors. The full CSS selector
spec is NOT supported. This is fine because the selectors in
selectors.js are all simple, and the real-browser verification
(Phase 5) will catch any issues with complex selectors.

## Runtime verification (headless Chrome 150)

| Check | Result |
|---|---|
| Chrome loaded extension with 9 content_scripts | PASS (CDP SW target present) |
| Service worker registered | PASS |
| No errors mentioning our files in Chrome stderr | PASS |
| Manifest parsed cleanly with 9-file content_scripts | PASS |

## Known limitations (deferred to 3e/3f)

- The `onSendIntercept` callback uses `window.confirm()` as a
  placeholder. The banner UI (3f) will replace this with a
  proper modal with send/redact/cancel buttons.
- The `detectPrompt()` function only runs the PII facet. The
  6-facet dispatcher (3e) will replace it with the full
  pipeline (PII + Secrets + XSS + Compliance + ML-Toxicity +
  ML-Prompt-Injection).
- The selectors are based on the AI providers' public DOM
  structures as of July 2026. If a provider changes their DOM,
  the MutationObserver will log a warning and try fallbacks.
  Long-term, per-provider plugins would be more resilient.

## What was NOT tested in this automated run

- Real ChatGPT/Claude/etc. navigation (Phase 5)
- ML facets 5+6 (3h)
- Banner UI (3f)
- SW message transport (3g)

## Sign-off

The Step 3d verification gate is satisfied:
- 78/78 gap analysis PASS
- 141/141 unit tests PASS (across 6 node:test files)
- 16/16 selectors+prompt-detect tests PASS
- All 9 content_scripts load in headless Chrome
- No errors in Chrome stderr
- The prompt detector is wired into content.js

The next step (3e: detectors/index.js, the 6-facet dispatcher
that aggregates PII + Secrets + XSS + Compliance + ML)
requires user sign-off before proceeding.
