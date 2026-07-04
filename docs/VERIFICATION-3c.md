# AegisGate Lens v0.1.0-beta — Step 3c verification record

**Date**: 2026-07-04 15:25 UTC
**Step**: Phase 3 / Step 3c (regex facets 2-4: secrets, source_xss, compliance)

## What was tested

Per the architecture doc Section 6 and the Phase 3 plan, Step 3c
delivers regex detectors for the remaining 3 of 4 regex facets:
- Facet 2: **Secrets** (17 categories)
- Facet 3: **Source / XSS** (6 categories)
- Facet 4: **Compliance** (17 categories, OWASP/ATLAS/EU AI Act/ANP/CU)

## Files added

| File | Lines | Purpose |
|---|---|---|
| `src/detectors/regex/secrets.js` | 99 | 17 secret patterns (AWS, GitHub, GCP, Azure, PEM, JWT, OAuth, generic API key, DB conn string, Slack, Stripe, Twilio, SendGrid, Mailgun, OpenAI, Anthropic, Heroku) |
| `src/detectors/regex/source_xss.js` | 75 | 6 XSS patterns (script tag, event handler, javascript: URL, data:text/html, SVG with script, DOM clobbering) |
| `src/detectors/regex/compliance.js` | 137 | 17 compliance patterns (OWASP LLM 01/04/08/09/10, ATLAS poison/exfil/jailbreak, EU AI Act high-risk/transparency/human-oversight/robustness, ANP personal-data/special-category, CU consumer-rights/minor-protection) |
| `test/unit/regex-secrets.test.mjs` | 144 | 27 secrets tests |
| `test/unit/regex-source-xss.test.mjs` | 76 | 18 XSS tests |
| `test/unit/regex-compliance.test.mjs` | 122 | 26 compliance tests |
| `test/unit/facet_gap_analysis.js` | 180 (extended) | 78 cases total (40 PII + 12 secrets + 8 XSS + 18 compliance) |

## Manifest updates

`content_scripts.js` now includes all 6 scripts in load order:
```
src/util/logger.js
src/detectors/luhn.js
src/detectors/regex/pii.js
src/detectors/regex/secrets.js
src/detectors/regex/source_xss.js
src/detectors/regex/compliance.js
src/content.js
```

## Test results

```
=== facet_gap_analysis.js ===
Cases run:    78
Pass:         78
Fail:         0
Pass rate:    100.0%

=== node:test all 5 test files ===
luhn.test.mjs:           17/17 PASS
regex-pii.test.mjs:      37/37 PASS
regex-secrets.test.mjs:  27/27 PASS
regex-source-xss.test.mjs: 18/18 PASS
regex-compliance.test.mjs: 26/26 PASS
TOTAL:                  125/125 PASS
```

**Combined with facet_gap_analysis.js: 203/203 tests passing across 6 test suites.**

## Bugs found and fixed during this step

The test suite caught 8 false positives / false negatives in the first run:

1. **compliance.js regex syntax error** (extra `)` in EU AI Act
   high-risk pattern) — fixed.

2. **compliance.js regex syntax error** (extra `)` in ANP
   special-category pattern) — fixed.

3. **GCP key regex too strict** (required exactly 35 chars after
   `AIza`; real keys can be 30-50) — relaxed to `{30,50}`.

4. **OpenAI regex swallowed Anthropic keys** (`sk-ant-*` matched
   both `sk-` and `sk-ant-`) — added negative lookahead
   `(?!ant-)` to OpenAI pattern.

5. **ATLAS poison regex too rigid** ("Retrain the model on this
   dataset" didn't match because "model" was between the action
   and the data source) — added optional `(?:the\s+)?(?:model|
   network|system|LLM)?` between action and data.

6. **Some test expectations were too strict** (expected only one
   category when multiple legitimately fire, e.g., LLM08 +
   EU AI Act human-oversight both match "without human oversight")
   — updated tests to accept all valid categories.

7. **Some test inputs were unrealistic** (Azure AccountKey with
   16 chars when real ones are 88) — updated test input to
   realistic base64 length.

8. **pii.js silently passed through CC matches when luhn.js was
   unavailable** — this was the most serious bug. Without Luhn
   validation, any 13-19 digit run would be flagged as a credit
   card (catastrophic FP rate). Fixed: postProcess now logs a
   warning AND drops the match if luhn.js is not loaded.

## Runtime verification (headless Chrome 150)

| Check | Result |
|---|---|
| Chrome loaded extension with all 6 content_scripts | PASS (CDP SW target present) |
| Service worker registered (`chrome-extension://fignfifoniblkonapihmkfakmlgkbkcf/service_worker.js`) | PASS |
| No errors mentioning our files in Chrome stderr | PASS |
| Manifest parsed cleanly with 6-file content_scripts array | PASS |

## Coverage summary

Across all 4 regex facets, the detectors now cover:
- **Facet 1 (PII)**: 11 categories — SSN, email, phone, credit
  card (Luhn-validated), DOB, address, driver license, passport,
  tax ID (EIN), bank account, IP address
- **Facet 2 (Secrets)**: 17 categories — AWS, GitHub, GCP, Azure,
  PEM private key, OAuth, JWT, generic API key, DB conn string,
  Slack, Stripe, Twilio, SendGrid, Mailgun, OpenAI, Anthropic,
  Heroku
- **Facet 3 (XSS)**: 6 categories — script tag, event handler,
  javascript: URL, data:text/html URL, SVG with script, DOM
  clobbering
- **Facet 4 (Compliance)**: 17 categories — OWASP LLM
  01/04/08/09/10, ATLAS poison/exfil/jailbreak, EU AI Act
  high-risk/transparency/human-oversight/robustness, ANP
  personal-data/special-category, CU consumer-rights/minor-protection

**Total: 51 categories across 4 regex facets, all with > 95%
recall on the test suite and 0 false positives on the gap
analysis.**

## What was NOT tested in this automated run

- Real browser UX on chat.openai.com (Phase 5)
- ML facets 5+6 (toxicity + prompt injection) — these are 3h
- Cross-prompt dedup (the dispatcher in 3e handles this)

## Sign-off

The Step 3c verification gate is satisfied:
- 78/78 gap analysis cases PASS
- 125/125 unit tests PASS
- All 4 regex facets implemented and tested
- Manifest updated; extension loads in headless Chrome with no errors
- All 8 bugs found by the test suite are fixed and re-verified

The next step (3d: util/prompt-detect.js + util/selectors.js,
the SPA MutationObserver for real ChatGPT/Claude/etc.) requires
user sign-off before proceeding.
