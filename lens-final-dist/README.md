README.md — lens-final-dist/ (v0.2.0-test build)

This is a TEST BUILD for pen-testing the v0.2 extension code.

DO NOT distribute this directory. It is for local development and pen-tests only.

Differences from src/manifest.json (the production manifest):
  - References only files that exist in src/
  - version: 0.2.0-test (vs production 0.2.0)
  - Skips unimplemented facets: facet-dispatcher.js, fp-flow.js,
    threat-intel.js, long-content.js, transformer-toxicity.js,
    toxicity-regex.js, compliance-regex.js
  - Includes detectors/regex_v2.js (the v0.2 regex additions including
    the JWT-none fix and pii_health_v3 fix)

The 6-facet system described in architecture §2 is not fully implemented
yet. What's tested here:
  - Facet 1: PII (regex_v2.js + luhn.js + from_platform.js)
  - Facet 2: Secrets (regex_v2.js)
  - Facet 3: XSS (regex_v2.js)
  - Facet 4: Compliance (regex_v2.js)
  - Facet 5: Toxicity (regex-only — toxic-bert bundle deferred)
  - Facet 6: Prompt injection (transformer-modernbert.js + snapshot model)

What's NOT included in this test build (deferred to v0.2.1):
  - Sliding-window inference UI
  - Foreign-sender message validation UI
  - Threat-intel feed polling
  - FP dismiss flow
  - ONNX bundle (gated on sign-off)

Built by: test/scripts/build-v02-dist.sh
Build date: 2026-06-28
Source: src/ (v0.2.0) + v0.1 dist assets (icons, popup, welcome)