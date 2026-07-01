# Phase 2 — Status Report

**Date**: 2026-06-28
**Status**: ✅ Tests passing, awaiting ONNX export sign-off for final step

## Files created/modified this phase

### New files
- `src/util/transformer-modernbert.js` (441 LOC) — sliding-window inference path
- `test/transformer-modernbert.test.mjs` (24 tests, all passing)
- `test/model-loader.test.mjs` (12 tests, all passing)
- `test/scripts/sliding-window-sizing.py` — sizing decision archive
- `test/scripts/run-6-facet-validation.js` — full validation runner
- `test/scripts/README.md` — test scripts directory documentation
- `test/scripts/PHASE-2-PLAN.md` — Phase 2 planning notes
- `test/scripts/sliding-window-sizing-results-2026-06-28T22-00-00Z.log` — sizing experiment archive
- `test/eval/transformer-modernbert-results.json` — test results archive
- `test/eval/model-loader-results.json` — test results archive
- `test/eval/6-facet-validation-summary.json` — validation summary archive

### Modified files
- `src/util/bundle-loader.js` — extended to support binary files (`.onnx`)
- `src/util/model-loader.js` — wired bundle parsing → ONNX session creation
- `src/util/model-loader.js` — added `log` declaration (was missing)

## Test results summary

| Suite | Tests | Status |
|-------|-------|--------|
| `test/transformer-modernbert.test.mjs` | 24 | ✅ all pass |
| `test/model-loader.test.mjs` | 12 | ✅ all pass |
| `tools/test_detectors_v2.js` | 34 | ✅ all pass |
| `tools/facet_gap_analysis.js` | 44 | ✅ all pass |
| `corpora/SHA256SUMS.v2` | 19 files | ✅ all verified |
| `models/release-candidates/.../SHA256SUMS` | 10 files | ✅ all verified |

**Total tests passing**: 36 unit/integration tests + 78 detector/gap-analysis tests + 29 file integrity checks

## 6-Facet status

| Facet | Status | Coverage |
|-------|--------|----------|
| 1. PII | ✅ 100% | regex_v2.js + Luhn |
| 2. Secrets | ✅ 100% | regex_v2.js |
| 3. XSS/Source | ✅ 100% | regex_v2.js |
| 4. Compliance | ✅ 100% | regex_v2.js |
| 5. Toxicity | ⚠️ regex-only (deferred per architecture) | regex_v2.js; ML bundle pending |
| 6. Prompt injection | ✅ Sliding window + snapshot model working | transformer-modernbert.js |

## Sliding-window design (locked)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `max_length` | 2048 | Matches training distribution |
| `stride` | 1024 | 50% overlap |
| `max_windows` | 4 | 5120-token coverage; matches 8K recall on long-context corpus |
| Adaptive short-circuit | ≤512 tokens → single window | Avoids sliding overhead for 61% of documents |
| Aggregation | max-pool P(attack) | Conservative; any window hit = flag |
| Threshold | 0.5 | Standard binary |

## Sliding window validation (against r8_attack_long_context sample)

| Strategy | Recall | Avg P(attack) |
|----------|--------|---------------|
| Single 2048-token window | 50% | 0.5040 |
| Sliding 2048/1024/4 (current) | 75% | 0.7704 |
| **Improvement** | **+25pp** | **+0.27** |

## Bundle wire-up status

| Component | Status |
|-----------|--------|
| Bundle format (binary files support) | ✅ Implemented |
| Ed25519 signature verification | ✅ Implemented (existing) |
| License audit (Apache-2.0/MIT/etc.) | ✅ Implemented (existing) |
| ONNX session creation | ✅ Implemented (in code) |
| Chrome storage caching | ✅ Implemented (existing) |
| End-to-end with REAL ONNX bundle | ⏳ Awaiting Phase 2 final step |

## What's left (Phase 2 final step)

**ONNX export of rc1 model with q4f16 quantization — REQUIRES YOUR SIGN-OFF**

After your sign-off:
1. Export `models/release-candidates/prompt-injection-v0.2.0-rc1/` to ONNX
2. Save to `test/bundles/` (NOT shipping location)
3. Build a real signed bundle with the ONNX bytes
4. Test end-to-end: real bundle → real ort session → real inference → real classifications
5. Verify parity with Python baseline (≥95% score agreement)
6. STOP and archive results, await further sign-off to copy to shipping location

## How to re-verify

```bash
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02

# Full 6-facet validation (everything in one command)
node test/scripts/run-6-facet-validation.js

# Individual suites
node test/transformer-modernbert.test.mjs
node test/model-loader.test.mjs
node tools/test_detectors_v2.js
node tools/facet_gap_analysis.js
```