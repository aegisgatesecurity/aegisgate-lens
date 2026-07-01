# Phase 2 — Status Update (2026-06-28)

## Phase 1 ✅ Complete
- Detector fix (pii_health_v3) → 34/34 tests pass
- Data integrity audit (SHA256SUMS.v2) → 19 corpora verified
- Release candidate created (chmod 555) → 10 files verified
- All work documented in PROVENANCE.md

## Phase 2 — In Progress

### Step 1 ✅ Complete — transformer-modernbert.js
- **File**: `src/util/transformer-modernbert.js` (441 LOC)
- **Tests**: 24/24 passing
- **Key innovation**: Sliding-window inference (2048/1024/4) with adaptive short-circuit for short prompts
- **Validated against**: real snapshot model on r8_attack_long_context
  - Single-window recall: 50% → sliding-window recall: **75%**
  - Average P(attack): 0.50 → **0.77**

### Step 2 ✅ Complete — model-loader.js bundle wire-up
- **Files modified**:
  - `src/util/bundle-loader.js` — extended to support binary files (`.onnx`)
  - `src/util/model-loader.js` — wired verifyBundle → createSession → cache → transformer-modernbert
- **Tests**: 12/12 passing
- **Validates**: Ed25519 signature verification, license audit, ONNX bytes extraction, session creation, chrome.storage caching

### Step 3 ✅ Complete — Re-validate all 6 facets
- **Facets 1-4** (regex): 100% on gap analysis (44/44)
- **Facet 5** (toxicity regex-only): 100% on regex subset, ML deferred per architecture doc
- **Facet 6** (prompt-injection): 24/24 unit tests pass + 50%→75% recall improvement on real long-context attacks
- **Validator**: `test/scripts/run-6-facet-validation.js` — single command runs all checks
- **Note**: Browser-extension end-to-end test requires live Chrome instance (manual step)

### Step 4 ⏳ Pending — ONNX export (REQUIRES SIGN-OFF)

## Phase 2 deliverables — file locations

```
src/util/
├── transformer-modernbert.js       (NEW - 441 LOC)
├── model-loader.js                  (MODIFIED - bundle wire-up)
├── bundle-loader.js                 (MODIFIED - binary file support)
├── bundle-registry.js               (unchanged)
├── license-checker.js               (unchanged)
├── transformer-engine.js            (unchanged - v0.1 compat stub)
├── webgpu-detect.js                 (unchanged)
└── logger.js                        (unchanged)

test/
├── transformer-modernbert.test.mjs   (NEW - 24 tests)
├── model-loader.test.mjs             (NEW - 12 tests)
├── eval/
│   ├── PHASE-2-STATUS.md             (NEW - this file's sibling)
│   ├── 6-facet-validation-summary.json
│   ├── transformer-modernbert-results.json
│   └── model-loader-results.json
└── scripts/
    ├── README.md                    (NEW)
    ├── PHASE-2-PLAN.md              (NEW - planning notes)
    ├── sliding-window-sizing.py     (NEW - sizing experiment)
    ├── sliding-window-sizing-results-2026-06-28T22-00-00Z.log  (NEW)
    └── run-6-facet-validation.js    (NEW - all-in-one validator)

models/release-candidates/
├── README.md                        (NEW)
└── prompt-injection-v0.2.0-rc1/
    ├── PROVENANCE.md                (NEW)
    ├── SHA256SUMS                   (NEW)
    └── (10 files copied from snapshot)

corpora/
└── SHA256SUMS.v2                    (NEW - 19 files, locked)
```

## What's next

**Phase 2 step 4**: ONNX export of rc1 with q4f16 quantization
- Requires explicit user sign-off
- Output goes to `test/bundles/` (NOT shipping location)
- After ONNX export + bundle build + end-to-end test, archive results and await further sign-off before promoting to shipping location

## Re-verification

```bash
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02
node test/scripts/run-6-facet-validation.js
```