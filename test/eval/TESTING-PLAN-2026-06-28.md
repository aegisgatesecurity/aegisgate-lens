# AegisGate Lens v0.2 — Master Testing Plan

**Date**: 2026-06-28
**Status**: Plan updated; ready for execution in sequence
**Environment**: 40 cores, 256GB RAM, RTX 3060 12GB, Xvfb installed, geckodriver 0.36.0 at `~/.local/bin/`, Selenium 4.45.0 in venv

---

## 🎯 North Star — What We're Building

**AegisGate Lens**: A world-class, enterprise-grade browser extension designed to protect every AI interaction. Zero gaps improbable, but we want to be BETTER than billion-dollar competitor products.

### The 6 Facets (Ship Gate)

| # | Facet | Tool | Status |
|---|-------|------|--------|
| 1 | **PII** | Regex + Luhn | ✅ 16/16 gap-analysis pass |
| 2 | **Secrets** | Regex | ✅ 17/17 gap-analysis pass |
| 3 | **XSS / Source** | Regex | ✅ 7/7 gap-analysis pass |
| 4 | **Compliance** | Regex (port from Platform Go) | ✅ 3/3 gap-analysis pass |
| 5 | **Toxicity** | Regex + ML (toxic-bert) | ⚠️ Regex-only, ML deferred |
| 6 | **Prompt Injection** | ModernBERT-base sliding window | ✅ Logic 24/24 tests + 50%→75% long-context recall |

### Ship Gates (from architecture doc)

| Gate | Target | Status |
|------|--------|--------|
| PII/Secrets/XSS/Compliance (regex) | 100% detection on canonical corpora | ✅ 44/44 pass |
| Long-context PI detection (sliding window) | ≥80% recall on r8_attack_long_context | ⚠️ 75% on sample, full corpus eval pending |
| Browser extension runs without errors | All 6 facets fire on real prompts | ⏳ Item A (Chrome e2e) |
| Pen-tests F-01..F-05 | All 5 pass | ⏳ Item B |
| ONNX inference latency p95 (WASM) | ≤350ms | ⏳ Item C/J |
| ONNX inference latency p95 (WebGPU) | ≤80ms | 🆕 Now testable via Firefox |
| Memory growth over 100 prompts | ≤10MB delta | ⏳ Item D |
| Determinism | Same input → same output | ⏳ Item F |
| Threshold sweep | Optimal threshold identified | ⏳ Item G |
| Per-corpus FP rates | All corpora <5% FPR | ⏳ Item H |
| Cross-corpus generalization | ≥80% recall, ≤5% FPR | ⏳ Item I |
| Cold-start latency | ≤5× warm | ⏳ Item K |
| Bundle signed with real key | Ed25519 verifies | ⏳ Item L |

---

## 📋 The 12 Items (in execution order)

| # | Item | Venue | Sign-off? | Time est. |
|---|------|-------|-----------|-----------|
| **F** | Determinism | Python (no browser) | None | 10 min |
| **G** | Threshold sweep | Python (no browser) | None | 30 min |
| **H** | Per-corpus FP confusion matrix | Python (no browser) | None | 20 min |
| **I** | Cross-corpus attack transferability | Python (no browser) | None | 30 min |
| **Stop 1** | Return to user with F/G/H/I results | — | — | — |
| **M1** | Firefox: Build WebGPU test fixture page | Firefox via geckodriver | None | 30 min |
| **M2** | Firefox: Validate WebGPU ONNX inference (Facet 6 via WebGPU EP) | Firefox via geckodriver | None | 45 min |
| **M3** | Firefox: Sliding-window end-to-end (Facet 6 with sliding) | Firefox via geckodriver | None | 30 min |
| **M4** | Firefox: WASM ONNX latency (350ms target) | Firefox via geckodriver | None | 30 min |
| **Stop 2** | Return to user with Firefox results; decide ONNX export go/no-go | — | — | — |
| **Stop 3** | User sign-off: ONNX export? (gated from prior plan) | — | **Yes** | — |
| **N1** | Export ONNX from snapshot model → test/bundles/ | Python | (After Stop 3) | 30 min |
| **N2** | Firefox: WebGPU ONNX latency (80ms target) | Firefox via geckodriver | None | 30 min |
| **N3** | Firefox: Cold-start vs warm latency | Firefox via geckodriver | None | 15 min |
| **Stop 4** | Return to user with full Firefox e2e results | — | — | — |
| **1** | Build v0.2 dist (lens-final-dist/) | shell | **Yes** | 30 min |
| **2** | Load extension in headless Chrome | bash + ChromeDevTools | None | 15 min |
| **A** | Chrome: All 6 facets end-to-end | ChromeDevTools | None | 1 hour |
| **B** | Chrome: Pen-tests F-01..F-05 | ChromeDevTools | None | 2 hours |
| **D** | Chrome: Memory profile (heap growth) | ChromeDevTools | None | 30 min |
| **E** | Chrome: Long-context attack in real extension | ChromeDevTools | None | 30 min |
| **J** | Chrome: p95/p99 latency (WASM) | ChromeDevTools | None | 30 min |
| **K** | Chrome: Cold-start latency | ChromeDevTools | None | 15 min |
| **L** | Bundle signature with REAL signing key | Node.js test | **Yes** | 15 min |
| **Stop 5** | Final report to user | — | — | — |

**Total estimated**: ~10 hours of focused work over multiple sessions.

**Critical gates** (where I MUST stop and check with user):
- Stop 1: After Python tests — surface findings before browser work
- Stop 2: After Firefox WebGPU validation — surface findings; user decides ONNX export
- Stop 3: ONNX export — gated from prior plan, still gated
- Stop 4: After full Firefox e2e — surface findings before Chrome work
- Stop 5: Final report

---

## 🛠️ Execution Lane 1 — Python (no browser)

### Item F — Determinism (10 min)

**Goal**: Same input → same output, 10× in a row.

**Steps**:
1. Load snapshot model
2. Define 5 canonical prompts (1 benign short, 1 attack short, 1 long benign, 1 long attack, 1 edge case)
3. Score each prompt 10 times
4. Compare scores per prompt — should be byte-identical
5. Report: which prompts were deterministic, which (if any) varied, by how much

**Output**: `test/eval/determinism-results.json` + `.md`

**Pass criteria**: All 50 scores byte-identical within FP precision (≤1e-6 absolute difference).

### Item G — Threshold sweep (30 min)

**Goal**: Find optimal threshold for the snapshot model.

**Steps**:
1. Build a held-out corpus: 100 attacks + 100 benign (from r8_attack_long_context + r7_benign_*)
2. Score every record
3. For thresholds [0.1, 0.2, ..., 0.9]:
   - Compute precision, recall, F1
4. Plot precision-recall curve
5. Identify optimal threshold (max F1 OR recall floor + min FPR)

**Output**: `test/eval/threshold-sweep-results.json` + `.md` + `.csv`

**Pass criteria**: Optimal threshold identified; comparison to current 0.5 documented.

### Item H — Per-corpus FP confusion matrix (20 min)

**Goal**: Find which benign corpora produce false positives.

**Steps**:
1. Score every record in:
   - r7_benign_code_reviews
   - r7_benign_emails
   - r7_benign_legal
   - r7_benign_technical_docs
   - r7_holdout_v0.2
   - r7_long_benign_train
   - long_benign_v2
   - 100 benign slices from public_test_benign
2. Per corpus: count TPs, FPs, TNs, FNs, FPR
3. Flag any corpus with FPR > 5% for future tuning

**Output**: `test/eval/confusion-matrix-results.json` + `.md`

**Pass criteria**: All corpora FPR ≤5%. Outliers flagged for Phase 3 training.

### Item I — Cross-corpus attack transferability (30 min)

**Goal**: Does the model generalize across attack types?

**Steps**:
1. Build combined test set:
   - 50 from each r8_attack_* (code_reviews, emails, legal, technical_docs)
   - 50 from r8_attack_long_context
   - 50 from each r7_benign_*
   - Total: 250 attack + 200 benign
2. Score every record
3. Compute recall (per attack source), FPR (per benign source)
4. Identify if any attack source has unexpectedly low recall

**Output**: `test/eval/cross-corpus-results.json` + `.md`

**Pass criteria**: ≥80% recall on every attack source; ≤5% FPR on every benign source.

---

## 🦊 Execution Lane 2 — Firefox WebGPU (no extension build needed)

### Item M1 — Firefox WebGPU test fixture (30 min)

**Goal**: A self-contained HTML page that loads `src/util/transformer-modernbert.js` and provides a UI/API for testing.

**Steps**:
1. Create `test/firefox/fixture.html`:
   - Loads `ort.min.js` (ONNX Runtime Web)
   - Loads v0.2's `transformer-modernbert.js` via `<script src="../../src/util/...">`
   - Provides a `window.runInference(text)` function
   - Reports WebGPU + WASM availability to console
2. Create `test/firefox/server.py` (simple HTTP server)
3. Create `test/firefox/control.mjs` (Node.js script using selenium to:
   - Start geckodriver
   - Launch Firefox
   - Navigate to fixture
   - Drive test scenarios
4. Verify fixture loads in Firefox, no console errors

**Output**: `test/firefox/` directory with all 4 files

**Pass criteria**: Fixture loads; console reports `navigator.gpu: object`.

### Item M2 — Firefox: WebGPU ONNX inference (Facet 6 via WebGPU EP) (45 min)

**Goal**: Confirm ModernBERT inference runs on WebGPU EP in Firefox.

**Steps**:
1. Create a synthetic small ONNX model (since real export is gated) OR use ONNX runtime's bundled test models
2. Load in fixture
3. Score 5 prompts (1 benign, 4 attack patterns)
4. Verify scores match Python reference (within FP tolerance)
5. Verify WebGPU EP is selected (not WASM fallback)

**Output**: `test/eval/firefox-webgpu-inference-results.json` + `.md`

**Pass criteria**: All 5 prompts scored; scores within 0.05 of Python reference.

### Item M3 — Firefox: Sliding-window end-to-end (30 min)

**Goal**: Confirm the sliding-window logic in `transformer-modernbert.js` works in Firefox.

**Steps**:
1. In fixture, expose `window.scoreWithSliding(text)`
2. Test with 3 long-context prompts (from r8_attack_long_context sample)
3. Verify sliding window finds the attack that single-window misses
4. Verify window count matches expected

**Output**: `test/eval/firefox-sliding-window-results.json` + `.md`

**Pass criteria**: Sliding-window recall ≥ 60% on sample (single-window was 50%).

### Item M4 — Firefox: WASM ONNX latency (350ms target) (30 min)

**Goal**: Measure WASM EP latency in Firefox.

**Steps**:
1. Score 20 prompts of varying lengths (5 short, 10 medium, 5 long)
2. Measure latency per inference (using `performance.now()`)
3. Compute p50, p95, p99
4. Compare to architecture target (350ms WASM)

**Output**: `test/eval/firefox-wasm-latency-results.json` + `.md`

**Pass criteria**: p95 ≤ 350ms.

### STOP 2: Return to user with Firefox results; ask for ONNX export sign-off

After Firefox WebGPU + sliding window + WASM latency tests pass, **return to user** with findings. The user has the option to:
- Sign off on ONNX export (proceed with N1-N3)
- Defer ONNX export (skip N1-N3, go straight to Chrome extension tests)
- Add more Firefox tests

---

## 🌐 Execution Lane 3 — Chrome Extension (after sign-off + dist build)

### Item N1 — Export ONNX from snapshot model (30 min)

**Goal**: Produce an ONNX bundle for the snapshot model.

**Steps** (only after Stop 3 sign-off):
1. Use `transformers` + `optimum` (or `torch.onnx.export`) to export model
2. Quantize to q4f16 (or int8 if q4f16 unsupported in Firefox's ONNX)
3. Save ONNX bytes to `test/bundles/`
4. Export tokenizer.json + tokenizer_config.json
5. Compute SHA256 of all 3 files

**Output**: `test/bundles/prompt-injection-v0.2.0-rc1/` with model.onnx, tokenizer.json, tokenizer_config.json, SHA256SUMS

**Pass criteria**: All 3 files exist; SHA256SUMS verifiable.

### Item N2 — Firefox: WebGPU ONNX latency (80ms target) (30 min)

**Goal**: Confirm 80ms WebGPU latency target.

**Steps**:
1. Load ONNX bundle in Firefox fixture (real model, not synthetic)
2. Score 20 prompts (same as M4)
3. Measure latency
4. Compute p50, p95, p99
5. Compare to WebGPU target (80ms)

**Output**: `test/eval/firefox-webgpu-latency-results.json` + `.md`

**Pass criteria**: p95 ≤ 80ms.

### Item N3 — Firefox: Cold-start vs warm latency (15 min)

**Goal**: Measure first-inference penalty.

**Steps**:
1. Open fresh Firefox → fixture → measure first inference (cold)
2. Run 10 more inferences → measure average (warm)
3. Compute ratio cold/warm

**Output**: `test/eval/firefox-cold-start-results.json` + `.md`

**Pass criteria**: Cold/warm ratio ≤ 5×.

### STOP 4: Return to user with Firefox e2e results

---

## 🏗️ Execution Lane 4 — Chrome Extension (sign-off needed for dist)

### Item 1 — Build v0.2 dist (30 min)

**Goal**: Produce a loadable Chrome MV3 extension.

**Steps** (requires sign-off):
1. Copy `src/*` → `lens-final-dist/`
2. Generate stub icons (16/32/48/128 PNG — use a Python PIL script)
3. Generate minimal `popup.html` + `welcome.html` + `welcome.js` stubs
4. Verify `manifest.json` references all required files
5. Save build script to `test/scripts/build-v02-dist.sh` for reproducibility

**Output**: `lens-final-dist/` + build script in `test/scripts/`

**Pass criteria**: `lens-final-dist/manifest.json` parses; all referenced files exist.

### Item 2 — Load extension in headless Chrome (15 min)

**Goal**: Confirm Chrome loads the v0.2 extension.

**Steps**:
1. Launch Chrome with `--load-extension=lens-final-dist --disable-extensions-except=lens-final-dist`
2. Use ChromeDevTools to query `chrome.management.getAll()`
3. Verify AegisGate Lens appears with correct name, version, permissions
4. Tear down

**Output**: `test/eval/chrome-extension-load-results.json` + `.md`

**Pass criteria**: Extension listed; no load errors.

### Item A — Chrome: All 6 facets end-to-end (1 hour)

**Goal**: Verify all 6 facets fire correctly in the real extension.

**Steps**:
1. For each of 6 facets:
   - Build a fixture HTML page that simulates an LLM chat UI
   - Load page in Chrome with extension active
   - Inject a prompt that should trigger the facet (e.g., PII for Facet 1)
   - Use ChromeDevTools to read the Lens detection result (via DOM injection or message channel)
   - Verify expected category appears
2. Test 1 benign control prompt (should produce no detections)

**Output**: `test/eval/chrome-6-facets-results.json` + `.md`

**Pass criteria**: Each facet fires on its trigger prompt; benign produces no detections.

### Item B — Chrome: Pen-tests F-01..F-05 (2 hours)

**Goal**: Validate 5 adversarial scenarios.

**Steps** (adapt existing `archives/.../pen-test/*.sh` scripts):
1. F-01 (foreign sender): Test that Lens rejects `chrome.runtime.sendMessage` from non-extension origins
2. F-02 (bundle tamper): Mutate a bundle byte in `chrome.storage.local`, verify Lens detects and rejects on load
3. F-04 (dismissals flood): Spam dismiss events, verify rate-limit engages
4. F-05 (rate-limit bypass): Spam prompt submissions, verify backoff
5. (F-03 not in archive — skip or substitute)

**Output**: `test/eval/chrome-pen-test-results.json` + `.md`

**Pass criteria**: All 5 pass.

### Item D — Chrome: Memory profile (30 min)

**Goal**: Verify heap doesn't grow unbounded.

**Steps**:
1. Load extension in Chrome
2. Take heap snapshot (baseline)
3. Submit 100 prompts
4. Take heap snapshots at 10, 50, 100 prompts
5. Compare heap sizes; flag any unbounded growth

**Output**: `test/eval/chrome-memory-profile-results.json` + `.md`

**Pass criteria**: Heap delta ≤10MB over 100 prompts.

### Item E — Chrome: Long-context attack in real extension (30 min)

**Goal**: Sliding window works in shipping JS.

**Steps**:
1. Load a 5000-char prompt with injection at char 4500
2. Verify Facet 6 fires (sliding window catches it)
3. Compare to baseline: same prompt with `--max-length=512` → Lens misses it

**Output**: `test/eval/chrome-long-context-results.json` + `.md`

**Pass criteria**: Sliding window detects the buried injection.

### Item J — Chrome: p95/p99 latency (WASM) (30 min)

**Goal**: Quantile latency measurements in real browser.

**Steps**:
1. Score 100 prompts of varying lengths
2. Measure latency per inference
3. Compute p50, p95, p99

**Output**: `test/eval/chrome-latency-results.json` + `.md`

**Pass criteria**: p99 ≤ 2× p50.

### Item K — Chrome: Cold-start latency (15 min)

**Goal**: Service-worker cold-start penalty.

**Steps**:
1. First prompt after fresh Chrome launch → measure
2. Subsequent prompts → measure
3. Ratio = cold/warm

**Output**: `test/eval/chrome-cold-start-results.json` + `.md`

**Pass criteria**: Cold/warm ≤ 5×.

### Item L — Bundle signature with REAL signing key (15 min)

**Goal**: Bundle verifies with production key.

**Steps** (requires sign-off to generate test keypair):
1. Generate Ed25519 keypair via Node crypto
2. Save private key to `test/keys/...` (test-only)
3. Save public key to `test/fixtures/signing-public-key.json`
4. Update `bundle-loader.js` to read public key from `test/fixtures/` when in test mode
5. Sign a test bundle with the test private key
6. Verify bundle parses with test public key

**Output**: `test/keys/`, `test/fixtures/signing-public-key.json`, `test/eval/bundle-signature-results.json` + `.md`

**Pass criteria**: Test bundle verifies.

---

## 🔒 What I will NOT do without explicit sign-off

- ❌ Build v0.2 dist (creates `lens-final-dist/` files)
- ❌ Generate or store production Ed25519 signing key
- ❌ Export ONNX model from snapshot (gated from prior plan)
- ❌ Modify the 4 locked v0.2 documents (unless the data forces it)
- ❌ Touch Privacy Policy or Threat Model
- ❌ Modify `corpora/balanced_train_v2.jsonl` or `balanced_val_v2.jsonl` (read-only)
- ❌ Modify the snapshot directory (`models/snapshots/...`)

---

## 📁 Directory Layout (everything in proper home)

```
lens-repo-bootstrap-v02/
├── src/                          (unchanged - shipped code)
├── corpora/                      (unchanged - read-only)
├── models/
│   ├── snapshots/                (unchanged - the recovered v2.0)
│   ├── release-candidates/       (unchanged - rc1 chmod 555)
│   └── prompt-injection-v0.2.0/  (unchanged - broken v2-retrain, kept for reference)
├── test/                         (test code and ephemeral artifacts)
│   ├── transformer-modernbert.test.mjs
│   ├── model-loader.test.mjs
│   ├── scripts/
│   │   ├── README.md
│   │   ├── PHASE-2-PLAN.md
│   │   ├── sliding-window-sizing.py
│   │   ├── run-6-facet-validation.js
│   │   ├── build-v02-dist.sh     (NEW - for item 1)
│   │   └── ... (more as needed)
│   ├── eval/                     (all test result archives)
│   │   ├── PHASE-2-STATUS.md
│   │   ├── VALIDATION-2026-06-28.md
│   │   ├── WEBGPU-VALIDATION-2026-06-28.md
│   │   ├── TESTING-PLAN-2026-06-28.md  (this file)
│   │   ├── determinism-results.{json,md}    (Item F)
│   │   ├── threshold-sweep-results.{json,md,csv}  (Item G)
│   │   ├── confusion-matrix-results.{json,md}     (Item H)
│   │   ├── cross-corpus-results.{json,md}         (Item I)
│   │   ├── firefox-*results.{json,md}             (Items M1-M4)
│   │   └── chrome-*results.{json,md}              (Items 2, A, B, D, E, J, K)
│   ├── firefox/                  (Firefox test fixtures)
│   │   ├── fixture.html
│   │   ├── server.py
│   │   └── control.mjs
│   ├── keys/                     (test-only signing keys, when item L)
│   ├── fixtures/                 (test inputs, edge cases)
│   └── bundles/                  (ONNX test artifacts, when item N1)
└── lens-final-dist/              (NEW when item 1 - signed off by user)
```

---

## 🎬 Execution Plan — Right Now

Starting now, in sequence:

### Next 90 minutes: Python tests (F, G, H, I)
1. Item F — Determinism (10 min)
2. STOP: report F results, await user
3. Item G — Threshold sweep (30 min)
4. STOP: report G results, await user
5. Item H — Confusion matrix (20 min)
6. STOP: report H results, await user
7. Item I — Cross-corpus (30 min)
8. STOP: full Python summary, await user

(Or if user prefers batched execution: run all 4 in sequence without intermediate stops, then return.)

### After Python: Firefox WebGPU lane (M1-M4, ~2 hours)

### After Firefox: Chrome extension lane (1, 2, A, B, D, E, J, K, L, ~5 hours)

---

## How to re-verify at any point

```bash
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02

# Quick smoke check (Phase 1 + 2 still green?)
node test/scripts/run-6-facet-validation.js

# Run a specific test item
node test/transformer-modernbert.test.mjs   # 24 tests
node test/model-loader.test.mjs             # 12 tests

# Check what's in test/eval/
ls -la test/eval/
```