# Phase 2 — ModernBERT Inference Path Implementation Plan

**Date**: 2026-06-28
**Status**: Implementation in progress
**Target file**: `src/util/transformer-modernbert.js`

## Decision (informed by `sliding-window-sizing.py`)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `max_length` | 2048 | Matches training distribution; covers most reachable attacks |
| `stride` | 1024 | 50% overlap; no gap between windows |
| `max_windows` | 4 | Total coverage = 5120 tokens; experiment showed no recall gain beyond this on r8_attack_long_context |
| Adaptive short-circuit | if tokens ≤ 512 → single 512-token window | Avoids sliding overhead for 61% of documents |
| Batch inference | All windows of one doc → single ONNX forward pass | Single GPU call per doc |
| Aggregation | max-pool P(attack) across windows | Conservative: any window hits = flag |
| Threshold | 0.5 | Standard binary threshold |

**Note on FN's at token positions >8000**: These are unreachable by this
model architecture regardless of window size. They represent an architecture
limitation, not an inference bug. Capturing them requires either:
- Phase 3: retrain on more long-context data
- Future work: switch to a longer-context model (e.g., ModernBERT-large with 8K + RoPE)

## File structure

```
src/util/transformer-modernbert.js
├── Constants (SLIDING_WINDOW, STRIDE, MAX_WINDOWS, ADAPTIVE_SHORT_THRESHOLD, AGGREGATION, THRESHOLD)
├── Tokenization helpers (clipped-tokenize)
├── Score function (scoreModernBERT — sliding window + max-pool)
├── Prewarm (prewarmModernBERT — lazy load + warm)
├── Public API (NS.util.transformerModernBert)
└── Internal cache
```

## Test plan (`test/transformer-modernbert.test.mjs`)

1. **Unit tests** (no real model — mock ort):
   - Tokenizer is called with full text, no truncation
   - Window extraction produces correct number of windows
   - Empty text returns benign (P=0)
   - Single-window fast path is used for short text
   - Aggregation uses max-pool

2. **Integration tests** (real model from snapshot):
   - Load rc1 checkpoint
   - Score a benign prompt → low P(attack)
   - Score an attack prompt → high P(attack)
   - Score a long-context attack → high P(attack) (sliding window captures it)
   - Score a long benign → low P(attack)
   - Latency: short prompt <100ms, long prompt <1000ms

3. **Comparative tests** (against PyTorch baseline):
   - All 20 sample cases produce P(attack) within 0.02 of PyTorch reference

## Bundle strategy

**Decision deferred**: Stay with v0.1 single-file bundle format
(`AEGISGATE_LENS_BUNDLE_V1`). Extend the v0.1 bundle format to support
ONNX payloads instead of JSON LR/MLP configs. The bundle-loader.js
already supports arbitrary file payloads (just stores as parsed JSON);
we need to extend it to pass-through raw bytes for ONNX files.

**Implementation plan for bundle support**: Update `bundle-loader.js`
to add a `parseBundleWithBinary` variant that preserves raw bytes for
files with `.onnx` extension. The v0.1 JSON path stays intact for
backwards compat (toxicity, etc. may still use JSON weights in
production builds if simpler).

## ONNX export (Phase 2 step 6, conditional on tests)

After `transformer-modernbert.js` tests pass:
1. Export `models/release-candidates/prompt-injection-v0.2.0-rc1/` to
   ONNX via `optimum-cli export onnx` with q4f16 quantization
2. Output to `test/bundles/` (NOT `models/bundles/`)
3. Test ONNX model end-to-end against PyTorch baseline
4. If parity confirmed: STOP, archive results, await sign-off to copy
   from `test/bundles/` to shipping location

**Never write ONNX directly into `models/bundles/` or `vendor/bundles/`
without explicit sign-off**. Those are shipping locations.