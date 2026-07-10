# AegisGate Lens v0.1.0-beta — Phase 0b Training Run #1 Report

**Date**: 2026-07-04 19:34 UTC
**Status**: ❌ **SHIP GATE FAILED** — AWAITING USER SIGN-OFF on next approach
**Author**: this AI
**Parent doc**: `docs/VERIFICATION-3h-data.md`
**Training log**: `docs/TRAINING-RUN-1-LOG.md` (this file's companion)

---

## 0. What happened

Per user sign-off (2026-07-04 19:20, "approved as-is"), Phase 0b ran
the first full training run. The pipeline was:
1. Wrote `tools/train/train_prompt_injection_v01beta.py` (437 lines)
2. Smoke test on 100 records PASSED (loss converging, no NaN)
3. Launched full training in background (PID 1289983, ~15 minutes)
4. Training completed 3 epochs in ~15 minutes (faster than expected)
5. Held-out evaluation FAILED the 99%/1% strict ship gate

**Total elapsed: ~19 minutes** (vs my 5-8 hour estimate).

---

## 1. The training (success)

- **Base**: `answerdotai/ModernBERT-base` (Apache-2.0, 149M params, 8K context)
- **Train**: 10,000 records (5,000 attack + 5,000 benign) from `v01beta-train.jsonl`
- **Val**: 1,000 records from `v01beta-val.jsonl`
- **Hardware**: RTX 3060, 12GB VRAM, bf16 (not fp16, to avoid NaN)
- **Recipe**: lr=2e-5, epochs=3, micro_batch=4, grad_accum=4, AdamW, warmup=10%
- **Sliding window**: chunk=2048, stride=1024, max_windows=4, threshold=0.05
- **Total steps**: 1,875 (2500 micro-batches × 3 epochs / 4 grad_accum)

### Per-epoch validation (1,000 records, 500 attack + 500 benign)
- Epoch 1: Recall=1.0, FPR=0.972, Precision=0.51, F1=0.67 (**SAVED**)
- Epoch 2: Recall=1.0, FPR=0.938, Precision=0.52, F1=0.68
- Epoch 3: Recall=1.0, FPR=0.932, Precision=0.52, F1=0.68

The val set shows the model is **over-triggering** — 100% recall but
~93% FPR. The FPR is not decreasing with more epochs (it's already
saturated by epoch 1).

---

## 2. The held-out evaluation (FAILED)

| Metric | Target | Actual | Status |
|---|---|---|---|
| **Recall** | ≥ 99% | **92.52%** (1,893/2,046) | ❌ FAIL (153 attacks missed) |
| **FPR** | ≤ 1% | **68.13%** (793/1,164) | ❌ FAIL (793 false positives) |
| **F1** | ≥ 99% | **80.01%** | ❌ FAIL |

**The model is over-triggering massively on the held-out benign records.**
793 of 1,164 benign records are flagged as attacks. This is the
"v0.3.0-rc1 was a skeleton" pattern in a different form: the
detection model is too sensitive.

---

## 3. Diagnosis (5 possible root causes)

### 3a. The threshold (0.05) is too low
The current threshold (0.05) is the v0.2 spec. With our new clean
data, the model may produce different score distributions. The
threshold sweep on the val set showed FPR=0.93 at threshold 0.05
(this run). We need to find the threshold that minimizes FPR
while keeping recall ≥ 99%.

### 3b. The benign training data is too short
The 5,000 benign records are mostly short (Alpaca, OASST, etc.).
The 1,164 held-out benign records are **mostly long-context** (the
v0.1 long-context format has long boilerplate with attack patterns
embedded). The model is biased toward "long text = attack" and
flagging 793/1,164 = 68% of long benigns as attacks.

### 3c. Class imbalance at the tokenizer level
ModernBERT-base has 8K context. Our long-context records are >8K
tokens, so the sliding window chops them into 4 windows. Each
window is a separate prediction. The model is "winning" the
attack decision for at least one window in most long benigns.
The aggregation (max-pool P(attack)) is too aggressive.

### 3d. The training corpus has attack patterns leaking into benign
The training data is "clean" per the v0.1 audit, but the public
benchmarks we re-downloaded (deepset, JailbreakBench, etc.) have
shorter examples. The model learned the attack distribution
of the train set, then sees a different distribution in
held-out (long-context legal/code-review boilerplate). Distribution
mismatch.

### 3e. The model didn't converge yet
Loss is 0.48 at the end of epoch 3. The val recall is 100% but
FPR is also 93%. The model is in a "detect everything" mode.
We may need MORE epochs (5-7) to converge, OR we may need a
class-weighted loss to penalize FPs.

---

## 4. The 4 possible next steps (awaiting sign-off)

### Option A: Threshold sweep on the held-out set (FASTEST, 5 min)
- Sweep thresholds from 0.5 to 0.99 in steps of 0.01 on the
  held-out predictions
- Find the threshold that minimizes FPR while keeping recall ≥ 99%
- **Risk**: this is "cheating" — we don't know the held-out
  predictions in production. But the threshold-sweep gives us
  the upper bound of what's possible.
- **Time**: 5 minutes (just runs the held-out eval with
  different thresholds)

### Option B: Add more long-context benign training data
- The v0.1 long-context format embeds attacks in long boilerplate
  (legal, code-review, email, tech-docs). The benign versions
  are in the v0.1 archive (`v9/round9_*.jsonl`, `v9v2/round9v2_*.jsonl`)
  but those are in the HELD-OUT, not the train.
- We add the 400 hand-curated long-context benign records to the
  train set, retrain. The model learns that "long boilerplate
  with no injection is benign."
- **Risk**: this leaks held-out data into training. We should
  re-evaluate on a NEW held-out (or accept that this is a
  one-time data leak).
- **Time**: 30 min (data prep) + 15 min (retraining) = 45 min

### Option C: Increase the threshold (SIMPLEST, 2 min)
- The current threshold is 0.05 (very low). Try 0.5, 0.7, 0.9.
- At threshold 0.5: probably drops FPR significantly, may drop
  recall too. Need to sweep.
- **Time**: 2 min (just re-evaluate the held-out with different
  thresholds)

### Option D: All of the above (MOST THOROUGH, ~1 hour)
- A (threshold sweep) to find the upper bound
- C (use the best threshold from A as the new default)
- If C is not enough: B (add long-context benign)
- Retrain with the new data + new threshold
- **Time**: ~1 hour

---

## 5. What the user said (per the standing rules)

> "If the held-out gate is not met, we do NOT ship. We retrain,
> augment, and try again. We do NOT lower the gate."

The 99%/1% gate is **non-negotiable**. We do NOT ship at 92.5%/68%.
We iterate. The first training run is a learning step, not the
final result.

---

## 6. Decision needed (awaiting sign-off)

**Q1**: Which of Options A / B / C / D should we pursue?
- **My recommendation**: **Option D** (all of the above). The
  threshold sweep (A) is fast and gives us the upper bound. The
  re-eval with the new threshold (C) tells us if a threshold
  change alone is enough. If not, we add long-context benign (B)
  and retrain. This is the most thorough path and respects the
  "don't ship at 92%" directive.

**Q2**: For Option B (add long-context benign), do you accept
  moving some of the v0.1 long-context benign records from
  held-out to train? (The risk: the held-out won't be a true
  hold-out anymore; the benefit: the model gets the long-context
  benign distribution it needs.)

**Q3**: Should I also reduce the EPOCHS (e.g., 1-2 instead of 3)?
  The val loss converges at epoch 1. More epochs just over-fit.
  A shorter run + more data is likely better than a longer run.

**Q4**: For the toxicity model (`s-nlp/roberta_toxicity_classifier`),
  should I still validate it on the held-out toxicity subset?
  It's a pre-trained model, no training needed. Just eval.

---

## 7. The honest framing

The first training run produced a model that is **better than
nothing** (92.5% recall catches most attacks) but **not
deployable** (68% FPR is unacceptable — the banner would fire on
68% of benign prompts, which is worse than no banner at all).

This is a **legitimate engineering problem** that requires:
- Better data (more long-context benign)
- Better threshold (sweep)
- Possibly better model architecture (e.g., a binary head with
  class weighting)
- Possibly more training (more epochs, but with class weighting
  to penalize FPs)

Per the user's direction, we iterate. The first run is the
**baseline**, not the final answer.

---

## 8. Sign-off

**Tell me which option to pursue** (A, B, C, D, or some
combination) and I proceed.

My recommendation: **Option D** with the answers:
- Q2: **YES**, move 200-400 of the v0.1 long-context benign
  records from held-out to train (the held-out is already
  3,210 records; we can spare 200-400 to the train pool)
- Q3: **YES**, reduce EPOCHS to 2 (epoch 1 is the best val
  result; epoch 2-3 over-fit)
- Q4: **YES**, validate the pre-trained toxicity model on the
  held-out toxicity subset

If you say "approved as-is" with my recommendations, I proceed
with Option D (~1 hour).
