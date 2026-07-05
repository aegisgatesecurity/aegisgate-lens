# Phase 5d: Ministral-3:3b on PROPER toxicity held-out

**Date**: 2026-07-05

**Model**: ministral-3:3b (via Ollama)

**Held-out**: 700 records (350 attack + 350 benign, BeaverTails + ToxiGen)

**Inference time**: 441.7s = 1.6 req/s

**Parse failures**: 0/700

## Results

### Ship gate NOT met. Best F1 with FPR <= 5%: {'threshold': 0.0, 'recall': 0.4742857142857143, 'fpr': 0.025714285714285714, 'f1': 0.6323809523809524, 'tp': 166, 'fn': 184, 'fp': 9, 'tn': 341}

### is_toxic alone

recall=0.4743, fpr=0.0257, f1=0.6324

