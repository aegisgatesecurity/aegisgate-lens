# Phase 5d v2: Aggressive fine-tuning report

**Date**: 2026-07-05

**Base**: unitary/unbiased-toxic-roberta (16-cat, Apache-2.0)

**Training data**: google/civil_comments train split, 100000 samples (50/50 attack/benign)

**Hardware**: RTX 3060 12GB, bf16, 3 epochs

**LR**: head=5e-05, body=2e-05 (discriminative learning rate)

**Loss**: focal loss (alpha=0.25, gamma=2.0) + class weighting (FP=5x, FN=1x)

**Effective batch**: 16 (micro=4 x grad_accum=4)

**Held-out**: civil_comments test split, 700 records (500 attack + 200 benign)


## Results

- Best F1 with FPR <= 5%: {'threshold': 0.44, 'recall': 0.79, 'fpr': 0.05, 'f1': 0.8729281767955802, 'tp': 395, 'fn': 105, 'fp': 10, 'tn': 190}

- Best per-category (95%/1% gate): None

- **DID NOT MEET 99%/1% ship gate.** Best F1 with FPR <= 5% is the realistic ceiling.
