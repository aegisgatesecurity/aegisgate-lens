# Phase 5d: Fine-tuned toxicity model report

**Date**: 2026-07-05

**Base**: unitary/unbiased-toxic-roberta (16-cat, Apache-2.0)

**Training data**: google/civil_comments train split, 50000 samples (50/50 attack/benign)

**Hardware**: RTX 3060 12GB, bf16, 1 epoch

**Held-out**: civil_comments test split, 700 records (500 attack + 200 benign)


## Results

- Best F1 with FPR <= 5%: {'threshold': np.float64(0.45), 'recall': 0.808, 'fpr': 0.05, 'f1': 0.8840262582056893, 'tp': 404, 'fn': 96, 'fp': 10, 'tn': 190}

- Best at recall >= 95%: [{'threshold': 0.05, 'recall': 0.99, 'fpr': 0.415, 'f1': 0.9183673469387754, 'tp': 495, 'fn': 5, 'fp': 83, 'tn': 117}, {'threshold': 0.1, 'recall': 0.982, 'fpr': 0.295, 'f1': 0.9352380952380952, 'tp': 491, 'fn': 9, 'fp': 59, 'tn': 141}, {'threshold': 0.2, 'recall': 0.966, 'fpr': 0.21, 'f1': 0.942439024390244, 'tp': 483, 'fn': 17, 'fp': 42, 'tn': 158}]
