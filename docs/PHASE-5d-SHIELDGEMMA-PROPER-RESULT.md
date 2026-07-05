# Phase 5d: ShieldGemma:2b on PROPER toxicity held-out

**Date**: 2026-07-05

**Model**: shieldgemma:2b (Google, Apache-2.0, 2B params, 1.7GB)

**Held-out**: 700 records (350 attack + 350 benign) from BeaverTails + ToxiGen

**Prompt**: yes/no (ShieldGemma does not follow JSON format reliably)

**Inference time**: 367s for 700 records = 1.9 req/s


## Results

  TP=94 FN=256 FP=5 TN=345

  Recall: 0.2686
  FPR: 0.0143
  F1: 0.4187

  Gate (99%/1%): NO (need 99%/98.6%)

## Per-source breakdown

  toxigen: tp=94 fn=256 fp=5 tn=345
