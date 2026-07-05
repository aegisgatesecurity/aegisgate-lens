# Phase 5f: ModernBERT-large on CLEAN PI held-out

**Date**: 2026-07-05

**Model**: answerdotai/ModernBERT-large (395M params, Apache-2.0, 8K context)

**Held-out**: v2 CLEAN PI (554 records: 318 attack + 236 benign)

## 5-fold cross-validation results

Per-fold:

| Fold | Train | Eval | Recall | FPR | Precision | F1 |
|---|---|---|---|---|---|---|
| 1 | 444 | 110 | 1.0000 | 0.0204 | 0.9839 | 0.9919 |
| 2 | 444 | 110 | 1.0000 | 0.0000 | 1.0000 | 1.0000 |
| 3 | 444 | 110 | 0.9841 | 0.0213 | 0.9841 | 0.9841 |
| 4 | 444 | 110 | 1.0000 | 0.0000 | 1.0000 | 1.0000 |
| 5 | 444 | 110 | 1.0000 | 0.0000 | 1.0000 | 1.0000 |

Mean +/- std:

- Recall: 0.9968 +/- 0.0063
- FPR: 0.0083 +/- 0.0102
- Precision: 0.9936
- F1: 0.9952

## Ship gate (99% recall, 1% FPR)

**PASS**

## Upper bound (train on all, eval on all)

- Recall: 1.0000
- FPR: 0.0000
- F1: 1.0000

## Held-out location

`/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01beta-CLEAN-PI-heldout-v2.jsonl`

## Model location

`/home/chaos/Desktop/AegisGate/aegisgate-lens/models/pi-v0.1.0-beta/finetuned-large`
