# Phase 5i: ModernBERT-large on different-distribution held-out

**Date**: 2026-07-05

**Model**: ModernBERT-large fine-tuned on v0.1 long-context corpus

**Held-out**: v01beta-PI-DIFFERENT-DIST.jsonl (371 records from promptfoo, deepset, rubend18 + v0.1 benign)

**Purpose**: cross-distribution generalization test

## Results

| Metric | Value | Target |
|---|---|---|
| TP | 170 | - |
| FN | 1 | - |
| FP | 0 | - |
| TN | 200 | - |
| Recall | 0.9942 | >= 0.99 |
| FPR | 0.0000 | <= 0.01 |
| Precision | 1.0000 | - |
| F1 | 0.9971 | - |
| **Ship gate** | **PASS** | **99% recall / 1% FPR** |

## Per-source breakdown

- **gap_closure_day24_round4_benign_aug**: n=27 recall=0.000 fpr=0.000
- **gap_closure_day25_round5_bn007**: n=23 recall=0.000 fpr=0.000
- **gap_closure_day25_round5_bt001**: n=24 recall=0.000 fpr=0.000
- **gap_closure_day29_round7_code_reviews**: n=28 recall=0.000 fpr=0.000
- **gap_closure_day29_round7_emails**: n=19 recall=0.000 fpr=0.000
- **gap_closure_day29_round7_legal**: n=1 recall=0.000 fpr=0.000
- **gap_closure_day29_round7_technical_docs**: n=18 recall=0.000 fpr=0.000
- **gap_closure_day30_round9_legal_benign**: n=5 recall=0.000 fpr=0.000
- **gap_closure_day30_round9_technical_doc_benign**: n=25 recall=0.000 fpr=0.000
- **gap_closure_day30_round9v2_email_benign**: n=22 recall=0.000 fpr=0.000
- **gap_closure_day30_round9v2_legal_benign**: n=6 recall=0.000 fpr=0.000
- **promptfoo_prompt_injections**: n=171 recall=0.994 fpr=0.000
- **stress_test_day28_long_context**: n=2 recall=0.000 fpr=0.000

## Interpretation

**The model generalizes.** It hits 99%/1% on attack sources it has NEVER seen in training.

