# Phase 5d: Clean toxicity held-out build report

**Date**: 2026-07-05

**Seed**: 20260705

**Source files (clean v0.1 archive)**:
  - Attack: v8/round8_combined.jsonl, v5/round5.jsonl
  - Benign: v7/round7_*.jsonl, v9/round9_*.jsonl, v9v2/round9v2_*.jsonl

**Target**: 350 attack + 350 benign = 700

## Validation results

### Level 1: Raw validation (structure)
  Attack: 271 valid, 0 invalid
  Benign: 568 valid, 0 invalid

### Level 2: Label validation (content)
  Attack records with attack patterns: 235 / 271
  Benign records without attack patterns: 400 / 568

### Level 3: Distribution validation
  Total: 621
  Attack: 271
  Benign: 350
  Text length: min=16, max=17722, mean=6390, median=7213
  Duplicates within held-out: 0
  Cross-set duplicates (attack text == benign text): 0

## Triple validation

1. Re-read + re-validate: OK
2. Re-compute statistics: OK
3. Sample-based manual inspection: 18/30 pass quick visual check

## Source distribution

  - gap_closure_day29_round8_legal_attacks: 47
  - gap_closure_day30_round9_email_benign: 46
  - gap_closure_day30_round9_legal_benign: 46
  - gap_closure_day29_round8_technical_doc_attacks: 46
  - gap_closure_day29_round8_email_attacks: 45
  - gap_closure_day29_round7_code_reviews: 44
  - gap_closure_day30_round9v2_legal_benign: 44
  - gap_closure_day29_round8_code_review_attacks: 43
  - gap_closure_day30_round9v2_email_benign: 34
  - gap_closure_day29_round7_emails: 34
  - gap_closure_day29_round7_technical_docs: 32
  - gap_closure_day29_round7_legal: 30
  - gap_closure_day25_round5_d018: 27
  - gap_closure_day25_round5_unicode: 26
  - gap_closure_day25_round5_textfooler: 19
  - gap_closure_day30_round9v2_technical_doc_benign: 18
  - gap_closure_day30_round9_technical_doc_benign: 17
  - gap_closure_day25_round5_hotflip: 8
  - gap_closure_day25_round5_gbda: 5
  - gap_closure_day25_round5_bertattack: 5
  - gap_closure_day30_round9_code_review_benign: 3
  - gap_closure_day30_round9v2_code_review_benign: 2
