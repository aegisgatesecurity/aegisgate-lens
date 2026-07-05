# Phase 5d v3: Cascade evaluation report

**Date**: 2026-07-05

**Key finding**: The ML toxicity tier alone cannot hit 99%/1% on the Jigsaw held-out (max 39% recall at 1% FPR). This is a structural limitation of the 16-cat architecture.

**This evaluation measures the OVERALL CASCADE** (2 toxicity regex fallbacks + ML toxicity v2) to determine if the product as a whole can hit the gate.

## Cascade results

| ML threshold | Recall | FPR | F1 | regex-only TP | ML-only TP | both-TP |
|---|---|---|---|---|---|---|
| 0.44 | 0.7940 | 0.0700 | 0.8716 | 2 | 390 | 5 |
| 0.5 | 0.7320 | 0.0550 | 0.8347 | 2 | 359 | 5 |
| 0.6 | 0.6320 | 0.0350 | 0.7679 | 3 | 309 | 4 |
| 0.7 | 0.5140 | 0.0350 | 0.6728 | 5 | 250 | 2 |
| 0.8 | 0.3420 | 0.0250 | 0.5059 | 6 | 164 | 1 |
| 0.9 | 0.1740 | 0.0250 | 0.2939 | 7 | 80 | 0 |

## 99%/1% gate

**CASCADE does NOT meet 99%/1% gate.** The realistic ceiling is the best F1 with FPR <= 5%.
