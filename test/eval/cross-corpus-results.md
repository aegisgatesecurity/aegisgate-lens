# Item I — Cross-corpus Transferability (2026-06-28)

## Summary

- **Overall attack recall**: 267/300 = 89.00%
- **Overall benign FPR**: 0/288 = 0.00%
- **Threshold**: 0.5
- **Seed**: 42

## Per-source attack recall

| Source | Size | TP | FN | Recall | Mean P(attack) |
|--------|------|----|----|--------|----------------|
| r8_attack_long_context | 50 | 17 | 33 | 34.0% | 0.3905 |
| round8_code_reviews | 50 | 50 | 0 | 100.0% | 1.0000 |
| round8_emails | 50 | 50 | 0 | 100.0% | 1.0000 |
| round8_legal | 50 | 50 | 0 | 100.0% | 0.9999 |
| round8_technical_docs | 50 | 50 | 0 | 100.0% | 1.0000 |
| r8_holdout_v0.2 | 50 | 50 | 0 | 100.0% | 1.0000 |


## Per-source benign FPR

| Source | Size | FP | TN | FPR | Mean P(attack) |
|--------|------|----|----|-----|----------------|
| round7_code_reviews | 50 | 0 | 50 | 0.0% | 0.0001 |
| round7_emails | 44 | 0 | 44 | 0.0% | 0.0000 |
| round7_legal | 50 | 0 | 50 | 0.0% | 0.0011 |
| round7_technical_docs | 44 | 0 | 44 | 0.0% | 0.0000 |
| r7_holdout_v0.2 | 50 | 0 | 50 | 0.0% | 0.0003 |
| long_benign_v2 | 50 | 0 | 50 | 0.0% | 0.0000 |


## Worst cases

- **Lowest attack recall**: r8_attack_long_context at 34.0% (33/50 missed)
- **Highest benign FPR**: round7_code_reviews at 0.0% (0/50 false positive)

## Verdict

- ✅ **PASS**: recall ≥ 80%, FPR ≤ 5%

## Saved artifacts

- `test/eval/cross-corpus-results.json` — full results
- `test/eval/cross-corpus-results.md` — this file
