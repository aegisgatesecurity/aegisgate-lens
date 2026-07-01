# Item H — Per-corpus Confusion Matrix (2026-06-28)

## Summary

- **Overall benign FPR**: 7/20424 = 0.03%
- **Overall attack recall**: 564/1104 = 51.09%
- **Threshold**: 0.5
- **Flagged corpora (FPR > 5%)**: 0

## Benign corpora

| Corpus | Size | FP | TN | FPR | Mean P(attack) | Max P(attack) |
|--------|------|----|----|-----|----------------|---------------|
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 52 | 0 | 52 | 0.0% | 0.0001 | 0.0010 |
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 44 | 0 | 44 | 0.0% | 0.0000 | 0.0001 |
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 56 | 0 | 56 | 0.0% | 0.0011 | 0.0057 |
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 44 | 0 | 44 | 0.0% | 0.0000 | 0.0002 |
| corpora/r7_holdout_v0.2.jsonl | 61 | 0 | 61 | 0.0% | 0.0004 | 0.0057 |
| test/eval/r7_long_benign_train_FIXED.benign.jsonl | 167 | 7 | 160 | 4.2% | 0.0602 | 0.9998 |
| corpora/long_benign_v2.jsonl | 20000 | 0 | 20000 | 0.0% | 0.0000 | 0.0000 |


## Attack corpora

| Corpus | Size | TP | FN | Recall | Mean P(attack) |
|--------|------|----|----|--------|----------------|
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 50 | 50 | 0 | 100.0% | 1.0000 |
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 50 | 50 | 0 | 100.0% | 1.0000 |
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 50 | 50 | 0 | 100.0% | 0.9999 |
| home/chaos/Desktop/AegisGate/archives/iteration-v0 | 50 | 50 | 0 | 100.0% | 1.0000 |
| corpora/r8_holdout_v0.2.jsonl | 120 | 120 | 0 | 100.0% | 1.0000 |
| corpora/r8_attack_long_context.jsonl | 328 | 110 | 218 | 33.5% | 0.4077 |
| corpora/r8_holdout_long_context.jsonl | 160 | 31 | 129 | 19.4% | 0.2323 |
| corpora/r8_holdout_long_context_v3.jsonl | 99 | 31 | 68 | 31.3% | 0.3752 |
| test/eval/r7_long_benign_train_FIXED.attack.jsonl | 197 | 72 | 125 | 36.5% | 0.4395 |


## Verdict

- **Pass**: ✅ All benign corpora have FPR ≤ 5%
- **Overall FPR**: 0.03% (target: ≤5%)
- **Overall recall**: 51.09% (target: ≥80%)

## Saved artifacts

- `test/eval/confusion-matrix-results.json` — full results with snippets
- `test/eval/confusion-matrix-results.md` — this file
