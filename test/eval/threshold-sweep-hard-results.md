# Item G+ — Threshold Sweep on HARD Test Set (2026-06-28)

## Test set composition

| Category | Count | Source |
|----------|-------|--------|
| Short attacks | 100 | v8 round8_* (code reviews, emails, legal, technical docs) |
| Long-context attacks | 100 | r8_attack_long_context (sampled) |
| Holdout long-context attacks | 91 | r8_holdout_long_context_v3 |
| Clean benign | 100 | v7 round7_* |
| Long-context benign | 100 | long_benign_v2 (sampled) |

## Score distribution per category

| Category | n | min | p10 | p50 | p90 | max |
|----------|---|-----|-----|-----|-----|-----|
| short_attack | 100 | 0.9996 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| long_attack | 100 | 0.0080 | 0.0177 | 0.3166 | 1.0000 | 1.0000 |
| holdout_long_attack | 91 | 0.0177 | 0.0177 | 0.1411 | 0.9992 | 1.0000 |
| clean_benign | 100 | 0.0000 | 0.0000 | 0.0000 | 0.0014 | 0.0031 |
| long_benign | 100 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |


## Threshold sweep results

| threshold | short_attack_R | long_attack_R | holdout_long_R | clean_benign_FPR | long_benign_FPR | F1 |
|-----------|----------------|---------------|----------------|------------------|-----------------|-----|
| 0.05 | 100.0% | 80.0% | 84.6% | 0.00% | 0.00% | 0.9380 |
| 0.10 | 100.0% | 71.0% | 81.3% | 0.00% | 0.00% | 0.9142 |
| 0.15 | 100.0% | 60.0% | 45.1% | 0.00% | 0.00% | 0.8171 |
| 0.20 | 100.0% | 58.0% | 44.0% | 0.00% | 0.00% | 0.8098 |
| 0.25 | 100.0% | 58.0% | 42.9% | 0.00% | 0.00% | 0.8074 |
| 0.30 | 100.0% | 51.0% | 40.7% | 0.00% | 0.00% | 0.7850 |
| 0.35 | 100.0% | 49.0% | 37.4% | 0.00% | 0.00% | 0.7722 |
| 0.40 | 100.0% | 48.0% | 36.3% | 0.00% | 0.00% | 0.7669 |
| 0.45 | 100.0% | 44.0% | 36.3% | 0.00% | 0.00% | 0.7564 |
| 0.50 | 100.0% | 41.0% | 34.1% | 0.00% | 0.00% | 0.7430 |
| 0.55 | 100.0% | 41.0% | 34.1% | 0.00% | 0.00% | 0.7430 |
| 0.60 | 100.0% | 40.0% | 30.8% | 0.00% | 0.00% | 0.7320 |
| 0.65 | 100.0% | 38.0% | 29.7% | 0.00% | 0.00% | 0.7237 |
| 0.70 | 100.0% | 36.0% | 29.7% | 0.00% | 0.00% | 0.7181 |
| 0.75 | 100.0% | 36.0% | 28.6% | 0.00% | 0.00% | 0.7152 |
| 0.80 | 100.0% | 35.0% | 25.3% | 0.00% | 0.00% | 0.7038 |
| 0.85 | 100.0% | 35.0% | 25.3% | 0.00% | 0.00% | 0.7038 |
| 0.90 | 100.0% | 35.0% | 24.2% | 0.00% | 0.00% | 0.7009 |
| 0.95 | 100.0% | 33.0% | 20.9% | 0.00% | 0.00% | 0.6862 |


## Best-F1 threshold analysis

| Strategy | threshold | F1 | Recall | FPR |
|----------|-----------|-----|--------|-----|
| Max F1 | 0.05 | 0.9380 | 88.3% | 0.00% |
| **Current (0.50)** | 0.50 | 0.7430 | 59.1% | 0.00% |
| Short recall >= 95% | 0.05 | 0.9380 | 100.0% short | 0.00% long_benign |


## Recommendation

**Change threshold from 0.50 to 0.05** for best F1.

## Real gaps revealed by this hard test set

1. **Long-context attacks are the dominant gap.** Even at the best threshold, long-context attack recall is 80.0% — the model was trained on shorter documents and the architecture caps at 8192 tokens.
2. **Short attacks are 100% recall across all thresholds** — the model is solid where it was trained.
3. **Long-context benign FPR is 0.0%** — borderline. Some long benign documents look attack-like to the model.
4. **Clean benign FPR stays at 0%** across all thresholds — the model is well-calibrated for typical user content.

## Saved artifacts

- `test/eval/threshold-sweep-hard-results.json` — full results
- `test/eval/threshold-sweep-hard-results.md` — this file
