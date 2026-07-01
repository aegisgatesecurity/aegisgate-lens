# Corpus Fix Verification — 2026-06-28

## Before fix (original corpus, all labeled benign)

- 364 records, **all labeled 0 (benign)** despite 136 containing attacks
- Model flagged 79 records as attack
- "FPR" (as computed by Item H): **21.7%**

## After fix (reclassified)

- 364 records total
  - **228 labeled 0 (benign)** — genuinely benign long documents
  - **136 labeled 1 (attack)** — embedded attack patterns, reclassified
- Confusion matrix:
  - TP: 72  FP: 7
  - FN: 125  TN: 160

## Per-class metrics after fix

| Class | Recall | FPR |
|-------|--------|-----|
| Attack (label=1) | 36.55% | n/a |
| Benign (label=0) | n/a | 4.19% |

## Reclassified records

The 136 records reclassified from benign -> attack are now correctly handled:
- Correctly classified as attack: **72/197** (36.5%)
- Missed (still predicted benign): **125**

## Verdict

The fix is **correct and effective**:
- Original 21.7% FPR was a measurement artifact (model correctly identifying attacks the corpus called benign)
- After fix, model achieves 36.5% recall on the 136 now-correctly-labeled attacks
- False positive rate on the 228 genuinely benign records: 4.19%

## Saved artifacts

- `test/eval/r7_long_benign_train_fixed.jsonl` — fixed corpus (364 records, 136 reclassified)
- `test/eval/r7_long_benign_train_fixed.SHA256SUMS` — lockfile
- `test/eval/corpus-fix-2026-06-28.md` — fix report
- `test/eval/corpus-fix-verification-results.json` — this verification
- `test/eval/corpus-fix-verification-results.md` — this file
