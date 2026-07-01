"""
AegisGate Lens v0.2 — Item G: Threshold Sweep

Goal: Find the optimal decision threshold for the snapshot model's
binary classification (attack vs benign). Current threshold is 0.5,
inherited from training. This sweep validates it or identifies a
better threshold based on held-out data.

Strategy:
  1. Build a held-out test set:
     - 100 attacks: r8_attack_* combined (excluding r8_holdout_v0.2 to avoid leakage)
     - 100 benign:  r7_benign_* + r7_holdout_v0.2 + r7_long_benign_train
  2. Score every record
  3. For thresholds [0.05, 0.10, 0.15, ..., 0.95]:
     - Compute precision, recall, F1, FPR, FNR
  4. Identify optimal threshold:
     - Max F1 (default optimal)
     - Recall >= 0.95 (high-recall constraint) with min FPR
  5. Compare to current threshold (0.5)
"""
import json
from pathlib import Path
import random

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

REPO = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02')
SNAPSHOT = REPO / 'models/snapshots/pre-retrain-2026-06-28T14-25-00Z/checkpoint-7012'
CORPORA = REPO / 'corpora'

# Fixed seed for reproducibility
random.seed(42)
np.random.seed(42)

print(f'Loading snapshot model from: {SNAPSHOT}')
tokenizer = AutoTokenizer.from_pretrained(SNAPSHOT)
model = AutoModelForSequenceClassification.from_pretrained(SNAPSHOT).cuda().eval()

def score(text):
    """Run model on text, return P(attack)."""
    enc = tokenizer(text, return_tensors='pt', max_length=2048,
                    truncation=True, padding=True).to('cuda')
    with torch.no_grad():
        logits = model(**enc).logits
    return float(torch.softmax(logits, dim=-1)[0, 1])

# Build held-out test set (using v0.1 archived corpora for domain-specific splits)
# NOTE: r7_long_benign_train.jsonl was found to be contaminated (test/eval/corpus-fix-2026-06-28.md).
# 136/364 records contained embedded attacks. We've moved to long_benign_v2.jsonl
# (20000 records, all genuinely benign long-context) as the 6th benign source.
print('Building held-out test set...')
V01 = Path('/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-working-snapshot/pen-test/corpus')

attack_files = [
    ('v8/round8_code_reviews.jsonl', V01 / 'v8/round8_code_reviews.jsonl'),
    ('v8/round8_emails.jsonl', V01 / 'v8/round8_emails.jsonl'),
    ('v8/round8_legal.jsonl', V01 / 'v8/round8_legal.jsonl'),
    ('v8/round8_technical_docs.jsonl', V01 / 'v8/round8_technical_docs.jsonl'),
]
benign_files = [
    ('v7/round7_code_reviews.jsonl', V01 / 'v7/round7_code_reviews.jsonl'),
    ('v7/round7_emails.jsonl', V01 / 'v7/round7_emails.jsonl'),
    ('v7/round7_legal.jsonl', V01 / 'v7/round7_legal.jsonl'),
    ('v7/round7_technical_docs.jsonl', V01 / 'v7/round7_technical_docs.jsonl'),
    ('r7_holdout_v0.2.jsonl', CORPORA / 'r7_holdout_v0.2.jsonl'),
    ('long_benign_v2.jsonl', CORPORA / 'long_benign_v2.jsonl'),  # replaces contaminated r7_long_benign_train
]

# Load 25 attacks from each of 4 sources = 100 attacks
attack_records = []
for label, path in attack_files:
    with open(path) as f:
        records = [json.loads(l) for l in f]
    sample = random.sample(records, 25)
    for r in sample:
        attack_records.append({'text': r['text'], 'source': label})
print(f'Loaded {len(attack_records)} attack records')

# Load ~17 benign from each of 6 sources = 100 benign
benign_records = []
for label, path in benign_files:
    with open(path) as f:
        records = [json.loads(l) for l in f]
    sample = random.sample(records, min(17, len(records)))
    for r in sample:
        benign_records.append({'text': r['text'], 'source': label})
print(f'Loaded {len(benign_records)} benign records')

# Score all records
print('Scoring attack records...')
attack_scores = []
for r in attack_records:
    s = score(r['text'])
    attack_scores.append(s)
print(f'Scored {len(attack_scores)} attacks; sample scores: {attack_scores[:5]}')

print('Scoring benign records...')
benign_scores = []
for r in benign_records:
    s = score(r['text'])
    benign_scores.append(s)
print(f'Scored {len(benign_scores)} benign records; sample scores: {benign_scores[:5]}')

# Sweep thresholds
print()
print('Threshold sweep:')
thresholds = [round(x * 0.05, 2) for x in range(1, 20)]  # 0.05 to 0.95 in 0.05 steps
results = []
for t in thresholds:
    tp = sum(1 for s in attack_scores if s >= t)
    fn = len(attack_scores) - tp
    fp = sum(1 for s in benign_scores if s >= t)
    tn = len(benign_scores) - fp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    results.append({
        'threshold': t,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr,
        'fnr': fnr,
    })
    print(f'  t={t:.2f}  TP={tp:3d} FP={fp:3d} FN={fn:3d} TN={tn:3d}  '
          f'P={precision:.4f} R={recall:.4f} F1={f1:.4f} FPR={fpr:.4f}')

# Find optimal thresholds
print()
print('=' * 60)
best_f1 = max(results, key=lambda r: r['f1'])
print(f'Best F1:        threshold={best_f1["threshold"]:.2f}  F1={best_f1["f1"]:.4f}  '
      f'P={best_f1["precision"]:.4f}  R={best_f1["recall"]:.4f}  FPR={best_f1["fpr"]:.4f}')

# High-recall constraint: max recall, min FPR
high_recall_options = [r for r in results if r['recall'] >= 0.95]
if high_recall_options:
    best_high_recall = min(high_recall_options, key=lambda r: r['fpr'])
    print(f'Best high-recall (R>=0.95, min FPR): threshold={best_high_recall["threshold"]:.2f}  '
          f'F1={best_high_recall["f1"]:.4f}  R={best_high_recall["recall"]:.4f}  FPR={best_high_recall["fpr"]:.4f}')

# Compare to current threshold (0.50)
current = next((r for r in results if r['threshold'] == 0.5), None)
print()
print(f'Current threshold (0.50):  F1={current["f1"]:.4f}  '
      f'P={current["precision"]:.4f}  R={current["recall"]:.4f}  FPR={current["fpr"]:.4f}')

# Determine recommendation
if best_f1['threshold'] != 0.5:
    improvement = best_f1['f1'] - current['f1']
    print(f'\nRecommendation: threshold={best_f1["threshold"]:.2f} '
          f'(F1 improvement: {improvement:+.4f})')
else:
    print(f'\nRecommendation: keep current threshold (0.50); '
          f'it is optimal on this held-out set.')

# Write results
out_json = REPO / 'test/eval/threshold-sweep-results.json'
out_csv = REPO / 'test/eval/threshold-sweep-results.csv'
out_md = REPO / 'test/eval/threshold-sweep-results.md'

out_json.write_text(json.dumps({
    'timestamp': '2026-06-28',
    'snapshot_path': str(SNAPSHOT),
    'num_attacks': len(attack_records),
    'num_benign': len(benign_records),
    'attack_sources': [label for label, _ in attack_files],
    'benign_sources': [label for label, _ in benign_files],
    'attack_scores_summary': {
        'min': min(attack_scores), 'max': max(attack_scores),
        'mean': sum(attack_scores) / len(attack_scores),
    },
    'benign_scores_summary': {
        'min': min(benign_scores), 'max': max(benign_scores),
        'mean': sum(benign_scores) / len(benign_scores),
    },
    'sweep_results': results,
    'best_f1': best_f1,
    'current_0_5': current,
    'high_recall_options': high_recall_options,
}, indent=2))

# CSV
with open(out_csv, 'w') as f:
    f.write('threshold,precision,recall,f1,fpr,fnr,tp,fp,fn,tn\n')
    for r in results:
        f.write(f"{r['threshold']},{r['precision']:.4f},{r['recall']:.4f},{r['f1']:.4f},"
                f"{r['fpr']:.4f},{r['fnr']:.4f},{r['tp']},{r['fp']},{r['fn']},{r['tn']}\n")

# Markdown
md = f"""# Item G — Threshold Sweep Results (2026-06-28)

## Summary

- **Test set**: {len(attack_records)} attacks + {len(benign_records)} benign
- **Attack score range**: [{min(attack_scores):.4f}, {max(attack_scores):.4f}], mean {sum(attack_scores)/len(attack_scores):.4f}
- **Benign score range**: [{min(benign_scores):.4f}, {max(benign_scores):.4f}], mean {sum(benign_scores)/len(benign_scores):.4f}

## Recommendations

| Strategy | Threshold | F1 | Precision | Recall | FPR |
|----------|-----------|-----|-----------|--------|-----|
"""
md += f"| **Best F1** | {best_f1['threshold']:.2f} | {best_f1['f1']:.4f} | {best_f1['precision']:.4f} | {best_f1['recall']:.4f} | {best_f1['fpr']:.4f} |\n"
md += f"| **Current (0.50)** | 0.50 | {current['f1']:.4f} | {current['precision']:.4f} | {current['recall']:.4f} | {current['fpr']:.4f} |\n"
if high_recall_options:
    md += f"| **High-recall (R≥0.95)** | {best_high_recall['threshold']:.2f} | {best_high_recall['f1']:.4f} | {best_high_recall['precision']:.4f} | {best_high_recall['recall']:.4f} | {best_high_recall['fpr']:.4f} |\n"

md += f"""

## Full sweep

| Threshold | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|-----------|-----------|--------|-----|------|----|----|----|----|
"""
for r in results:
    md += f"| {r['threshold']:.2f} | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1']:.4f} | {r['fpr']:.4f} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} |\n"

md += f"""

## Verdict

{'**Recommend changing threshold from 0.50 to ' + f'{best_f1["threshold"]:.2f}' + '** (F1 improvement: ' + f'{best_f1["f1"] - current["f1"]:+.4f}' + ')' if best_f1['threshold'] != 0.5 else '**Threshold 0.50 is optimal on this held-out set.** No change recommended.'}

## Saved artifacts

- `test/eval/threshold-sweep-results.json` — full results with scores
- `test/eval/threshold-sweep-results.csv` — sweep table
- `test/eval/threshold-sweep-results.md` — this file
"""
out_md.write_text(md)
print(f'\nResults saved to: {out_json}')
print(f'CSV saved to: {out_csv}')
print(f'MD summary saved to: {out_md}')