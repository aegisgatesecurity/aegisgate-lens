"""
AegisGate Lens v0.2 — Item H: Per-corpus Confusion Matrix

Goal: Identify which benign corpora produce false positives with the
snapshot model. Output: per-corpus TPs/FPs/TNs/FNs/FPR table.

Strategy:
  1. Score every record in:
     - r7_benign_code_reviews (archived v0.1)
     - r7_benign_emails
     - r7_benign_legal
     - r7_benign_technical_docs
     - r7_holdout_v0.2
     - r7_long_benign_train (364 records, FIXED at test/eval/r7_long_benign_train_fixed.jsonl)
     - long_benign_v2 (in v0.2 corpora)
     - r8_attack_long_context benign subset (8 records)
  2. Per corpus: count FP, TN, FPR
  3. Flag any corpus with FPR > 5%
  4. Also report on r8 attacks for context (TP, FN, recall)
"""
import json
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

REPO = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02')
SNAPSHOT = REPO / 'models/snapshots/pre-retrain-2026-06-28T14-25-00Z/checkpoint-7012'
CORPORA = REPO / 'corpora'
V01 = Path('/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-working-snapshot/pen-test/corpus')

THRESHOLD = 0.5  # current threshold

print(f'Loading snapshot model...')
tokenizer = AutoTokenizer.from_pretrained(SNAPSHOT)
model = AutoModelForSequenceClassification.from_pretrained(SNAPSHOT).cuda().eval()

def score(text):
    enc = tokenizer(text, return_tensors='pt', max_length=2048,
                    truncation=True, padding=True).to('cuda')
    with torch.no_grad():
        logits = model(**enc).logits
    return float(torch.softmax(logits, dim=-1)[0, 1])

def score_corpus(path, label):
    """Score all records in a corpus, return TP/FP/TN/FN counts."""
    records = []
    with open(path) as f:
        for line in f:
            records.append(json.loads(line))
    if not records:
        return {'corpus': str(path), 'label': label, 'size': 0,
                'fp': 0, 'fn': 0, 'tp': 0, 'tn': 0, 'fpr': 0, 'recall': 0,
                'mean_score': 0, 'max_score': 0, 'min_score': 0,
                'worst_fps': []}
    scores = []
    for r in records:
        s = score(r['text'])
        scores.append((s, r.get('text', '')[:100]))
    if label == 'benign':
        fp = sum(1 for s, _ in scores if s >= THRESHOLD)
        tn = len(scores) - fp
        fpr = fp / len(scores) if scores else 0
        return {
            'corpus': str(path), 'label': label, 'size': len(scores),
            'fp': fp, 'tn': tn, 'fpr': fpr,
            'mean_score': sum(s for s, _ in scores) / len(scores),
            'max_score': max(s for s, _ in scores),
            'min_score': min(s for s, _ in scores),
            'worst_fps': [{'score': s, 'snippet': t} for s, t in scores if s >= THRESHOLD][:5],
        }
    elif label == 'attack':
        score_list = [s for s, _ in scores]
        tp = sum(1 for s, _ in scores if s >= THRESHOLD)
        fn = len(scores) - tp
        recall = tp / len(scores) if scores else 0
        return {
            'corpus': str(path), 'label': label, 'size': len(scores),
            'tp': tp, 'fn': fn, 'recall': recall,
            'mean_score': sum(score_list) / len(score_list) if score_list else 0,
            'min_score': min(score_list) if score_list else 0,
            'worst_fns': [{'score': s, 'snippet': t} for s, t in scores if s < THRESHOLD][:5],
        }

# Define corpora to score
benign_corpora = [
    ('v7/round7_code_reviews.jsonl', V01 / 'v7/round7_code_reviews.jsonl'),
    ('v7/round7_emails.jsonl', V01 / 'v7/round7_emails.jsonl'),
    ('v7/round7_legal.jsonl', V01 / 'v7/round7_legal.jsonl'),
    ('v7/round7_technical_docs.jsonl', V01 / 'v7/round7_technical_docs.jsonl'),
    ('r7_holdout_v0.2.jsonl', CORPORA / 'r7_holdout_v0.2.jsonl'),
    # The original r7_long_benign_train.jsonl was contaminated (136/364 records
    # contained attacks). We split the fixed corpus into single-class subsets:
    ('r7_long_benign_train_FIXED.benign.jsonl', REPO / 'test/eval/r7_long_benign_train_FIXED.benign.jsonl'),
    ('long_benign_v2.jsonl', CORPORA / 'long_benign_v2.jsonl'),
]
attack_corpora = [
    ('v8/round8_code_reviews.jsonl', V01 / 'v8/round8_code_reviews.jsonl'),
    ('v8/round8_emails.jsonl', V01 / 'v8/round8_emails.jsonl'),
    ('v8/round8_legal.jsonl', V01 / 'v8/round8_legal.jsonl'),
    ('v8/round8_technical_docs.jsonl', V01 / 'v8/round8_technical_docs.jsonl'),
    ('r8_holdout_v0.2.jsonl', CORPORA / 'r8_holdout_v0.2.jsonl'),
    ('r8_attack_long_context.jsonl', CORPORA / 'r8_attack_long_context.jsonl'),
    ('r8_holdout_long_context.jsonl', CORPORA / 'r8_holdout_long_context.jsonl'),
    ('r8_holdout_long_context_v3.jsonl', CORPORA / 'r8_holdout_long_context_v3.jsonl'),
    # Attack half of the previously contaminated r7_long_benign_train corpus
    ('r7_long_benign_train_FIXED.attack.jsonl', REPO / 'test/eval/r7_long_benign_train_FIXED.attack.jsonl'),
]

print()
print('=' * 70)
print('BENIGN CORPORA — false-positive analysis')
print('=' * 70)
benign_results = []
for label, path in benign_corpora:
    r = score_corpus(path, 'benign')
    benign_results.append(r)
    fp_pct = f"{r['fpr']*100:.1f}%" if r['size'] > 0 else "n/a"
    print(f"{label:45s}  size={r['size']:5d}  FP={r['fp']:4d}  TN={r['tn']:5d}  "
          f"FPR={fp_pct:>6s}  mean_P={r['mean_score']:.4f}  max_P={r['max_score']:.4f}")
    if r['fpr'] > 0.05:
        print(f"  ⚠️ FPR > 5% — flagged for review")
        for fp_record in r['worst_fps']:
            print(f"     FP snippet (P={fp_record['score']:.4f}): {fp_record['snippet']!r}")

print()
print('=' * 70)
print('ATTACK CORPORA — recall analysis')
print('=' * 70)
attack_results = []
for label, path in attack_corpora:
    r = score_corpus(path, 'attack')
    attack_results.append(r)
    recall_pct = f"{r['recall']*100:.1f}%" if r['size'] > 0 else "n/a"
    print(f"{label:45s}  size={r['size']:5d}  TP={r['tp']:4d}  FN={r['fn']:4d}  "
          f"recall={recall_pct:>6s}  mean_P={r['mean_score']:.4f}")

# Summary
print()
print('=' * 70)
print('SUMMARY')
print('=' * 70)
total_benign = sum(r['size'] for r in benign_results)
total_fp = sum(r['fp'] for r in benign_results)
overall_fpr = total_fp / total_benign if total_benign > 0 else 0
print(f'Overall benign FPR: {total_fp}/{total_benign} = {overall_fpr*100:.2f}%')

total_attack = sum(r['size'] for r in attack_results)
total_tp = sum(r['tp'] for r in attack_results)
overall_recall = total_tp / total_attack if total_attack > 0 else 0
print(f'Overall attack recall: {total_tp}/{total_attack} = {overall_recall*100:.2f}%')

flagged_corpora = [r for r in benign_results if r['fpr'] > 0.05]
if flagged_corpora:
    print(f'\n⚠️ {len(flagged_corpora)} benign corpora flagged for FPR > 5%:')
    for r in flagged_corpora:
        print(f"   - {r['corpus']}: FPR={r['fpr']*100:.1f}%")

# Write results
out_json = REPO / 'test/eval/confusion-matrix-results.json'
out_md = REPO / 'test/eval/confusion-matrix-results.md'

out_json.write_text(json.dumps({
    'timestamp': '2026-06-28',
    'snapshot_path': str(SNAPSHOT),
    'threshold': THRESHOLD,
    'benign_results': benign_results,
    'attack_results': attack_results,
    'overall_fpr': overall_fpr,
    'overall_recall': overall_recall,
    'flagged_corpus_count': len(flagged_corpora),
}, indent=2))

md = f"""# Item H — Per-corpus Confusion Matrix (2026-06-28)

## Summary

- **Overall benign FPR**: {total_fp}/{total_benign} = {overall_fpr*100:.2f}%
- **Overall attack recall**: {total_tp}/{total_attack} = {overall_recall*100:.2f}%
- **Threshold**: {THRESHOLD}
- **Flagged corpora (FPR > 5%)**: {len(flagged_corpora)}

## Benign corpora

| Corpus | Size | FP | TN | FPR | Mean P(attack) | Max P(attack) |
|--------|------|----|----|-----|----------------|---------------|
"""
for r in benign_results:
    fp_pct = f"{r['fpr']*100:.1f}%" if r['size'] > 0 else "n/a"
    flag = " ⚠️" if r['fpr'] > 0.05 else ""
    md += f"| {r['corpus'].replace(str(REPO), '').lstrip('/')[:50]} | {r['size']} | {r['fp']} | {r['tn']} | {fp_pct}{flag} | {r['mean_score']:.4f} | {r['max_score']:.4f} |\n"

md += f"""

## Attack corpora

| Corpus | Size | TP | FN | Recall | Mean P(attack) |
|--------|------|----|----|--------|----------------|
"""
for r in attack_results:
    recall_pct = f"{r['recall']*100:.1f}%" if r['size'] > 0 else "n/a"
    md += f"| {r['corpus'].replace(str(REPO), '').lstrip('/')[:50]} | {r['size']} | {r['tp']} | {r['fn']} | {recall_pct} | {r['mean_score']:.4f} |\n"

if flagged_corpora:
    md += f"""

## ⚠️ Flagged corpora (FPR > 5%) — requires investigation

"""
    for r in flagged_corpora:
        md += f"### {r['corpus']}\n\nFPR: {r['fpr']*100:.1f}%\n\nWorst false positives:\n\n"
        for fp in r['worst_fps']:
            md += f"- P(attack)={fp['score']:.4f}: `{fp['snippet'][:80]}...`\n"
        md += "\n"

md += f"""

## Verdict

- **Pass**: {'✅ All benign corpora have FPR ≤ 5%' if len(flagged_corpora) == 0 else f'❌ {len(flagged_corpora)} corpora exceed 5% FPR — review needed'}
- **Overall FPR**: {overall_fpr*100:.2f}% (target: ≤5%)
- **Overall recall**: {overall_recall*100:.2f}% (target: ≥80%)

## Saved artifacts

- `test/eval/confusion-matrix-results.json` — full results with snippets
- `test/eval/confusion-matrix-results.md` — this file
"""
out_md.write_text(md)
print(f'\nResults saved to: {out_json}')
print(f'Summary saved to: {out_md}')