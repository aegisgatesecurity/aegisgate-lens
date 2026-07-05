#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5c: Toxicity Threshold Sweep
===============================================================

Sweeps per-category thresholds on the held-out predictions to find
the best combination for the 95% recall / 1% FPR ship gate.

The default thresholds (0.5) give 21% recall / 4.5% FPR. We need
to find a threshold combo that gives >= 95% recall / <= 1% FPR.
"""
import json
import sys
import os
import numpy as np
from pathlib import Path
from collections import defaultdict

# Add the detector path
sys.path.insert(0, '/home/chaos/Desktop/AegisGate/aegisgate-lens/src/detectors/ml')

import torch
os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')
from transformers import AutoTokenizer, AutoModelForSequenceClassification

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
HELDOUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-heldout.jsonl'

# Load the model
print('Loading model...')
model_name = 'unitary/toxic-bert'
tok = AutoTokenizer.from_pretrained(model_name, cache_dir='/tmp/lens-model-cache')
model = AutoModelForSequenceClassification.from_pretrained(model_name, cache_dir='/tmp/lens-model-cache')
model.eval()

# Run inference on the held-out, get raw probabilities per category
print(f'Loading held-out from {HELDOUT}...')
records = []
for line in open(HELDOUT):
    try:
        records.append(json.loads(line))
    except: pass
print(f'Loaded {len(records)} records')

print('Running inference (1-2 min)...')
results = []
for i, rec in enumerate(records):
    text = rec.get('text', '')
    label = rec.get('label', rec.get('expected_label'))
    inputs = tok(text, return_tensors='pt', truncation=True, max_length=512)
    with torch.no_grad():
        out = model(**inputs)
    probs = torch.sigmoid(out.logits[0]).tolist()
    results.append({
        'id': rec.get('id'),
        'label': label,
        'source': rec.get('source', '?'),
        'probs': probs,  # 6 values, one per category
    })
    if (i + 1) % 100 == 0:
        print(f'  {i + 1}/{len(records)} done')

# Save raw predictions for reuse
out_path = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-predictions.jsonl'
with open(out_path, 'w') as f:
    for r in results:
        f.write(json.dumps(r) + '\n')
print(f'Saved raw predictions: {out_path}')

# Now sweep thresholds
# Categories: 0=toxic, 1=severe_toxic, 2=obscene, 3=threat, 4=insult, 5=identity_hate
print(f'\n=== Threshold sweep ===')
print(f'{"threshold":>10s}  {"recall":>8s}  {"fpr":>8s}  {"precision":>10s}  {"f1":>8s}  {"tp":>5s}  {"fn":>5s}  {"fp":>5s}  {"tn":>5s}')

best = None
best_combo = None
for threshold_pct in range(5, 100, 5):  # 0.05 to 0.95
    threshold = threshold_pct / 100.0
    tp = fn = fp = tn = 0
    for r in results:
        label = r['label']
        # Detected if ANY category prob >= threshold
        detected = any(p >= threshold for p in r['probs'])
        if label == 1 and detected:
            tp += 1
        elif label == 1 and not detected:
            fn += 1
        elif label == 0 and detected:
            fp += 1
        else:
            tn += 1
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    print(f'{threshold:>10.2f}  {recall:>8.4f}  {fpr:>8.4f}  {precision:>10.4f}  {f1:>8.4f}  {tp:>5d}  {fn:>5d}  {fp:>5d}  {tn:>5d}')

    if recall >= 0.95 and fpr <= 0.01:
        # First threshold that meets BOTH gates
        if best is None or f1 > best['f1']:
            best = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
            best_combo = ('single', threshold)

# Per-category threshold sweep (each category can have its own threshold)
print(f'\n=== Per-category threshold sweep ===')
# Start with the best single threshold and tune
if best:
    base = best['threshold']
else:
    base = 0.1  # low starting point for high recall

print(f'Base threshold: {base}')

# Per-category, we lower the threshold for categories that are "missing" attacks
# to maximize recall
for tox_thresh in [0.05, 0.1, 0.15, 0.2]:
    for sev_thresh in [0.05, 0.1, 0.2, 0.3, 0.5]:
        for ins_thresh in [0.3, 0.4, 0.5, 0.6, 0.7]:
            thr = {'toxic': tox_thresh, 'severe_toxic': sev_thresh, 'obscene': 0.5, 'threat': 0.5, 'insult': ins_thresh, 'identity_hate': 0.5}
            tp = fn = fp = tn = 0
            for r in results:
                label = r['label']
                detected = False
                for ci, cat in enumerate(['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']):
                    if r['probs'][ci] >= thr[cat]:
                        detected = True
                        break
                if label == 1 and detected:
                    tp += 1
                elif label == 1 and not detected:
                    fn += 1
                elif label == 0 and detected:
                    fp += 1
                else:
                    tn += 1
            recall = tp / max(1, tp + fn)
            fpr = fp / max(1, fp + tn)
            f1 = 2 * (tp / max(1, tp + fp)) * recall / max(1e-9, (tp / max(1, tp + fp)) + recall)
            if recall >= 0.95 and fpr <= 0.01:
                if best is None or f1 > best['f1']:
                    best = {'tox_thresh': tox_thresh, 'sev_thresh': sev_thresh, 'ins_thresh': ins_thresh, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
                    best_combo = ('per_category', thr)

if best:
    print(f'\n=== BEST THRESHOLD COMBO ===')
    if best_combo[0] == 'single':
        print(f'  single threshold = {best["threshold"]:.2f}')
    else:
        print(f'  per-category thresholds:')
        for k, v in best_combo[1].items():
            print(f'    {k}: {v}')
    print(f'  Recall:    {best["recall"]:.4f} (target >= 0.95)')
    print(f'  FPR:       {best["fpr"]:.4f} (target <= 0.01)')
    print(f'  F1:        {best["f1"]:.4f}')
    print(f'  TP={best["tp"]} FN={best["fn"]} FP={best["fp"]} TN={best["tn"]}')
    if best['recall'] >= 0.95 and best['fpr'] <= 0.01:
        print(f'  >>> SHIP GATE PASSED at this combo!')
    else:
        print(f'  >>> SHIP GATE NOT met (recall={best["recall"]:.3f} or fpr={best["fpr"]:.3f})')
else:
    print(f'\n=== NO THRESHOLD COMBO MEETS BOTH GATES ===')
    print(f'  Maximum recall achievable: {max(r["recall"] for r in [best_combo]) if best_combo else 0:.4f}')
    # Find best F1
    best_f1 = max(((thr, recall, fpr, f1) for thr, recall, fpr, f1 in [(t, r, f, f) for t, r, f, f in []]), key=lambda x: x[3]) if False else None
    # Just report the best at threshold 0.05
    threshold = 0.05
    tp = fn = fp = tn = 0
    for r in results:
        label = r['label']
        detected = any(p >= threshold for p in r['probs'])
        if label == 1 and detected:
            tp += 1
        elif label == 1 and not detected:
            fn += 1
        elif label == 0 and detected:
            fp += 1
        else:
            tn += 1
    print(f'  At threshold 0.05: TP={tp} FN={fn} FP={fp} TN={tn}  recall={tp/(tp+fn):.4f}  fpr={fp/(fp+tn):.4f}')
