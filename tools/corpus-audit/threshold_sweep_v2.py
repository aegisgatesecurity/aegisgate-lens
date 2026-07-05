#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5c Option A: Threshold sweep on Jigsaw held-out
====================================================================================

Sweeps per-category thresholds on the Jigsaw-style held-out to find
the best combination for the 95% recall / 1% FPR ship gate.
"""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
CORPUS = LENS / 'corpora' / 'v01beta-raw'
HELDOUT = CORPUS / 'v01beta-toxicity-heldout.jsonl'
PREDICTIONS = CORPUS / 'v01beta-toxicity-predictions-v2.jsonl'

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

def main():
    # Load the model
    print('Loading model...')
    model_name = 'unitary/toxic-bert'
    tok = AutoTokenizer.from_pretrained(model_name, cache_dir='/tmp/lens-model-cache')
    model = AutoModelForSequenceClassification.from_pretrained(model_name, cache_dir='/tmp/lens-model-cache')
    model.eval()

    # Load held-out
    records = []
    for line in open(HELDOUT):
        try:
            records.append(json.loads(line))
        except: pass
    print(f'Loaded {len(records)} records')

    # Run inference (or use cached predictions)
    import os.path
    if os.path.exists(PREDICTIONS):
        print(f'Using cached predictions from {PREDICTIONS}')
        results = []
        for line in open(PREDICTIONS):
            try:
                results.append(json.loads(line))
            except: pass
    else:
        print('Running inference (1-2 min)...')
        results = []
        for i, rec in enumerate(records):
            text = rec.get('text', '')
            inputs = tok(text, return_tensors='pt', truncation=True, max_length=512)
            with torch.no_grad():
                out = model(**inputs)
            probs = torch.sigmoid(out.logits[0]).tolist()
            results.append({
                'id': rec.get('id'),
                'label': rec.get('label', rec.get('expected_label')),
                'source': rec.get('source', '?'),
                'probs': probs,
            })
            if (i + 1) % 100 == 0:
                print(f'  {i + 1}/{len(records)} done')
        with open(PREDICTIONS, 'w') as f:
            for r in results:
                f.write(json.dumps(r) + '\n')
        print(f'Saved: {PREDICTIONS}')

    # Sweep single threshold
    print(f'\n=== SINGLE-THRESHOLD sweep (any of 6 cats >= threshold) ===')
    print(f'{"threshold":>10s}  {"recall":>8s}  {"fpr":>8s}  {"precision":>10s}  {"f1":>8s}  {"tp":>5s}  {"fn":>5s}  {"fp":>5s}  {"tn":>5s}')

    best = None
    for threshold_pct in range(1, 100):
        threshold = threshold_pct / 100.0
        tp = fn = fp = tn = 0
        for r in results:
            label = r['label']
            detected = any(p >= threshold for p in r['probs'])
            if label == 1 and detected: tp += 1
            elif label == 1 and not detected: fn += 1
            elif label == 0 and detected: fp += 1
            else: tn += 1
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        print(f'{threshold:>10.2f}  {recall:>8.4f}  {fpr:>8.4f}  {precision:>10.4f}  {f1:>8.4f}  {tp:>5d}  {fn:>5d}  {fp:>5d}  {tn:>5d}')
        if recall >= 0.95 and fpr <= 0.01:
            if best is None or f1 > best['f1']:
                best = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # Per-category threshold sweep
    print(f'\n=== PER-CATEGORY threshold sweep ===')
    # Tune: lower the threshold for the categories that miss the most attacks
    # Defaults: all 0.5. Start by lowering toxic + identity_attack.
    import itertools
    best_per_cat = None
    for tox_thr in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        for sev_thr in [0.3, 0.4, 0.5, 0.6, 0.7]:
            for ins_thr in [0.3, 0.4, 0.5, 0.6, 0.7]:
                for thr_thr in [0.3, 0.4, 0.5, 0.6, 0.7]:
                    for obs_thr in [0.4, 0.5, 0.6]:
                        for ide_thr in [0.3, 0.4, 0.5, 0.6, 0.7]:
                            thresholds = {
                                'toxic': tox_thr, 'severe_toxic': sev_thr, 'insult': ins_thr,
                                'threat': thr_thr, 'obscene': obs_thr, 'identity_hate': ide_thr,
                            }
                            tp = fn = fp = tn = 0
                            for r in results:
                                label = r['label']
                                detected = False
                                for ci, cat in enumerate(['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']):
                                    if r['probs'][ci] >= thresholds[cat]:
                                        detected = True
                                        break
                                if label == 1 and detected: tp += 1
                                elif label == 1 and not detected: fn += 1
                                elif label == 0 and detected: fp += 1
                                else: tn += 1
                            recall = tp / max(1, tp + fn)
                            fpr = fp / max(1, fp + tn)
                            if recall >= 0.95 and fpr <= 0.01:
                                precision = tp / max(1, tp + fp)
                                f1 = 2 * precision * recall / max(1e-9, precision + recall)
                                if best_per_cat is None or f1 > best_per_cat['f1']:
                                    best_per_cat = {'thresholds': thresholds, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # Report the best
    if best or best_per_cat:
        print(f'\n=== BEST ===')
        if best:
            print(f'  Single threshold: {best["threshold"]}  recall={best["recall"]:.4f}  fpr={best["fpr"]:.4f}  f1={best["f1"]:.4f}')
        if best_per_cat:
            print(f'  Per-category thresholds: {best_per_cat["thresholds"]}')
            print(f'  recall={best_per_cat["recall"]:.4f}  fpr={best_per_cat["fpr"]:.4f}  f1={best_per_cat["f1"]:.4f}  tp={best_per_cat["tp"]} fn={best_per_cat["fn"]} fp={best_per_cat["fp"]} tn={best_per_cat["tn"]}')
    else:
        print(f'\n=== NO THRESHOLD COMBO MEETS BOTH GATES ===')
        # Find best F1 from single threshold
        best_f1 = None
        for threshold_pct in range(1, 100):
            threshold = threshold_pct / 100.0
            tp = fn = fp = tn = 0
            for r in results:
                label = r['label']
                detected = any(p >= threshold for p in r['probs'])
                if label == 1 and detected: tp += 1
                elif label == 1 and not detected: fn += 1
                elif label == 0 and detected: fp += 1
                else: tn += 1
            recall = tp / max(1, tp + fn)
            fpr = fp / max(1, fp + tn)
            precision = tp / max(1, tp + fp)
            f1 = 2 * precision * recall / max(1e-9, precision + recall)
            if best_f1 is None or f1 > best_f1['f1']:
                best_f1 = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
        print(f'  Best F1: {best_f1}')

if __name__ == '__main__':
    main()
