#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5c Option A: Jigsaw-style toxicity validation
====================================================================================

Validates the toxicity detector against the NEW Jigsaw-style held-out
(from google/civil_comments test split) which matches the model's
training distribution. The previous held-out (ToxiGen/BeaverTails) was
a distribution mismatch.

The Jigsaw held-out: 500 attack + 200 benign = 700 records
Random-sampled from google/civil_comments test split (97,320 records).
Each record has the 7-category Jigsaw probabilities; we use the
standard Jigsaw threshold of 0.5 for label determination.
"""
import json
import os
import sys
from collections import Counter
from pathlib import Path

os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
CORPUS = LENS / 'corpora' / 'v01beta-raw'
HELDOUT = CORPUS / 'v01beta-toxicity-heldout.jsonl'
PREDICTIONS = CORPUS / 'v01beta-toxicity-predictions-v2.jsonl'

sys.path.insert(0, str(LENS / 'src' / 'detectors' / 'ml'))
from toxicity import detect as toxicity_detect

def main():
    records = []
    for line in open(HELDOUT):
        try:
            records.append(json.loads(line))
        except: pass
    print(f'Loaded {len(records)} records from {HELDOUT}')

    n_attack = sum(1 for r in records if r.get('label') == 1)
    n_benign = sum(1 for r in records if r.get('label') == 0)
    print(f'  Attack: {n_attack}, Benign: {n_benign}')

    # Check if predictions are cached
    import os.path
    if os.path.exists(PREDICTIONS):
        print(f'\nUsing cached predictions from {PREDICTIONS}...')
        predictions = {}
        for line in open(PREDICTIONS):
            try:
                p = json.loads(line)
                predictions[p['id']] = p
            except: pass
        print(f'  Cached predictions: {len(predictions)}')
    else:
        predictions = None

    print('\n=== Running toxicity detector on Jigsaw held-out (1-2 min) ===')
    tp = fn = fp = tn = 0
    per_source_stats = {}
    for i, rec in enumerate(records):
        text = rec.get('text', '')
        label = rec.get('label', rec.get('expected_label'))
        rid = rec.get('id', f'r{i}')

        if predictions and rid in predictions:
            events = predictions[rid].get('events', [])
        else:
            try:
                events = toxicity_detect(text)
            except Exception as e:
                events = []
        detected = len(events) > 0

        if label == 1 and detected:
            tp += 1
        elif label == 1 and not detected:
            fn += 1
        elif label == 0 and detected:
            fp += 1
        else:
            tn += 1

        if (i + 1) % 100 == 0:
            print(f'  {i + 1}/{len(records)} done')

    # Compute overall metrics
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    accuracy = (tp + tn) / max(1, tp + fn + fp + tn)

    print(f'\n=== RESULTS (Jigsaw-style held-out: {len(records)} records) ===')
    print(f'  TP (attack caught):       {tp}')
    print(f'  FN (attack missed):      {fn}')
    print(f'  FP (false positive):     {fp}')
    print(f'  TN (correctly rejected): {tn}')
    print()
    print(f'  Recall:    {recall:.4f} (target >= 0.95)')
    print(f'  FPR:       {fpr:.4f} (target <= 0.01)')
    print(f'  Precision: {precision:.4f}')
    print(f'  F1:        {f1:.4f}')
    print(f'  Accuracy:  {accuracy:.4f}')

    # Ship gate
    print(f'\n=== SHIP GATE ===')
    if recall >= 0.95 and fpr <= 0.01:
        print(f'  SHIP GATE PASSED.  Recall={recall:.4f} >= 0.95, FPR={fpr:.4f} <= 0.01')
        return True
    else:
        print(f'  SHIP GATE FAILED.')
        if recall < 0.95:
            print(f'    Recall {recall:.4f} < 0.95 ({fn} attacks missed)')
        if fpr > 0.01:
            print(f'    FPR {fpr:.4f} > 0.01 ({fp} false positives)')
        return False

if __name__ == '__main__':
    passed = main()
    sys.exit(0 if passed else 1)
