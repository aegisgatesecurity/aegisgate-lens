#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5c Option C: Best per-category threshold search
====================================================================================

Searches for the best per-category threshold combination to achieve
the 95% recall / 1% FPR ship gate on the 16-cat model.

The 6-cat model had a recall ceiling of 21% at the 1% FPR gate.
The 16-cat model is better; this script searches the per-category
threshold space more aggressively.
"""
import json
import os
import sys
import itertools
from pathlib import Path

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
CORPUS = LENS / 'corpora' / 'v01beta-raw'
PREDICTIONS = CORPUS / 'v01beta-toxicity-predictions-16cat.jsonl'

def main():
    # Load predictions
    records = []
    for line in open(PREDICTIONS):
        try:
            records.append(json.loads(line))
        except: pass
    print(f'Loaded {len(records)} prediction records')

    # The 6 toxicity categories we care about (8 indices including sexual + psychiatric)
    tox_idxs = [0, 1, 2, 3, 4, 5, 6, 15]  # toxicity, severe_toxicity, obscene, identity_attack, insult, threat, sexual_explicit, psychiatric
    cat_names = ['toxicity', 'severe_toxicity', 'obscene', 'identity_attack', 'insult', 'threat', 'sexual_explicit', 'psychiatric']

    # Use a tighter threshold range per category, with finer granularity
    # Each category gets its own threshold in [0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]
    # That's 10 thresholds per category, 10^8 = 100M combinations. Too many.
    # Use 5 thresholds per category: [0.1, 0.2, 0.3, 0.4, 0.5]
    # That's 5^8 = 390625 combinations. Manageable.

    # Actually, let me be smarter. The dominant category for most attacks is
    # "toxicity" (idx 0). Let me find the best threshold for "toxicity" first
    # holding others at 0.5, then sweep the rest.

    print('\n=== Step 1: Sweep toxicity threshold (others at 0.5) ===')
    print(f'{"tox_thr":>8s}  {"recall":>8s}  {"fpr":>8s}  {"f1":>8s}  {"tp":>5s}  {"fn":>5s}  {"fp":>5s}  {"tn":>5s}')
    for thr in [0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6]:
        thresholds = {c: thr for c in cat_names}
        thresholds['toxicity'] = thr  # vary
        thresholds['severe_toxicity'] = 0.5
        thresholds['obscene'] = 0.5
        thresholds['identity_attack'] = 0.5
        thresholds['insult'] = 0.5
        thresholds['threat'] = 0.5
        thresholds['sexual_explicit'] = 0.5
        thresholds['psychiatric'] = 0.5
        tp = fn = fp = tn = 0
        for r in records:
            label = r['label']
            detected = False
            for i, cat in enumerate(cat_names):
                if r['probs'][tox_idxs[i]] >= thresholds[cat]:
                    detected = True
                    break
            if label == 1 and detected: tp += 1
            elif label == 1 and not detected: fn += 1
            elif label == 0 and detected: fp += 1
            else: tn += 1
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        print(f'{thr:>8.2f}  {recall:>8.4f}  {fpr:>8.4f}  {f1:>8.4f}  {tp:>5d}  {fn:>5d}  {fp:>5d}  {tn:>5d}')

    # Now sweep all 8 categories with a smaller grid (3 thresholds each)
    # 3^8 = 6561 combinations, very fast
    print('\n=== Step 2: Per-category sweep (3 thresholds per cat) ===')
    best = None
    total = 0
    for thresh_combo in itertools.product([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7], repeat=8):
        total += 1
        thresholds = dict(zip(cat_names, thresh_combo))
        tp = fn = fp = tn = 0
        for r in records:
            label = r['label']
            detected = False
            for i, cat in enumerate(cat_names):
                if r['probs'][tox_idxs[i]] >= thresholds[cat]:
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
            if best is None or f1 > best['f1']:
                best = {'thresholds': thresholds, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
    print(f'  Tested {total} combinations')

    if best:
        print(f'\n=== BEST PER-CATEGORY (95%/1% gate) ===')
        print(f'  Thresholds: {best["thresholds"]}')
        print(f'  recall={best["recall"]:.4f}  fpr={best["fpr"]:.4f}  f1={best["f1"]:.4f}  tp={best["tp"]} fn={best["fn"]} fp={best["fp"]} tn={best["tn"]}')
    else:
        # Find best F1 with fpr <= 0.05
        best_f1 = None
        for thresh_combo in itertools.product([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7], repeat=8):
            thresholds = dict(zip(cat_names, thresh_combo))
            tp = fn = fp = tn = 0
            for r in records:
                label = r['label']
                detected = False
                for i, cat in enumerate(cat_names):
                    if r['probs'][tox_idxs[i]] >= thresholds[cat]:
                        detected = True
                        break
                if label == 1 and detected: tp += 1
                elif label == 1 and not detected: fn += 1
                elif label == 0 and detected: fp += 1
                else: tn += 1
            recall = tp / max(1, tp + fn)
            fpr = fp / max(1, fp + tn)
            if fpr <= 0.05:
                precision = tp / max(1, tp + fp)
                f1 = 2 * precision * recall / max(1e-9, precision + recall)
                if best_f1 is None or f1 > best_f1['f1']:
                    best_f1 = {'thresholds': thresholds, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
        if best_f1:
            print(f'\n=== BEST PER-CATEGORY (FPR <= 5%) ===')
            print(f'  Thresholds: {best_f1["thresholds"]}')
            print(f'  recall={best_f1["recall"]:.4f}  fpr={best_f1["fpr"]:.4f}  f1={best_f1["f1"]:.4f}  tp={best_f1["tp"]} fn={best_f1["fn"]} fp={best_f1["fp"]} tn={best_f1["tn"]}')

    # Also: try the "logical OR" approach with high recall focus
    # Lower the threshold for "toxicity" (the dominant signal) and use higher
    # thresholds for the other categories
    print('\n=== Step 3: OR-combination (high recall, low FPR) ===')
    # For each category, find the threshold that catches the most attacks
    # without too many FPs
    # This is a per-category threshold tuned for high recall

    # Find the threshold for each category that gives 90% recall on attacks
    # of that category
    for cat, idx in zip(cat_names, tox_idxs):
        # Of the 500 attack records, how many have this category's prob > 0.5?
        n_attack_high = sum(1 for r in records if r['label'] == 1 and r['probs'][idx] > 0.5)
        n_benign_high = sum(1 for r in records if r['label'] == 0 and r['probs'][idx] > 0.5)
        print(f'  {cat:25s} (idx {idx}): {n_attack_high}/500 attack, {n_benign_high}/200 benign have prob > 0.5')

if __name__ == '__main__':
    main()
