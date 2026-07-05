#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5c Option C: Validate the 16-cat model
============================================================================

Validates `unitary/unbiased-toxic-roberta` (16 categories, Apache-2.0)
against the Jigsaw-style held-out.

The 16 categories include:
- 6 toxicity categories: toxicity, severe_toxicity, obscene, threat,
  insult, identity_attack
- 1 sexual: sexual_explicit (covers our toxicity_sexual!)
- 1 mental health: psychiatric_or_mental_illness (may cover self_harm)
- 8 demographics: male, female, homosexual_gay_or_lesbian, christian,
  jewish, muslim, black, white (NOT in our schema; ignored)

The 16-cat model is the SAME RoBERTa-base architecture but with 16
output classes. It's a 2024 model (vs 2021 for toxic-bert). We test
whether the additional categories + better training improve performance.
"""
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
CORPUS = LENS / 'corpora' / 'v01beta-raw'
HELDOUT = CORPUS / 'v01beta-toxicity-heldout.jsonl'
PREDICTIONS = CORPUS / 'v01beta-toxicity-predictions-16cat.jsonl'

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

def main():
    # Load the model
    print('Loading model unitary/unbiased-toxic-roberta...')
    model_name = 'unitary/unbiased-toxic-roberta'
    tok = AutoTokenizer.from_pretrained(model_name, cache_dir='/tmp/lens-model-cache')
    model = AutoModelForSequenceClassification.from_pretrained(model_name, cache_dir='/tmp/lens-model-cache')
    model.eval()

    # Load held-out
    records = []
    for line in open(HELDOUT):
        try:
            records.append(json.loads(line))
        except: pass
    print(f'Loaded {len(records)} records from held-out')

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
        start = time.time()
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
                elapsed = time.time() - start
                eta = elapsed / (i + 1) * (len(records) - i - 1)
                print(f'  {i + 1}/{len(records)} done, ETA {eta:.0f}s')
        with open(PREDICTIONS, 'w') as f:
            for r in results:
                f.write(json.dumps(r) + '\n')
        print(f'Saved: {PREDICTIONS}')

    # Categories: 0-15 (see below)
    # The 6 toxicity + sexual_explicit + psychiatric are the ones we care about
    # Categories:
    # 0=toxicity, 1=severe_toxicity, 2=obscene, 3=identity_attack, 4=insult,
    # 5=threat, 6=sexual_explicit, 7=male, 8=female, 9=homosexual_gay_or_lesbian,
    # 10=christian, 11=jewish, 12=muslim, 13=black, 14=white, 15=psychiatric_or_mental_illness

    # Sweep single threshold
    print(f'\n=== SINGLE-THRESHOLD sweep (any of 16 cats >= threshold) ===')
    print(f'{"threshold":>10s}  {"recall":>8s}  {"fpr":>8s}  {"precision":>10s}  {"f1":>8s}  {"tp":>5s}  {"fn":>5s}  {"fp":>5s}  {"tn":>5s}')

    best_single = None
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
            if best_single is None or f1 > best_single['f1']:
                best_single = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # Sweep with only the 8 toxicity-relevant categories (0-6 + 15)
    # Demographic categories (7-14) are NOT in our schema; we ignore them
    print(f'\n=== TOXICITY-ONLY threshold sweep (8 cats: 0-6 + 15) ===')
    print(f'{"threshold":>10s}  {"recall":>8s}  {"fpr":>8s}  {"precision":>10s}  {"f1":>8s}  {"tp":>5s}  {"fn":>5s}  {"fp":>5s}  {"tn":>5s}')
    tox_idxs = [0, 1, 2, 3, 4, 5, 6, 15]  # toxicity, severe_toxicity, obscene, identity_attack, insult, threat, sexual_explicit, psychiatric

    best_tox = None
    for threshold_pct in range(1, 100):
        threshold = threshold_pct / 100.0
        tp = fn = fp = tn = 0
        for r in results:
            label = r['label']
            detected = any(r['probs'][i] >= threshold for i in tox_idxs)
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
            if best_tox is None or f1 > best_tox['f1']:
                best_tox = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # Per-category sweep on the 8 toxicity categories
    print(f'\n=== PER-CATEGORY threshold sweep (8 toxicity cats) ===')
    best_per_cat = None
    cat_names = ['toxicity', 'severe_toxicity', 'obscene', 'identity_attack', 'insult', 'threat', 'sexual_explicit', 'psychiatric']
    # Try a small grid: each category gets a threshold in [0.3, 0.4, 0.5, 0.6, 0.7]
    import itertools
    for thresh_vals in itertools.product([0.3, 0.4, 0.5, 0.6, 0.7], repeat=8):
        thresholds = dict(zip(cat_names, thresh_vals))
        tp = fn = fp = tn = 0
        for r in results:
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
        if recall >= 0.95 and fpr <= 0.01:
            if best_per_cat is None or f1 > best_per_cat['f1']:
                best_per_cat = {'thresholds': thresholds, 'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
    print(f'  Per-category sweep: {len(list(itertools.product([0.3, 0.4, 0.5, 0.6, 0.7], repeat=8)))} combinations tested')

    # Report
    print(f'\n=== BEST ===')
    if best_single:
        print(f'  Single threshold (any of 16 cats): {best_single["threshold"]}  recall={best_single["recall"]:.4f}  fpr={best_single["fpr"]:.4f}  f1={best_single["f1"]:.4f}')
    if best_tox:
        print(f'  Single threshold (toxicity 8 cats): {best_tox["threshold"]}  recall={best_tox["recall"]:.4f}  fpr={best_tox["fpr"]:.4f}  f1={best_tox["f1"]:.4f}')
    if best_per_cat:
        print(f'  Per-category thresholds: {best_per_cat["thresholds"]}')
        print(f'  recall={best_per_cat["recall"]:.4f}  fpr={best_per_cat["fpr"]:.4f}  f1={best_per_cat["f1"]:.4f}')

    if not (best_single or best_tox or best_per_cat):
        print('  NO threshold combination meets both gates (95% recall + 1% FPR)')
        # Find best F1
        best_f1 = None
        for threshold_pct in range(1, 100):
            threshold = threshold_pct / 100.0
            tp = fn = fp = tn = 0
            for r in results:
                label = r['label']
                detected = any(r['probs'][i] >= threshold for i in tox_idxs)
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
        print(f'  Best F1 (toxicity 8 cats): {best_f1}')

if __name__ == '__main__':
    main()
