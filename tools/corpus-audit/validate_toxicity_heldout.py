#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5c: Toxicity Validation
============================================================

Builds a toxicity held-out from the train pool (ToxiGen + BeaverTails +
PyRIT AIRT) and validates the toxicity detector against it.

Per the v0.1.0-beta model decision (Section 4.5 ship gate):
- Recall >= 95% on held-out toxicity subset
- FPR <= 1% on held-out toxicity subset

Source: train+val toxicity records (6,798 total: 4,784 attack + 1,540 benign).
Held-out: 500 attack + 200 benign = 700 records (10% of attack + 13% of benign).
Train: remaining 4,284 attack + 1,340 benign = 5,624 records.
Val: same as before (626 records, already includes toxicity).

The held-out is randomly sampled (seed 20260704) and saved separately
so it can be re-used for future validation runs.
"""
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

# Add the detector to the path
sys.path.insert(0, '/home/chaos/Desktop/AegisGate/aegisgate-lens/src/detectors/ml')
from toxicity import detect as toxicity_detect

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
CORPUS = LENS / 'corpora' / 'v01beta-raw'


def load_jsonl(path):
    records = []
    for line in open(path):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def save_jsonl(path, records):
    with open(path, 'w') as f:
        for r in records:
            f.write(json.dumps(r) + '\n')


def main():
    # Load train+val, extract toxicity records
    train = load_jsonl(CORPUS / 'v01beta-train.jsonl')
    val = load_jsonl(CORPUS / 'v01beta-val.jsonl')

    tox_train = [r for r in train if any(s in r.get('source', '').lower() for s in ['toxigen', 'beavertails', 'airt', 'pyrit'])]
    tox_val = [r for r in val if any(s in r.get('source', '').lower() for s in ['toxigen', 'beavertails', 'airt', 'pyrit'])]

    print(f'Toxicity train records: {len(tox_train)} (attack={sum(1 for r in tox_train if r.get("label")==1)}, benign={sum(1 for r in tox_train if r.get("label")==0)})')
    print(f'Toxicity val records:   {len(tox_val)} (attack={sum(1 for r in tox_val if r.get("label")==1)}, benign={sum(1 for r in tox_val if r.get("label")==0)})')

    # Build the held-out: 500 attack + 200 benign
    random.seed(20260704)
    attacks = [r for r in tox_train if r.get('label') == 1]
    benigns = [r for r in tox_train if r.get('label') == 0]

    random.shuffle(attacks)
    random.shuffle(benigns)

    heldout_attacks = attacks[:500]
    heldout_benigns = benigns[:200]
    heldout = heldout_attacks + heldout_benigns
    random.shuffle(heldout)

    # Remove heldout from train
    heldout_ids = {r.get('id') for r in heldout}
    train_remaining = [r for r in train if r.get('id') not in heldout_ids]

    print(f'\nBuilt toxicity held-out: {len(heldout)} records (500 attack + 200 benign)')
    print(f'Removed {len(heldout)} from train; remaining {len(train_remaining)}')

    # Save heldout
    heldout_path = CORPUS / 'v01beta-toxicity-heldout.jsonl'
    save_jsonl(heldout_path, heldout)
    print(f'Saved: {heldout_path}')

    # Save updated train (without the heldout)
    save_jsonl(CORPUS / 'v01beta-train.jsonl', train_remaining)
    print(f'Updated: {CORPUS / "v01beta-train.jsonl"} ({len(train_remaining)} records)')

    # Validate
    print(f'\n=== Running toxicity detector on held-out ({len(heldout)} records) ===')
    print('This may take 1-2 minutes for 700 records...')

    tp = fn = fp = tn = 0
    per_source_stats = {}
    errors = 0
    for i, rec in enumerate(heldout):
        text = rec.get('text', '')
        label = rec.get('label', rec.get('expected_label'))
        source = rec.get('source', '?')

        try:
            events = toxicity_detect(text)
            # An attack is detected if ANY event is returned
            # (multi-label: any of the 6 categories firing is "toxic")
            detected = len(events) > 0
        except Exception as e:
            errors += 1
            detected = False

        if source not in per_source_stats:
            per_source_stats[source] = {'tp': 0, 'fn': 0, 'fp': 0, 'tn': 0, 'errors': 0}
        if errors > 0 and detected is False and label == 1:
            per_source_stats[source]['errors'] += 1

        if label == 1 and detected:
            tp += 1
            per_source_stats[source]['tp'] += 1
        elif label == 1 and not detected:
            fn += 1
            per_source_stats[source]['fn'] += 1
        elif label == 0 and detected:
            fp += 1
            per_source_stats[source]['fp'] += 1
        else:
            tn += 1
            per_source_stats[source]['tn'] += 1

        if (i + 1) % 100 == 0:
            print(f'  {i + 1}/{len(heldout)} done')

    # Compute overall metrics
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    accuracy = (tp + tn) / max(1, tp + fn + fp + tn)

    print(f'\n=== RESULTS (held-out: {len(heldout)} records) ===')
    print(f'  TP (attack caught):       {tp}')
    print(f'  FN (attack missed):      {fn}')
    print(f'  FP (false positive):     {fp}')
    print(f'  TN (correctly rejected): {tn}')
    print(f'  Errors:                  {errors}')
    print()
    print(f'  Recall:    {recall:.4f} (target >= 0.95)')
    print(f'  FPR:       {fpr:.4f} (target <= 0.01)')
    print(f'  Precision: {precision:.4f}')
    print(f'  F1:        {f1:.4f}')
    print(f'  Accuracy:  {accuracy:.4f}')

    # Per-source breakdown
    print(f'\n=== Per-source breakdown ===')
    for src, stats in sorted(per_source_stats.items()):
        total = sum(stats.values()) - stats.get('errors', 0)
        if total == 0:
            continue
        s_tp, s_fn = stats['tp'], stats['fn']
        s_fp, s_tn = stats['fp'], stats['tn']
        s_recall = s_tp / max(1, s_tp + s_fn)
        s_fpr = s_fp / max(1, s_fp + s_tn)
        print(f'  {src:35s}: tp={s_tp:3d} fn={s_fn:3d} fp={s_fp:3d} tn={s_tn:3d}  recall={s_recall:.3f}  fpr={s_fpr:.3f}')

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
