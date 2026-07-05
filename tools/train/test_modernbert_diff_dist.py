#!/usr/bin/env python3
"""
Test the already-trained ModernBERT-large on the different-distribution held-out.

The model was trained on the v0.1 long-context corpus (CLEAN PI held-out v2).
This test asks: does the model generalize to attacks from a DIFFERENT source?
"""
import os
import json
import sys
import torch
from pathlib import Path

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
MODEL_PATH = LENS / 'models' / 'pi-v0.1.0-beta' / 'finetuned-large'
DIFF_DIST = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-PI-DIFFERENT-DIST.jsonl'
REPORT = LENS / 'docs' / 'PHASE-5i-MODERNBERT-LARGE-DIFF-DIST-RESULTS.md'

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def main():
    print(f'=== Phase 5i: ModernBERT-large on DIFFERENT-distribution held-out ===')
    print(f'Device: {DEVICE}')

    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    tok = AutoTokenizer.from_pretrained(str(MODEL_PATH))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_PATH)).to(DEVICE)
    model.eval()

    records = []
    with open(DIFF_DIST) as f:
        for line in f:
            try: records.append(json.loads(line))
            except: pass
    print(f'Loaded {len(records)} records')
    print(f'  Attack: {sum(1 for r in records if r.get("label")==1)}')
    print(f'  Benign: {sum(1 for r in records if r.get("label")==0)}')

    print(f'\nRunning inference...')
    results = []
    for i, r in enumerate(records):
        text = r.get('text', '')[:1500]
        label = r.get('label')
        rid = r.get('id')
        inputs = tok(text, return_tensors='pt', truncation=True, max_length=512)
        inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = model(**inputs)
        pred = torch.argmax(outputs.logits, dim=-1).item()
        results.append({'id': rid, 'label': label, 'pred': pred, 'source': r.get('source', '?')})
        if (i + 1) % 50 == 0:
            print(f'  {i+1}/{len(records)} done')

    # Metrics
    tp = sum(1 for r in results if r['label'] == 1 and r['pred'] == 1)
    fn = sum(1 for r in results if r['label'] == 1 and r['pred'] == 0)
    fp = sum(1 for r in results if r['label'] == 0 and r['pred'] == 1)
    tn = sum(1 for r in results if r['label'] == 0 and r['pred'] == 0)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)

    print(f'\n=== RESULTS (DIFFERENT distribution) ===')
    print(f'  TP={tp}  FN={fn}  FP={fp}  TN={tn}')
    print(f'  Recall:    {recall:.4f}  (target >= 0.99)')
    print(f'  FPR:       {fpr:.4f}  (target <= 0.01)')
    print(f'  Precision: {precision:.4f}')
    print(f'  F1:        {f1:.4f}')
    gate = recall >= 0.99 and fpr <= 0.01
    print(f'\n  Ship gate: {"PASS" if gate else "FAIL"}')

    # Per-source breakdown
    pred_map = {r['id']: r['pred'] for r in results}
    print(f'\n=== Per-source breakdown ===')
    sources = set(r.get('source', '?') for r in records)
    for src in sorted(sources):
        src_recs = [r for r in records if r.get('source') == src]
        s_tp = sum(1 for r in src_recs if r.get('label') == 1 and pred_map.get(r.get('id')) == 1)
        s_fn = sum(1 for r in src_recs if r.get('label') == 1 and pred_map.get(r.get('id')) == 0)
        s_fp = sum(1 for r in src_recs if r.get('label') == 0 and pred_map.get(r.get('id')) == 1)
        s_tn = sum(1 for r in src_recs if r.get('label') == 0 and pred_map.get(r.get('id')) == 0)
        s_recall = s_tp / max(1, s_tp + s_fn)
        s_fpr = s_fp / max(1, s_fp + s_tn)
        s_total = s_tp + s_fn + s_fp + s_tn
        print(f'  {src[:50]:50s}: n={s_total}  recall={s_recall:.3f}  fpr={s_fpr:.3f}  tp={s_tp} fn={s_fn} fp={s_fp} tn={s_tn}')

    # Save report
    with open(REPORT, 'w') as f:
        f.write(f'# Phase 5i: ModernBERT-large on different-distribution held-out\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Model**: ModernBERT-large fine-tuned on v0.1 long-context corpus\n\n')
        f.write(f'**Held-out**: v01beta-PI-DIFFERENT-DIST.jsonl ({len(records)} records from promptfoo, deepset, rubend18 + v0.1 benign)\n\n')
        f.write(f'**Purpose**: cross-distribution generalization test\n\n')
        f.write(f'## Results\n\n')
        f.write(f'| Metric | Value | Target |\n')
        f.write(f'|---|---|---|\n')
        f.write(f'| TP | {tp} | - |\n')
        f.write(f'| FN | {fn} | - |\n')
        f.write(f'| FP | {fp} | - |\n')
        f.write(f'| TN | {tn} | - |\n')
        f.write(f'| Recall | {recall:.4f} | >= 0.99 |\n')
        f.write(f'| FPR | {fpr:.4f} | <= 0.01 |\n')
        f.write(f'| Precision | {precision:.4f} | - |\n')
        f.write(f'| F1 | {f1:.4f} | - |\n')
        f.write(f'| **Ship gate** | **{"PASS" if gate else "FAIL"}** | **99% recall / 1% FPR** |\n\n')
        f.write(f'## Per-source breakdown\n\n')
        for src in sorted(sources):
            src_recs = [r for r in records if r.get('source') == src]
            s_tp = sum(1 for r in src_recs if r.get('label') == 1 and pred_map.get(r.get('id')) == 1)
            s_fn = sum(1 for r in src_recs if r.get('label') == 1 and pred_map.get(r.get('id')) == 0)
            s_fp = sum(1 for r in src_recs if r.get('label') == 0 and pred_map.get(r.get('id')) == 1)
            s_tn = sum(1 for r in src_recs if r.get('label') == 0 and pred_map.get(r.get('id')) == 0)
            s_recall = s_tp / max(1, s_tp + s_fn)
            s_fpr = s_fp / max(1, s_fp + s_tn)
            f.write(f'- **{src}**: n={s_tp+s_fn+s_fp+s_tn} recall={s_recall:.3f} fpr={s_fpr:.3f}\n')
        f.write(f'\n## Interpretation\n\n')
        if gate:
            f.write(f'**The model generalizes.** It hits 99%/1% on attack sources it has NEVER seen in training.\n\n')
        else:
            f.write(f'**The model does NOT fully generalize.** See metrics above.\n\n')

    print(f'\nReport: {REPORT}')


if __name__ == '__main__':
    main()
