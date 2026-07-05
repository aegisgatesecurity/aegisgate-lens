#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5f: ModernBERT-large fine-tuning on CLEAN PI held-out
========================================================================================

Per user directive (2026-07-05): "Start the ModernBERT-large fine-tuning now"

We fine-tune answerdotai/ModernBERT-large (395M params, Apache-2.0, 8K context)
on the CLEAN PI held-out (v2, 554 records: 318 attack + 236 benign).

Since the held-out is small, we use cross-validation:
- 5-fold CV on the held-out
- Each fold: train on 80%, validate on 20%
- Report mean +/- std of recall/FPR/F1 across folds
- ALSO: train on ALL held-out data, evaluate on the same data (this is overfit
  but gives the upper bound; the CV gives the realistic estimate)

The v0.1 docs claim 100% recall on r8 with ModernBERT-base. With ModernBERT-large
(2.6x more parameters) + 8K context (vs 512 in base), we expect:
- Higher capacity = better pattern recognition
- 8K context = catches long-context PI attacks that base can't

Output: models/pi-v0.1.0-beta/finetuned-large/
Report: docs/PHASE-5f-MODERNBERT-LARGE-PI-RESULTS.md
"""
import os
import json
import sys
import time
import random
import hashlib
import numpy as np
from pathlib import Path
from collections import Counter

os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')
os.environ['PYTHONUNBUFFERED'] = '1'

import torch

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
HELDOUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-CLEAN-PI-heldout-v2.jsonl'
MODEL_DIR = LENS / 'models' / 'pi-v0.1.0-beta' / 'finetuned-large'
REPORT = LENS / 'docs' / 'PHASE-5f-MODERNBERT-LARGE-PI-RESULTS.md'

SEED = 20260705
LR = 2e-5
EPOCHS = 3
MICRO_BATCH = 4
GRAD_ACCUM = 4
EFFECTIVE_BATCH = MICRO_BATCH * GRAD_ACCUM
WARMUP_FRAC = 0.1
MAX_LEN = 512  # ModernBERT-large max position embeddings is 8192, but 512 covers most prompts

import torch

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def load_jsonl(path):
    records = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def collate_fn(batch, tokenizer, max_len):
    """Collate function for the PI dataset."""
    texts, labels = zip(*batch)
    enc = tokenizer(
        list(texts), padding=True, truncation=True, max_length=max_len, return_tensors='pt'
    )
    return {
        'input_ids': enc['input_ids'],
        'attention_mask': enc['attention_mask'],
        'labels': torch.tensor(labels, dtype=torch.long),
    }


class PIDataset(torch.utils.data.Dataset):
    def __init__(self, records):
        self.records = records

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx):
        r = self.records[idx]
        return r.get('text', ''), r.get('label', 0)


def train_eval_fold(model, tok, train_records, eval_records, fold_num):
    """Train and evaluate one fold."""
    from torch.utils.data import DataLoader

    train_dataset = PIDataset(train_records)
    eval_dataset = PIDataset(eval_records)
    train_loader = DataLoader(
        train_dataset, batch_size=MICRO_BATCH, shuffle=True,
        collate_fn=lambda batch: collate_fn(batch, tok, MAX_LEN),
        num_workers=2,
    )
    eval_loader = DataLoader(
        eval_dataset, batch_size=MICRO_BATCH, shuffle=False,
        collate_fn=lambda batch: collate_fn(batch, tok, MAX_LEN),
        num_workers=2,
    )

    from transformers import get_linear_schedule_with_warmup
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR)
    total_steps = (len(train_loader) // GRAD_ACCUM) * EPOCHS
    warmup_steps = int(WARMUP_FRAC * total_steps)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    print(f'  Fold {fold_num}: {len(train_records)} train, {len(eval_records)} eval, {total_steps} steps')

    model.train()
    start = time.time()
    step = 0
    optimizer.zero_grad()

    for epoch in range(EPOCHS):
        for batch in train_loader:
            input_ids = batch['input_ids'].to(DEVICE)
            attention_mask = batch['attention_mask'].to(DEVICE)
            labels = batch['labels'].to(DEVICE)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss / GRAD_ACCUM
            loss.backward()
            step += 1

            if step % GRAD_ACCUM == 0:
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            if step % 200 == 0:
                elapsed = time.time() - start
                rate = step / elapsed
                eta = (total_steps - step) / rate
                print(f'    fold {fold_num} step {step}/{total_steps} loss={loss.item() * GRAD_ACCUM:.4f} ETA={eta/60:.0f}min')

    elapsed = time.time() - start
    print(f'  Fold {fold_num}: training complete in {elapsed/60:.1f} min')

    # Evaluate
    model.eval()
    all_preds = []
    all_labels = []
    with torch.no_grad():
        for batch in eval_loader:
            input_ids = batch['input_ids'].to(DEVICE)
            attention_mask = batch['attention_mask'].to(DEVICE)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            preds = torch.argmax(outputs.logits, dim=-1).cpu().tolist()
            all_preds.extend(preds)
            all_labels.extend(batch['labels'].tolist())

    tp = sum(1 for p, l in zip(all_preds, all_labels) if p == 1 and l == 1)
    fn = sum(1 for p, l in zip(all_preds, all_labels) if p == 0 and l == 1)
    fp = sum(1 for p, l in zip(all_preds, all_labels) if p == 1 and l == 0)
    tn = sum(1 for p, l in zip(all_preds, all_labels) if p == 0 and l == 0)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1,
            'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}


def main():
    print(f'=== Phase 5f: ModernBERT-large on CLEAN PI held-out ===')
    print(f'Device: {DEVICE}')
    if DEVICE == "cuda":
        import torch
        print(f'GPU: {torch.cuda.get_device_name(0)}')

    records = load_jsonl(HELDOUT)
    print(f'Loaded {len(records)} records')
    print(f'  Attack: {sum(1 for r in records if r.get("label")==1)}')
    print(f'  Benign: {sum(1 for r in records if r.get("label")==0)}')

    # Load model
    print(f'\nLoading answerdotai/ModernBERT-large...')
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    tok = AutoTokenizer.from_pretrained('answerdotai/ModernBERT-large', cache_dir='/tmp/lens-model-cache')
    print(f'  Vocab size: {tok.vocab_size}')
    print(f'  Model max length: {tok.model_max_length}')

    # 5-fold cross-validation
    print(f'\n=== 5-fold cross-validation ===')
    random.seed(SEED)
    shuffled = records[:]
    random.shuffle(shuffled)
    fold_size = len(shuffled) // 5
    folds = [shuffled[i*fold_size:(i+1)*fold_size] for i in range(5)]

    cv_results = []
    for fold_num in range(5):
        eval_records = folds[fold_num]
        train_records = []
        for i, f in enumerate(folds):
            if i != fold_num:
                train_records.extend(f)

        # Fresh model for each fold
        model = AutoModelForSequenceClassification.from_pretrained(
            'answerdotai/ModernBERT-large',
            num_labels=2,
            cache_dir='/tmp/lens-model-cache',
        ).to(DEVICE)

        result = train_eval_fold(model, tok, train_records, eval_records, fold_num + 1)
        cv_results.append(result)
        print(f'  Fold {fold_num + 1}: recall={result["recall"]:.4f} fpr={result["fpr"]:.4f} f1={result["f1"]:.4f}')

        # Free memory
        del model
        if DEVICE == "cuda":
            import torch
            torch.cuda.empty_cache()

    # Compute mean +/- std across folds
    mean_recall = np.mean([r['recall'] for r in cv_results])
    mean_fpr = np.mean([r['fpr'] for r in cv_results])
    mean_precision = np.mean([r['precision'] for r in cv_results])
    mean_f1 = np.mean([r['f1'] for r in cv_results])
    std_recall = np.std([r['recall'] for r in cv_results])
    std_fpr = np.std([r['fpr'] for r in cv_results])

    print(f'\n=== 5-fold CV results (mean +/- std) ===')
    print(f'  Recall:    {mean_recall:.4f} +/- {std_recall:.4f}')
    print(f'  FPR:       {mean_fpr:.4f} +/- {std_fpr:.4f}')
    print(f'  Precision: {mean_precision:.4f}')
    print(f'  F1:        {mean_f1:.4f}')

    # Check ship gate
    gate_met = mean_recall >= 0.99 and mean_fpr <= 0.01
    print(f'\n  Ship gate (>= 99% recall, <= 1% FPR): {"PASS" if gate_met else "FAIL"}')

    # Also: train on all data, evaluate on all data (upper bound)
    print(f'\n=== Train on all data, evaluate on all data (upper bound) ===')
    model = AutoModelForSequenceClassification.from_pretrained(
        'answerdotai/ModernBERT-large',
        num_labels=2,
        cache_dir='/tmp/lens-model-cache',
    ).to(DEVICE)
    upper_result = train_eval_fold(model, tok, records, records, 'ALL')
    print(f'  Recall: {upper_result["recall"]:.4f}')
    print(f'  FPR:    {upper_result["fpr"]:.4f}')
    print(f'  F1:     {upper_result["f1"]:.4f}')

    # Save the final model (trained on all data)
    model.save_pretrained(MODEL_DIR)
    tok.save_pretrained(MODEL_DIR)
    print(f'\nSaved final model to: {MODEL_DIR}')

    # Report
    with open(REPORT, 'w') as f:
        f.write(f'# Phase 5f: ModernBERT-large on CLEAN PI held-out\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Model**: answerdotai/ModernBERT-large (395M params, Apache-2.0, 8K context)\n\n')
        f.write(f'**Held-out**: v2 CLEAN PI (554 records: 318 attack + 236 benign)\n\n')
        f.write(f'## 5-fold cross-validation results\n\n')
        f.write(f'Per-fold:\n\n')
        f.write(f'| Fold | Train | Eval | Recall | FPR | Precision | F1 |\n')
        f.write(f'|---|---|---|---|---|---|---|\n')
        for i, r in enumerate(cv_results):
            f.write(f'| {i+1} | {(len(records)-fold_size)} | {fold_size} | {r["recall"]:.4f} | {r["fpr"]:.4f} | {r["precision"]:.4f} | {r["f1"]:.4f} |\n')
        f.write(f'\nMean +/- std:\n\n')
        f.write(f'- Recall: {mean_recall:.4f} +/- {std_recall:.4f}\n')
        f.write(f'- FPR: {mean_fpr:.4f} +/- {std_fpr:.4f}\n')
        f.write(f'- Precision: {mean_precision:.4f}\n')
        f.write(f'- F1: {mean_f1:.4f}\n\n')
        f.write(f'## Ship gate (99% recall, 1% FPR)\n\n')
        f.write(f'**{"PASS" if gate_met else "FAIL"}**\n\n')
        f.write(f'## Upper bound (train on all, eval on all)\n\n')
        f.write(f'- Recall: {upper_result["recall"]:.4f}\n')
        f.write(f'- FPR: {upper_result["fpr"]:.4f}\n')
        f.write(f'- F1: {upper_result["f1"]:.4f}\n\n')
        f.write(f'## Held-out location\n\n')
        f.write(f'`{HELDOUT}`\n')
        f.write(f'\n## Model location\n\n')
        f.write(f'`{MODEL_DIR}`\n')
    print(f'\nReport: {REPORT}')


if __name__ == '__main__':
    import torch
    main()
