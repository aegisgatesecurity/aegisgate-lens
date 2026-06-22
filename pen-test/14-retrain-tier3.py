#!/usr/bin/env python3
"""
AegisGate Lens - Day 14: Tier 3 Continuation Training

Fine-tunes the existing Tier 3 model on the augmented training
corpus that includes 500 creative-writing-frame attacks.

Approach: CONTINUE training from ml-artifacts/models/minilm_l12_tier3/
(not from scratch). This preserves the existing 99%+ recall on direct
attacks while teaching the model to recognize creative-writing frames
as injection.

After training, re-export to ONNX and re-run pen-test/13-pair-adversarial.py
to measure the new bypass rate.

Inputs:
  - ml-artifacts/models/minilm_l12_tier3/ (existing Tier 3 checkpoint)
  - ml-artifacts/training_data_tier3/train.jsonl (now includes 500 cw-frame)
  - ml-artifacts/training_data_tier3/val.jsonl (original; unchanged)

Outputs:
  - ml-artifacts/models/minilm_l12_tier3_v2/ (new checkpoint)
  - ml-artifacts/dist_tier3_v2/model.onnx (regenerated)
  - ml-artifacts/dist_tier3_v2/metrics_v2.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Suppress HF noise.
os.environ.setdefault('TRANSFORMERS_NO_ADVISORY_WARNINGS', '1')
os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')
os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')


def main():
    parser = argparse.ArgumentParser(description='Day 14 retrain (continuation)')
    parser.add_argument('--base-model',
                        default='ml-artifacts/models/minilm_l12_tier3/',
                        help='Existing Tier 3 checkpoint to continue from')
    parser.add_argument('--train',
                        default='ml-artifacts/training_data_tier3/train.jsonl')
    parser.add_argument('--val',
                        default='ml-artifacts/training_data_tier3/val.jsonl')
    parser.add_argument('--output',
                        default='ml-artifacts/models/minilm_l12_tier3_v2/')
    parser.add_argument('--epochs', type=int, default=1,
                        help='Continuation epochs (1 is enough since data is '
                             'augmented, not the model)')
    parser.add_argument('--batch-size', type=int, default=32)
    parser.add_argument('--lr', type=float, default=2e-5)
    parser.add_argument('--max-length', type=int, default=128)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    print('=' * 70)
    print('AegisGate Lens - Day 14: Tier 3 Continuation Training')
    print('=' * 70)
    print(f'Base model:        {args.base_model}')
    print(f'Train data:        {args.train}')
    print(f'Val data:          {args.val}')
    print(f'Output:            {args.output}')
    print(f'Epochs:            {args.epochs}')
    print(f'Batch size:        {args.batch_size}')
    print(f'Learning rate:     {args.lr}')
    print()

    import torch
    import numpy as np
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        TrainingArguments, Trainer, DataCollatorWithPadding,
    )
    from torch.utils.data import Dataset
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support

    if torch.cuda.is_available():
        print(f'GPU: {torch.cuda.get_device_name(0)}')
        print(f'VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB')
    else:
        print('GPU: not available, using CPU')
    print()

    # Load tokenizer + model from existing checkpoint.
    print(f'Loading base model from {args.base_model}...')
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)

    # Load data.
    print('Loading training data...')
    train_records = []
    with open(args.train) as f:
        for line in f:
            line = line.strip()
            if line:
                train_records.append(json.loads(line))
    val_records = []
    with open(args.val) as f:
        for line in f:
            line = line.strip()
            if line:
                val_records.append(json.loads(line))

    # Filter to label 0/1.
    train_records = [r for r in train_records if r.get('label') in (0, 1)]
    val_records = [r for r in val_records if r.get('label') in (0, 1)]

    # Show corpus stats.
    train_attack = sum(1 for r in train_records if r['label'] == 1)
    train_benign = sum(1 for r in train_records if r['label'] == 0)
    cw_count = sum(1 for r in train_records if r.get('source') == 'creative_writing_frame/train')
    print(f'  Train: {len(train_records)} ({train_attack} attack, {train_benign} benign, {cw_count} creative-writing)')
    print(f'  Val:   {len(val_records)}')

    # Build HF Dataset.
    class TextDataset(Dataset):
        def __init__(self, records, tokenizer, max_length):
            self.records = records
            self.tokenizer = tokenizer
            self.max_length = max_length
        def __len__(self):
            return len(self.records)
        def __getitem__(self, idx):
            r = self.records[idx]
            enc = self.tokenizer(
                r['text'],
                padding='max_length',
                truncation=True,
                max_length=self.max_length,
                return_tensors='pt',
            )
            return {
                'input_ids': enc['input_ids'].squeeze(0),
                'attention_mask': enc['attention_mask'].squeeze(0),
                'token_type_ids': enc.get('token_type_ids', enc['attention_mask']).squeeze(0)
                  if 'token_type_ids' in enc else torch.zeros_like(enc['attention_mask'].squeeze(0)),
                'labels': torch.tensor(int(r['label']), dtype=torch.long),
            }

    train_ds = TextDataset(train_records, tokenizer, args.max_length)
    val_ds = TextDataset(val_records, tokenizer, args.max_length)

    # Metrics.
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        acc = accuracy_score(labels, preds)
        prec, rec, f1, _ = precision_recall_fscore_support(
            labels, preds, average='binary', zero_division=0)
        return {
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1': f1,
        }

    # Training arguments.
    training_args = TrainingArguments(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        warmup_steps=200,
        weight_decay=0.01,
        logging_dir=os.path.join(args.output, 'logs'),
        logging_steps=100,
        eval_strategy='epoch',
        save_strategy='epoch',
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model='f1',
        greater_is_better=True,
        seed=args.seed,
        fp16=torch.cuda.is_available(),
        report_to='none',
        dataloader_num_workers=2,
    )

    trainer_kwargs = dict(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )
    # transformers 5.x renamed `tokenizer` kwarg to `processing_class`.
    try:
        trainer = Trainer(processing_class=tokenizer, **trainer_kwargs)
    except TypeError:
        trainer = Trainer(tokenizer=tokenizer, **trainer_kwargs)

    print()
    print('Starting training...')
    trainer.train()

    print()
    print('Evaluating on validation set...')
    metrics = trainer.evaluate()
    print(f'  Validation metrics: {metrics}')

    # Save model + tokenizer.
    print(f'Saving model to {args.output}...')
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)

    # Save metrics.
    metrics_path = os.path.join(args.output, 'metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f'Saved metrics to {metrics_path}')

    # Save a manifest with corpus stats + provenance.
    manifest = {
        'base_model': args.base_model,
        'train_size': len(train_records),
        'val_size': len(val_records),
        'creative_writing_frame_count': cw_count,
        'epochs': args.epochs,
        'batch_size': args.batch_size,
        'learning_rate': args.lr,
        'final_metrics': metrics,
        'description': 'Day 14 retrain: augmented with 500 creative-writing-frame attacks to close F-10.',
    }
    manifest_path = os.path.join(args.output, 'training_manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f'Saved manifest to {manifest_path}')

    print()
    print('=' * 70)
    print('Day 14 retrain complete. Next steps:')
    print(f'  1. Re-export to ONNX: python3 ml-artifacts/scripts/export_minilm_onnx_v2.py')
    print(f'  2. Re-run PAIR test:   python3 pen-test/13-pair-adversarial.py')
    print('=' * 70)


if __name__ == '__main__':
    main()
