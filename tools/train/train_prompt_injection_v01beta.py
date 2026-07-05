#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta — Prompt Injection Training
====================================================

Trains ModernBERT-base on the v0.1.0-beta clean corpus. The training
data is in corpora/v01beta-raw/v01beta-train.jsonl (10,000 records,
50/50 attack/benign). The val set is v01beta-val.jsonl (1,000 records).
The held-out is v01beta-heldout.jsonl (3,630 records, hand-curated).

Per the v0.1.0-beta model decision (plans/AEGISGATE-LENS-V01BETA-MODEL-DECISION.md):
- Base: answerdotai/ModernBERT-base (Apache-2.0, 149M params, 8K context)
- License: Apache-2.0
- ONNX export: optimum, opset 17, q4f16 (in Phase 0c)
- Sliding window: chunk=2048, stride=1024, max_windows=4
- Threshold: 0.05
- Aggregation: max-pool P(attack) across windows
- Training recipe: lr=2e-5, epochs=3, micro_batch=4, grad_accum=4, fp16/bf16
- Optimizer: AdamW, warmup=10%, seed=20260704

STRICT SHIP GATE (per user direction 2026-07-04 19:09):
- Recall >= 99% on held-out (2,436 attacks)
- FPR <= 1% on held-out (1,194 benigns)
- F1 >= 99% on held-out

If the held-out gate is not met, we do NOT ship. We retrain, augment
the data, and try again. We do NOT lower the gate.

Usage:
    python3 tools/train/train_prompt_injection_v01beta.py train   # full training
    python3 tools/train/train_prompt_injection_v01beta.py eval    # eval on held-out
    python3 tools/train/train_prompt_injection_v01beta.py smoke  # 100-record smoke test

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import argparse
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    get_linear_schedule_with_warmup,
)

# ============================================================
# Configuration (per the v0.1.0-beta model decision)
# ============================================================

BASE_MODEL = "answerdotai/ModernBERT-base"
SEED = 20260704
LR = 2e-5
EPOCHS = 3
MICRO_BATCH = 4
GRAD_ACCUM = 4
EFFECTIVE_BATCH = MICRO_BATCH * GRAD_ACCUM
WARMUP_FRAC = 0.1
MAX_LEN = 2048  # sliding window chunk (per the v0.2 transformer-engine.js)
STRIDE = 1024  # 50% overlap
MAX_WINDOWS = 4  # cap on windows per doc
THRESHOLD = 0.05  # P(attack) >= 0.05 = attack (per the v0.2 threshold)
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpora/v01beta-raw"
TRAIN_FILE = CORPUS_DIR / "v01beta-train.jsonl"
VAL_FILE = CORPUS_DIR / "v01beta-val.jsonl"
HELDOUT_FILE = CORPUS_DIR / "v01beta-heldout.jsonl"

# Output dir for model checkpoints
OUTPUT_DIR = Path("/home/chaos/Desktop/AegisGate/aegisgate-lens/models/prompt-injection-v0.1.0-beta")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# Reproducibility
# ============================================================

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ============================================================
# Data loading
# ============================================================

def load_jsonl(path):
    """Load a JSONL file. Each line is a record with `text` and `label`."""
    records = []
    for line in open(path):
        try:
            rec = json.loads(line)
            if "text" in rec and "label" in rec:
                records.append(rec)
        except json.JSONDecodeError:
            pass
    return records


def sliding_window_tokenize(tokenizer, text, max_len=MAX_LEN, stride=STRIDE, max_windows=MAX_WINDOWS):
    """Tokenize text with sliding window. Returns up to max_windows input chunks."""
    enc = tokenizer(text, return_tensors=None, add_special_tokens=False, truncation=False)
    input_ids = enc["input_ids"]
    if len(input_ids) <= max_len - 2:
        ids = [tokenizer.cls_token_id] + input_ids + [tokenizer.sep_token_id]
        mask = [1] * len(ids)
        return [(ids, mask)]
    cls_id = tokenizer.cls_token_id
    sep_id = tokenizer.sep_token_id
    windows = []
    start = 0
    while len(windows) < max_windows and start < len(input_ids):
        end = min(start + max_len - 2, len(input_ids))
        chunk = input_ids[start:end]
        ids = [cls_id] + chunk + [sep_id]
        mask = [1] * len(ids)
        windows.append((ids, mask))
        if end >= len(input_ids):
            break
        start += stride
    return windows


class InjectionDataset(Dataset):
    """Dataset for prompt-injection detection."""
    def __init__(self, records, tokenizer, mode="train"):
        self.records = records
        self.tokenizer = tokenizer
        self.mode = mode

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx):
        rec = self.records[idx]
        text = rec["text"]
        label = rec.get("label", rec.get("expected_label", 0))
        windows = sliding_window_tokenize(self.tokenizer, text)
        if self.mode == "train":
            window = random.choice(windows)
        else:
            window = windows[0] if len(windows) == 1 else windows
        return {
            "input_ids": window[0],
            "attention_mask": window[1],
            "label": torch.tensor(label, dtype=torch.long),
            "all_windows": windows,
        }


def collate_train(batch):
    """Collate for training: pad to max length in batch."""
    max_len = max(len(item["input_ids"]) for item in batch)
    pad_id = 0
    input_ids = torch.zeros((len(batch), max_len), dtype=torch.long)
    attention_mask = torch.zeros((len(batch), max_len), dtype=torch.long)
    labels = torch.zeros(len(batch), dtype=torch.long)
    for i, item in enumerate(batch):
        n = len(item["input_ids"])
        input_ids[i, :n] = torch.tensor(item["input_ids"], dtype=torch.long)
        attention_mask[i, :n] = torch.tensor(item["attention_mask"], dtype=torch.long)
        labels[i] = item["label"]
    return {"input_ids": input_ids, "attention_mask": attention_mask, "labels": labels}


def collate_eval(batch):
    """Collate for eval: variable-length windows per record."""
    flat_ids = []
    flat_mask = []
    window_counts = []
    record_idx = []
    labels = []
    for i, item in enumerate(batch):
        windows = item["all_windows"] if isinstance(item["all_windows"][0], tuple) else item["all_windows"]
        window_counts.append(len(windows))
        for ids, mask in windows:
            flat_ids.append(ids)
            flat_mask.append(mask)
            record_idx.append(i)
        labels.append(item["label"].item() if isinstance(item["label"], torch.Tensor) else item["label"])
    max_len = max(len(ids) for ids in flat_ids)
    input_ids = torch.zeros((len(flat_ids), max_len), dtype=torch.long)
    attention_mask = torch.zeros((len(flat_ids), max_len), dtype=torch.long)
    for i, (ids, mask) in enumerate(zip(flat_ids, flat_mask)):
        n = len(ids)
        input_ids[i, :n] = torch.tensor(ids, dtype=torch.long)
        attention_mask[i, :n] = torch.tensor(mask, dtype=torch.long)
    return {
        "input_ids": input_ids,
        "attention_mask": attention_mask,
        "record_idx": torch.tensor(record_idx, dtype=torch.long),
        "window_counts": window_counts,
        "labels": torch.tensor(labels, dtype=torch.long),
        "batch_size": len(batch),
    }


# ============================================================
# Training
# ============================================================

def train():
    set_seed(SEED)
    print("=== AegisGate Lens v0.1.0-beta -- Prompt Injection Training ===")
    print("Device:", DEVICE)
    print("Base model:", BASE_MODEL)
    print("Output:", OUTPUT_DIR)
    print("Train:", TRAIN_FILE)
    print("Val:", VAL_FILE)

    print("\nLoading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    print("Loading model...")
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)
    model.to(DEVICE)
    # Use bf16 instead of fp16 for stability on RTX 3060 (Ampere+).
    # bf16 has the same dynamic range as fp32 but half the precision,
    # so it doesn't need loss scaling and doesn't produce NaN losses
    # in the first step. RTX 3060 (Ampere) supports bf16 natively.
    if DEVICE == "cuda":
        model = model.to(torch.bfloat16)

    print("Loading data...")
    train_records = load_jsonl(TRAIN_FILE)
    val_records = load_jsonl(VAL_FILE)
    print("  Train:", len(train_records), "records")
    print("  Val:  ", len(val_records), "records")

    train_ds = InjectionDataset(train_records, tokenizer, mode="train")
    val_ds = InjectionDataset(val_records, tokenizer, mode="eval")

    train_loader = DataLoader(train_ds, batch_size=MICRO_BATCH, shuffle=True,
                              collate_fn=collate_train, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=MICRO_BATCH, shuffle=False,
                            collate_fn=collate_eval, num_workers=0)

    optimizer = AdamW(model.parameters(), lr=LR)
    total_steps = (len(train_loader) // GRAD_ACCUM) * EPOCHS
    warmup_steps = int(WARMUP_FRAC * total_steps)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    print("\nTraining for", EPOCHS, "epochs (total steps:", total_steps, ")...")
    best_val_recall = 0
    best_epoch = 0
    for epoch in range(EPOCHS):
        model.train()
        epoch_loss = 0
        step = 0
        optimizer.zero_grad()
        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            labels = batch["labels"].to(DEVICE)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss / GRAD_ACCUM
            loss.backward()
            epoch_loss += loss.item() * GRAD_ACCUM
            step += 1
            if step % GRAD_ACCUM == 0:
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()
            if step % 100 == 0:
                print("  Epoch", epoch+1, "Step", step, "/", len(train_loader), "Loss:", round(loss.item() * GRAD_ACCUM, 4))
        print("\n  Epoch", epoch+1, "complete. Avg loss:", round(epoch_loss / step, 4))
        val_recall, val_fpr, val_f1 = evaluate(model, tokenizer, val_loader, prefix="  Val")
        if val_recall > best_val_recall:
            best_val_recall = val_recall
            best_epoch = epoch + 1
            print("  New best val recall:", round(val_recall, 4), ". Saving model...")
            model.save_pretrained(OUTPUT_DIR / f"checkpoint-epoch{epoch+1}")
            tokenizer.save_pretrained(OUTPUT_DIR / f"checkpoint-epoch{epoch+1}")

    print("\n=== Training complete. Best epoch:", best_epoch, "(val recall", round(best_val_recall, 4), ") ===")
    print("Best model saved to:", OUTPUT_DIR, "/checkpoint-epoch", best_epoch)
    return best_epoch


def evaluate(model, tokenizer, val_loader, prefix="Eval"):
    """Evaluate on a loader. Returns (recall, fpr, f1) for the attack class."""
    model.eval()
    all_labels = []
    all_preds = []
    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            labels = batch["labels"]
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)[:, 1]
            record_idx = batch["record_idx"]
            window_counts = batch["window_counts"]
            batch_size = batch["batch_size"]
            record_probs = torch.zeros(batch_size)
            for i in range(probs.size(0)):
                ri = record_idx[i].item()
                if probs[i].item() > record_probs[ri]:
                    record_probs[ri] = probs[i].item()
            preds = (record_probs > THRESHOLD).long().cpu()
            for i in range(batch_size):
                all_labels.append(labels[i].item())
                all_preds.append(preds[i].item())
    tp = sum(1 for l, p in zip(all_labels, all_preds) if l == 1 and p == 1)
    fn = sum(1 for l, p in zip(all_labels, all_preds) if l == 1 and p == 0)
    fp = sum(1 for l, p in zip(all_labels, all_preds) if l == 0 and p == 1)
    tn = sum(1 for l, p in zip(all_labels, all_preds) if l == 0 and p == 0)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    print(prefix, "TP=", tp, "FN=", fn, "FP=", fp, "TN=", tn, "| Recall=", round(recall, 4), "FPR=", round(fpr, 4), "Precision=", round(precision, 4), "F1=", round(f1, 4))
    return recall, fpr, f1


def evaluate_heldout():
    """Evaluate the best checkpoint on the held-out test set."""
    set_seed(SEED)
    print("=== Held-out Evaluation (strict ship gate) ===")
    print("Targets: Recall >= 99%, FPR <= 1%, F1 >= 99%")
    print()
    if not (OUTPUT_DIR / "checkpoint-epoch1").exists():
        print("ERROR: no checkpoint found at", OUTPUT_DIR, "/checkpoint-epoch1")
        sys.exit(1)
    best = max([d for d in OUTPUT_DIR.iterdir() if d.is_dir() and d.name.startswith("checkpoint-epoch")],
               key=lambda d: int(d.name.split("epoch")[1]))
    print("Loading best checkpoint:", best.name)
    tokenizer = AutoTokenizer.from_pretrained(best)
    model = AutoModelForSequenceClassification.from_pretrained(best)
    model.to(DEVICE)
    if DEVICE == "cuda":
        model = model.to(torch.bfloat16)

    heldout_records = load_jsonl(HELDOUT_FILE)
    print("Held-out:", len(heldout_records), "records")
    n_attack = sum(1 for r in heldout_records if r.get("label", r.get("expected_label")) == 1)
    n_benign = sum(1 for r in heldout_records if r.get("label", r.get("expected_label")) == 0)
    print("  Attack:", n_attack, ", Benign:", n_benign)

    heldout_ds = InjectionDataset(heldout_records, tokenizer, mode="eval")
    heldout_loader = DataLoader(heldout_ds, batch_size=MICRO_BATCH, shuffle=False,
                                collate_fn=collate_eval, num_workers=0)
    recall, fpr, f1 = evaluate(model, tokenizer, heldout_loader, prefix="Held-out")
    print()
    print("=" * 60)
    if recall >= 0.99 and fpr <= 0.01 and f1 >= 0.99:
        print("  SHIP GATE PASSED. Recall=", round(recall, 4), "FPR=", round(fpr, 4), "F1=", round(f1, 4))
        return True
    else:
        print("  SHIP GATE FAILED.")
        if recall < 0.99:
            print("    Recall", round(recall, 4), "< 0.99 (", n_attack - int(recall * n_attack), "attacks missed)")
        if fpr > 0.01:
            print("    FPR", round(fpr, 4), "> 0.01 (", int(fpr * n_benign), "false positives)")
        if f1 < 0.99:
            print("    F1", round(f1, 4), "< 0.99")
        return False


def smoke_test():
    """Smoke test: train on 100 records, 1 epoch, verify the pipeline works."""
    set_seed(SEED)
    print("=== SMOKE TEST (100 records, 1 epoch) ===")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)
    model.to(DEVICE)
    if DEVICE == "cuda":
        model = model.to(torch.bfloat16)

    train_records = load_jsonl(TRAIN_FILE)[:100]
    val_records = load_jsonl(VAL_FILE)[:50]
    train_ds = InjectionDataset(train_records, tokenizer, mode="train")
    val_ds = InjectionDataset(val_records, tokenizer, mode="eval")
    train_loader = DataLoader(train_ds, batch_size=MICRO_BATCH, shuffle=True,
                              collate_fn=collate_train, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=MICRO_BATCH, shuffle=False,
                            collate_fn=collate_eval, num_workers=0)

    optimizer = AdamW(model.parameters(), lr=LR)
    total_steps = (len(train_loader) // GRAD_ACCUM) * 1
    scheduler = get_linear_schedule_with_warmup(optimizer, int(WARMUP_FRAC * total_steps), total_steps)

    model.train()
    optimizer.zero_grad()
    step = 0
    for batch in train_loader:
        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        labels = batch["labels"].to(DEVICE)
        outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
        loss = outputs.loss / GRAD_ACCUM
        loss.backward()
        step += 1
        if step % GRAD_ACCUM == 0:
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()
        if step % 5 == 0:
            print("  Step", step, "/", len(train_loader), "Loss:", round(loss.item() * GRAD_ACCUM, 4))
    print("\n  Smoke training complete. Final loss:", round(loss.item() * GRAD_ACCUM, 4))
    print("  Validating on 50 records...")
    evaluate(model, tokenizer, val_loader, prefix="  Smoke val")
    print("\nSMOKE TEST PASSED. Pipeline is working.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["train", "eval", "smoke"], help="train=full training, eval=eval on held-out, smoke=100-record smoke test")
    args = parser.parse_args()
    if args.mode == "smoke":
        smoke_test()
    elif args.mode == "train":
        best_epoch = train()
        print()
        passed = evaluate_heldout()
        if passed:
            print("Ready to proceed to Phase 0c (ONNX export).")
        else:
            print("Need to retrain. Do NOT proceed to Phase 0c.")
            sys.exit(1)
    elif args.mode == "eval":
        passed = evaluate_heldout()
        if not passed:
            sys.exit(1)


if __name__ == "__main__":
    main()
