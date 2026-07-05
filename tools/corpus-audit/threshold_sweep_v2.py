#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta — Tier 1: Threshold sweep on the held-out
========================================================================

Per the contingency plan approved 2026-07-04 21:08:
- Tier 1: Sweep thresholds 0.05 -> 0.99 on the held-out, find best
  for the 99%/1% gate.
- The current threshold is 0.05. The model converges with
  ~92% FPR at this threshold.
- A higher threshold (e.g., 0.5, 0.7, 0.9) may drop FPR significantly.

This script:
1. Loads the best checkpoint (epoch 1, the only one saved)
2. Runs the model on the held-out to get per-record probabilities
3. Sweeps thresholds from 0.01 to 0.99 in 0.01 steps
4. Computes recall, FPR, F1 at each threshold
5. Reports the best threshold that meets the 99%/1% gate
6. If no threshold meets the gate, reports the lowest-FPR threshold
   that still has recall >= 99%

Output: printed to stdout, and saved to
docs/PHASE-0B-RUN-2-THRESHOLD-SWEEP.md

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import json
import os
import sys
from pathlib import Path
from collections import Counter

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

CORPUS = Path("/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw")
HELDOUT_FILE = CORPUS / "v01beta-heldout.jsonl"
MODEL_DIR = Path("/home/chaos/Desktop/AegisGate/aegisgate-lens/models/prompt-injection-v0.1.0-beta")
OUTPUT_FILE = Path("/home/chaos/Desktop/AegisGate/aegisgate-lens/docs/PHASE-0B-RUN-2-THRESHOLD-SWEEP.md")

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MAX_LEN = 2048
STRIDE = 1024
MAX_WINDOWS = 4


def sliding_window_tokenize(tokenizer, text, max_len=MAX_LEN, stride=STRIDE, max_windows=MAX_WINDOWS):
    enc = tokenizer(text, return_tensors=None, add_special_tokens=False, truncation=False)
    input_ids = enc["input_ids"]
    if len(input_ids) <= MAX_LEN - 2:
        ids = [tokenizer.cls_token_id] + input_ids + [tokenizer.sep_token_id]
        mask = [1] * len(ids)
        return [(ids, mask)]
    cls_id = tokenizer.cls_token_id
    sep_id = tokenizer.sep_token_id
    windows = []
    start = 0
    while len(windows) < MAX_WINDOWS and start < len(input_ids):
        end = min(start + MAX_LEN - 2, len(input_ids))
        chunk = input_ids[start:end]
        ids = [cls_id] + chunk + [sep_id]
        mask = [1] * len(ids)
        windows.append((ids, mask))
        if end >= len(input_ids):
            break
        start += stride
    return windows


def load_heldout():
    records = []
    for line in open(HELDOUT_FILE):
        try:
            rec = json.loads(line)
            if "text" in rec and "label" in rec:
                records.append(rec)
        except json.JSONDecodeError:
            pass
    return records


def main():
    print("=== AegisGate Lens v0.1.0-beta -- Tier 1: Threshold Sweep ===")
    print(f"Device: {DEVICE}")

    # Find the best checkpoint
    if not (MODEL_DIR / "checkpoint-epoch1").exists():
        print(f"ERROR: no checkpoint found at {MODEL_DIR}/checkpoint-epoch1")
        sys.exit(1)
    checkpoint = MODEL_DIR / "checkpoint-epoch1"
    print(f"Loading checkpoint: {checkpoint.name}")

    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint)
    model.to(DEVICE)
    if DEVICE == "cuda":
        model = model.to(torch.bfloat16)
    model.eval()

    records = load_heldout()
    print(f"Held-out: {len(records)} records")
    n_attack = sum(1 for r in records if r.get("label") == 1)
    n_benign = sum(1 for r in records if r.get("label") == 0)
    print(f"  Attack: {n_attack}, Benign: {n_benign}")

    # Run inference: get per-record max-pool P(attack)
    print("\nRunning inference (this takes ~5 min on 287 records)...")
    p_attack_per_record = []  # list of (label, max_prob)
    for i, rec in enumerate(records):
        text = rec["text"]
        label = rec.get("label", rec.get("expected_label", 0))
        windows = sliding_window_tokenize(tokenizer, text)
        max_prob = 0.0
        for ids, mask in windows:
            # Pad to MAX_LEN
            n = len(ids)
            padded_ids = [0] * MAX_LEN
            padded_mask = [0] * MAX_LEN
            padded_ids[:n] = ids
            padded_mask[:n] = mask
            input_ids = torch.tensor([padded_ids], dtype=torch.long).to(DEVICE)
            attention_mask = torch.tensor([padded_mask], dtype=torch.long).to(DEVICE)
            with torch.no_grad():
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)[:, 1]
            p = probs.item()
            if p > max_prob:
                max_prob = p
        p_attack_per_record.append((label, max_prob))
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(records)} done")

    # Sweep thresholds
    print("\n=== THRESHOLD SWEEP ===")
    sweep_results = []
    for threshold_pct in range(1, 100):
        threshold = threshold_pct / 100.0
        tp = sum(1 for l, p in p_attack_per_record if l == 1 and p > threshold)
        fn = sum(1 for l, p in p_attack_per_record if l == 1 and p <= threshold)
        fp = sum(1 for l, p in p_attack_per_record if l == 0 and p > threshold)
        tn = sum(1 for l, p in p_attack_per_record if l == 0 and p <= threshold)
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        sweep_results.append({
            "threshold": threshold,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": recall, "fpr": fpr, "precision": precision, "f1": f1
        })

    # Find the lowest FPR threshold that still has recall >= 99%
    qualifying = [r for r in sweep_results if r["recall"] >= 0.99]
    if qualifying:
        # Sort by fpr, then f1 descending
        qualifying.sort(key=lambda r: (r["fpr"], -r["f1"]))
        best = qualifying[0]
        print(f"\n=== BEST THRESHOLD that meets recall >= 99% ===")
        print(f"  threshold = {best['threshold']:.2f}")
        print(f"  TP={best['tp']} FN={best['fn']} FP={best['fp']} TN={best['tn']}")
        print(f"  Recall = {best['recall']:.4f} (target >= 0.99)")
        print(f"  FPR    = {best['fpr']:.4f} (target <= 0.01)")
        print(f"  F1     = {best['f1']:.4f} (target >= 0.99)")
        meets_ship = best["recall"] >= 0.99 and best["fpr"] <= 0.01 and best["f1"] >= 0.99
        if meets_ship:
            print(f"  >>> SHIP GATE PASSED at threshold {best['threshold']:.2f}!")
        else:
            print(f"  >>> SHIP GATE NOT met. Best FPR is {best['fpr']:.4f} (need 0.01).")
            print(f"  >>> Need Tier 2 (data enrichment) or Tier 3 (architecture change).")
    else:
        # No threshold meets recall >= 99%
        best = min(sweep_results, key=lambda r: (r["fpr"], -r["recall"]))
        print(f"\n=== NO THRESHOLD meets recall >= 99% ===")
        print(f"  Lowest FPR achieved: {best['fpr']:.4f} at threshold {best['threshold']:.2f}")
        print(f"  At that threshold: recall = {best['recall']:.4f}, F1 = {best['f1']:.4f}")
        print(f"  This is a CATASTROPHIC FAILURE -- the model is unable to distinguish")
        print(f"  benign from attack even at the highest threshold.")
        print(f"  Need Tier 2 (data enrichment) -- synthetic long-context benign.")

    # Show the full sweep (top 20 lowest FPR that meet recall >= 99%)
    print("\n=== Top 20 thresholds (lowest FPR, recall >= 99%) ===")
    print(f"{'Threshold':>10s} {'Recall':>8s} {'FPR':>8s} {'F1':>8s} {'TP':>4s} {'FN':>4s} {'FP':>4s} {'TN':>4s}")
    for r in qualifying[:20]:
        print(f"{r['threshold']:>10.2f} {r['recall']:>8.4f} {r['fpr']:>8.4f} {r['f1']:>8.4f} {r['tp']:>4d} {r['fn']:>4d} {r['fp']:>4d} {r['tn']:>4d}")
    if not qualifying:
        print("  (none)")

    # Save the full sweep + the best
    with open(OUTPUT_FILE, "w") as f:
        f.write("# AegisGate Lens v0.1.0-beta -- Tier 1 Threshold Sweep\n\n")
        f.write(f"**Date**: 2026-07-04\n")
        f.write(f"**Model**: {checkpoint.name} (from Run #2)\n")
        f.write(f"**Held-out**: {len(records)} records ({n_attack} attack, {n_benign} benign)\n\n")
        f.write("## Result\n\n")
        if qualifying:
            best = qualifying[0]
            f.write(f"**Best threshold that meets recall >= 99%**: {best['threshold']:.2f}\n")
            f.write(f"  - TP={best['tp']}, FN={best['fn']}, FP={best['fp']}, TN={best['tn']}\n")
            f.write(f"  - Recall = {best['recall']:.4f} (target >= 0.99)\n")
            f.write(f"  - FPR    = {best['fpr']:.4f} (target <= 0.01)\n")
            f.write(f"  - F1     = {best['f1']:.4f} (target >= 0.99)\n\n")
            meets_ship = best["recall"] >= 0.99 and best["fpr"] <= 0.01 and best["f1"] >= 0.99
            if meets_ship:
                f.write("**SHIP GATE PASSED** at this threshold.\n")
            else:
                f.write(f"**SHIP GATE NOT met**. Best FPR is {best['fpr']:.4f} (need 0.01).\n")
                f.write("Need Tier 2 (data enrichment) or Tier 3 (architecture change).\n")
        else:
            best = min(sweep_results, key=lambda r: (r["fpr"], -r["recall"]))
            f.write(f"**NO THRESHOLD meets recall >= 99%**.\n")
            f.write(f"Lowest FPR achieved: {best['fpr']:.4f} at threshold {best['threshold']:.2f}.\n")
            f.write(f"At that threshold: recall = {best['recall']:.4f}, F1 = {best['f1']:.4f}.\n")
            f.write("This is a CATASTROPHIC FAILURE. Need Tier 2 (data enrichment).\n")
        f.write("\n## Full threshold sweep\n\n")
        f.write(f"| {'Threshold':>10s} | {'Recall':>8s} | {'FPR':>8s} | {'Precision':>10s} | {'F1':>8s} | {'TP':>4s} | {'FN':>4s} | {'FP':>4s} | {'TN':>4s} |\n")
        f.write("|" + "|".join(["---"] * 9) + "|\n")
        for r in sweep_results:
            f.write(f"| {r['threshold']:>10.2f} | {r['recall']:>8.4f} | {r['fpr']:>8.4f} | {r['precision']:>10.4f} | {r['f1']:>8.4f} | {r['tp']:>4d} | {r['fn']:>4d} | {r['fp']:>4d} | {r['tn']:>4d} |\n")
    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
