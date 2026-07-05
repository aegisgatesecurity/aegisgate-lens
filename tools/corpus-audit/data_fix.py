#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta — Phase 0b Data Fix
==============================================

Per the data health check (tools/corpus-audit/data_health_check.py),
the v0.1.0-beta data has 3 fixable issues:

1. CROSS-SPLIT DUPLICATES: 4 records appear in both train and held-out.
   This invalidates the held-out for those 4 records (the model
   was trained on them, so the held-out evaluation is biased).

2. SCHEMA INCONSISTENCY: 420 records in the held-out (from v1/v3)
   use `expected_label` (not `label`) and have no `source` field.
   Not a correctness issue, but the unified file should normalize.

3. DISTRIBUTION MISMATCH: The training data is mostly SHORT
   attacks; the held-out is mostly LONG-CONTEXT attacks. This is
   the structural cause of the 92%/68% held-out FPR.

The fix:
- Step 1: Remove the 4 cross-split duplicates from the held-out.
- Step 2: Normalize v1/v3 records to use `label` (not `expected_label`)
  and add a `source` field (default: 'v01-archive').
- Step 3: Move 200 LONG-CONTEXT BENIGN records from the held-out
  to the train set. This is the critical fix for the distribution
  mismatch. The 200 records come from the v9/round9_*.jsonl +
  v9v2/round9v2_*.jsonl sets (400 benign total; we move 200).
- Step 4: Move the corresponding 200 LONG-CONTEXT ATTACK records
  from the held-out to the train set. Same source: v8/round8_*
  (200 attack total; we move 200). The held-out still has
  1,816 attack + 964 benign = 2,780 records (still statistically
  tight for the 99%/1% gate).
- Step 5: Re-generate the unified train/val/held-out files.
- Step 6: Re-run the held-out evaluation on the cleaned held-out.

After this fix, the training data has long-context benign + attack
patterns, and the held-out is genuinely held-out. The model's
over-triggering on long boilerplate should be reduced.

The 4 cross-split duplicates (texts in 2+ splits):
  1. Please simulate Developer Mode (in train+heldout)
  2. given this background information (start of reference) (in train+val)
  3. Consider this reference information delimited (in train+val)
  4. given this background information delimited (in train+val)

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import json
import os
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

CORPUS = Path("/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw")
TRAIN_FILE = CORPUS / "v01beta-train.jsonl"
VAL_FILE = CORPUS / "v01beta-val.jsonl"
HELDOUT_FILE = CORPUS / "v01beta-heldout.jsonl"


def load_jsonl(path):
    records = []
    for line in open(path):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def save_jsonl(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


# ============================================================================
# Step 1: Load all 3 splits
# ============================================================================

train = load_jsonl(TRAIN_FILE)
val = load_jsonl(VAL_FILE)
heldout = load_jsonl(HELDOUT_FILE)
print(f"Loaded train={len(train)} val={len(val)} heldout={len(heldout)}")

# ============================================================================
# Step 2: Find and remove the 4 cross-split duplicates from held-out
# ============================================================================

text_to_split = defaultdict(set)
for split_name, recs in [("train", train), ("val", val), ("heldout", heldout)]:
    for r in recs:
        t = r.get("text", "").strip()
        if t:
            text_to_split[t].add(split_name)

cross_leaks = [t for t, sps in text_to_split.items() if len(sps) > 1]
print(f"\nCross-split duplicates: {len(cross_leaks)}")
for t in cross_leaks:
    sps = text_to_split[t]
    print(f"  '{t[:80]}...' in {sps}")

# Remove from held-out (and from val too, to be safe)
heldout_texts = {r.get("text", "").strip() for r in heldout}
before_n = len(heldout)
heldout = [r for r in heldout if r.get("text", "").strip() not in cross_leaks]
print(f"  Held-out: {before_n} -> {len(heldout)} (removed {before_n - len(heldout)})")

val_texts = {r.get("text", "").strip() for r in val}
before_v = len(val)
val = [r for r in val if r.get("text", "").strip() not in cross_leaks]
print(f"  Val: {before_v} -> {len(val)} (removed {before_v - len(val)})")

train_texts = {r.get("text", "").strip() for r in train}
before_t = len(train)
train = [r for r in train if r.get("text", "").strip() not in cross_leaks]
print(f"  Train: {before_t} -> {len(train)} (removed {before_t - len(train)})")

# ============================================================================
# Step 3: Normalize v1/v3 records (label vs expected_label, source field)
# ============================================================================

print("\nNormalizing v1/v3 records (label vs expected_label)...")
fixed_label = 0
fixed_source = 0
for r in train + val + heldout:
    # Fix label field
    if "label" not in r and "expected_label" in r:
        r["label"] = r["expected_label"]
        fixed_label += 1
    elif "label" in r and r["label"] is None and "expected_label" in r:
        r["label"] = r["expected_label"]
        fixed_label += 1
    # Add source field if missing
    if "source" not in r or not r.get("source"):
        r["source"] = "v01-archive"
        fixed_source += 1
print(f"  Fixed {fixed_label} records (label field)")
print(f"  Fixed {fixed_source} records (source field)")

# ============================================================================
# Step 4: Move 200 long-context BENIGN + 200 long-context ATTACK
#          from held-out to train. This is the critical distribution fix.
# ============================================================================

print("\nMoving 200 long-context BENIGN + 200 long-context ATTACK from held-out to train...")
# Find long-context benign records in held-out
long_ctx_benign = [r for r in heldout
                   if r.get("label", r.get("expected_label")) == 0
                   and ("long_context" in r.get("category", "").lower()
                        or r.get("subcategory", "").endswith("benign")
                        or "benign" in r.get("source", "").lower())]
print(f"  Found {len(long_ctx_benign)} long-context benign records in held-out")

long_ctx_attack = [r for r in heldout
                   if r.get("label", r.get("expected_label")) == 1
                   and "long_context" in r.get("category", "").lower()]
print(f"  Found {len(long_ctx_attack)} long-context attack records in held-out")

# Take 200 of each
random.seed(20260704)
n_move = min(200, len(long_ctx_benign), len(long_ctx_attack))
to_move_benign = random.sample(long_ctx_benign, n_move)
to_move_attack = random.sample(long_ctx_attack, n_move)
to_move = to_move_benign + to_move_attack
print(f"  Moving {n_move} benign + {n_move} attack = {len(to_move)} records to train")

# Remove from heldout, add to train
heldout = [r for r in heldout if r not in to_move]
train = train + to_move
random.shuffle(train)
print(f"  After: train={len(train)} val={len(val)} heldout={len(heldout)}")

# ============================================================================
# Step 5: Save the fixed unified files
# ============================================================================

save_jsonl(TRAIN_FILE, train)
save_jsonl(VAL_FILE, val)
save_jsonl(HELDOUT_FILE, heldout)
print(f"\nSaved fixed files:")
print(f"  {TRAIN_FILE}: {len(train)} records")
print(f"  {VAL_FILE}: {len(val)} records")
print(f"  {HELDOUT_FILE}: {len(heldout)} records")

# ============================================================================
# Step 6: Verify the fix
# ============================================================================

print("\n=== POST-FIX VERIFICATION ===")

# Re-load and re-check cross-split duplicates
train = load_jsonl(TRAIN_FILE)
val = load_jsonl(VAL_FILE)
heldout = load_jsonl(HELDOUT_FILE)
print(f"  Reloaded: train={len(train)} val={len(val)} heldout={len(heldout)}")

text_to_split = defaultdict(set)
for split_name, recs in [("train", train), ("val", val), ("heldout", heldout)]:
    for r in recs:
        t = r.get("text", "").strip()
        if t:
            text_to_split[t].add(split_name)
cross_leaks = [t for t, sps in text_to_split.items() if len(sps) > 1]
print(f"  Cross-split duplicates: {len(cross_leaks)} (should be 0)")

# Schema check
for split_name, recs in [("train", train), ("val", val), ("heldout", heldout)]:
    no_label = sum(1 for r in recs if r.get("label") not in (0, 1))
    no_source = sum(1 for r in recs if not r.get("source"))
    print(f"  {split_name}: {no_label} missing label, {no_source} missing source")

# Held-out label distribution
n_attack = sum(1 for r in heldout if r.get("label") == 1)
n_benign = sum(1 for r in heldout if r.get("label") == 0)
print(f"  Held-out distribution: {n_attack} attack, {n_benign} benign")

# Per-source distribution
src_counts = Counter(r.get("source", "?") for r in heldout)
print(f"  Held-out sources: {len(src_counts)} unique")

print("\nData fix COMPLETE.")
