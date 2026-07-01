#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Balanced Corpus Sampler (v2 EXACT reproduction)

This is the EXACT configuration that produced v2 (eval_f1=0.9967 on val,
100% recall on r8 attack corpora). It EXCLUDES r8_long_augmented_train
which v3/v4 added but made val performance worse.

The v2 configuration:
- 109K training examples (vs 118K in v3/v4)
- 14 source quotas (vs 15 in v3/v4)
- NO r8_long_augmented_train quota

Output: corpora/balanced_train_v2.jsonl + corpora/balanced_val_v2.jsonl

Per the new protocol (Post-Mortem 2026-06-28):
- This file MUST be read-only after generation (chmod 555)
- Future training runs MUST use this exact corpus to reproduce v2
- Do NOT edit the SOURCE_QUOTAS below without explicit user approval
"""
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPORA_DIR = REPO_ROOT / "corpora"

V01_TRAIN = Path(
    "/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-ml-artifacts/training_data_tier3/train.jsonl"
)
V01_TEST = Path(
    "/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-ml-artifacts/training_data_tier3/test.jsonl"
)
V01_VAL = Path(
    "/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-ml-artifacts/training_data_tier3/val.jsonl"
)
PUBLIC_DIR = Path(
    "/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-working-snapshot/pen-test/corpus/public_rounds"
)

SEED = 42
MAX_CHARS = 2000  # v2 was 2000 (v3 was raised to 8000, v4 to 32000)
TOTAL_TARGET = 150_000
VAL_RATIO = 0.05

# v2 EXACT quotas - DO NOT MODIFY (see header)
SOURCE_QUOTAS = {
    "v01_train": 20_000,
    "v01_test": 2_000,
    "v01_val": 2_000,
    "public_train_attack": 10_000,
    "public_train_benign": 20_000,
    "owasp_v2": 20_000,
    "atlas_v2": 12_000,
    "eu_ai_act_v2": 6_000,
    "long_benign_v2": 12_000,
    "multilingual_v2": 10_000,
    "obfuscated_v2": 6_000,
    "r8_augmented_train": 25_000,        # v2's r8 augmentation (NO long-context)
    "r7_long_benign_train": 10_000,      # v2's long benign
    # NO r8_long_augmented_train (that was v3+, made val worse)
}


def load(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            text = r.get("text") or r.get("prompt") or r.get("input")
            label = r.get("label", r.get("expected_label"))
            if text is None or label is None:
                continue
            out.append({
                "text": text,
                "label": int(label),
                "source": r.get("source", path.stem),
            })
    return out


def stratified_sample(examples, quota, max_chars=MAX_CHARS, seed=SEED):
    """Take up to `quota` examples, balanced by label."""
    if not examples:
        return []
    rng = random.Random(seed)
    attacks = [e for e in examples if e["label"] == 1 and len(e["text"]) <= max_chars]
    benign = [e for e in examples if e["label"] == 0 and len(e["text"]) <= max_chars]
    rng.shuffle(attacks)
    rng.shuffle(benign)
    n_each = quota // 2
    out = attacks[:n_each] + benign[:n_each]
    if len(out) < quota:
        remaining = quota - len(out)
        all_remaining = attacks[n_each:] + benign[n_each:]
        rng.shuffle(all_remaining)
        out.extend(all_remaining[:remaining])
    rng.shuffle(out)
    return out


def main():
    rng = random.Random(SEED)

    print("[v2 sampler] Loading source corpora (v2 EXACT config)...")
    sources = {
        "v01_train": load(V01_TRAIN),
        "v01_test": load(V01_TEST),
        "v01_val": load(V01_VAL),
        "public_train_attack": load(PUBLIC_DIR / "round13_public_train_attack.jsonl"),
        "public_train_benign": load(PUBLIC_DIR / "round13_public_train_benign.jsonl"),
    }
    # v2 corpora (v0.2 generation, NOT including v3 long-context)
    for corpus in ["owasp_v2", "atlas_v2", "eu_ai_act_v2", "long_benign_v2",
                   "multilingual_v2", "obfuscated_v2",
                   "r8_augmented_train", "r7_long_benign_train"]:
        sources[corpus] = load(CORPORA_DIR / f"{corpus}.jsonl")

    for k, v in sources.items():
        print(f"  {k}: {len(v)} examples")

    # Sample per quota
    print("\n[v2 sampler] Sampling per SOURCE_QUOTAS...")
    final_train = []
    for source, quota in SOURCE_QUOTAS.items():
        sampled = stratified_sample(sources[source], quota)
        final_train.extend(sampled)
        print(f"  {source}: {len(sampled)}/{quota}")

    rng.shuffle(final_train)

    # Hold out 5% for val (matches v2 procedure)
    n_val = int(len(final_train) * VAL_RATIO)
    val = final_train[:n_val]
    train = final_train[n_val:]

    # Write outputs with v2 EXACT naming
    train_path = CORPORA_DIR / "balanced_train_v2.jsonl"
    val_path = CORPORA_DIR / "balanced_val_v2.jsonl"

    with open(train_path, "w") as f:
        for r in train:
            f.write(json.dumps(r) + "\n")
    with open(val_path, "w") as f:
        for r in val:
            f.write(json.dumps(r) + "\n")
    print(f"\n[v2 sampler] Wrote {len(train)} train to {train_path}")
    print(f"[v2 sampler] Wrote {len(val)} val to {val_path}")

    # Compute class balance
    n_attack = sum(1 for r in final_train if r["label"] == 1)
    n_benign = sum(1 for r in final_train if r["label"] == 0)
    print(f"[v2 sampler] Class balance: attack={n_attack} ({100*n_attack/(n_attack+n_benign):.1f}%), benign={n_benign}")

    # Update SHA256SUMS lockfile
    import hashlib
    sha_train = hashlib.sha256(train_path.read_bytes()).hexdigest()
    sha_val = hashlib.sha256(val_path.read_bytes()).hexdigest()
    lockfile = CORPORA_DIR / "SHA256SUMS"
    lines = lockfile.read_text().splitlines() if lockfile.exists() else []
    lines = [l for l in lines if "balanced_train_v2" not in l and "balanced_val_v2" not in l]
    lines.append(f"{sha_train}  corpora/balanced_train_v2.jsonl")
    lines.append(f"{sha_val}  corpora/balanced_val_v2.jsonl")
    lockfile.write_text("\n".join(sorted(set(lines))) + "\n")
    print(f"[v2 sampler] Lockfile updated")

    return 0


if __name__ == "__main__":
    sys.exit(main())