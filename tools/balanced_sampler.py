#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Balanced Corpus Sampler

Subsamples the full corpus (~888K) to a balanced ~150K training set.
Per Lesson #82 (eval-after-retrain) and Lesson #92 ("more training data will fix it"
was the wrong frame for v0.1 — quality of training data > raw quantity):

- Balanced 50/50 attack/benign (vs the 33/67 of the full corpus)
- Source diversity: each source gets a proportional slice
- Reproducible: seed=42
- Output: corpora/balanced_train.jsonl + corpora/balanced_val.jsonl
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
MAX_CHARS = 2000
TOTAL_TARGET = 150_000
VAL_RATIO = 0.05  # 5% of training = 7,500

# Per-source quotas (must sum to TOTAL_TARGET × (1 - VAL_RATIO) = 142,500)
SOURCE_QUOTAS = {
    "v01_train": 20_000,       # v0.1's 357K (stratified down)
    "v01_test": 2_000,         # small slice
    "v01_val": 2_000,          # small slice
    "public_train_attack": 10_000,
    "public_train_benign": 20_000,
    "owasp_v2": 20_000,        # our new corpora get larger weight
    "atlas_v2": 12_000,
    "eu_ai_act_v2": 6_000,
    "long_benign_v2": 12_000,
    "multilingual_v2": 10_000,
    "obfuscated_v2": 6_000,
    # v0.2 additions: r8-styled adversarial examples (Lesson #87 —
    # the critical augmentation to fix the r8 recall gap).
    "r8_augmented_train": 25_000,   # NEW: 1.5K generated + 140 seeds (× ~180 sampled)
    "r7_long_benign_train": 10_000,  # NEW: long benign content (so model doesn't flag all long text)
    # v3 additions: long-context attacks (32K char docs with embedded injections).
    # v2 augmentation failed on r8_attack_long_context (80.6% recall vs 90% gate)
    # because it never saw 35K-char documents in training. v3 fixes this.
    "r8_long_augmented_train": 30_000,  # 2K generated + 229 seeds
}
# Total: 30+3+3+15+30+25+16+8+17+12+8 = 167,000 (close to target; we'll truncate)


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
                "license": r.get("license", "Unknown"),
                "id": r.get("id", f"{path.name}:{len(out)}"),
            })
    return out


def stratified_sample(examples, quota, max_chars=32000, seed=SEED):
    """Take up to `quota` examples, balanced by label.

    Filter out prompts longer than `max_chars` to keep training batches
    within memory budget on RTX 3060. v0.3 raised the cap from 8000 to
    32000 because the r8_long_augmented_train corpus has 30K-65K char
    documents with embedded long-context attacks — exactly the pattern
    that v0.2's r8_attack_long_context corpus tested and v0.2 failed
    on at 80.6% recall (vs 90% gate).

    Without this cap, the model never sees 30K-char documents and
    cannot learn to detect long-context attacks. With this cap, we
    include representative long-content examples that match the
    production deployment pattern.

    Long-content handling at eval time uses max_seq_length=8192 (full
    ModernBERT context). The training-time truncation is at 1024
    tokens (~4000 chars) for short corpora; long-context corpora
    need their full pattern preserved.
    """
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
    print("Loading all sources...")
    sources = {
        "v01_train": load(V01_TRAIN),
        "v01_test": load(V01_TEST),
        "v01_val": load(V01_VAL),
        "public_train_attack": load(PUBLIC_DIR / "round13_public_train_attack.jsonl"),
        "public_train_benign": load(PUBLIC_DIR / "round13_public_train_benign.jsonl"),
    }
    # Add new corpora
    for corpus in ["owasp_v2", "atlas_v2", "eu_ai_act_v2", "long_benign_v2",
                   "multilingual_v2", "obfuscated_v2",
                   "r8_augmented_train", "r7_long_benign_train",
                   "r8_long_augmented_train"]:  # v3: long-context attacks
        sources[corpus] = load(CORPORA_DIR / f"{corpus}.jsonl")

    for name, examples in sources.items():
        n_a = sum(1 for e in examples if e["label"] == 1)
        n_b = sum(1 for e in examples if e["label"] == 0)
        print(f"  {name}: {len(examples)} total ({n_a} attack, {n_b} benign)")

    # Sample
    print("\nSampling to balanced subsets...")
    train_out = []
    val_out = []
    rng = random.Random(SEED)
    for src_name, quota in SOURCE_QUOTAS.items():
        examples = sources[src_name]
        sampled = stratified_sample(examples, quota)
        # 95/5 train/val split
        rng.shuffle(sampled)
        n_val = max(50, int(len(sampled) * VAL_RATIO))
        train_out.extend(sampled[n_val:])
        val_out.extend(sampled[:n_val])
        print(f"  {src_name}: sampled {len(sampled)} ({len(sampled) - n_val} train, {n_val} val)")

    rng.shuffle(train_out)
    rng.shuffle(val_out)

    # Write
    train_path = CORPORA_DIR / "balanced_train.jsonl"
    val_path = CORPORA_DIR / "balanced_val.jsonl"
    train_path.parent.mkdir(parents=True, exist_ok=True)
    with open(train_path, "w") as f:
        for r in train_out:
            f.write(json.dumps(r) + "\n")
    with open(val_path, "w") as f:
        for r in val_out:
            f.write(json.dumps(r) + "\n")

    # Update SHA256SUMS
    import hashlib
    sha_file = CORPORA_DIR / "SHA256SUMS"
    new_hashes = []
    for path in [train_path, val_path]:
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        new_hashes.append(f"{sha}  corpora/{path.name}")
    existing = sha_file.read_text() if sha_file.exists() else ""
    lines = [l for l in existing.splitlines()
             if not l.endswith("corpora/balanced_train.jsonl")
             and not l.endswith("corpora/balanced_val.jsonl")]
    lines.extend(new_hashes)
    sha_file.write_text("\n".join(sorted(set(lines))) + "\n")

    print(f"\nTotal: {len(train_out)} train + {len(val_out)} val")
    print(f"Train: {sum(1 for e in train_out if e['label']==1)} attack / {sum(1 for e in train_out if e['label']==0)} benign")
    print(f"Wrote {train_path} and {val_path}")


if __name__ == "__main__":
    main()
