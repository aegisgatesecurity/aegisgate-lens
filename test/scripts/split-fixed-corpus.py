"""
Update Item H to properly handle the fixed corpus.

The fixed corpus is now mixed (228 benign + 136 attack).
We split it into two single-class corpora for analysis:
  - r7_long_benign_train_FIXED.benign.jsonl (228 records, all label 0)
  - r7_long_benign_train_FIXED.attack.jsonl (136 records, all label 1)

This keeps Item H's analysis clean: each "corpus" is single-class.
"""
import json
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

REPO = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02')
SNAPSHOT = REPO / 'models/snapshots/pre-retrain-2026-06-28T14-25-00Z/checkpoint-7012'
FIXED = REPO / 'test/eval/r7_long_benign_train_fixed.jsonl'
BENIGN_OUT = REPO / 'test/eval/r7_long_benign_train_FIXED.benign.jsonl'
ATTACK_OUT = REPO / 'test/eval/r7_long_benign_train_FIXED.attack.jsonl'

# Read fixed corpus
records = []
with open(FIXED) as f:
    for line in f:
        records.append(json.loads(line))

benign_records = [r for r in records if r['label'] == 0]
attack_records = [r for r in records if r['label'] == 1]

# Write split files
with open(BENIGN_OUT, 'w') as f:
    for r in benign_records:
        f.write(json.dumps(r) + '\n')
with open(ATTACK_OUT, 'w') as f:
    for r in attack_records:
        f.write(json.dumps(r) + '\n')

print(f'Split {FIXED.name} into:')
print(f'  {BENIGN_OUT.name}: {len(benign_records)} records (label 0)')
print(f'  {ATTACK_OUT.name}: {len(attack_records)} records (label 1)')

# Compute SHA256 for each
import hashlib
def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

print(f'\nSHA256:')
print(f'  {BENIGN_OUT.name}: {sha256(BENIGN_OUT)}')
print(f'  {ATTACK_OUT.name}: {sha256(ATTACK_OUT)}')

# Update SHA256SUMS
sha_file = BENIGN_OUT.parent / 'r7_long_benign_train_split.SHA256SUMS'
sha_file.write_text(
    f'# AegisGate Lens v0.2 — Fixed corpus split lockfile\n'
    f'# Generated 2026-06-28 from r7_long_benign_train_fixed.jsonl\n'
    f'# Split into single-class subsets for Item H analysis\n'
    f'# Original corpus (mixed): {sha256(FIXED)}\n'
    f'{sha256(BENIGN_OUT)}  {BENIGN_OUT.name}\n'
    f'{sha256(ATTACK_OUT)}  {ATTACK_OUT.name}\n'
)
print(f'\nWrote lockfile: {sha_file}')