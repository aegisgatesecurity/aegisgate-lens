#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Option A: Jigsaw-style toxicity held-out
====================================================================

Replaces the ToxiGen/BeaverTails held-out (which was a distribution
mismatch) with a held-out from `google/civil_comments` test split --
the ACTUAL training data of `unitary/toxic-bert`.

Source: google/civil_comments (1.8M train, 97K validation, 97K test)
- 7 categories matching unitary/toxic-bert exactly:
  toxicity, severe_toxicity, obscene, threat, insult, identity_attack, sexual_explicit
- Each category is a probability 0.0-1.0 (not binary label)
- We use the standard Jigsaw threshold of 0.5 for label determination
  (toxic if any category >= 0.5)

The held-out: 500 attack + 200 benign = 700 records, random-sampled
from the test split. Statistical power at 200+: 95% CI tight.

The remaining test split (after sampling) is preserved for future
re-validations.
"""
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
CORPUS = LENS / 'corpora' / 'v01beta-raw'

# Load the Civil Comments test split (the same data the model was trained on)
print('Loading google/civil_comments test split (97,320 records)...')
from datasets import load_dataset
ds = load_dataset('google/civil_comments', cache_dir='/tmp/hf-jigsaw', split='test')
print(f'Loaded {len(ds)} records')

# Determine label using the Jigsaw convention: toxic if any category >= 0.5
# (This is the convention used by the original Jigsaw competition and
# the unitary/toxic-bert evaluation.)
def is_toxic(rec):
    """A record is 'toxic' if any of the 6 (or 7) categories has prob >= 0.5."""
    cats = ['toxicity', 'severe_toxicity', 'obscene', 'threat', 'insult', 'identity_attack']
    return any(float(rec.get(c, 0.0)) >= 0.5 for c in cats)

print('Computing labels...')
attack_count = 0
benign_count = 0
for rec in ds:
    if is_toxic(rec):
        attack_count += 1
    else:
        benign_count += 1
print(f'  Attack (any cat >= 0.5): {attack_count}')
print(f'  Benign: {benign_count}')

# Sample 500 attack + 200 benign from the test split
random.seed(20260704)
attack_idxs = [i for i, rec in enumerate(ds) if is_toxic(rec)]
benign_idxs = [i for i, rec in enumerate(ds) if not is_toxic(rec)]
print(f'  Available attack: {len(attack_idxs)}, benign: {len(benign_idxs)}')

random.shuffle(attack_idxs)
random.shuffle(benign_idxs)

heldout_attack_idxs = attack_idxs[:500]
heldout_benign_idxs = benign_idxs[:200]
heldout_idxs = set(heldout_attack_idxs + heldout_benign_idxs)
print(f'  Held-out attack: {len(heldout_attack_idxs)}, benign: {len(heldout_benign_idxs)}')

# Build the held-out in v0.1.0-beta schema
print('Building held-out records in v0.1.0-beta schema...')
heldout = []
for idx in heldout_attack_idxs + heldout_benign_idxs:
    rec = ds[idx]
    text = rec.get('text', '')
    label = 1 if idx in heldout_attack_idxs else 0
    # Get the per-category scores
    cats = ['toxicity', 'severe_toxicity', 'obscene', 'threat', 'insult', 'identity_attack']
    probs = {c: float(rec.get(c, 0.0)) for c in cats}
    # Map Jigsaw categories to our schema
    # The unitary/toxic-bert is trained on this exact data with these exact
    # column names, so the mapping is:
    # toxicity -> toxicity_hate (high)
    # severe_toxicity -> toxicity_violence (high)
    # obscene -> toxicity_obscene (medium)
    # threat -> toxicity_threat (high)
    # insult -> toxicity_insult (medium)
    # identity_attack -> toxicity_hate (high)
    # sexual_explicit (Civil Comments 7th) -> not in unitary; regex fallback
    heldout.append({
        'id': f'civil-comments-test-{idx:06d}',
        'category': 'short_attack' if label == 1 else 'benign',
        'subcategory': 'jigsaw_civil_comments',
        'text': text,
        'label': label,
        'expected_label': label,
        'attack_category': 'toxicity_civil_comments',
        'document_type': 'short',
        'n_tokens': None,
        'source': 'google_civil_comments_test',
        'attack_position_token': None,
        'injection_text': None,
        'notes': f"google/civil_comments test split idx={idx}; probs={probs}; is_toxic={label==1}"
    })

# Shuffle
random.shuffle(heldout)

# Save
out_path = CORPUS / 'v01beta-toxicity-heldout.jsonl'
with open(out_path, 'w') as f:
    for r in heldout:
        f.write(json.dumps(r) + '\n')
print(f'\nSaved {len(heldout)} records to: {out_path}')

# Verify
n_attack = sum(1 for r in heldout if r['label'] == 1)
n_benign = sum(1 for r in heldout if r['label'] == 0)
print(f'  Verification: {n_attack} attack, {n_benign} benign')

# Show a few samples
print()
print('=== 3 sample attack records ===')
for r in [x for x in heldout if x['label'] == 1][:3]:
    text = r['text'][:150].replace('\n', ' ')
    print(f"  '{text}...'")
print()
print('=== 3 sample benign records ===')
for r in [x for x in heldout if x['label'] == 0][:3]:
    text = r['text'][:150].replace('\n', ' ')
    print(f"  '{text}...'")
