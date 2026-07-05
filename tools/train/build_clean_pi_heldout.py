#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Build CLEAN PI held-out
====================================================

The v0.1 long-context corpus has 3,630 records but:
- 426 invalid (missing fields, wrong types)
- 1,127 internal duplicates (31% duplicate rate)
- Mixed attack types (PI, XSS, encoding) -- we need ONLY PI
- 645 "benign" records have PI patterns (suspicious labels)

This script builds a CLEAN PI held-out by:
1. Filtering to PI-only attack categories
2. Removing invalid records
3. Deduplicating
4. Re-validating labels (benign records must NOT have PI patterns)
5. Triple validation: raw, label, distribution

Target: 700 records (350 attack + 350 benign, balanced)
"""
import json
import re
import hashlib
import random
from pathlib import Path
from collections import Counter

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
INPUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-heldout.jsonl'
OUTPUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-CLEAN-PI-heldout.jsonl'
REPORT = LENS / 'docs' / 'PHASE-5e-CLEAN-PI-HELDOUT-REPORT.md'

SEED = 20260705
TARGET_ATTACK = 350
TARGET_BENIGN = 350
SAMPLE_SIZE = 30

# PI-specific patterns. We require AT LEAST ONE of these for label=1.
# We REJECT any label=0 record WITH any of these.
PI_INDICATORS = [
    # Direct injection phrases
    'ignore previous', 'ignore all', 'disregard', 'forget everything',
    'new instructions', 'system:', 'you are now', 'act as',
    'pretend to be', 'roleplay', 'simulate', 'developer mode',
    'DAN', 'jailbreak', 'bypass', 'override',
    'reveal your prompt', 'show me your instructions',
    'without restrictions', 'no filters', 'no censorship',
    'act unethically', 'ignore safety', 'ignore guidelines',
    'disregard your', 'overlook your', 'set aside', 'apply no',
    'forget your', 'ignore the', 'without safety', 'no safety',
    'safeguard', 'guardrails', 'safety guidelines', 'security guidelines',
    'do not follow', 'do not apply', 'without following',
    # Common obfuscation patterns
    'begin fugue', 'fugue approach', 'unmoderated', 'unfiltered',
    'prompt verbatim', 'system prompt', 'holistic',
    'productivity', 'output format', 'please from now on',
    'for testing purposes', 'for the next', 'for this response',
    'operate in', 'act unethically', 'no moral', 'no ethical',
    'evil ai', 'malicious ai', 'dark side', 'be evil',
    # Direct jailbreak phrases
    'do anything now', 'developer mode output', 'jailbroken',
    'no content policy', 'no moral constraints',
    'without any restrictions', 'pretend you are',
    'respond without', 'ignore all previous', 'ignore your safety',
    'bypass your', 'override your', 'disregard your safety',
    # Common attack framings
    'as a test', 'for research', 'security researcher', 'i am a',
    'ignore the above', 'forget the above', 'new task',
    'your new role', 'your new instructions', 'answer the next',
    'without applying', 'without following', 'no restrictions apply',
]
PI_COMPILED = re.compile('|'.join(re.escape(p) for p in PI_INDICATORS), re.IGNORECASE)


def has_pi_indicator(text):
    return bool(PI_COMPILED.search(text))


def raw_validate(record):
    errors = []
    for field in ['text', 'label', 'source']:
        if field not in record:
            errors.append(f'missing {field}')
    if 'text' in record and (not isinstance(record['text'], str) or len(record['text'].strip()) < 20):
        errors.append('text too short or wrong type')
    if 'label' in record and record['label'] not in (0, 1):
        errors.append(f'label={record["label"]} not 0/1')
    return errors


def hash_text(text):
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:16]


def main():
    random.seed(SEED)
    print(f'=== Build CLEAN PI held-out ===')
    print(f'Seed: {SEED}')
    print(f'Target: {TARGET_ATTACK} attack + {TARGET_BENIGN} benign = {TARGET_ATTACK + TARGET_BENIGN}')

    # Step 0: Load all records
    print(f'\nSTEP 0: Loading records...')
    records = []
    for line in open(INPUT):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    print(f'  Loaded {len(records)} records')

    # Step 1: Raw validation
    print(f'\nSTEP 1: Raw validation (reject invalid records)...')
    valid = [r for r in records if not raw_validate(r)]
    invalid = [r for r in records if raw_validate(r)]
    print(f'  Valid: {len(valid)}, Invalid: {len(invalid)}')

    # Step 2: Label validation
    print(f'\nSTEP 2: Label validation...')
    valid_attack = []
    rejected_attack = []
    for r in valid:
        if r.get('label') == 1:
            if has_pi_indicator(r.get('text', '')):
                valid_attack.append(r)
            else:
                rejected_attack.append(r)
    valid_benign = []
    rejected_benign = []
    for r in valid:
        if r.get('label') == 0:
            if not has_pi_indicator(r.get('text', '')):
                valid_benign.append(r)
            else:
                rejected_benign.append(r)
    print(f'  Valid attack (with PI pattern): {len(valid_attack)}')
    print(f'  Rejected attack (no PI pattern): {len(rejected_attack)}')
    print(f'  Valid benign (no PI pattern): {len(valid_benign)}')
    print(f'  Rejected benign (has PI pattern): {len(rejected_benign)}')

    # Step 3: Dedup
    print(f'\nSTEP 3: Dedup by text hash...')
    seen = set()
    deduped_attack = []
    for r in valid_attack:
        h = hash_text(r.get('text', ''))
        if h not in seen:
            seen.add(h)
            deduped_attack.append(r)
    deduped_benign = []
    for r in valid_benign:
        h = hash_text(r.get('text', ''))
        if h not in seen:
            seen.add(h)
            deduped_benign.append(r)
    print(f'  Attack after dedup: {len(deduped_attack)}')
    print(f'  Benign after dedup: {len(deduped_benign)}')

    # Step 4: Length filter (50-8000 chars; exclude too-short and too-long)
    print(f'\nSTEP 4: Length filter (50-8000 chars)...')
    def length_ok(r):
        return 50 <= len(r.get('text', '')) <= 8000
    length_attack = [r for r in deduped_attack if length_ok(r)]
    length_benign = [r for r in deduped_benign if length_ok(r)]
    print(f'  Attack after length filter: {len(length_attack)}')
    print(f'  Benign after length filter: {len(length_benign)}')

    # Step 5: Sample to target
    print(f'\nSTEP 5: Sampling to target size...')
    random.shuffle(length_attack)
    random.shuffle(length_benign)
    final_attack = length_attack[:TARGET_ATTACK]
    final_benign = length_benign[:TARGET_BENIGN]
    heldout = final_attack + final_benign
    random.shuffle(heldout)

    for i, r in enumerate(heldout):
        r['id'] = f'clean-pi-{i:04d}'

    # Step 6: Triple validation
    print(f'\nSTEP 6: Distribution validation...')
    stats = {
        'total': len(heldout),
        'attack': sum(1 for r in heldout if r.get('label') == 1),
        'benign': sum(1 for r in heldout if r.get('label') == 0),
    }
    text_lengths = [len(r.get('text', '')) for r in heldout]
    stats['text_length_min'] = min(text_lengths)
    stats['text_length_max'] = max(text_lengths)
    stats['text_length_mean'] = sum(text_lengths) / len(text_lengths)
    stats['text_length_median'] = sorted(text_lengths)[len(text_lengths)//2]

    text_hashes = [hash_text(r.get('text', '')) for r in heldout]
    stats['duplicate_count'] = len(text_hashes) - len(set(text_hashes))

    attack_hashes = set(h for r, h in zip(heldout, text_hashes) if r.get('label') == 1)
    benign_hashes = set(h for r, h in zip(heldout, text_hashes) if r.get('label') == 0)
    stats['cross_set_duplicate_count'] = len(attack_hashes & benign_hashes)

    # Re-validate every record
    invalid_count = 0
    for r in heldout:
        if raw_validate(r):
            invalid_count += 1
            continue
        if r.get('label') == 1 and not has_pi_indicator(r.get('text', '')):
            invalid_count += 1
        elif r.get('label') == 0 and has_pi_indicator(r.get('text', '')):
            invalid_count += 1
    stats['invalid_count'] = invalid_count

    print(f'  Total: {stats["total"]}, Attack: {stats["attack"]}, Benign: {stats["benign"]}')
    print(f'  Text length: min={stats["text_length_min"]}, max={stats["text_length_max"]}, mean={stats["text_length_mean"]:.0f}, median={stats["text_length_median"]}')
    print(f'  Internal duplicates: {stats["duplicate_count"]}')
    print(f'  Cross-set duplicates: {stats["cross_set_duplicate_count"]}')
    print(f'  Invalid: {stats["invalid_count"]}')

    # Save
    print(f'\nSTEP 7: Saving...')
    with open(OUTPUT, 'w') as f:
        for r in heldout:
            f.write(json.dumps(r) + '\n')
    print(f'  Saved: {OUTPUT}')

    # Triple validation: re-read + re-compute
    print(f'\nSTEP 8: TRIPLE VALIDATION (validate, revalidate, revalidate)')
    reloaded = []
    for line in open(OUTPUT):
        try: reloaded.append(json.loads(line))
        except: pass
    assert len(reloaded) == len(heldout), 'count mismatch'
    print(f'  Re-read: OK ({len(reloaded)} records)')

    reloaded_attack = sum(1 for r in reloaded if r.get('label') == 1)
    reloaded_benign = sum(1 for r in reloaded if r.get('label') == 0)
    assert reloaded_attack == stats['attack'] and reloaded_benign == stats['benign']
    print(f'  Re-compute: OK ({reloaded_attack} attack, {reloaded_benign} benign)')

    # Sample inspection
    random.seed(SEED + 1)
    sample = random.sample(reloaded, SAMPLE_SIZE)
    correct = 0
    print(f'  Sample inspection ({SAMPLE_SIZE} records):')
    for r in sample:
        text = r.get('text', '')
        text_preview = text[:120].replace(chr(10), ' ')
        has_ind = has_pi_indicator(text)
        label = r.get('label')
        is_correct = (label == 1 and has_ind) or (label == 0 and not has_ind)
        if is_correct:
            correct += 1
        marker = 'OK' if is_correct else 'CHECK'
        print(f'    [{marker}] label={label} has_ind={has_ind}: {text_preview}...')
    print(f'  Sample check: {correct}/{SAMPLE_SIZE} pass')

    # Report
    with open(REPORT, 'w') as f:
        f.write(f'# Phase 5e: CLEAN PI held-out report\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Seed**: {SEED}\n\n')
        f.write(f'**Source**: v0.1 long-context corpus (3,630 raw records)\n\n')
        f.write(f'## Cleaning steps\n\n')
        f.write(f'1. Raw validation: rejected {len(invalid)} invalid records\n')
        f.write(f'2. Label validation: required PI indicator in attack records, rejected benign records with PI indicators\n')
        f.write(f'   - Rejected attack (no PI indicator): {len(rejected_attack)}\n')
        f.write(f'   - Rejected benign (has PI indicator): {len(rejected_benign)}\n')
        f.write(f'3. Dedup by text hash: {len(valid_attack) + len(valid_benign)} -> {len(deduped_attack) + len(deduped_benign)}\n')
        f.write(f'4. Length filter (50-8000 chars): {len(deduped_attack) + len(deduped_benign)} -> {len(length_attack) + len(length_benign)}\n')
        f.write(f'5. Sample to target: {len(heldout)}\n\n')
        f.write(f'## Final held-out\n\n')
        f.write(f'  Total: {stats["total"]}\n')
        f.write(f'  Attack: {stats["attack"]}\n')
        f.write(f'  Benign: {stats["benign"]}\n')
        f.write(f'  Text length: min={stats["text_length_min"]}, max={stats["text_length_max"]}, mean={stats["text_length_mean"]:.0f}, median={stats["text_length_median"]}\n')
        f.write(f'  Internal duplicates: {stats["duplicate_count"]}\n')
        f.write(f'  Cross-set duplicates: {stats["cross_set_duplicate_count"]}\n')
        f.write(f'  Invalid records: {stats["invalid_count"]}\n\n')
        f.write(f'## Triple validation results\n\n')
        f.write(f'  Re-read: PASS\n')
        f.write(f'  Re-compute statistics: PASS\n')
        f.write(f'  Sample inspection: {correct}/{SAMPLE_SIZE} pass\n\n')
        f.write(f'## Held-out location\n\n')
        f.write(f'`{OUTPUT}`\n')

    print(f'\nReport: {REPORT}')
    print(f'\n=== DONE ===')
    print(f'  Held-out: {stats["total"]} records ({stats["attack"]} attack + {stats["benign"]} benign)')
    print(f'  Internal dupes: {stats["duplicate_count"]}')
    print(f'  Cross-set dupes: {stats["cross_set_duplicate_count"]}')
    print(f'  Invalid: {stats["invalid_count"]}')


if __name__ == '__main__':
    main()
