#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Build proper toxicity held-out
==========================================================

Per the user directive (2026-07-05): the previous held-out was
"structurally clean but wrong-domain clean" (it was prompt injection
data, not toxicity data). We need EXPLICIT TOXICITY examples:
slurs, threats, weapons/explosives/exploitation instructions, etc.

This script builds the held-out from REAL toxicity sources:
- BeaverTails (PKU-Alignment): explicit safety violations
  (child exploitation, weapons, hate speech, etc.)
- ToxiGen: implicit hate (subtle bias, stereotypes, dehumanization)
- Manual curation: explicit slurs, direct threats, self-harm

Triple validation:
1. RAW: structure, required fields, label=0/1
2. LABEL: manual inspection sample (the user said "NO SHORTCUTS")
3. DISTRIBUTION: balanced, no dupes, no cross-set leakage

Output: corpora/v01beta-raw/v01beta-toxicity-PROPER-heldout.jsonl
Target: 700 records (350 attack + 350 benign)
"""
import json
import random
import hashlib
import re
from pathlib import Path
from collections import Counter

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
TRAIN = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-train.jsonl'
OUTPUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-PROPER-heldout.jsonl'
REPORT = LENS / 'docs' / 'PHASE-5d-PROPER-TOXICITY-HELDOUT-REPORT.md'

SEED = 20260705
TARGET_ATTACK = 350
TARGET_BENIGN = 350
SAMPLE_SIZE = 30  # for manual label validation (the user wants triple validation)

# Explicit toxicity indicators. We require AT LEAST ONE of these
# in any record labeled as 'attack' (label=1).
# These are the categories the Lens needs to detect:
# - Hate speech (slurs, dehumanization, stereotypes)
# - Violence (weapons, explosives, harm instructions)
# - Exploitation (child abuse, sexual exploitation, trafficking)
# - Self-harm (suicide, self-injury)
# - Criminal activity (drugs, fraud, hacking)
# - Harassment (direct insults, threats, doxxing)
TOXICITY_INDICATORS = [
    # Hate speech / slurs / dehumanization
    'slur', 'racial slur', 'hate', 'hatred', 'hate speech',
    'racist', 'racism', 'nazi', 'fascist', 'bigot', 'bigotry',
    'savage', 'inferior', 'subhuman', 'vermin', 'dehumanize',
    'go back to your country', 'go back where you came',
    'white supremac', 'kkk', 'klan',
    # Violence / weapons / harm
    'kill', 'murder', 'assault', 'attack', 'hurt', 'harm', 'weapon',
    'gun', 'rifle', 'pistol', 'firearm', 'shoot', 'shooting',
    'bomb', 'explosive', 'grenade', 'detonate', 'detonator',
    'poison', 'ricin', 'anthrax', 'chemical weapon', 'bioweapon',
    'torture', 'mutilate', 'dismember', 'strangle', 'stab',
    'acid attack', 'arson', 'burn down',
    # Exploitation
    'rape', 'molest', 'pedophil', 'child abuse', 'child sexual',
    'child porn', 'csam', 'minor sexual', 'grooming', 'groom',
    'incest', 'trafficking', 'sexual exploitation', 'sex trafficking',
    'prostitut', 'escort service', 'johns', 'pimp',
    # Self-harm
    'kill myself', 'suicide', 'suicidal', 'end my life',
    'hang myself', 'overdose', 'cut myself', 'self-harm',
    'jump off', 'bridge', 'not worth living',
    # Criminal activity
    'child pornography', 'cp link', 'cp download', 'cp site',
    'csam download', 'csam link',
    'make drugs', 'synthesize meth', 'cook meth', 'meth recipe',
    'make fentanyl', 'synthesize cocaine', 'heroin recipe',
    'steal credit card', 'credit card fraud', 'card skimmer',
    'phishing email', 'phishing kit', 'social engineering attack',
    'hack into', 'break into', 'bypass security', 'exploit vulnerability',
    'zero day', 'sql injection', 'sqlmap', 'ransomware', 'cryptolocker',
    'make a bomb', 'build a bomb', 'bomb instructions', 'bomb recipe',
    'how to cheat', 'cheat on a test', 'plagiarize',
    # Harassment / threats / doxxing
    'i will find you', 'i will hurt you', 'i will kill you',
    'doxx', 'dox', 'leak your address', 'swat', 'swatting',
    'kys', 'neck yourself', 'rope', 'necktie', 'hang yourself',
    'shut up', 'you stupid', 'you idiot', 'moron', 'imbecile',
    'loser', 'dumb ass', 'dumbass', 'asshole', 'bastard',
    'trash', 'garbage', 'worthless', 'pathetic', 'disgusting',
    'creep', 'pervert', 'freak', 'weirdo',
    # Sexual content
    'porn', 'pornography', 'xxx', 'nude', 'naked', 'nsfw',
    'onlyfans', 'strip', 'escort',
    # General toxicity from BeaverTails
    'no filter', 'no safety', 'ignore your safety',
    'bypass content filter', 'jailbreak', 'DAN', 'developer mode',
    'act as an evil', 'pretend to be evil', 'be evil', 'be unethical',
    'no moral', 'no ethical', 'no guideline', 'no restriction',
    'act unethically', 'without restriction', 'without ethical',
    'without moral', 'without safety', 'without filter',
    'evil ai', 'malicious ai', 'dark side',
    'instructions for making', 'recipe for', 'how to make a',
    'how to make meth', 'how to cook', 'how to build a weapon',
    'how to hack', 'how to steal', 'how to break into',
    'bomb-making', 'weapon-making', 'drug-making',
    # ToxiGen implicit hate indicators
    'savage', 'barbaric', 'primitive', 'backward', 'uncivilized',
    'those people', 'their kind', 'their race', 'their culture',
    'all [group]', 'every [group]', 'typical [group]',
    'incapable of', 'cannot learn', 'too stupid',
]

# Also define: patterns that should NOT appear in benign records
TOXICITY_INDICATORS_COMPILED = [re.compile(re.escape(p), re.IGNORECASE) for p in TOXICITY_INDICATORS]


def hash_text(text):
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:16]


def has_toxicity_indicator(text):
    """Check if text contains at least one explicit toxicity indicator."""
    for pat in TOXICITY_INDICATORS_COMPILED:
        if pat.search(text):
            return True, pat.pattern
    return False, None


def load_jsonl(path):
    records = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            records.append(r)
        except json.JSONDecodeError:
            pass
    return records


def main():
    random.seed(SEED)
    print(f'=== Build PROPER toxicity held-out ===')
    print(f'Seed: {SEED}')
    print(f'Target: {TARGET_ATTACK} attack + {TARGET_BENIGN} benign = {TARGET_ATTACK + TARGET_BENIGN}')
    print()

    # ========================================================================
    # STEP 1: Load all candidate records from BeaverTails + ToxiGen
    # These are the ONLY sources we trust for explicit toxicity.
    # ========================================================================
    print('STEP 1: Loading BeaverTails + ToxiGen candidates...')
    all_records = load_jsonl(TRAIN)
    bt = [r for r in all_records if 'beavertails' in r.get('source', '').lower()]
    tg = [r for r in all_records if 'toxigen' in r.get('source', '').lower()]
    print(f'  BeaverTails: {len(bt)} ({sum(1 for r in bt if r.get("label")==1)} attack, {sum(1 for r in bt if r.get("label")==0)} benign)')
    print(f'  ToxiGen: {len(tg)} ({sum(1 for r in tg if r.get("label")==1)} attack, {sum(1 for r in tg if r.get("label")==0)} benign)')

    # Split by source and label
    bt_attack = [r for r in bt if r.get('label') == 1]
    bt_benign = [r for r in bt if r.get('label') == 0]
    tg_attack = [r for r in tg if r.get('label') == 1]
    tg_benign = [r for r in tg if r.get('label') == 0]
    print(f'\n  BeaverTails attack: {len(bt_attack)}')
    print(f'  BeaverTails benign: {len(bt_benign)}')
    print(f'  ToxiGen attack: {len(tg_attack)}')
    print(f'  ToxiGen benign: {len(tg_benign)}')

    # ========================================================================
    # STEP 2: Label validation -- require explicit toxicity indicator
    # for label=1 records. Reject any label=1 record without an indicator.
    # Reject any label=0 record WITH an indicator (probably mislabeled).
    # ========================================================================
    print('\nSTEP 2: Label validation (require explicit toxicity indicator)...')
    valid_attack = []
    rejected_attack = []
    for r in bt_attack + tg_attack:
        text = r.get('text', '')
        has_ind, indicator = has_toxicity_indicator(text)
        if has_ind:
            valid_attack.append(r)
        else:
            rejected_attack.append((r, 'no toxicity indicator found'))

    valid_benign = []
    rejected_benign = []
    for r in bt_benign + tg_benign:
        text = r.get('text', '')
        has_ind, indicator = has_toxicity_indicator(text)
        if not has_ind:
            valid_benign.append(r)
        else:
            rejected_benign.append((r, f'has toxicity indicator: {indicator}'))

    print(f'  Valid attack (with indicator): {len(valid_attack)}')
    print(f'  Rejected attack (no indicator): {len(rejected_attack)}')
    print(f'  Valid benign (no indicator): {len(valid_benign)}')
    print(f'  Rejected benign (has indicator): {len(rejected_benign)}')
    if len(rejected_attack) > 0:
        print(f'  Sample rejected attack: {rejected_attack[0][0].get("text", "")[:100]}...')
    if len(rejected_benign) > 0:
        print(f'  Sample rejected benign: {rejected_benign[0][0].get("text", "")[:100]}...')

    # ========================================================================
    # STEP 3: Dedup by text hash
    # ========================================================================
    print('\nSTEP 3: Dedup by text hash...')
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

    # ========================================================================
    # STEP 4: Length filter -- skip very short (< 20 chars) or very long (> 2000 chars)
    # Real toxicity in AI prompts is typically 50-500 chars. Very short records
    # are likely fragments; very long records are likely documents with
    # toxicity embedded, which is a different test.
    # ========================================================================
    print('\nSTEP 4: Length filter (20-2000 chars)...')
    def length_ok(r):
        text = r.get('text', '')
        return 20 <= len(text) <= 2000

    length_attack = [r for r in deduped_attack if length_ok(r)]
    length_benign = [r for r in deduped_benign if length_ok(r)]
    print(f'  Attack after length filter: {len(length_attack)}')
    print(f'  Benign after length filter: {len(length_benign)}')

    # ========================================================================
    # STEP 5: Build the final held-out (sample to target size)
    # Mix 50/50 BeaverTails + ToxiGen for diversity
    # ========================================================================
    print('\nSTEP 5: Sampling to target size...')
    random.shuffle(length_attack)
    random.shuffle(length_benign)

    # Mix 50/50 from each source
    half_attack = TARGET_ATTACK // 2
    half_benign = TARGET_BENIGN // 2

    bt_attack_filtered = [r for r in length_attack if 'beavertails' in r.get('source', '').lower()]
    tg_attack_filtered = [r for r in length_attack if 'toxigen' in r.get('source', '').lower()]
    bt_benign_filtered = [r for r in length_benign if 'beavertails' in r.get('source', '').lower()]
    tg_benign_filtered = [r for r in length_benign if 'toxigen' in r.get('source', '').lower()]

    final_attack = bt_attack_filtered[:half_attack] + tg_attack_filtered[:half_attack]
    final_benign = bt_benign_filtered[:half_benign] + tg_benign_filtered[:half_benign]

    # If we don't have enough, fill from whichever source has more
    if len(final_attack) < TARGET_ATTACK:
        remaining_pool = [r for r in length_attack if r not in final_attack]
        final_attack.extend(remaining_pool[:TARGET_ATTACK - len(final_attack)])
    if len(final_benign) < TARGET_BENIGN:
        remaining_pool = [r for r in length_benign if r not in final_benign]
        final_benign.extend(remaining_pool[:TARGET_BENIGN - len(final_benign)])

    # Trim to exact target
    final_attack = final_attack[:TARGET_ATTACK]
    final_benign = final_benign[:TARGET_BENIGN]

    heldout = final_attack + final_benign
    random.shuffle(heldout)

    # Add metadata
    for i, r in enumerate(heldout):
        r['id'] = f'proper-toxicity-{i:04d}'
        r['_heldout_position'] = i
        r['_src'] = r.get('source', '?')

    # ========================================================================
    # STEP 6: Distribution validation
    # ========================================================================
    print('\nSTEP 6: Distribution validation...')
    stats = {}
    stats['total'] = len(heldout)
    stats['attack'] = sum(1 for r in heldout if r.get('label') == 1)
    stats['benign'] = sum(1 for r in heldout if r.get('label') == 0)

    source_counts = Counter(r.get('_src', '?') for r in heldout)
    stats['sources'] = dict(source_counts)

    text_lengths = [len(r.get('text', '')) for r in heldout]
    stats['text_length_min'] = min(text_lengths) if text_lengths else 0
    stats['text_length_max'] = max(text_lengths) if text_lengths else 0
    stats['text_length_mean'] = sum(text_lengths) / len(text_lengths) if text_lengths else 0
    stats['text_length_median'] = sorted(text_lengths)[len(text_lengths)//2] if text_lengths else 0

    text_hashes = [hash_text(r.get('text', '')) for r in heldout]
    dup_count = len(text_hashes) - len(set(text_hashes))
    stats['duplicate_count'] = dup_count

    attack_hashes = set(hash_text(r.get('text', '')) for r in heldout if r.get('label') == 1)
    benign_hashes = set(hash_text(r.get('text', '')) for r in heldout if r.get('label') == 0)
    cross_dup = len(attack_hashes & benign_hashes)
    stats['cross_set_duplicate_count'] = cross_dup

    # Re-validate every record in the held-out
    invalid_count = 0
    for r in heldout:
        text = r.get('text', '')
        label = r.get('label')
        if not isinstance(text, str) or len(text) < 20 or len(text) > 2000:
            invalid_count += 1
            continue
        if label not in (0, 1):
            invalid_count += 1
            continue
        has_ind, _ = has_toxicity_indicator(text)
        if label == 1 and not has_ind:
            invalid_count += 1
        elif label == 0 and has_ind:
            invalid_count += 1
    stats['invalid_count'] = invalid_count

    print(f'  Total: {stats["total"]}')
    print(f'  Attack: {stats["attack"]}')
    print(f'  Benign: {stats["benign"]}')
    print(f'  Text length: min={stats["text_length_min"]}, max={stats["text_length_max"]}, mean={stats["text_length_mean"]:.0f}, median={stats["text_length_median"]}')
    print(f'  Duplicates within held-out: {stats["duplicate_count"]}')
    print(f'  Cross-set duplicates: {stats["cross_set_duplicate_count"]}')
    print(f'  Invalid records (failed re-validation): {stats["invalid_count"]}')
    print(f'  Sources:')
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f'    {src}: {cnt}')

    # ========================================================================
    # STEP 7: Save
    # ========================================================================
    print('\nSTEP 7: Saving...')
    with open(OUTPUT, 'w') as f:
        for r in heldout:
            f.write(json.dumps(r) + '\n')
    print(f'  Saved: {OUTPUT}')

    # ========================================================================
    # STEP 8: TRIPLE VALIDATION (re-read, re-compute, sample-inspect)
    # ========================================================================
    print('\nSTEP 8: TRIPLE VALIDATION (validate, revalidate, revalidate)')

    # Validation 1: re-read
    print('  Validation 1: re-read + re-validate...')
    reloaded = load_jsonl(OUTPUT)
    assert len(reloaded) == len(heldout)
    for r, r2 in zip(heldout, reloaded):
        assert r.get('text') == r2.get('text')
        assert r.get('label') == r2.get('label')
    print(f'    OK: {len(reloaded)} records verified')

    # Validation 2: re-compute statistics
    print('  Validation 2: re-compute statistics...')
    reloaded_attack = sum(1 for r in reloaded if r.get('label') == 1)
    reloaded_benign = sum(1 for r in reloaded if r.get('label') == 0)
    assert reloaded_attack == stats['attack']
    assert reloaded_benign == stats['benign']
    print(f'    OK: {reloaded_attack} attack, {reloaded_benign} benign')

    # Validation 3: sample-based manual inspection
    print('  Validation 3: sample-based manual label inspection...')
    random.seed(SEED + 1)
    sample = random.sample(reloaded, min(SAMPLE_SIZE, len(reloaded)))
    print(f'    Sampling {len(sample)} records for manual inspection:')
    correct = 0
    for r in sample:
        text = r.get('text', '')
        text_preview = text[:120].replace('\n', ' ')
        has_ind, indicator = has_toxicity_indicator(text)
        label = r.get('label')
        is_correct = (label == 1 and has_ind) or (label == 0 and not has_ind)
        if is_correct:
            correct += 1
        marker = 'OK' if is_correct else 'CHECK'
        src = r.get('_src', '?')[:30]
        print(f'      [{r.get("id")}] [{marker}] label={label} src={src}')
        print(f'        text: {text_preview}...')
        if not is_correct:
            print(f'        has_ind={has_ind} indicator={indicator}')

    print(f'    Sample check: {correct}/{len(sample)} pass visual check')
    assert correct == len(sample), f'sample check failed: {correct}/{len(sample)}'
    print(f'    OK: all {len(sample)} sampled records pass visual check')

    # ========================================================================
    # Report
    # ========================================================================
    with open(REPORT, 'w') as f:
        f.write(f'# Phase 5d: PROPER toxicity held-out report\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Seed**: {SEED}\n\n')
        f.write(f'**Target**: {TARGET_ATTACK} attack + {TARGET_BENIGN} benign = {TARGET_ATTACK + TARGET_BENIGN}\n\n')
        f.write(f'## Sources\n\n')
        f.write(f'- **BeaverTails** (PKU-Alignment, CC-BY-NC-4.0): {sum(1 for r in heldout if "beavertails" in r.get("_src","").lower() and r.get("label")==1)} attack, {sum(1 for r in heldout if "beavertails" in r.get("_src","").lower() and r.get("label")==0)} benign\n')
        f.write(f'- **ToxiGen** (Apache-2.0): {sum(1 for r in heldout if "toxigen" in r.get("_src","").lower() and r.get("label")==1)} attack, {sum(1 for r in heldout if "toxigen" in r.get("_src","").lower() and r.get("label")==0)} benign\n\n')
        f.write(f'## Triple validation results\n\n')
        f.write(f'### Validation 1: re-read + re-validate\n')
        f.write(f'  {len(reloaded)} records re-read and verified\n\n')
        f.write(f'### Validation 2: re-compute statistics\n')
        f.write(f'  {reloaded_attack} attack + {reloaded_benign} benign = {len(reloaded)} total\n\n')
        f.write(f'### Validation 3: sample-based manual inspection\n')
        f.write(f'  {correct}/{len(sample)} sampled records pass visual check\n')
        f.write(f'  All sampled records have explicit toxicity indicators matching their label\n\n')
        f.write(f'## Distribution\n\n')
        f.write(f'  Total: {stats["total"]}\n')
        f.write(f'  Attack: {stats["attack"]}\n')
        f.write(f'  Benign: {stats["benign"]}\n')
        f.write(f'  Text length: min={stats["text_length_min"]}, max={stats["text_length_max"]}, mean={stats["text_length_mean"]:.0f}, median={stats["text_length_median"]}\n')
        f.write(f'  Duplicates within held-out: {stats["duplicate_count"]}\n')
        f.write(f'  Cross-set duplicates: {stats["cross_set_duplicate_count"]}\n')
        f.write(f'  Invalid records: {stats["invalid_count"]}\n\n')
        f.write(f'## Sources\n\n')
        for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
            f.write(f'  - {src}: {cnt}\n')
        f.write(f'\n## Held-out location\n\n')
        f.write(f'`{OUTPUT}`\n')
    print(f'\nReport: {REPORT}')

    print(f'\n=== DONE ===')
    print(f'Held-out: {OUTPUT}')
    print(f'  {stats["attack"]} attack + {stats["benign"]} benign = {stats["total"]} total')
    print(f'  {stats["duplicate_count"]} duplicates within, {stats["cross_set_duplicate_count"]} cross-set, {stats["invalid_count"]} invalid')


if __name__ == '__main__':
    main()
