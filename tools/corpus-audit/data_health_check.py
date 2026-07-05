#!/usr/bin/env python3
"""
Per Lesson BB: verify the data is not corrupted. The v0.1 failure
mode was "FPs fire as TPs and vice versa" — the labels were wrong.
We do 3 things:
1. Cross-split duplicate check (no text in train+val in held-out)
2. Per-source label consistency check (sample from each source)
3. Held-out manual review sample

If any of these fail, we MUST re-verify before retraining.
"""
import json
import random
import re
from collections import Counter, defaultdict

CORPUS = "/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw"

INJECTION_PHRASES = [
    r"ignore (all )?previous instructions", r"disregard (your|the|all) (instructions|safety|guidelines|rules)",
    r"forget (everything|all|your instructions)", r"you are (now|an? )?DAN",
    r"developer mode", r"DAN (do anything now|jailbreak)", r"do anything now",
    r"jailbreak", r"override (your|the) (safety|rules|guidelines)",
    r"without (any )?restrictions", r"no (filters|restrictions|limitations|rules)",
    r"reveal (your|the) (system|initial) prompt", r"in (developer|DAN|jailbreak) mode",
    r"new instructions:", r"@senior-reviewer", r"PWNED", r"AI with Developer Mode",
    r"how to make a bomb", r"how to hack a wifi network", r"Create a phishing email",
]
INJECTION_RE = re.compile("|".join(INJECTION_PHRASES), re.IGNORECASE)


# 1. Load all 3 splits
splits = {}
for split in ["v01beta-train.jsonl", "v01beta-val.jsonl", "v01beta-heldout.jsonl"]:
    records = []
    path = f"{CORPUS}/{split}"
    for line in open(path):
        try:
            records.append(json.loads(line))
        except Exception:
            pass
    splits[split] = records
    print(f"Loaded {split}: {len(records)} records")

# 2. CROSS-SPLIT DUPLICATE CHECK
print("\n=== CROSS-SPLIT DUPLICATE CHECK (the most important) ===")
text_to_split = defaultdict(list)
for split_name, recs in splits.items():
    for r in recs:
        text = r.get("text", "").strip()
        if text:
            text_to_split[text].append(split_name)
cross_leaks = {t: sps for t, sps in text_to_split.items() if len(set(sps)) > 1}
print(f"  Cross-split text duplicates (same text in 2+ splits): {len(cross_leaks)}")
if cross_leaks:
    print("  CRITICAL: this would invalidate the held-out!")
    print("  (text in train that ALSO appears in held-out means we tested on training data)")
    for t, sps in list(cross_leaks.items())[:5]:
        print(f"    '{t[:80]}...' in {set(sps)}")
else:
    print("  PASS: no cross-split duplicates. Held-out is truly held-out.")

# 3. SCHEMA CHECK
print("\n=== SCHEMA CHECK (all 3 splits) ===")
required_fields = ["id", "text", "label", "source"]
for split_name, recs in splits.items():
    bad = 0
    field_counts = Counter()
    for r in recs:
        for f in required_fields:
            if f not in r or r.get(f) in (None, ""):
                bad += 1
            else:
                field_counts[f] += 1
    print(f"  {split_name}: {len(recs) - bad} OK, {bad} missing fields")
    if bad:
        for f in required_fields:
            missing = sum(1 for r in recs if f not in r or r.get(f) in (None, ""))
            if missing:
                print(f"    {f}: {missing} records missing")

# 4. PER-SOURCE LABEL CHECK
print("\n=== PER-SOURCE LABEL CHECK (sample 5 from each source) ===")
sources = {}
for split_name, recs in splits.items():
    for r in recs:
        src = r.get("source", "unknown")
        if src not in sources:
            sources[src] = []
        sources[src].append((split_name, r))

for src, recs in sorted(sources.items()):
    print(f"\n  Source: {src} ({len(recs)} total records)")
    random.seed(20260704 + hash(src) % 10000)
    sample = random.sample(recs, min(5, len(recs)))
    for split_name, r in sample:
        label = r.get("label", r.get("expected_label"))
        text = r.get("text", "")[:160].replace(chr(10), " ")
        has_injection = bool(INJECTION_RE.search(r.get("text", "")))
        # soft check
        match = "MATCH" if (label == 1 and has_injection) or (label == 0 and not has_injection) else "SOFT-MISMATCH"
        print(f"    [{split_name:20s}] label={label} inj={has_injection} {match}")
        print(f"      '{text}...'")

# 5. HELD-OUT MANUAL REVIEW (30 samples, first 150 chars of each)
print("\n=== HELD-OUT MANUAL REVIEW (30 samples, first 150 chars) ===")
records = splits["v01beta-heldout.jsonl"]
random.seed(20260704)
sample = random.sample(records, 30)
for i, r in enumerate(sample):
    label = r.get("label", r.get("expected_label"))
    src = r.get("source", "?")
    cat = r.get("category", "?")
    sub = r.get("subcategory", "?")
    text = r.get("text", "")[:150].replace(chr(10), " ")
    print(f"\n[{i+1:2d}] label={label} source={src}")
    print(f"     cat={cat} sub={sub}")
    print(f"     '{text}...'")
