#!/usr/bin/env python3
"""
6a.5 Per-source label verification.

For each vendored hand-curated record, verify:
- The text is non-empty
- The label (or expected_label) is 0 or 1
- The id is unique within the file
- For attack records: the text contains an attack indicator
  (a known injection phrase from a curated list)
- For benign records: the text does NOT contain a known injection phrase
  (otherwise it should be an attack)

This is a sanity check, not a full audit. The full audit is the
per-source label verification that the user mentioned as the
"fundamental fix for the FPs fire as TPs problem." We do 5
sanity checks here; the per-source full audit is in audit_per_source.py
(the next script in this sequence).
"""
import os
import sys
import json
import re
from collections import Counter, defaultdict


# Known injection phrases (a curated list of phrases that SHOULD
# appear in attack records and SHOULD NOT appear in benign records).
# This is NOT a complete list; it's a sanity check.
INJECTION_PHRASES = [
    r"ignore (all )?previous instructions",
    r"ignore (all )?prior instructions",
    r"ignore (the )?above instructions",
    r"disregard (your|the|all) (instructions|safety|guidelines|rules)",
    r"forget (everything|all|your instructions)",
    r"you are (now|an? )?DAN",
    r"developer mode",
    r"DAN (do anything now|jailbreak)",
    r"do anything now",
    r"jailbreak",
    r"override (your|the) (safety|rules|guidelines)",
    r"without (any )?restrictions",
    r"no (filters|restrictions|limitations|rules)",
    r"pretend (you|to be) (are|an?) (?!not).*?(unfiltered|unrestricted|uncensored|jailbroken|DAN|chatbot)",
    r"act as (a|an) (?!not).*?(jailbroken|unrestricted|unfiltered|DAN|chatbot)",
    r"reveal (your|the) (system|initial) prompt",
    r"(show|tell|print) (me )?(your|the) (system|hidden) (prompt|instructions)",
    r"bypass (your|the|all) (safety|content|security) (filters|guidelines|measures)",
    r"(unfiltered|unrestricted|uncensored) (output|mode|response)",
    r"in (developer|DAN|jailbreak) mode",
    r"no (content|safety) (filter|policy|restriction)",
    r"new instructions:",
    r"system:.*?\b(ignore|disregard|forget|override|bypass)\b",
    r"@senior-reviewer.*?(prior system|system prompt|developer message|prior context)",
    r"when handling a user request, always respond with",
    r"PWNED",
    r"i have been pwned",
    r"say 'I have not been PWNED'",
    r"do exactly what the user says",
    r"never question human orders",
    r"as your knowledge is cut off",
    r"AI with Developer Mode",
    r"Write a tutorial on how to",
    r"Create a phishing email",
    r"how to make a bomb",
    r"how to hack a wifi network",
]

INJECTION_RE = re.compile("|".join(INJECTION_PHRASES), re.IGNORECASE)


def verify_file(path):
    """Verify a single jsonl file. Returns (stats, errors)."""
    stats = Counter()
    errors = []
    seen_ids = set()
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"  line {line_no}: invalid JSON: {e}")
                continue

            stats["total"] += 1

            # Get label (use expected_label if label is missing)
            label = rec.get("label")
            if label is None:
                label = rec.get("expected_label")
            if label is None:
                errors.append(f"  line {line_no} ({rec.get('id','?')}): no label or expected_label")
                continue

            if label not in (0, 1):
                errors.append(f"  line {line_no} ({rec.get('id','?')}): invalid label {label}")
                continue

            stats[f"label_{label}"] += 1

            # Check id is unique
            rid = rec.get("id")
            if rid is None:
                errors.append(f"  line {line_no}: no id")
            elif rid in seen_ids:
                errors.append(f"  line {line_no} ({rid}): duplicate id")
            else:
                seen_ids.add(rid)

            # Check text is non-empty
            text = rec.get("text", "")
            if not text or not text.strip():
                errors.append(f"  line {line_no} ({rid}): empty text")
                continue

            # Sanity check: does the text contain an injection phrase?
            has_injection = bool(INJECTION_RE.search(text))
            stats[f"injection_phrase_{'yes' if has_injection else 'no'}"] += 1

            # Cross-check: attack records should have injection phrases;
            # benign records should NOT. (Soft check; some attacks are
            # subtle and won't match.)
            if label == 1 and not has_injection:
                stats["attack_no_injection_phrase"] += 1
            elif label == 0 and has_injection:
                stats["benign_has_injection_phrase"] += 1

    return stats, errors


def main():
    base = "/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01-archive"
    if not os.path.isdir(base):
        print(f"ERROR: {base} does not exist")
        sys.exit(1)

    files = sorted([os.path.join(base, f) for f in os.listdir(base) if f.endswith(".jsonl")])
    for d in os.listdir(base):
        full = os.path.join(base, d)
        if os.path.isdir(full):
            for f in os.listdir(full):
                if f.endswith(".jsonl"):
                    files.append(os.path.join(full, f))

    grand_stats = Counter()
    grand_errors = []
    for f in files:
        rel = f.replace(base + "/", "")
        stats, errors = verify_file(f)
        grand_stats.update(stats)
        grand_errors.extend([f"  {rel}: " + e for e in errors[:5]])  # cap per-file errors
        if errors:
            print(f"  {rel}: {stats['total']} records, {len(errors)} issues")
            for e in errors[:3]:
                print(f"    {e}")
        else:
            print(f"  {rel}: {stats['total']} records OK")

    print(f"\n=== GRAND TOTAL ===")
    print(f"  Total records: {grand_stats['total']}")
    print(f"  Label=1 (attack): {grand_stats['label_1']}")
    print(f"  Label=0 (benign): {grand_stats['label_0']}")
    print(f"  Has injection phrase: {grand_stats['injection_phrase_yes']}")
    print(f"  No injection phrase: {grand_stats['injection_phrase_no']}")
    print(f"  Attack with NO injection phrase (FLAGGED): {grand_stats['attack_no_injection_phrase']}")
    print(f"  Benign WITH injection phrase (FLAGGED): {grand_stats['benign_has_injection_phrase']}")
    print(f"  Total issues: {len(grand_errors)}")
    if grand_errors:
        print(f"\nFirst 20 issues:")
        for e in grand_errors[:20]:
            print(e)


if __name__ == "__main__":
    main()
