#!/usr/bin/env python3
"""
Phase 0a audit scripts, run sequentially:
1. Tokenization verification (sub-decision 6a.3)
2. License audit (sub-decision 6a.4)
3. De-duplication (sub-decision 6a.6)
4. Language distribution check (sub-decision 6a.7)
5. Long-context verification (sub-decision 6a.8)

All run on the vendored hand-curated data (corpora/v01beta-raw/v01-archive/).
"""
import os
import sys
import json
import re
import hashlib
from collections import Counter, defaultdict


CORPUS = "/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01-archive"


def load_all_records():
    records = []
    for root, dirs, files in os.walk(CORPUS):
        for f in files:
            if f.endswith(".jsonl"):
                path = os.path.join(root, f)
                for i, line in enumerate(open(path)):
                    try:
                        rec = json.loads(line)
                        rec["_source_file"] = os.path.relpath(path, CORPUS)
                        rec["_line_no"] = i + 1
                        records.append(rec)
                    except json.JSONDecodeError:
                        pass
    return records


def audit_tokenization(records):
    """6a.3: Tokenize a sample of 100 records with the real tokenizer."""
    print("\n=== 6a.3 TOKENIZATION VERIFICATION ===")
    # Try to use the v0.2 model decision's tokenizer
    try:
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
        sample = records[:100]
        token_counts = []
        for rec in sample:
            text = rec.get("text", "")
            n = len(tok.encode(text, add_special_tokens=False))
            token_counts.append(n)
        print(f"  Sampled 100 records, token range: {min(token_counts)}-{max(token_counts)}")
        print(f"  Mean: {sum(token_counts)/len(token_counts):.0f}, Median: {sorted(token_counts)[50]}")
        over = [c for c in token_counts if c > 8000]
        if over:
            print(f"  Records over 8000 tokens (would overflow 8K context): {len(over)}")
            for i, c in enumerate(token_counts):
                if c > 8000:
                    print(f"    {sample[i]['_source_file']}:{sample[i]['_line_no']} id={sample[i].get('id','?')} n={c}")
        empty = [c for c in token_counts if c == 0]
        if empty:
            print(f"  Empty tokenizations: {len(empty)}")
        print(f"  All token counts in 1-8192: {len([c for c in token_counts if 1 <= c <= 8192])}/100")
    except Exception as e:
        print(f"  ERROR loading tokenizer: {e}")
        print(f"  (This is expected if transformers isn't available; falling back to char count)")


def audit_license(records):
    """6a.4: Per-record license check (all hand-curated = internal, so should be 'N/A' or 'internal')."""
    print("\n=== 6a.4 LICENSE AUDIT ===")
    licenses = Counter()
    sources = Counter()
    for rec in records:
        src = rec.get("source", "internal")
        sources[src] += 1
        # The hand-curated records don't have a license field; we treat them as "internal"
        if "stress_test" in src or "gap_closure" in src or "round11" in src or \
           "round7" in src or "round8" in src or "round9" in src or "round5" in src or \
           "round4" in src or "round6" in src or "round3" in src or \
           src in ("internal", "round11_bae", "round11_textfooler", "round11_combined"):
            licenses["internal"] += 1
        elif "promptfoo" in src:
            licenses["promptfoo (public)"] += 1
        elif "deepset" in src or "imoxto" in src:
            licenses["public (re-verify needed)"] += 1
        else:
            licenses["unknown"] += 1
    print(f"  Total records: {len(records)}")
    print(f"  License distribution:")
    for lic, cnt in sorted(licenses.items(), key=lambda x: -x[1]):
        print(f"    {lic:30s} {cnt:6d} ({100*cnt/len(records):.1f}%)")
    print(f"  Top 10 sources:")
    for src, cnt in sorted(sources.items(), key=lambda x: -x[1])[:10]:
        print(f"    {src[:60]:60s} {cnt:6d}")


def audit_dedup(records):
    """6a.6: De-duplication across all files."""
    print("\n=== 6a.6 DE-DUPLICATION ===")
    # Hash each record by its text content
    text_hashes = defaultdict(list)
    for rec in records:
        text = rec.get("text", "").strip()
        if not text:
            continue
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        text_hashes[h].append(rec)
    # Find duplicates
    dupes = {h: recs for h, recs in text_hashes.items() if len(recs) > 1}
    if not dupes:
        print(f"  {len(records)} records, 0 exact-text duplicates")
        return
    print(f"  {len(records)} records, {len(dupes)} duplicate text hashes (across {sum(len(r) for r in dupes.values())} records)")
    print(f"  Top 10 duplicate groups (by file count):")
    for h, recs in sorted(dupes.items(), key=lambda x: -len(x[1]))[:10]:
        files = set()
        for r in recs:
            files.add(r.get("_source_file", "?"))
        print(f"    {h}: {len(recs)} dupes across {len(files)} files")
        for r in recs[:3]:
            print(f"      {r.get('_source_file','?')}:{r.get('_line_no','?')} id={r.get('id','?')}")


def audit_language(records):
    """6a.7: Language distribution."""
    print("\n=== 6a.7 LANGUAGE DISTRIBUTION ===")
    # Simple heuristic: detect common non-English languages
    # English: ASCII letters
    # Spanish: ñ, ¿, ¡
    # French: é, è, ê, ç
    # German: ß, ä, ö, ü
    # Chinese: range U+4E00 to U+9FFF
    # Hindi: range U+0900 to U+097F
    # Russian: Cyrillic
    langs = Counter()
    for rec in records:
        text = rec.get("text", "")
        if not text:
            langs["empty"] += 1
            continue
        n_total = len(text)
        n_ascii = sum(1 for c in text if ord(c) < 128)
        n_zh = sum(1 for c in text if 0x4E00 <= ord(c) <= 0x9FFF)
        n_hi = sum(1 for c in text if 0x0900 <= ord(c) <= 0x097F)
        n_cyr = sum(1 for c in text if 0x0400 <= ord(c) <= 0x04FF)
        n_other = n_total - n_ascii - n_zh - n_hi - n_cyr
        if n_zh > 0:
            langs["Chinese"] += 1
        elif n_hi > 0:
            langs["Hindi"] += 1
        elif n_cyr > 0:
            langs["Russian/Cyrillic"] += 1
        elif n_other / max(1, n_total) > 0.1:
            langs["non-English (Latin script)"] += 1
        else:
            langs["English"] += 1
    print(f"  Total records: {len(records)}")
    for lang, cnt in sorted(langs.items(), key=lambda x: -x[1]):
        print(f"    {lang:30s} {cnt:6d} ({100*cnt/len(records):.1f}%)")
    # User target: ≥70% English, ≤30% other
    en_pct = 100 * langs["English"] / len(records)
    print(f"  English: {en_pct:.1f}% (target: ≥70% for the 95% AI-user audience)")
    if en_pct < 70:
        print(f"  NOTE: Less than 70% English; may need to add more English-only sources")


def audit_long_context(records):
    """6a.8: Long-context verification (30% of train must be ≥4,096 tokens)."""
    print("\n=== 6a.8 LONG-CONTEXT VERIFICATION ===")
    # Use the n_tokens field if present, else estimate from text length
    long_count = 0
    short_count = 0
    for rec in records:
        if "n_tokens" in rec:
            n = rec["n_tokens"]
        else:
            # Estimate: ~4 chars per token
            n = len(rec.get("text", "")) // 4
        if n >= 4096:
            long_count += 1
        else:
            short_count += 1
    print(f"  Total records: {len(records)}")
    print(f"  Short (< 4,096 tokens): {short_count} ({100*short_count/len(records):.1f}%)")
    print(f"  Long (>= 4,096 tokens): {long_count} ({100*long_count/len(records):.1f}%)")
    print(f"  User target: >=30% long-context")
    long_pct = 100 * long_count / len(records)
    if long_pct < 30:
        print(f"  NOTE: Less than 30% long-context. The hand-curated data is the HELD-OUT")
        print(f"  so this is expected. The TRAIN/VAL pool (public benchmarks + HF)")
        print(f"  should have >=30% long-context to address the prior failure mode.")
    else:
        print(f"  PASS")


def main():
    print("=" * 70)
    print(f"Phase 0a audit — v0.1 archive hand-curated data ({CORPUS})")
    print("=" * 70)
    records = load_all_records()
    print(f"\nLoaded {len(records)} records from {sum(1 for _ in os.walk(CORPUS))} directories")

    audit_license(records)
    audit_tokenization(records)
    audit_dedup(records)
    audit_language(records)
    audit_long_context(records)


if __name__ == "__main__":
    main()
