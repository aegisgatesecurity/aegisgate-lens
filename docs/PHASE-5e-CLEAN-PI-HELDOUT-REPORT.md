# Phase 5e: CLEAN PI held-out report

**Date**: 2026-07-05

**Seed**: 20260705

**Source**: v0.1 long-context corpus (3,630 raw records)

## Cleaning steps

1. Raw validation: rejected 460 invalid records
2. Label validation: required PI indicator in attack records, rejected benign records with PI indicators
   - Rejected attack (no PI indicator): 643
   - Rejected benign (has PI indicator): 642
3. Dedup by text hash: 1885 -> 1350
4. Length filter (50-8000 chars): 1350 -> 591
5. Sample to target: 591

## Final held-out

  Total: 591
  Attack: 331
  Benign: 260
  Text length: min=50, max=7985, mean=2209, median=1321
  Internal duplicates: 0
  Cross-set duplicates: 0
  Invalid records: 0

## Triple validation results

  Re-read: PASS
  Re-compute statistics: PASS
  Sample inspection: 30/30 pass

## Held-out location

`/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01beta-CLEAN-PI-heldout.jsonl`
