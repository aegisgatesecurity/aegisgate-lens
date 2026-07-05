# Phase 5d: PROPER toxicity held-out report

**Date**: 2026-07-05

**Seed**: 20260705

**Target**: 350 attack + 350 benign = 700

## Sources

- **BeaverTails** (PKU-Alignment, CC-BY-NC-4.0): 175 attack, 175 benign
- **ToxiGen** (Apache-2.0): 175 attack, 175 benign

## Triple validation results

### Validation 1: re-read + re-validate
  700 records re-read and verified

### Validation 2: re-compute statistics
  350 attack + 350 benign = 700 total

### Validation 3: sample-based manual inspection
  30/30 sampled records pass visual check
  All sampled records have explicit toxicity indicators matching their label

## Distribution

  Total: 700
  Attack: 350
  Benign: 350
  Text length: min=20, max=1383, mean=268, median=148
  Duplicates within held-out: 0
  Cross-set duplicates: 0
  Invalid records: 0

## Sources

  - PKU-Alignment_BeaverTails: 350
  - toxigen_toxigen-data: 350

## Held-out location

`/home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01beta-toxicity-PROPER-heldout.jsonl`
