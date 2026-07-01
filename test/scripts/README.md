# `test/scripts/` — Phase 2 development scripts

This directory contains scripts used during Phase 2 (ModernBERT inference
path + sliding-window) development and validation. These are **dev
artifacts**, not shipped test code.

## Why these are separate from `test/*.test.mjs`

The committed test suite (`test/*.test.mjs`) runs as part of the regular
CI test pass and exercises the shipped code paths. The scripts here
were used to **make architectural decisions** (sizing, thresholds,
strategy) before committing to the final implementation.

Keeping them around means future contributors can:
1. Re-run the sizing experiment if a new corpus appears
2. Audit *why* the chosen max_length/stride/max_windows values
3. Compare alternate strategies without re-deriving the experiment

## Files

| Script | Purpose | Status |
|--------|---------|--------|
| `sliding-window-sizing.py` | A/B/C/D comparison of sliding-window strategies on r8_attack_long_context sample. Used to pick max_length=2048/stride=1024/max_windows=4. | Archived. Decision recorded in PROVENANCE-style header. |

## Re-running

```bash
# Activate venv
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02
source .venv-v02/bin/activate

# Run sizing experiment (uses 12-attack + 8-benign sample for speed)
python test/scripts/sliding-window-sizing.py
```

Output is printed to stdout. To archive a run's output:
```bash
python test/scripts/sliding-window-sizing.py 2>&1 | tee test/eval/sliding-window-sizing-$(date -u +%FT%H-%M-%SZ).log
```

## Why these aren't in `corpora/` or `tools/`

- `corpora/` is for **training/eval data only** (JSONL files + SHA256SUMS).
  Adding executable scripts would conflate data with code.
- `tools/` is for **shipped analysis scripts** (facet_gap_analysis.js,
  test_detectors_v2.js, etc.). These are invoked by the build pipeline.
  Adding dev-only experiment scripts would pollute that surface.

`test/scripts/` is the right home for Phase 2 dev artifacts.