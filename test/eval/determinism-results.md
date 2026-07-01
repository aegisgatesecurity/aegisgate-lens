# Item F — Determinism Results (2026-06-28)

## Summary

- **All deterministic**: ✅ YES
- **Classification accuracy**: 5/5 prompts correctly classified
- **Runs per prompt**: 10
- **FP tolerance**: 1e-06

## Per-prompt details

| ID | Description | Text length | Mean P(attack) | Range | Deterministic | Correctly classified |
|----|-------------|-------------|----------------|-------|---------------|---------------------|
| p1_benign_short | Benign short | 58 | 0.000000 | 0.00e+00 | ✅ | ✅ |
| p2_attack_short | Attack short (classic injection) | 75 | 1.000000 | 0.00e+00 | ✅ | ✅ |
| p3_benign_long | Benign long (legal boilerplate, no injection) | 14250 | 0.020172 | 0.00e+00 | ✅ | ✅ |
| p4_attack_long | Attack long (injection embedded at char ~2700) | 9495 | 0.999995 | 0.00e+00 | ✅ | ✅ |
| p5_edge_case | Edge case (minimal content) | 6 | 0.003172 | 0.00e+00 | ✅ | ✅ |


## Raw scores (all 10 runs per prompt)

- **p1_benign_short**: [0.00000001, 0.00000001, 0.00000001, 0.00000001, 0.00000001, 0.00000001, 0.00000001, 0.00000001, 0.00000001, 0.00000001]
- **p2_attack_short**: [1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000, 1.00000000]
- **p3_benign_long**: [0.02017177, 0.02017177, 0.02017177, 0.02017177, 0.02017177, 0.02017177, 0.02017177, 0.02017177, 0.02017177, 0.02017177]
- **p4_attack_long**: [0.99999547, 0.99999547, 0.99999547, 0.99999547, 0.99999547, 0.99999547, 0.99999547, 0.99999547, 0.99999547, 0.99999547]
- **p5_edge_case**: [0.00317224, 0.00317224, 0.00317224, 0.00317224, 0.00317224, 0.00317224, 0.00317224, 0.00317224, 0.00317224, 0.00317224]


## Verdict

**PASS**: All 50 scores byte-identical within FP tolerance. Model is deterministic.

## Saved artifacts

- `test/eval/determinism-results.json` — full results with all 50 raw scores
- `test/eval/determinism-results.md` — this file
