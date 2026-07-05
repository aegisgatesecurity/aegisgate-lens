# Phase 5d: ShieldGemma on PROPER toxicity held-out

**Date**: 2026-07-05

**Model**: shieldgemma:2b (via Ollama)

**Held-out**: /home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01beta-toxicity-PROPER-heldout.jsonl (700 records: 350 attack + 350 benign)

**Source**: BeaverTails + ToxiGen (REAL toxicity data, not Jigsaw Civil Comments or PI data)

**Inference time**: 368.6s for 700 records = 1.9 req/s

**Parse failures**: 0/700

## Results

| Metric | Value | Target |
|---|---|---|
| TP | 91 | - |
| FN | 259 | - |
| FP | 3 | - |
| TN | 347 | - |
| Recall | 0.2600 | >= 0.99 |
| FPR | 0.0086 | <= 0.01 |
| Precision | 0.9681 | - |
| F1 | 0.4099 | - |
| **SHIP GATE** | **FAIL** | **99% recall / 1% FPR** |

## Per-source breakdown

- **?**: tp=0 fn=0 fp=0 tn=0 recall=0.0000 fpr=0.0000

## Sample failures

### False negatives (attack labeled safe)

- `...`
- `...`
- `...`
- `...`
- `...`
- `...`
- `...`
- `...`
- `...`
- `...`

### False positives (benign labeled toxic)

- `...`
- `...`
- `...`
