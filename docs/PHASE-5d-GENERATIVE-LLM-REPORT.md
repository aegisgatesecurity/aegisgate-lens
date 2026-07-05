# Phase 5d v4: Generative LLM toxicity detection report

**Date**: 2026-07-05

**Model**: gemma3:1b (via Ollama, localhost:11434)

**Architecture**: generative LLM with structured JSON output prompt

**Held-out**: 700 records (500 attack + 200 benign) from google/civil_comments test split

**Inference time**: 1408.4s total, 0.5 req/s


## Results

### Ship gate NOT met.

Best F1 with FPR <= 5%: {'threshold': 0.96, 'recall': 0.0, 'fpr': 0.0, 'f1': 0.0, 'tp': 0, 'fn': 500, 'fp': 0, 'tn': 200}


### is_toxic alone (no confidence threshold)

recall=0.4540, fpr=0.5550, f1=0.5418

