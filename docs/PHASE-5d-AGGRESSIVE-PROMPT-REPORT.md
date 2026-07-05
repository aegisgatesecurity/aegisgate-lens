# Phase 5d v5: Aggressive prompt + Ministral3:3b report

**Date**: 2026-07-05

**Model**: ministral-3:3b (via Ollama)

**Prompt strategy**: AGGRESSIVE -- model told to flag any rudeness, sarcasm, name-calling, profanity, condescension, or unfriendly content per Civil Comments community standards.

**Total inference time**: 887.5s for 700 records = 0.8 req/s

**Parse failures**: 16/700


## Results

### Ship gate NOT met. Best F1 with FPR <= 5%: {'threshold': 1.0, 'recall': 0.082, 'fpr': 0.01, 'f1': 0.1510128913443831, 'tp': 41, 'fn': 459, 'fp': 2, 'tn': 198}

### is_toxic alone

recall=0.9660, fpr=0.8550, f1=0.8371

