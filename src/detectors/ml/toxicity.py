#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Tier 5 Toxicity Detector
========================================================

Loads `unitary/toxic-bert` (Apache-2.0, 6-class Jigsaw taxonomy)
and runs inference on a prompt text. Returns events in the
v0.1.0-beta 7-category schema.

The 6 unitary/toxic-bert output categories map to 6 of our 7
schema categories. The remaining 2 (`toxicity_sexual`,
`toxicity_self_harm`) are handled by regex fallback (see
`src/detectors/regex/compliance.js` or a new `toxicity.js`).

The detector is:
- 100% on-device (no network calls)
- 100% deterministic (no model mutations)
- Idempotent (same text -> same output)

Usage:
    # From Python:
    from toxicity import detect
    events = detect("You are an idiot")
    # Returns: [{'facet': 'toxicity', 'category': 'toxicity_insult', ...}, ...]

    # From Node/JS via subprocess:
    # (not yet implemented; future work)

The detector is invoked from `src/detectors/index.js` (the
6-facet dispatcher) when the regex chain has fired AND
toxicity inference is needed. Per the v0.3 architecture,
toxicity is Tier 5 -- a pre-trained model, no fine-tuning,
loaded lazily from the service worker.

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

# Lazy model loading (only load when detect() is first called)
_MODEL = None
_TOKENIZER = None

# Default thresholds per category (from the unitary/toxic-bert model card).
# Each of the 6 categories has its own threshold. We use 0.5 as the
# default. Future versions may adjust per category.
DEFAULT_THRESHOLDS = {
    'toxic': 0.5,
    'severe_toxic': 0.5,
    'obscene': 0.5,
    'threat': 0.5,
    'insult': 0.5,
    'identity_hate': 0.5,
}

# Mapping from unitary/toxic-bert's 6 raw outputs to our 7 schema
# categories (per docs/PHASE-5a-COMPLETION.md and the v0.1.0-beta
# model decision doc). The 2 missing categories (toxicity_sexual,
# toxicity_self_harm) are handled by regex fallback.
RAW_TO_SCHEMA = {
    'toxic':         ('toxicity_hate',     'high'),
    'severe_toxic':  ('toxicity_violence', 'high'),
    'obscene':       ('toxicity_obscene',  'medium'),
    'threat':        ('toxicity_threat',   'high'),
    'insult':        ('toxicity_insult',   'medium'),
    'identity_hate': ('toxicity_hate',     'high'),
    # toxicity_sexual -> regex fallback (Phase 5b)
    # toxicity_self_harm -> regex fallback (Phase 5b)
}

# Schema version (per the architecture spec)
SCHEMA_VERSION = '0.1.0-beta'


def _load_model():
    """Lazy-load the model and tokenizer. Cached after first call."""
    global _MODEL, _TOKENIZER
    if _MODEL is not None and _TOKENIZER is not None:
        return _MODEL, _TOKENIZER

    # Suppress HuggingFace progress bars (per the data audit gotcha)
    os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch

    model_name = 'unitary/toxic-bert'
    cache_dir = os.environ.get('LENS_MODEL_CACHE', '/tmp/lens-model-cache')
    os.makedirs(cache_dir, exist_ok=True)

    _TOKENIZER = AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
    _MODEL = AutoModelForSequenceClassification.from_pretrained(model_name, cache_dir=cache_dir)
    _MODEL.eval()
    return _MODEL, _TOKENIZER


def detect(text: str, thresholds: Optional[Dict[str, float]] = None) -> List[Dict[str, Any]]:
    """
    Run toxicity detection on a text. Returns a list of events
    in the v0.1.0-beta schema.

    Args:
        text: The input text to scan.
        thresholds: Optional dict overriding the default per-category
            thresholds. Format: {'toxic': 0.5, 'severe_toxic': 0.5, ...}.

    Returns:
        List of events, each in the format:
        {
            'facet': 'toxicity',
            'category': 'toxicity_insult',  # one of the 7 schema categories
            'severity': 'medium',  # 'critical' | 'high' | 'medium' | 'low'
            'confidence': 0.87,  # 0.0 - 1.0
            'ml_score': 0.87,  # raw model output (sigmoid)
            'ml_model_version': 'unitary/toxic-bert@<commit>',
        }

    Returns empty list if text is empty or no category exceeds its
    threshold (i.e., the text is benign).
    """
    if not isinstance(text, str) or not text:
        return []

    if thresholds is None:
        thresholds = DEFAULT_THRESHOLDS

    # Lazy import (so loading the module is fast)
    import torch
    model, tokenizer = _load_model()

    # Tokenize (RoBERTa base has 512 token limit; we truncate)
    # For long texts, we could chunk and aggregate, but for v0.1.0-beta
    # we use the simple approach: take the first 512 tokens.
    # Future versions: chunk + max-pool (per the v0.3 architecture).
    inputs = tokenizer(
        text,
        return_tensors='pt',
        truncation=True,
        max_length=512,
        padding=False,
    )

    # Inference (no grad)
    with torch.no_grad():
        outputs = model(**inputs)
    logits = outputs.logits[0]
    probs = torch.sigmoid(logits)

    events = []
    for i, (raw_cat, (schema_cat, severity)) in enumerate(RAW_TO_SCHEMA.items()):
        threshold = thresholds.get(raw_cat, DEFAULT_THRESHOLDS.get(raw_cat, 0.5))
        prob = float(probs[i].item())
        if prob >= threshold:
            events.append({
                'facet': 'toxicity',
                'category': schema_cat,
                'severity': severity,
                'confidence': round(prob, 4),
                'ml_score': round(prob, 4),
                'ml_model_version': 'unitary/toxic-bert',
            })

    return events


# CLI for testing
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python3 toxicity.py "<text>"')
        sys.exit(1)
    text = ' '.join(sys.argv[1:])
    events = detect(text)
    if not events:
        print(f"No toxicity detected in: {text[:80]}")
    else:
        print(f"Detected {len(events)} toxicity event(s) in: {text[:80]}")
        for e in events:
            print(f"  {e['category']:25s} severity={e['severity']:8s} ml_score={e['ml_score']:.3f}")
