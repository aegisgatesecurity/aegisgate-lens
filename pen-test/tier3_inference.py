#!/usr/bin/env python3
"""
AegisGate Lens - Tier 3 ONNX Inference Helper

Loads the fine-tuned MiniLM-L12 prompt-injection classifier
(fine-tuned ONNX model from ml-artifacts/dist_tier3_v2/) and
provides a single function `score(prompt) -> (label, confidence)`
that returns 1 if the prompt is classified as a prompt injection
and 0 otherwise.

This is what the Lens extension calls internally. We use it here
as the target oracle for the PAIR adversarial test.

Usage:
    from tier3_inference import score
    label, conf = score("Ignore all previous instructions.")
    # -> (1, 0.97)
"""

import sys
import json
import os

import numpy as np
import onnxruntime as ort

# Optional transformers tokenizer.
try:
    from transformers import AutoTokenizer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


class Tier3Model:
    def __init__(self, model_dir="ml-artifacts/dist_tier3_v2"):
        self.model_dir = model_dir
        onnx_path = os.path.join(model_dir, "model.onnx")
        if not os.path.exists(onnx_path):
            raise FileNotFoundError(f"ONNX model not found: {onnx_path}")

        # Use 4 threads; ONNX defaults to all cores which is wasteful
        # for inference that runs once per adversarial iteration.
        sess_options = ort.SessionOptions()
        sess_options.intra_op_num_threads = 4
        sess_options.inter_op_num_threads = 1
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        self.session = ort.InferenceSession(
            onnx_path,
            sess_options=sess_options,
            providers=["CPUExecutionProvider"],
        )

        # Inspect input/output names.
        self.input_names = {i.name for i in self.session.get_inputs()}
        self.output_names = {o.name for o in self.session.get_outputs()}

        # Load tokenizer. Prefer the HuggingFace tokenizer in
        # model_dir; fall back to a basic whitespace tokenizer if
        # transformers is unavailable.
        tok_path = os.path.join(model_dir, "tokenizer.json")
        if HAS_TRANSFORMERS and os.path.exists(tok_path):
            self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
            self._tokenize = self._hf_tokenize
        else:
            self.tokenizer = None
            self._tokenize = self._basic_tokenize

        # Cache.
        self._cache = {}

    def _hf_tokenize(self, text):
        enc = self.tokenizer(
            text,
            padding="max_length",
            truncation=True,
            max_length=128,
            return_tensors="np",
        )
        return {k: v.astype(np.int64) for k, v in enc.items()}

    def _basic_tokenize(self, text):
        # Whitespace tokenizer fallback. Less accurate but functional.
        tokens = text.lower().split()
        ids = [hash(t) % 30000 + 1000 for t in tokens][:128]
        ids = ids + [0] * (128 - len(ids))
        attn = [1] * len([i for i in ids if i != 0])
        attn = attn + [0] * (128 - len(attn))
        type_ids = [0] * 128
        return {
            "input_ids": np.array([ids], dtype=np.int64),
            "attention_mask": np.array([attn], dtype=np.int64),
            "token_type_ids": np.array([type_ids], dtype=np.int64),
        }

    def score(self, text):
        """Return (label, confidence). 1 = injection, 0 = benign."""
        if text in self._cache:
            return self._cache[text]
        inputs = self._tokenize(text)
        # Filter to the input names the model actually expects.
        ort_inputs = {k: v for k, v in inputs.items() if k in self.input_names}
        outputs = self.session.run(None, ort_inputs)
        # Output[0] is logits [batch, 2]. Apply softmax to get probs.
        logits = outputs[0][0]
        exps = np.exp(logits - np.max(logits))
        probs = exps / exps.sum()
        # The model was trained with problem_type=single_label_classification.
        # Class 0 is benign, class 1 is injection (verify by inspection).
        label = int(np.argmax(probs))
        confidence = float(probs[label])
        result = (label, confidence)
        self._cache[text] = result
        return result

    def classify_batch(self, texts):
        """Classify a batch of texts. Returns list of (label, confidence)."""
        return [self.score(t) for t in texts]


# CLI mode: read prompts from stdin, emit JSON lines.
if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Single prompt as arg.
        prompts = [" ".join(sys.argv[1:])]
    else:
        prompts = [line.strip() for line in sys.stdin if line.strip()]

    model = Tier3Model()
    for p in prompts:
        label, conf = model.score(p)
        print(json.dumps({"prompt": p, "label": label, "confidence": conf}))
