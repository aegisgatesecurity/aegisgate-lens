#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Targeted Re-Eval for Timed-Out Corpora

After the main ship-readiness eval completes, individual corpora that
timed out can be re-evaluated in isolation with a longer timeout and
(optional) batch_size reduction.

Usage:
    python tools/reeval_corpus.py --checkpoint models/.../checkpoint-XXXX \
        --corpus r7_benign_long_context --timeout 1800 --batch-size 16

Or batched from the metrics file:
    python tools/reeval_corpus.py --checkpoint models/.../checkpoint-XXXX \
        --metrics-file models/.../ship_readiness_metrics.json

Why this exists:
- The main eval has a per-corpus timeout (default 300s for small files,
  up to 1800s for large files)
- r7_benign_long_context (~13MB) and r8_attack_combined (~10MB) may still
  exceed the timeout if the GPU is shared or the model is large
- This script allows targeted re-eval with adjusted parameters
- Output: appended to ship_readiness_metrics.json
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))


def main():
    parser = argparse.ArgumentParser(
        description="Re-evaluate timed-out corpora with custom parameters",
    )
    parser.add_argument("--checkpoint", type=Path, required=True,
                        help="Path to model checkpoint directory")
    parser.add_argument("--corpus", type=str, default=None,
                        help="Single corpus name to re-evaluate (e.g., "
                             "'r7_benign_long_context'). If omitted, all "
                             "corpora with 'error: timeout' in metrics file "
                             "are re-evaluated.")
    parser.add_argument("--metrics-file", type=Path, default=None,
                        help="Path to ship_readiness_metrics.json to update "
                             "with new results. The file's timed-out entries "
                             "are replaced if re-eval succeeds.")
    parser.add_argument("--timeout", type=int, default=1800,
                        help="Per-corpus timeout in seconds (default 1800 = 30 min)")
    parser.add_argument("--batch-size", type=int, default=8,
                        help="Batch size (default 8, reduced from 32 for "
                             "very long documents)")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="P(attack) threshold for classification (default 0.5)")
    args = parser.parse_args()

    # Lazy import the heavy deps
    import torch  # type: ignore
    from transformers import AutoTokenizer, AutoModelForSequenceClassification  # type: ignore

    # Lazy import the train script's eval helpers
    spec = __import__("importlib").util.spec_from_file_location(
        "train_lens_v0_2_x", REPO_ROOT / "tools" / "train_lens_v0.2.x.py")
    mod = __import__("importlib").util.module_from_spec(spec)
    sys.modules["train_lens_v0_2_x"] = mod
    spec.loader.exec_module(mod)

    print(f"Loading model from {args.checkpoint}")
    tokenizer = AutoTokenizer.from_pretrained(args.checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(args.checkpoint)
    device = next(model.parameters()).device
    if str(device) == "cpu":
        model = model.cuda()
        device = next(model.parameters()).device
    model.eval()
    print(f"Model loaded on {device}")

    # Determine which corpora to re-evaluate
    corpora_to_reeval = {}
    if args.corpus:
        # Single corpus mode
        path = mod.GATE_CORPORA.get(args.corpus)
        if not path or not path.exists():
            print(f"ERROR: corpus '{args.corpus}' not found in GATE_CORPORA or missing on disk")
            sys.exit(1)
        corpora_to_reeval[args.corpus] = path
    elif args.metrics_file:
        # Batch mode: re-evaluate all timed-out corpora from metrics file
        with open(args.metrics_file) as f:
            metrics = json.load(f)
        for name, m in metrics.items():
            if m.get("error") == "timeout":
                path = mod.GATE_CORPORA.get(name)
                if path and path.exists():
                    corpora_to_reeval[name] = path
                else:
                    print(f"  Skipping {name}: not in GATE_CORPORA or missing on disk")
    else:
        print("ERROR: must specify --corpus or --metrics-file")
        sys.exit(1)

    if not corpora_to_reeval:
        print("No corpora to re-evaluate")
        return

    print(f"Re-evaluating {len(corpora_to_reeval)} corpora (timeout={args.timeout}s, "
          f"batch_size={args.batch_size}, threshold={args.threshold})")

    def score_batch(texts):
        enc = tokenizer(
            texts,
            truncation=True,
            max_length=model.config.max_position_embeddings,
            padding=True,
            return_tensors="pt",
        ).to(device)
        with torch.no_grad():
            logits = model(**enc).logits
        return torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()

    def _alarm(signum, frame):
        raise TimeoutError("re-eval corpus timeout")

    new_metrics = {}
    for corpus_name, corpus_path in corpora_to_reeval.items():
        print(f"\n--- Re-eval {corpus_name} ---")
        scores, labels = [], []
        old_handler = signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(args.timeout)
        try:
            for batch in mod._batched_jsonl(corpus_path, batch_size=args.batch_size):
                batch_texts = [ex["text"] for ex in batch]
                batch_labels = [ex.get("label", ex.get("expected_label", 0)) for ex in batch]
                batch_scores = score_batch(batch_texts)
                # Apply threshold (default 0.5) to get predictions
                preds = (batch_scores >= args.threshold).astype(int)
                scores.extend(preds.tolist())
                labels.extend(batch_labels)
            metrics = mod._binary_classification_metrics(scores, labels)
            new_metrics[corpus_name] = metrics
            print(f"  RESULT: recall={metrics['recall']:.3f} FP={metrics['fpr']:.3f} "
                  f"F1={metrics['f1']:.3f} (n={len(labels)})")
        except TimeoutError:
            print(f"  STILL TIMEOUT after {args.timeout}s")
            new_metrics[corpus_name] = {"error": "timeout"}
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    # Update metrics file if provided
    if args.metrics_file:
        with open(args.metrics_file) as f:
            all_metrics = json.load(f)
        # Replace timed-out entries with re-eval results
        for name, m in new_metrics.items():
            all_metrics[name] = m
        with open(args.metrics_file, "w") as f:
            json.dump(all_metrics, f, indent=2)
        print(f"\nUpdated {args.metrics_file}")

    # Print final summary
    print("\n=== Re-eval Summary ===")
    for name, m in new_metrics.items():
        if m.get("error") == "timeout":
            print(f"  {name}: STILL TIMED OUT")
        else:
            print(f"  {name}: recall={m['recall']:.3f} FP={m['fpr']:.3f} F1={m['f1']:.3f} (n={m['n']})")


if __name__ == "__main__":
    main()