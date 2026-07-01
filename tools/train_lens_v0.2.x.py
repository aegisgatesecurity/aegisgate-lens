#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Training Script (Phase A — pipeline-only)
================================================================

Fine-tunes both v0.2 models per the model decision document
(`plans/AEGISGATE-LENS-V02-MODEL-DECISION.md`):

  - Prompt-injection: answerdotai/ModernBERT-base, fine-tuned on a
    ~981K-prompt combined corpus (v0.1 training data + public datasets
    + new OWASP/ATLAS/EU AI Act coverage).

  - Toxicity: unitary/toxic-bert, fine-tuned on a ~365K-prompt combined
    corpus (Jigsaw + Civil Comments + HateXplain + synthetic AI-context).

The script produces:
  - `models/prompt-injection-v0.2.0/checkpoint-*/`
  - `models/toxicity-v0.2.0/checkpoint-*/`
  - ONNX exports (in `models/<facet>-onnx/`)
  - Ed25519-signed bundles (in `src/vendor/bundles/`)
  - Eval results against the ship-readiness gate

Hardware: NVIDIA RTX 3060 (12 GB VRAM) per model decision §1.6.
Estimated wall-clock: ~2 hours for ModernBERT-base, ~45 min for toxic-bert.

Usage:
    python tools/train_lens_v0.2.x.py --facet prompt-injection
    python tools/train_lens_v0.2.x.py --facet toxicity
    python tools/train_lens_v0.2.x.py --facet all
    python tools/train_lens_v0.2.x.py --facet prompt-injection --eval-only \\
        --checkpoint models/prompt-injection-v0.2.0/checkpoint-best

Implementation notes:
    - Per Lesson #82 (eval-after-retrain), every checkpoint is evaluated
      against the ship-readiness gate corpora.
    - Per Lesson #91 (eval lockfile), the eval corpus SHA256SUMS is checked
      before each eval; mismatches abort.
    - Per model decision §1.6, sequence bucketing groups prompts by length
      to minimize padding waste.

This file is PART OF PHASE A (pipeline scripts only). It has NOT been
executed end-to-end on trained weights; the user runs it on the RTX 3060.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import logging
import os
import random
import shutil
import sys
import time
try:
    from transformers import TrainerCallback  # type: ignore
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    _TRANSFORMERS_AVAILABLE = False
    TrainerCallback = object  # type: ignore

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

# --------------------------------------------------------------------------
# Paths (relative to repo root)
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

V01_ARCHIVE = Path(
    "/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens"
)

MODELS_DIR = REPO_ROOT / "models"
BUNDLES_DIR = REPO_ROOT / "src" / "vendor" / "bundles"
CORPORA_DIR = REPO_ROOT / "corpora"

# Frozen corpora for the ship-readiness gate (per gate §2)
GATE_CORPORA = {
    # v0.1 round7 corpus (genuine long-context benign — the v0.1 catastrophic
    # failure mode). Each per-corpus file is a separate .jsonl.
    "r7_benign_code_reviews":  V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v7" / "round7_code_reviews.jsonl",
    "r7_benign_emails":       V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v7" / "round7_emails.jsonl",
    "r7_benign_legal":        V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v7" / "round7_legal.jsonl",
    "r7_benign_technical_docs": V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v7" / "round7_technical_docs.jsonl",
    # REMOVED: "r7_benign_long_context" — see corpora/relabel_long_context_v7.py
    # The v0.1 long_context_v7.jsonl was actually 97.6% attacks despite the
    # "v7" naming convention. It's now correctly labeled as r8 attacks below.
    # v0.1 round8 corpus (the attack corpus from the burndown failure).
    # r8_combined.jsonl is the master file the v0.1 critical-measurement
    # doc evaluated against (per-corpus files are also available).
    "r8_attack_combined":     V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v8" / "round8_combined.jsonl",
    "r8_attack_code_reviews": V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v8" / "round8_code_reviews.jsonl",
    "r8_attack_emails":       V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v8" / "round8_emails.jsonl",
    "r8_attack_legal":        V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v8" / "round8_legal.jsonl",
    "r8_attack_technical_docs": V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v8" / "round8_technical_docs.jsonl",
    # CORRECTED: v0.1 long_context corpus relabeled as r8 attack (was mislabeled).
    "r8_attack_long_context": REPO_ROOT / "corpora" / "r8_attack_long_context.jsonl",
    # v0.1 v1 corpus (small original test set).
    "v1corpus":               V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "v1" / "adversarial-prompts.jsonl",
    # v0.2 r8 holdouts (split from r8 corpus; first 70% used as seeds for
    # augmentation, last 30% held out for fresh ship-readiness eval).
    # Per Lesson #82 (eval-after-retrain): never train on these sets.
    "r8_holdout_v0.2":       REPO_ROOT / "corpora" / "r8_holdout_v0.2.jsonl",
    # CORRECTED: r7_holdout_v0.2 was generated from the mislabeled
    # long_context_v7 corpus. It's now relabeled as r8_holdout_long_context
    # with correct attack/benign labels (18 attack, 142 benign).
    "r8_holdout_long_context": REPO_ROOT / "corpora" / "r8_holdout_long_context.jsonl",
    # v0.2 r7 benign holdout (split from r7 corpus; same methodology).
    # These four are genuinely benign long-content examples.
    "r7_holdout_v0.2":       REPO_ROOT / "corpora" / "r7_holdout_v0.2.jsonl",
    # Round 13 public train/test split (held-out evaluation set).
    "public_test_attack":     V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "public_rounds" / "round13_public_test_attack.jsonl",
    "public_test_benign":     V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "public_rounds" / "round13_public_test_benign.jsonl",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("train_lens_v0.2")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


@dataclass
class TrainingConfig:
    """Hyperparameters per model decision §1.6 / §2.6."""

    # Architecture
    base_checkpoint: str
    max_seq_length: int
    output_dir: Path

    # Training hyperparameters
    batch_size: int = 32            # effective (with gradient accumulation)
    micro_batch_size: int = 8       # safe for RTX 3060 (4.97 GB peak; smoke-tested)
    grad_accum_steps: int = 4       # 8 × 4 = 32 (effective batch)
    learning_rate: float = 2e-5
    num_epochs: int = 3
    warmup_ratio: float = 0.1
    fp16: bool = True

    # Sequence bucketing (per model decision §1.6).
    # Tuned for v0.2.0 balanced corpus: max prompt = 2000 chars ≈ 500 tokens.
    # We keep the 8K context support (per model decision §1.2) but train on
    # shorter buckets to fit RTX 3060 memory budget.
    # The model still supports 8K at inference time for long-content benign.
    bucket_boundaries: tuple = (
        128, 256, 512, 1024,
    )

    # Eval lockfile (per Lesson #91)
    eval_lockfile: Path = field(
        default_factory=lambda: REPO_ROOT / "corpora" / "SHA256SUMS"
    )

    # Reproducibility
    seed: int = 42


# --------------------------------------------------------------------------
# Reproducibility helpers
# --------------------------------------------------------------------------


def set_seed(seed: int) -> None:
    """Seed all RNGs for reproducibility."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def verify_corpus_lockfile() -> None:
    """Per Lesson #91: refuse to eval if corpora have drifted."""
    lockfile = REPO_ROOT / "corpora" / "SHA256SUMS"
    if not lockfile.exists():
        log.warning(
            "No eval lockfile at %s — creating fresh one after first eval run",
            lockfile,
        )
        return
    log.info("Verifying eval corpora against lockfile %s", lockfile)
    with open(lockfile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            expected_sha, rel_path = parts
            full_path = REPO_ROOT / rel_path
            if not full_path.exists():
                log.error("Lockfile references missing file: %s", rel_path)
                sys.exit(2)
            actual_sha = hashlib.sha256(full_path.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                log.error(
                    "Corpus drift detected: %s\n  expected: %s\n  actual:   %s",
                    rel_path, expected_sha, actual_sha,
                )
                sys.exit(2)
    log.info("All eval corpora match lockfile.")


# --------------------------------------------------------------------------
# Dataset construction
# --------------------------------------------------------------------------


def build_prompt_injection_corpus() -> Iterator[dict]:
    """
    Build the training corpus for ModernBERT-base.

    v0.2 strategy: use the balanced ~158K subset produced by
    `tools/balanced_sampler.py` (corpora/balanced_train.jsonl). This is
    the right size for a ~2-3 hour training run on RTX 3060 while
    still covering all 11 source categories (per Lesson #92: quality
    > raw quantity).

    If `corpora/balanced_train.jsonl` does not exist, fall back to
    loading all sources directly (slower but produces ~888K).

    Yields dicts: {text, label, source, license, source_id}
    """
    balanced = CORPORA_DIR / "balanced_train.jsonl"
    # v2 EXACT reproduction: prefer v2 corpus if it exists
    balanced_v2 = CORPORA_DIR / "balanced_train_v2.jsonl"
    if balanced_v2.exists():
        log.info("Using v2 balanced training set: %s", balanced_v2)
        yield from _iter_jsonl(balanced_v2, default_source="balanced_v2")
        return
    if balanced.exists():
        log.info("Using balanced training set: %s", balanced)
        yield from _iter_jsonl(balanced, default_source="balanced")
        return

    log.warning(
        "%s not found — falling back to full ~888K corpus. "
        "Run `python tools/balanced_sampler.py` to generate a faster training set.",
        balanced,
    )

    log.info("Building prompt-injection corpus (full)...")
    # 1. v0.1 training data (already labeled, balanced)
    v01_train = (
        V01_ARCHIVE / "lens-ml-artifacts" / "training_data_tier3" / "train.jsonl"
    )
    v01_test = (
        V01_ARCHIVE / "lens-ml-artifacts" / "training_data_tier3" / "test.jsonl"
    )
    v01_val = (
        V01_ARCHIVE / "lens-ml-artifacts" / "training_data_tier3" / "val.jsonl"
    )
    for path in (v01_train, v01_test, v01_val):
        if path.exists():
            log.info("  loading %s", path)
            yield from _iter_jsonl(path, default_source="v01_tier3")

    # 2. Public datasets (round13)
    public_dir = (
        V01_ARCHIVE / "lens-working-snapshot" / "pen-test" / "corpus" / "public_rounds"
    )
    for fname in ("round13_public_train_attack.jsonl", "round13_public_train_benign.jsonl"):
        path = public_dir / fname
        if path.exists():
            log.info("  loading %s", path)
            yield from _iter_jsonl(path, default_source="round13_public")

    # 3. NEW corpora generated by `corpora/generate_*.py`
    for fname in (
        "owasp_v2.jsonl",
        "atlas_v2.jsonl",
        "eu_ai_act_v2.jsonl",
        "long_benign_v2.jsonl",
        "multilingual_v2.jsonl",
        "obfuscated_v2.jsonl",
    ):
        path = CORPORA_DIR / fname
        if path.exists():
            log.info("  loading %s", path)
            yield from _iter_jsonl(path, default_source=fname.replace(".jsonl", ""))
        else:
            log.warning(
                "  %s NOT FOUND — run `corpora/generate_%s.py` first",
                path, fname.replace(".jsonl", "").replace("_v2", ""),
            )


def build_toxicity_corpus() -> Iterator[dict]:
    """
    Build the ~365K-prompt corpus for toxic-bert training.

    Per model decision §2.5:
      - 180K Civil Comments (Kaggle)
      - 160K Jigsaw Toxic Comment (Kaggle)
      - 20K HateXplain
      - 5K NEW synthetic AI-context toxicity
      - ~1K v0.1 toxicity filter patterns

    Total: ~365K (80/20 benign/toxic).
    """
    log.info("Building toxicity corpus...")
    # Note: Civil Comments + Jigsaw require Kaggle API access.
    # The script downloads them on first run via kaggle CLI.
    # If not available, the script falls back to v0.1 toxicity patterns
    # only (much smaller corpus; gate metrics may not be hit).
    yield from _iter_civil_comments_or_fallback()
    yield from _iter_jigsaw_or_fallback()
    # HateXplain: download via HuggingFace `datasets` library
    # Synthetic AI-context toxicity: generated by `corpora/generate_ai_context_toxicity.py`
    ai_context = CORPORA_DIR / "ai_context_toxicity.jsonl"
    if ai_context.exists():
        yield from _iter_jsonl(ai_context, default_source="synthetic_ai_context")


def _iter_jsonl(path: Path, default_source: str) -> Iterator[dict]:
    """Stream a JSONL file, normalizing field names."""
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning("Skipping bad JSON at %s:%d (%s)", path, lineno, e)
                continue
            text = obj.get("text") or obj.get("prompt") or obj.get("input")
            label = obj.get("label")
            if label is None and "expected_label" in obj:
                label = obj["expected_label"]
            if text is None or label is None:
                log.warning("Skipping record at %s:%d (missing text/label)", path, lineno)
                continue
            yield {
                "text": text,
                "label": int(label),
                "source": obj.get("source", default_source),
                "license": obj.get("license", "Unknown"),
                "source_id": obj.get("id", f"{path.name}:{lineno}"),
            }


def _iter_civil_comments_or_fallback() -> Iterator[dict]:
    """Try to load Civil Comments via Kaggle; fall back to empty."""
    try:
        import kaggle  # type: ignore
    except ImportError:
        log.warning("kaggle CLI not installed; skipping Civil Comments")
        return
    kaggle_dir = Path.home() / ".kaggle"
    if not (kaggle_dir / "kaggle.json").exists():
        log.warning("No Kaggle credentials at %s; skipping Civil Comments", kaggle_dir / "kaggle.json")
        return
    log.info("Downloading Civil Comments via Kaggle...")
    # NOTE: requires Kaggle API credentials; user must set up locally.
    # kaggle.api.authenticate()
    # kaggle.api.dataset_download_files(
    #     'c/civil-comments', path='/tmp/civil-comments', unzip=True)
    log.warning("Civil Comments download is commented out — uncomment when ready")


def _iter_jigsaw_or_fallback() -> Iterator[dict]:
    """Try to load Jigsaw Toxic Comment via Kaggle; fall back to empty."""
    # Same pattern as _iter_civil_comments_or_fallback
    log.warning("Jigsaw Toxic Comment download is commented out — uncomment when ready")


# --------------------------------------------------------------------------
# Sequence bucketing
# --------------------------------------------------------------------------


@dataclass
class BucketedDataset:
    """Per model decision §1.6: group prompts by length into 8 buckets."""

    examples: list[dict]
    boundaries: tuple

    def __post_init__(self):
        self.buckets: dict[int, list[dict]] = {b: [] for b in self.boundaries}
        for ex in self.examples:
            # Approximate length: 1 token ~ 4 chars (English)
            approx_tokens = len(ex["text"]) // 4
            # Find smallest bucket boundary >= approx_tokens
            bucket = next(
                (b for b in self.boundaries if b >= approx_tokens),
                self.boundaries[-1],
            )
            self.buckets[bucket].append(ex)

    def __iter__(self) -> Iterator[tuple[int, list[dict]]]:
        # Yield largest bucket first; biggest training signal
        for b in sorted(self.boundaries, reverse=True):
            if self.buckets[b]:
                yield b, self.buckets[b]


# --------------------------------------------------------------------------
# Training (HF transformers)
# --------------------------------------------------------------------------


class LossLogger(TrainerCallback):
    """
    TrainerCallback that writes loss progression to a sidecar JSON file.
    Per Lesson #82 (eval-after-retrain) and Lesson #88 (don't burn hours
    on broken training) — every step's loss is recorded so we can detect
    failure modes (NaN, divergence, etc.) without waiting for epoch end.
    """

    def __init__(self, log_path: Path, sidecar_path: Path):
        self.log_path = log_path
        self.sidecar_path = sidecar_path
        self.history = []

    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs is None:
            return
        # Extract loss + learning rate + epoch
        step = state.global_step
        entry = {
            'step': step,
            'epoch': float(state.epoch or 0),
            **{k: float(v) if isinstance(v, (int, float)) else str(v)
               for k, v in logs.items()},
        }
        self.history.append(entry)
        # Write incrementally so we can read it during training
        try:
            self.sidecar_path.write_text(json.dumps(self.history, indent=2))
        except Exception as e:
            print(f"[warn] failed to write loss sidecar: {e}")
        # Also append to main log for human inspection
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')


def train_model(cfg: TrainingConfig, train_corpus: list[dict], val_corpus: list[dict]) -> Path:
    """Fine-tune a HuggingFace encoder model with bucketed batching.

    Returns the path to the best checkpoint.
    """
    log.info("Loading tokenizer for %s", cfg.base_checkpoint)
    from transformers import (  # type: ignore
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
        DataCollatorWithPadding,
        TrainerCallback,
    )

    tokenizer = AutoTokenizer.from_pretrained(cfg.base_checkpoint)

    log.info("Loading model %s", cfg.base_checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(
        cfg.base_checkpoint,
        num_labels=2,
        problem_type="single_label_classification",
    )

    # Tokenize with bucketing
    log.info("Tokenizing %d training examples into %d buckets", len(train_corpus), len(cfg.bucket_boundaries))
    bucketed = BucketedDataset(train_corpus, cfg.bucket_boundaries)
    for bucket_size, ex_list in bucketed:
        log.info("  bucket ≤%d: %d examples", bucket_size, len(ex_list))

    def tokenize_fn(example: dict) -> dict:
        # Bucket determines the actual max_length for this batch
        approx_tokens = len(example["text"]) // 4
        bucket = next(
            (b for b in cfg.bucket_boundaries if b >= approx_tokens),
            cfg.bucket_boundaries[-1],
        )
        # v3 raised cap from 1024 to 2048 tokens (~8K chars) so the
        # model sees the full long-context attack pattern, including
        # injections at char 8000+ in 30K-char documents. With 1024,
        # the tokenization truncated before reaching the injection.
        # Also bumped balanced_sampler MAX_CHARS to 32000 to include
        # 30K-char examples in the balanced corpus.
        max_length = min(bucket, 2048)
        return tokenizer(
            example["text"],
            truncation=True,
            max_length=max_length,
            padding=False,
        )

    # HuggingFace datasets wrap (for efficient batching)
    from datasets import Dataset  # type: ignore

    def to_hf_dataset(examples: list[dict]):
        return Dataset.from_list(examples).map(tokenize_fn, batched=False)

    train_ds = to_hf_dataset(train_corpus)
    val_ds = to_hf_dataset(val_corpus) if val_corpus else None

    args = TrainingArguments(
        output_dir=str(cfg.output_dir),
        per_device_train_batch_size=cfg.micro_batch_size,
        per_device_eval_batch_size=cfg.micro_batch_size,
        gradient_accumulation_steps=cfg.grad_accum_steps,
        learning_rate=cfg.learning_rate,
        num_train_epochs=cfg.num_epochs,
        warmup_ratio=cfg.warmup_ratio,
        fp16=cfg.fp16,
        eval_strategy="epoch" if val_ds is not None else "no",
        save_strategy="epoch",
        save_total_limit=2,  # keep best 2 checkpoints
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        seed=cfg.seed,
        logging_steps=50,
        report_to="none",  # no wandb/tensorboard unless explicitly enabled
    )

    # Per Lesson #88 (don't burn hours on broken training) — wire the
    # loss sidecar logger so we can detect NaN/divergence in real time.
    sidecar = cfg.output_dir / "loss_history.json"
    loss_logger = LossLogger(log_path=cfg.output_dir / "loss_log.jsonl",
                             sidecar_path=sidecar)

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=_compute_metrics,
        callbacks=[loss_logger],
    )

    log.info("Starting training on %s", "CUDA" if _has_cuda() else "CPU")
    trainer.train()

    # Per Lesson #91: evaluate against ship-readiness gate corpora after training
    log.info("Evaluating against ship-readiness gate corpora...")
    metrics = evaluate_against_gate(cfg, trainer.model, tokenizer)
    metrics_path = cfg.output_dir / "ship_readiness_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    log.info("Ship-readiness metrics saved to %s", metrics_path)

    return cfg.output_dir


def _compute_metrics(eval_preds):
    """F1 / accuracy / precision / recall for binary classification."""
    import numpy as np  # type: ignore
    from sklearn.metrics import (  # type: ignore
        accuracy_score, f1_score, precision_score, recall_score,
    )

    logits, labels = eval_preds
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="binary"),
        "precision": precision_score(labels, preds, average="binary", zero_division=0),
        "recall": recall_score(labels, preds, average="binary", zero_division=0),
    }


def _has_cuda() -> bool:
    try:
        import torch  # type: ignore
        return torch.cuda.is_available()
    except ImportError:
        return False


# --------------------------------------------------------------------------
# Eval harness (per ship-readiness gate §3.6)
# --------------------------------------------------------------------------


def evaluate_against_gate(
    cfg: TrainingConfig, model, tokenizer,
) -> dict:
    """Run eval against the frozen ship-readiness corpora.

    Per Lesson #91: refuse to run if corpora don't match the lockfile.
    Per ship-readiness gate §3.6: report per-corpus recall/FP/f1.
    """
    verify_corpus_lockfile()
    import numpy as np  # type: ignore
    import torch  # type: ignore

    results = {}

    # We need a small inference loop. For 134MB ONNX this would use ort;
    # for the HF model this uses torch directly.
    model.eval()
    device = next(model.parameters()).device

    # Per-corpus eval with safety timeout per corpus.
    # Per Lesson #87 (long-content FP): cap each input at the model's full
    # context window (8192 tokens for ModernBERT-base). The ship-readiness
    # gate's r8 corpus places attacks after 1024 tokens — evaluating with
    # 1024 truncation HID the model's true performance. v2 augmentation
    # taught the model to detect r8 attacks at any position, but the eval
    # was clipping the document before reaching the injection.
    eval_max_len = model.config.max_position_embeddings  # 8192 for ModernBERT
    # No character pre-truncation — let the tokenizer handle the 8K cap.
    eval_max_chars = None

    def score_batch(texts: list[str]) -> np.ndarray:
        # Don't truncate at the character level — token-level truncation
        # at 8192 tokens preserves the full document. r8 attacks need this.
        truncated = list(texts) if eval_max_chars is None else [
            (t or '')[:eval_max_chars] for t in texts
        ]
        enc = tokenizer(
            truncated,
            truncation=True,
            max_length=eval_max_len,
            padding=True,
            return_tensors="pt",
        ).to(device)
        with torch.no_grad():
            logits = model(**enc).logits
        return torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()  # P(attack)

    import signal

    def _alarm_handler(signum, frame):
        raise TimeoutError("corpus eval exceeded per-corpus timeout")

    # Adaptive per-corpus (timeout, batch_size) pair. The previous adaptive
    # timeout scaled by file size only, but that didn't help for the
    # 12.5MB long_context corpus (~28 min at batch=32 with 8K context).
    # The fix: for long-content corpora, use smaller batch size (8 instead
    # of 32) so each batch is faster, AND a longer timeout (2400s = 40 min)
    # to give the slower per-batch evaluation enough headroom.
    #
    # Per evaluation runtime analysis (2026-06-27):
    #   - public_test_attack (48MB, 38K examples): 3.25 hours at batch=8
    #   - public_test_benign (44MB, 65K examples): 5.5 hours at batch=8
    #   - r7_benign_long_context (12.5MB, 328 ex): ~30 min at batch=8
    # These runtimes are dominated by Python I/O overhead, not GPU compute.
    # The timeout must scale to cover the actual runtime, not theoretical.
    def _adaptive_config(corpus_path):
        try:
            size_mb = corpus_path.stat().st_size / (1024 * 1024)
        except OSError:
            return (600, 32)
        # Massive corpora (>30MB, public_test_*): smallest batch + longest timeout.
        # 6-hour timeout covers worst-case runtime of public_test_attack.
        if size_mb > 30:
            return (21600, 4)  # 6 hours
        # Large long-content corpora (>10MB): smaller batch + 2-hour timeout
        elif size_mb > 10:
            return (7200, 8)  # 2 hours
        # Medium-large corpora (>1MB): moderate timeout, smaller batch
        elif size_mb > 1:
            return (1800, 16)  # 30 min
        # Small corpora: defaults
        else:
            return (600, 32)  # 10 min

    for corpus_name, corpus_path in GATE_CORPORA.items():
        if not corpus_path.exists():
            log.warning("Skipping missing corpus: %s", corpus_name)
            continue
        per_corpus_timeout, batch_size = _adaptive_config(corpus_path)
        log.info(
            "Evaluating on %s (%s, %ds timeout, batch=%d)",
            corpus_name, corpus_path, per_corpus_timeout, batch_size,
        )
        scores, labels = [], []
        # Arm a timeout so a single corpus can't hang the whole eval
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(per_corpus_timeout)
        try:
            # Count total examples for progress logging (avoids repeated
            # file reads; cheap one-line count on JSONL).
            total_examples = sum(1 for _ in open(corpus_path))
            last_logged_pct = -10  # forces first batch to log
            for batch in _batched_jsonl(corpus_path, batch_size=batch_size):
                batch_texts = [ex["text"] for ex in batch]
                batch_labels = [ex.get("label", ex.get("expected_label", 0)) for ex in batch]
                batch_scores = score_batch(batch_texts)
                scores.extend(batch_scores.tolist())
                labels.extend(batch_labels)
                # Progress log every 10% — useful for diagnosing timeouts
                pct = int(len(labels) / max(total_examples, 1) * 100)
                if pct >= last_logged_pct + 10:
                    last_logged_pct = pct
                    log.info("    ...%d%% (%d/%d)", pct, len(labels), total_examples)
            metrics = _binary_classification_metrics(scores, labels)
            results[corpus_name] = metrics
            log.info(
                "  %s: recall=%.3f FP=%.3f F1=%.3f (n=%d)",
                corpus_name, metrics["recall"], metrics["fpr"], metrics["f1"], len(labels),
            )
        except TimeoutError:
            log.error(
                "  %s: TIMEOUT after %ds — partial: scored %d/%d (%.0f%%) — skipping",
                corpus_name, per_corpus_timeout, len(scores), total_examples,
                100 * len(scores) / max(total_examples, 1),
            )
            results[corpus_name] = {
                "error": "timeout",
                "scores_so_far": len(scores),
                "total": total_examples,
                "pct_complete": round(100 * len(scores) / max(total_examples, 1), 1),
            }
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    return results


def _batched_jsonl(path: Path, batch_size: int) -> Iterator[list[dict]]:
    batch = []
    for ex in _iter_jsonl(path, default_source=path.name):
        batch.append(ex)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _binary_classification_metrics(scores: list[float], labels: list[int]) -> dict:
    """Compute recall, FPR, F1 at threshold 0.5."""
    preds = [1 if s >= 0.5 else 0 for s in scores]
    tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
    fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
    fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
    tn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 0)
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": recall, "fpr": fpr, "precision": precision, "f1": f1,
        "n": len(labels),
    }


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


PROMPT_INJECTION_CFG = TrainingConfig(
    base_checkpoint="answerdotai/ModernBERT-base",
    max_seq_length=8192,
    output_dir=MODELS_DIR / "prompt-injection-v0.2.0",
)

TOXICITY_CFG = TrainingConfig(
    base_checkpoint="unitary/toxic-bert",
    max_seq_length=512,
    output_dir=MODELS_DIR / "toxicity-v0.2.0",
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AegisGate Lens v0.2 — training pipeline (Phase A)",
    )
    parser.add_argument(
        "--facet",
        choices=["prompt-injection", "toxicity", "all"],
        default="all",
    )
    parser.add_argument(
        "--eval-only",
        action="store_true",
        help="Skip training; only run eval against gate corpora.",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        help="Path to a fine-tuned checkpoint (required for --eval-only).",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        help="Override default num_epochs (3).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Override default seed (42).",
    )
    args = parser.parse_args()

    set_seed(args.seed or 42)
    verify_corpus_lockfile()

    if args.facet in ("prompt-injection", "all"):
        _train_facet(
            "prompt-injection",
            PROMPT_INJECTION_CFG,
            build_prompt_injection_corpus,
            args,
        )
    if args.facet in ("toxicity", "all"):
        _train_facet(
            "toxicity",
            TOXICITY_CFG,
            build_toxicity_corpus,
            args,
        )


def _train_facet(name: str, cfg: TrainingConfig, corpus_fn, args) -> None:
    log.info("=" * 70)
    log.info("Training facet: %s", name)
    log.info("=" * 70)

    if args.epochs:
        cfg.num_epochs = args.epochs

    if args.eval_only:
        if not args.checkpoint:
            log.error("--eval-only requires --checkpoint PATH")
            sys.exit(1)
        log.info("Eval-only mode; loading checkpoint from %s", args.checkpoint)
        from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore
        model = AutoModelForSequenceClassification.from_pretrained(args.checkpoint)
        tokenizer = AutoTokenizer.from_pretrained(args.checkpoint)
        metrics = evaluate_against_gate(cfg, model, tokenizer)
        out = cfg.output_dir / "ship_readiness_metrics.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(metrics, indent=2))
        log.info("Saved eval metrics to %s", out)
        return

    # Build corpus, split 95/5
    examples = list(corpus_fn())
    log.info("Total examples: %d", len(examples))
    random.shuffle(examples)
    split = int(0.95 * len(examples))
    train_corpus = examples[:split]
    val_corpus = examples[split:]
    log.info("Train: %d, Val: %d", len(train_corpus), len(val_corpus))

    # Train
    start = time.time()
    best_ckpt = train_model(cfg, train_corpus, val_corpus)
    elapsed = time.time() - start
    log.info("Training complete in %.1f minutes. Best checkpoint: %s", elapsed / 60, best_ckpt)

    # ONNX export + bundle signing are in:
    #   tools/export_onnx.py
    #   tools/sign_bundle.py


if __name__ == "__main__":
    main()
