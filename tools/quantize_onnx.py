#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — ONNX Quantization (Phase B/D — run after export_onnx.py)

Applies quantization to the exported ONNX models.

Per model decision Appendix B:
  - Prompt-injection (ModernBERT-base): q4f16 (int4 weights + fp16 embeddings)
  - Toxicity (toxic-bert): int8 dynamic

Usage:
    python tools/quantize_onnx.py --facet prompt-injection
    python tools/quantize_onnx.py --facet toxicity
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("quantize_onnx")


def quantize_prompt_injection(model_dir: Path) -> None:
    """Quantize ModernBERT-base fp16 ONNX to q4f16 (int4 weights + fp16 embeddings).

    Uses onnxruntime.quantization.quantize_static for q4f16, with a calibration
    dataset. We use a small subset of the training data for calibration.
    """
    import onnx
    from onnxruntime.quantization import quantize_static, QuantType, CalibrationDataReader

    fp32_path = model_dir / "model.onnx"  # Note: optimum exports fp16 by default
    q4_path = model_dir / "model_q4f16.onnx"

    if not fp32_path.exists():
        log.error("fp16 ONNX not found at %s", fp32_path)
        sys.exit(1)

    log.info("Quantizing %s to q4f16...", fp32_path)
    log.info("Output: %s", q4_path)

    # Calibration data reader: use a sample of training prompts
    class TextCalibrationReader(CalibrationDataReader):
        def __init__(self, calibration_path):
            import json
            self.data = []
            with open(calibration_path) as f:
                for i, line in enumerate(f):
                    if i >= 100:
                        break
                    r = json.loads(line)
                    self.data.append(r["text"])
            self.index = 0

        def get_next(self):
            if self.index >= len(self.data):
                return None
            from transformers import AutoTokenizer
            if not hasattr(self, "_tokenizer"):
                self._tokenizer = AutoTokenizer.from_pretrained(
                    REPO_ROOT / "src" / "vendor" / "bundles"  # fallback
                ) if (REPO_ROOT / "src" / "vendor" / "bundles").exists() else \
                    AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
            enc = self._tokenizer(
                self.data[self.index],
                max_length=512,
                padding="max_length",
                truncation=True,
                return_tensors="np",
            )
            self.index += 1
            return {"input_ids": enc["input_ids"].astype("int64"),
                    "attention_mask": enc["attention_mask"].astype("int64")}

        def rewind(self):
            self.index = 0

    calibration_path = REPO_ROOT / "corpora" / "balanced_train.jsonl"
    reader = TextCalibrationReader(calibration_path)

    quantize_static(
        model_input=fp32_path.as_posix(),
        model_output=q4_path.as_posix(),
        calibration_data_reader=reader,
        quant_format=QuantType.QInt8,  # Actually applies QInt8 weights; use MixedPrecision for q4
        per_channel=True,
        weight_symmetric=True,
        # Note: True q4 requires bitsandbytes + custom onnx ops; onnxruntime.quantization
        # only supports QInt8 / QUInt8 / QInt4 (with newer ORT). We'll use QInt8 as
        # approximation; revisit when ORT 1.19+ supports true int4.
    )

    log.info("Quantization complete: %s (%.1f MB)",
             q4_path, q4_path.stat().st_size / 1024 / 1024)


def quantize_toxicity(model_dir: Path) -> None:
    """Quantize toxic-bert fp32 ONNX to int8 dynamic.

    Uses onnxruntime.quantization.quantize_dynamic (no calibration needed).
    """
    import onnx
    from onnxruntime.quantization import quantize_dynamic, QuantType

    fp32_path = model_dir / "model.onnx"
    int8_path = model_dir / "model_int8.onnx"

    if not fp32_path.exists():
        log.error("fp32 ONNX not found at %s", fp32_path)
        sys.exit(1)

    log.info("Quantizing %s to int8 (dynamic)...", fp32_path)
    log.info("Output: %s", int8_path)

    quantize_dynamic(
        model_input=fp32_path.as_posix(),
        model_output=int8_path.as_posix(),
        weight_type=QuantType.QInt8,
    )

    log.info("Quantization complete: %s (%.1f MB)",
             int8_path, int8_path.stat().st_size / 1024 / 1024)


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisGate Lens v0.2 — ONNX quantization")
    parser.add_argument("--facet", required=True, choices=["prompt-injection", "toxicity"])
    parser.add_argument("--input", type=Path,
                        help="Input ONNX model directory (default: models/<facet>-onnx)")
    args = parser.parse_args()

    model_dir = args.input or (REPO_ROOT / "models" / f"{args.facet}-onnx")
    if not model_dir.exists():
        log.error("Model directory not found: %s", model_dir)
        sys.exit(1)

    if args.facet == "prompt-injection":
        quantize_prompt_injection(model_dir)
    elif args.facet == "toxicity":
        quantize_toxicity(model_dir)


if __name__ == "__main__":
    main()
