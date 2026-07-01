#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — ONNX Export Script (Phase A — pipeline-only)
==================================================================

Exports the fine-tuned v0.2 models to ONNX for browser inference.

Per model decision Appendix B:

  - Prompt-injection (ModernBERT-base, 149M):
      - Quantization: int4 weights + fp16 embeddings (q4f16)
      - Output: model_q4f16.onnx (~134 MB)
      - Opset: 17

  - Toxicity (toxic-bert, 110M):
      - Quantization: int8 dynamic
      - Output: model_int8.onnx (~110 MB)
      - Opset: 17

The export uses HuggingFace `optimum` library (already installed locally).

Usage:
    python tools/export_onnx.py --facet prompt-injection \\
        --checkpoint models/prompt-injection-v0.2.0/checkpoint-best

    python tools/export_onnx.py --facet toxicity \\
        --checkpoint models/toxicity-v0.2.0/checkpoint-best

Per model decision §1.7 (license audit): the script verifies the base
checkpoint's license is in the allowed list before export. This catches
accidentally importing a model with a non-redistribution license (e.g.,
Elastic 2.0).

The output goes to `models/<facet>-onnx/` and is then signed by
`tools/sign_bundle.py`.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("export_onnx")


# License allow-list (mirrors src/util/license-checker.js — keep in sync)
ALLOWED_LICENSES = {
    "apache-2.0", "apache2",
    "apache-2.0-with-llvm-exceptions",
    "mit", "bsd-2-clause", "bsd-3-clause",
    "openrail", "openrail++",
    "bigscience-rail-1.0", "cc0-1.0",
}


def audit_license(checkpoint_id: str) -> str:
    """Returns the license string for a HF model, after validating."""
    from huggingface_hub import HfApi  # type: ignore

    api = HfApi()
    try:
        info = api.model_info(checkpoint_id)
    except Exception as e:
        log.error("Failed to fetch HF model info for %s: %s", checkpoint_id, e)
        sys.exit(1)

    license_str = ""
    if info.cardData:
        license_str = info.cardData.get("license", "")
    if not license_str:
        # Fall back to parsing the LICENSE file on the repo
        try:
            from huggingface_hub import hf_hub_download
            lic_path = hf_hub_download(checkpoint_id, "LICENSE", repo_type="model")
            text = Path(lic_path).read_text()
            # Quick heuristic: Apache-2.0 first 50 lines
            for line in text.splitlines()[:50]:
                if "Apache License" in line or "Apache-2.0" in line:
                    license_str = "apache-2.0"
                    break
                if "MIT License" in line or "Permission is hereby granted" in text[:2000]:
                    license_str = "mit"
                    break
        except Exception:
            pass

    if not license_str:
        log.error("Could not determine license for %s", checkpoint_id)
        sys.exit(1)

    normalized = license_str.lower().strip()
    if normalized not in ALLOWED_LICENSES:
        log.error(
            "License %s for %s is NOT in the allow-list: %s",
            normalized, checkpoint_id, sorted(ALLOWED_LICENSES),
        )
        sys.exit(1)

    log.info("License for %s: %s (allowed)", checkpoint_id, normalized)
    return normalized


def export_prompt_injection(checkpoint: Path, output_dir: Path) -> None:
    """Export ModernBERT-base fine-tuned → q4f16 ONNX."""
    log.info("Exporting prompt-injection model from %s", checkpoint)
    log.info("Quantization: q4f16 (int4 weights + fp16 embeddings)")
    log.info("Expected output size: ~134 MB")

    from optimum.exporters.onnx import main_export  # type: ignore

    output_dir.mkdir(parents=True, exist_ok=True)

    # optimum's CLI: optimum-cli export onnx --model <ckpt> --task text-classification
    # --fp16 --quantize int4 --output <dir>
    main_export(
        model_name_or_path=str(checkpoint),
        output=str(output_dir),
        task="text-classification",
        opset=17,
        fp16=True,
        # quantization_config: requires bitsandbytes for int4
        # We pass via CLI flags instead of Python API for simplicity:
        # optimum-cli export onnx ... --quantize int4
    )

    # The optimum API doesn't support q4 directly; use a post-step:
    # onnxruntime.quantization.quantize_dynamic for int8 fallback, or
    # bitsandbytes for int4. For now, output the fp16 ONNX; quantization
    # is a separate post-step (int4 via bitsandbytes + onnx).
    log.info("ONNX export complete. Run quantization as a separate step.")
    log.info("Next: python tools/quantize_onnx.py --facet prompt-injection")


def export_toxicity(checkpoint: Path, output_dir: Path) -> None:
    """Export toxic-bert fine-tuned → int8 ONNX."""
    log.info("Exporting toxicity model from %s", checkpoint)
    log.info("Quantization: int8 dynamic")
    log.info("Expected output size: ~110 MB")

    from optimum.exporters.onnx import main_export  # type: ignore

    output_dir.mkdir(parents=True, exist_ok=True)

    main_export(
        model_name_or_path=str(checkpoint),
        output=str(output_dir),
        task="text-classification",
        opset=17,
        fp16=False,
    )

    log.info("ONNX export complete.")
    log.info("Next: apply int8 dynamic quantization with onnxruntime.")


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisGate Lens v0.2 — ONNX export")
    parser.add_argument("--facet", required=True, choices=["prompt-injection", "toxicity"])
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        help="Output directory (default: models/<facet>-onnx)")
    parser.add_argument("--skip-license-audit", action="store_true",
                        help="Skip HF license check (NOT RECOMMENDED)")
    args = parser.parse_args()

    if not args.checkpoint.exists():
        log.error("Checkpoint not found: %s", args.checkpoint)
        sys.exit(1)

    output_dir = args.output or (REPO_ROOT / "models" / f"{args.facet}-onnx")

    # License audit
    if not args.skip_license_audit:
        # Read base checkpoint from registry or config
        # For simplicity, hardcode the base model per facet
        base_map = {
            "prompt-injection": "answerdotai/ModernBERT-base",
            "toxicity": "unitary/toxic-bert",
        }
        audit_license(base_map[args.facet])

    if args.facet == "prompt-injection":
        export_prompt_injection(args.checkpoint, output_dir)
    elif args.facet == "toxicity":
        export_toxicity(args.checkpoint, output_dir)

    # Generate config.json (max_length etc.)
    config = {
        "prompt-injection": {
            "max_length": 8192,
            "hidden_size": 768,
            "num_labels": 2,
            "model_type": "modernbert",
        },
        "toxicity": {
            "max_length": 512,
            "hidden_size": 768,
            "num_labels": 2,
            "model_type": "distilbert",
        },
    }
    config_path = output_dir / "config.json"
    config_path.write_text(json.dumps(config[args.facet], indent=2))
    log.info("Wrote config to %s", config_path)


if __name__ == "__main__":
    main()
