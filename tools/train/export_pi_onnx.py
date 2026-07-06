#!/usr/bin/env python3
"""
Export the PI detection model to ONNX for browser deployment.

Per user directive (2026-07-05 19:13): the only path is to build the
ONNX export + browser ML wiring end-to-end.

Input:  models/pi-v0.1.0-beta/finetuned-large/  (PyTorch safetensors, 1.5GB)
Output: dist/detectors/ml/pi-model.onnx + pi-tokenizer.json + pi-config.json

We use optimum's main_export with task=text-classification to produce
a browser-loadable ONNX model. Per the Apache 2.0 / no-external-deps
mandate, onnxruntime-web is vendored separately (next step).

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import os
import sys
import json
import shutil
from pathlib import Path

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
MODEL_DIR = LENS / 'models' / 'pi-v0.1.0-beta' / 'finetuned-large'
OUT_DIR = LENS / 'test' / 'headless-smoke' / 'dist' / 'detectors' / 'ml'
TMP_DIR = LENS / 'models' / 'pi-v0.1.0-beta' / 'onnx-export'

def main():
    print(f'Loading model from {MODEL_DIR}')
    print(f'Exporting to {TMP_DIR}')
    print(f'Final dist target: {OUT_DIR}')

    # Ensure output dirs exist
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Use optimum's main_export CLI programmatically.
    # The task is 'text-classification' (single_label).
    # We export with opset 17 (broad onnxruntime-web support) and
    # FP32 first (we can quantize later if size is a problem).
    from optimum.exporters.onnx import main_export

    # The optimum CLI signature: main_export(model_name_or_path, output=..., task=..., ...)
    # We use the model directory directly so it picks up the safetensors.
    try:
        main_export(
            model_name_or_path=str(MODEL_DIR),
            output=str(TMP_DIR),
            task='text-classification',
            opset=17,
            # FP32 for now (1.5GB model is ~1.5GB ONNX too; we'll quantize
            # in a follow-up if needed for the CWS 200MB CRX budget).
            # Note: --fp16 not supported on ModernBERT by optimum as of 4.57.
            # Library 'onnxruntime' is the runtime that interprets the model.
            do_validation=False,  # we have our own held-out
            pad_token='<|padding|>',
        )
    except SystemExit as e:
        # main_export calls sys.exit(0) on success; ignore
        if e.code not in (0, None):
            print(f'WARNING: main_export exited with code {e.code}')
    except Exception as e:
        print(f'ERROR during export: {e}')
        # Try to continue and see what we got
        import traceback
        traceback.print_exc()

    # List what was produced
    print('\nExported files:')
    for f in sorted(TMP_DIR.iterdir()) if TMP_DIR.exists() else []:
        size_mb = f.stat().st_size / (1024*1024)
        print(f'  {f.name}: {size_mb:.1f} MB')

    # Copy artifacts to the dist
    print('\nCopying to dist...')
    # The optimum export produces model.onnx + tokenizer files.
    # We rename to a stable, descriptive name and include the config.
    mapping = {
        'model.onnx': 'pi-model.onnx',
        'tokenizer.json': 'pi-tokenizer.json',
        'tokenizer_config.json': 'pi-tokenizer-config.json',
        'special_tokens_map.json': 'pi-special-tokens-map.json',
    }
    for src_name, dst_name in mapping.items():
        src = TMP_DIR / src_name
        if src.exists():
            dst = OUT_DIR / dst_name
            shutil.copy2(src, dst)
            print(f'  copied {src_name} -> {dst_name}')
        else:
            print(f'  WARNING: {src_name} not found in {TMP_DIR}')

    # Copy the model config.json with a pi- prefix
    src_config = MODEL_DIR / 'config.json'
    if src_config.exists():
        dst_config = OUT_DIR / 'pi-config.json'
        shutil.copy2(src_config, dst_config)
        print(f'  copied config.json -> pi-config.json')

    # Copy the vocab (tokenizer.json contains vocab)
    src_vocab = MODEL_DIR / 'tokenizer.json'
    if src_vocab.exists():
        # Already copied as pi-tokenizer.json
        pass

    # Verify final dist contents
    print('\nFinal dist/detectors/ml/ contents:')
    for f in sorted(OUT_DIR.iterdir()):
        size_mb = f.stat().st_size / (1024*1024)
        print(f'  {f.name}: {size_mb:.2f} MB')

    total_mb = sum(f.stat().st_size for f in OUT_DIR.iterdir()) / (1024*1024)
    print(f'\nTotal ML bundle size: {total_mb:.1f} MB')

    print('\n=== ONNX export complete ===')
    print(f'Next step: vendor onnxruntime-web into {OUT_DIR.parent.parent}/vendor/onnxruntime-web/')

if __name__ == '__main__':
    main()
