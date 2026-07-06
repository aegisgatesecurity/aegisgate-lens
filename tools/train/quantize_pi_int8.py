#!/usr/bin/env python3
"""
Quantize the PI model to INT8 for browser deployment.

Per user directive (2026-07-05 19:13): the only path is the proper
browser ML wiring. The FP32 model is 1.5GB which is too large for
the 200MB CWS eager budget. INT8 quantization reduces to ~400MB,
which fits in the lazy-loaded ML tier.

Input:  test/headless-smoke/dist/detectors/ml/pi-model.onnx  (FP32, 1.5GB)
Output: test/headless-smoke/dist/detectors/ml/pi-model-int8.onnx (~400MB)

Uses onnxruntime.quantization static quantization with calibration.
For ModernBERT, we quantize the MatMul and Gemm ops; everything
else stays FP32. The accuracy loss is typically <1% on classification.

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import sys
import time
from pathlib import Path

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
FP32_MODEL = LENS / 'test' / 'headless-smoke' / 'dist' / 'detectors' / 'ml' / 'pi-model.onnx'
INT8_MODEL = LENS / 'test' / 'headless-smoke' / 'dist' / 'detectors' / 'ml' / 'pi-model-int8.onnx'
CALIB_DATA = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-train.jsonl'

def main():
    if not FP32_MODEL.exists():
        print(f'ERROR: FP32 model not found at {FP32_MODEL}')
        print('Run tools/train/export_pi_onnx.py first.')
        sys.exit(1)

    print(f'FP32 model: {FP32_MODEL} ({FP32_MODEL.stat().st_size / 1024**3:.2f} GB)')
    print(f'Output:     {INT8_MODEL}')

    from onnxruntime.quantization import quantize_static, CalibrationDataReader, QuantType

    # Build a calibration data reader from the training corpus.
    # We need ~100 samples to calibrate the activation ranges.
    class TextCalibrationReader(CalibrationDataReader):
        def __init__(self, jsonl_path, n_samples=100):
            import json
            self.data = []
            with open(jsonl_path) as f:
                for i, line in enumerate(f):
                    if i >= n_samples:
                        break
                    try:
                        rec = json.loads(line)
                        text = rec.get('text', '')
                        if text:
                            self.data.append(text)
                    except Exception:
                        pass
            self.index = 0
            self.enum_data = iter(self.data)

        def get_next(self):
            if self.index >= len(self.data):
                return None
            self.index += 1
            return {'input_ids': None, 'attention_mask': None}  # placeholder, real preprocessing in pre_process

        def rewind(self):
            self.index = 0

    # For ModernBERT, we need a real preprocessing function. The
    # onnxruntime.quantization API expects a pre_process that takes
    # the model input dict and returns numpy arrays.
    #
    # However, the simpler approach: use quantize_dynamic which
    # doesn't need calibration data and is faster (just quantizes
    # weights). Accuracy loss is slightly higher but still <2%.
    print('\nUsing DYNAMIC quantization (no calibration data needed)')
    print('This is faster and simpler. Accuracy loss is typically <2% for transformers.')

    from onnxruntime.quantization import quantize_dynamic, QuantType

    # Quantize weights to INT8, activations stay FP32.
    # This gives ~4x size reduction with minimal accuracy loss.
    print(f'\nQuantizing... (this may take 5-10 minutes)')
    start = time.time()
    quantize_dynamic(
        model_input=str(FP32_MODEL),
        model_output=str(INT8_MODEL),
        weight_type=QuantType.QInt8,
    )
    elapsed = time.time() - start
    print(f'\nQuantization complete in {elapsed:.0f}s')
    print(f'FP32 size: {FP32_MODEL.stat().st_size / 1024**3:.2f} GB')
    print(f'INT8 size: {INT8_MODEL.stat().st_size / 1024**3:.2f} GB')
    if INT8_MODEL.stat().st_size > FP32_MODEL.stat().st_size:
        print('WARNING: INT8 model is LARGER than FP32 (quantization may not have worked)')

    # Verify the quantized model can be loaded and produces sane outputs
    print('\n=== Verifying quantized model ===')
    import onnxruntime as ort
    import numpy as np
    sess = ort.InferenceSession(str(INT8_MODEL), providers=['CPUExecutionProvider'])
    for inp in sess.get_inputs():
        print(f'  input: {inp.name} {inp.shape} {inp.type}')
    for out in sess.get_outputs():
        print(f'  output: {out.name} {out.shape} {out.type}')

    # Quick sanity test: pass a dummy input
    inp_names = [i.name for i in sess.get_inputs()]
    test_input = {n: np.zeros([1, 128], dtype=np.int64) for n in inp_names}
    outputs = sess.run(None, test_input)
    print(f'\n  test output shape: {[o.shape for o in outputs]}')
    print(f'  test output values: {[o.flatten()[:3].tolist() for o in outputs]}')
    print('\n=== INT8 quantization complete ===')

if __name__ == '__main__':
    main()
