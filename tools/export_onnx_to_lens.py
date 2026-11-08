#!/usr/bin/env python3
"""
Export v16b ONNX model to Lens float16 JSON weight format.

Extracts weight tensors from an ONNX model, converts float32 → float16,
gzip compresses, base64 encodes, and packages as JSON with metadata.

Usage:
    python3 tools/export_onnx_to_lens.py <model.onnx> <output.json>
"""

import sys
import gzip
import base64
import json
import hashlib
import struct
import numpy as np
import onnx
from onnx import numpy_helper

def tensor_to_float16_bytes(tensor_proto):
    """Convert an ONNX tensor to float16 bytes."""
    arr = numpy_helper.to_array(tensor_proto)
    # Handle different dtypes
    if arr.dtype == np.float32:
        arr_f16 = arr.astype(np.float16)
    elif arr.dtype == np.int64 or arr.dtype == np.int32:
        # Keep integer tensors as-is (embedding weights are ints)
        # But the JS code treats everything as float16, so convert
        arr_f16 = arr.astype(np.float32).astype(np.float16)
    else:
        arr_f16 = arr.astype(np.float16)
    return arr_f16.tobytes()

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <model.onnx> <output.json>")
        sys.exit(1)

    model_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f"Loading ONNX model: {model_path}")
    model = onnx.load(model_path)

    # Collect tensor metadata and raw bytes
    meta = []
    all_bytes = bytearray()
    offset = 0

    for init in model.graph.initializer:
        arr = numpy_helper.to_array(init)
        shape = list(init.dims)
        f16_bytes = tensor_to_float16_bytes(init)
        byte_length = len(f16_bytes)

        meta.append({
            'n': init.name,
            's': shape,
            'o': offset,
            'l': byte_length  # byte length (float16 = 2 bytes per element)
        })

        all_bytes.extend(f16_bytes)
        offset += byte_length

    print(f"Found {len(meta)} tensors")
    print(f"Total weight bytes: {len(all_bytes)}")

    # Gzip compress
    compressed = gzip.compress(bytes(all_bytes))
    print(f"Compressed: {len(compressed)} bytes ({len(compressed)/len(all_bytes)*100:.1f}%)")

    # Base64 encode
    b64_data = base64.b64encode(compressed).decode('ascii')
    print(f"Base64: {len(b64_data)} chars")

    # Build JSON package
    package = {
        'v': '1.0',
        'meta': meta,
        'data': b64_data
    }

    # Write JSON (compact format)
    with open(output_path, 'w') as f:
        json.dump(package, f, separators=(',', ':'))

    # Compute SHA-256
    with open(output_path, 'rb') as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()

    print(f"\nOutput: {output_path}")
    print(f"Size: {len(content)} bytes")
    print(f"SHA-256: {sha256}")
    print(f"Tensors: {len(meta)}")

    # Print tensor summary
    for m in meta:
        print(f"  {m['n']}: shape={m['s']} offset={m['o']} len={m['l']}")

if __name__ == '__main__':
    main()