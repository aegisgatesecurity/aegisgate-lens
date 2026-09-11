# Third-Party Licenses — AegisGate Lens

This file lists all third-party dependencies used by AegisGate Lens.

**Total dependencies:** 0

---

## Overview

AegisGate Lens is a browser extension with **zero external dependencies**. It does not use npm, does not bundle any third-party JavaScript, and does not load any external resources at runtime.

All code is written in vanilla JavaScript and runs entirely on-device. The ML threat detector implements the Char CNN-BiLSTM forward pass in pure JavaScript — no ONNX Runtime, no WASM, no external inference library.

## Browser APIs

The extension uses standard browser extension APIs:
- `chrome.*` / `browser.*` (Manifest V3 APIs)
- `DecompressionStream` (built-in browser API for gzip decompression)
- `TextEncoder` / `TextDecoder` (built-in browser APIs)

These are platform APIs, not third-party libraries, and do not require license attribution.

## Model Weights

The trained ML model weights (`models/threat_cnn_bilstm_weights.bin.json`) are licensed under the [AegisGate Model Weight License v1.0](./WEIGHTS-LICENSE.md), separate from the Apache 2.0 code license.

---

*Copyright © 2026 AegisGate Security, LLC. All rights reserved.*
