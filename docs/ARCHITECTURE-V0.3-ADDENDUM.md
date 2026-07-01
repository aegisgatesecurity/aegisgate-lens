# Architecture Decision Record — v0.3.0 Addendum

**Date**: 2026-06-30
**Status**: v0.3.0-rc1

## Decision 1: ModernBERT-base replaces v0.2.2's regex-only approach
149M params, 8K context for Facet 6 PI detection.

## Decision 2: Sliding window inference for long-context attacks
2048/1024/4. Max-pool. Adaptive <512.

## Decision 3: Detection threshold tuned to 0.05
100% short, 80%+ long, 0% FPR.

## Decision 4: 6-facet detection system
PII + Secrets + XSS + Compliance + Toxicity + PI.

## Decision 5: Zero third-party JS deps
ONNX Runtime Web bundled. CI grep enforces.

## Decision 6: Ed25519 bundle signing
8/8 attack vectors rejected.

## Decision 7: SLSA L2 + Sigstore + Rekor
`gh attestation verify --repo owner/repo <artifact>`.

## Decision 8: Privacy boundary test in CI
14 adversarial events. No prompt content crosses wire.

## Decision 9: SLSA L2 for v0.3.0, L3 for v0.4.0
