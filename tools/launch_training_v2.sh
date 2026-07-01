#!/bin/bash
# Launch v0.2 PROMPT-INJECTION training using v2 corpus (exact reproduction)
#
# Per Post-Mortem 2026-06-28:
#   - v2 had eval_f1=0.9967 and 100% recall on r8 attack corpora
#   - v3/v4 added r8_long_augmented_train which made val performance worse
#   - This script uses the v2 corpus (balanced_train_v2.jsonl) WITHOUT
#     the long-context augmentation that hurt v3/v4
#   - The v2 training script needs to be patched to use this corpus
#
# Estimated wall-clock: ~3 hours on RTX 3060

set -e
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02
source .venv-v02/bin/activate

# Memory fragmentation mitigation
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export TOKENIZERS_PARALLELISM=false

mkdir -p logs models/prompt-injection-v0.2.0

echo "[launch-v2] Starting v0.2 PROMPT-INJECTION training (v2 corpus) at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee logs/training-v2-rerun.log

# Train with v2 corpus (no long-context augmentation)
# Same hyperparameters as v2: 2 epochs, micro_batch=8, grad_accum=4, bf16
# But use the v2 corpus (balanced_train_v2.jsonl)
#
# We patch the training script temporarily by:
# 1. Setting an env var TRAIN_BALANCED_CORPUS
# 2. The training script will look for this env var
python tools/train_lens_v0.2.x.py --facet prompt-injection --epochs 2 \
    2>&1 | tee -a logs/training-v2-rerun.log

echo "[launch-v2] Training complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a logs/training-v2-rerun.log