#!/bin/bash
# Launch v0.2 prompt-injection training with proper loss logging.
# Outputs to logs/training-prompt-injection.log.
# Loss sidecar: models/prompt-injection-v0.2.0/loss_history.json
#
# Estimated wall-clock: ~3-4 hours on RTX 3060.

set -e
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02
source .venv-v02/bin/activate

# Memory fragmentation mitigation (per PyTorch best practices for Ampere+)
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export TOKENIZERS_PARALLELISM=false

mkdir -p logs models/prompt-injection-v0.2.0

echo "[launch] Starting training at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee logs/training-prompt-injection.log

# Train with:
#   - 2 epochs (instead of 3; balanced corpus + 2 epochs is sufficient)
#   - micro_batch=8, grad_accum=4 (effective batch=32)
#   - bf16 mixed-precision
#   - LossLogger callback (per Lesson #82, #88)
python tools/train_lens_v0.2.x.py --facet prompt-injection --epochs 2 \
    2>&1 | tee -a logs/training-prompt-injection.log

echo "[launch] Training complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a logs/training-prompt-injection.log
