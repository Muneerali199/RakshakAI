#!/bin/bash
# RakshakAI training launcher — runs in background
cd "$(dirname "$0")"
export PYTHONWARNINGS="ignore"
nohup python3 train_lightweight.py \
  --num-samples 2000 \
  --d-model 128 \
  --num-heads 4 \
  --d-ff 256 \
  --num-layers 4 \
  --vocab-size 8000 \
  --max-length 256 \
  --batch-size 8 \
  --epochs 10 \
  --lr 2e-4 \
  --output-dir models/rakshakai-v1/ \
> training_run.log 2>&1 &
echo "Training PID: $!"
echo "Log: training_run.log"
echo "Monitor: tail -f training_run.log"
