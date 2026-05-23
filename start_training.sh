#!/bin/bash
# RakshakAI v2 training — improved dataset, class-weighted loss, more epochs
cd "$(dirname "$0")"
export PYTHONWARNINGS="ignore"

echo "Starting RakshakAI v2 training..."
echo "Config: 8000 samples, d_model=192, 4 layers, 25 epochs"
echo "Log: training_v2.log"
echo ""

nohup python3 -m rakshakai.train \
  --num-samples 8000 \
  --d-model 192 \
  --num-heads 6 \
  --d-ff 384 \
  --num-layers 4 \
  --vocab-size 8000 \
  --max-length 256 \
  --batch-size 12 \
  --epochs 25 \
  --lr 3e-4 \
  --dropout 0.15 \
  --output-dir models/rakshakai-v1/ \
> training_v2.log 2>&1 &

echo "PID: $!"
echo "Monitor: tail -f training_v2.log"
