#!/bin/bash
# RakshakAI — 14B QLoRA for Lightning.ai (fits 14 credits)
set -e
cd ~

START=$SECONDS
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   14B on A100 @ 2.50 cr/hr · 14 cr budget = 5.6h           ║"
echo "║   SFT (250K) ~3.5h + DPO (7K) ~0.8h + Eval ~0.5h = ~4.8h  ║"
echo "║   Budget remaining: ~$2.00                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo "[1/5] Cloning repo..."
GIT_ASKPASS=echo git clone https://github.com/Muneerali199/RakshakAI.git ~/RakshakAI --depth 1 2>&1 | tail -3

echo "[2/5] Extracting dataset..."
mkdir -p ~/RakshakAI/v2/inputs/datasets/axolotl ~/RakshakAI/v2/model ~/RakshakAI/v2/prepared
tar xzf ~/axolotl_dataset.tar.gz -C ~/RakshakAI/v2/inputs/datasets/axolotl/
rm ~/axolotl_dataset.tar.gz
echo "  Train:" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/train_250k.jsonl)
echo "  DPO:" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/dpo_train.jsonl)

echo "[3/5] Installing dependencies..."
pip install --break-system-packages torch==2.5.1 transformers==4.47.1 accelerate peft datasets bitsandbytes tensorboard sentencepiece axolotl==0.6.0 2>&1 | tail -3
python3 -c "import torch; print(f'  PyTorch {torch.__version__}, CUDA: {torch.cuda.is_available()}')"

echo "[4/5] 14B SFT phase (~3.5h)..."
cd ~/RakshakAI
python -m axolotl.cli.train v2/configs/lightning_14b_sft.yaml 2>&1 | tee ~/train_sft.log
SFT_END=$SECONDS
echo "SFT done: $(( (SFT_END - START) / 60 )) min elapsed"

echo "[5/5] 14B DPO phase (~0.8h)..."
python -m axolotl.cli.train v2/configs/lightning_14b_dpo.yaml 2>&1 | tee ~/train_dpo.log
END=$SECONDS
echo "Total: $(( (END - START) / 60 )) min"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   DONE! Cost: ~$(( (END - START) / 60 * 250 / 100 )) credits  ║"
echo "║   SFT: v2/model/sft_14b    DPO: v2/model/dpo_14b            ║"
echo "║   Push to HF:                                              ║"
echo "║     export HF_TOKEN=\"hf_...\"                               ║"
echo "║     python v2/scripts/merge_lora.py --sft v2/model/sft_14b  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
