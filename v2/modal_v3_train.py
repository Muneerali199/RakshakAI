"""
RakshakAI v3 — Modal QLoRA Training
Base: Qwen2.5-Coder-7B-Instruct
Dataset: Muneerali199/rakshak-cwe-v3-data (80K curated)
Hardware: A10G 24GB via QLoRA 4-bit
Output: Muneerali199/rakshak-cwe-v3 (LoRA adapter)

Usage:
    modal run v2/modal_v3_train.py::train --detach
"""
import os
from pathlib import Path
import modal

HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_DATASET = os.environ.get("HF_DATASET", "Muneerali199/rakshak-cwe-v3-data")
HF_REPO = os.environ.get("HF_REPO", "Muneerali199/rakshak-cwe-v3")

app = modal.App("rakshakai-v3")

image = (
    modal.Image.from_registry("pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel")
    .run_commands(
        "pip install --upgrade pip",
        "pip install transformers==4.47.1 datasets==3.2.0 accelerate==1.2.1 "
        "peft==0.14.0 trl==0.15.1 bitsandbytes==0.45.0 "
        "huggingface-hub==0.27.1 hf_transfer sentencepiece==0.2.0 protobuf==5.29.3",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HUB_DISABLE_SYMLINKS_WARNING": "1"})
)

@app.function(
    image=image,
    gpu="A10G",
    timeout=86400,
    secrets=[],
)
def train():
    import os, torch, gc
    from transformers import (
        AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments,
    )
    from peft import LoraConfig, prepare_model_for_kbit_training, get_peft_model
    from trl import SFTTrainer
    from datasets import load_dataset
    from huggingface_hub import login as hf_login

    os.environ["HF_TOKEN"] = HF_TOKEN
    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
    hf_login(HF_TOKEN)

    # ── Config ──
    MODEL_NAME = "Qwen/Qwen2.5-Coder-7B-Instruct"
    PER_DEVICE_BATCH_SIZE = 1
    GRADIENT_ACCUMULATION = 8
    MAX_STEPS = 2000
    LEARNING_RATE = 2e-4
    MAX_SEQ_LENGTH = 2048

    # ── Load model 4-bit ──
    print("Loading model...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.float16,
    )
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    tokenizer.model_max_length = MAX_SEQ_LENGTH
    print("Model loaded")

    # ── LoRA ──
    model = prepare_model_for_kbit_training(model)
    lora_config = LoraConfig(
        r=16, lora_alpha=32, target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"Trainable: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    # ── Dataset ──
    print(f"Loading dataset from {HF_DATASET}...")
    dataset = load_dataset(HF_DATASET, split="train")
    dataset = dataset.shuffle(seed=42)
    split = dataset.train_test_split(test_size=0.02, seed=42)
    train_dataset = split["train"]
    eval_dataset = split["test"]
    print(f"Train: {len(train_dataset)} | Eval: {len(eval_dataset)}")

    def format_chat(example):
        messages = example["messages"]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=False,
        )
        return {"text": text}

    # ── Training ──
    training_args = TrainingArguments(
        output_dir="/root/model",
        per_device_train_batch_size=PER_DEVICE_BATCH_SIZE,
        per_device_eval_batch_size=PER_DEVICE_BATCH_SIZE,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        max_steps=MAX_STEPS,
        learning_rate=LEARNING_RATE,
        fp16=True,
        logging_steps=25,
        save_steps=500,
        warmup_steps=100,
        lr_scheduler_type="cosine",
        optim="paged_adamw_8bit",
        report_to="none",
        remove_unused_columns=True,
        save_total_limit=2,
        push_to_hub=False,
        ddp_find_unused_parameters=False,
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        args=training_args,
        train_dataset=train_dataset,
        formatting_func=format_chat,
    )

    print("Starting training...")
    trainer.train()
    print("Training complete")

    # ── Save & Push ──
    print(f"Saving adapter to /root/model...")
    model.save_pretrained("/root/model")
    tokenizer.save_pretrained("/root/model")

    print(f"Pushing to {HF_REPO}...")
    model.push_to_hub(HF_REPO, token=HF_TOKEN)
    tokenizer.push_to_hub(HF_REPO, token=HF_TOKEN)
    print(f"Pushed to https://huggingface.co/{HF_REPO}")

    gc.collect()
    torch.cuda.empty_cache()
    print("Done!")
