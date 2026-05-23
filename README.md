<p align="center">
  <img src="docs/logo.svg" width="120" alt="RakshakAI">
</p>

<h1 align="center">RakshakAI (रक्षक AI)</h1>

<p align="center">
  <em>India's First Security AI — Lightweight Vulnerability Detection</em>
  <br>
  <strong>रक्षक</strong> means "Protector" in Sanskrit. Your code's first line of defense.
</p>

<p align="center">
  <a href="https://github.com/Muneerali199/RakshakAI/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License">
  </a>
  <a href="https://github.com/Muneerali199/RakshakAI/actions">
    <img src="https://github.com/Muneerali199/RakshakAI/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/params-1.5M--7.3M-green" alt="Params">
  <img src="https://img.shields.io/badge/model-6MB-orange" alt="Size">
</p>

---

## Overview

RakshakAI is a **custom, lightweight transformer** for real-time code vulnerability detection. Built from scratch in pure PyTorch — no HuggingFace dependency. Designed to run on any CPU in under 50ms.

| Feature | RakshakAI |
|---------|-----------|
| Architecture | Custom Transformer (6 layers, 256-dim) |
| Parameters | **1.5M – 7.3M** (17× smaller than CodeBERT) |
| Model Size | **6 MB** (vs 500 MB for CodeBERT) |
| Inference | **<50ms** on CPU per snippet |
| Classes | **21** vulnerability types + clean |
| Cost | **$0** — runs on your laptop |
| Privacy | **100% offline** — code never leaves |

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Start server
python server.py

# Scan code
curl -X POST http://localhost:8000/ml/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")", "language": "python"}'
```

## Installation

```bash
git clone https://github.com/Muneerali199/RakshakAI
cd RakshakAI
pip install -r requirements.txt
```

### Requirements

- Python 3.9+
- PyTorch 2.0+ (CPU or CUDA)
- 4GB RAM minimum

## Model Architecture

```
RakshakLightweightTransformer
├── Token Embedding (vocab=8K-16K, dim=128-256)
├── Sinusoidal Positional Encoding
├── 4-6× Transformer Encoder Blocks
│   ├── Multi-Head Attention (4-8 heads)
│   ├── LayerNorm + GELU
│   └── Feed-Forward (dim×2)
└── Classification Head (21 classes)
```

### Configurations

| Config | Params | Vocab | d_model | Heads | Layers | Speed |
|--------|--------|-------|---------|-------|--------|-------|
| Tiny | 1.5M | 8K | 128 | 4 | 4 | **<20ms** |
| Small | 7.3M | 16K | 256 | 8 | 6 | <50ms |
| Medium | 18M | 32K | 384 | 12 | 8 | <100ms |

## Training

```bash
# Quick training (2000 samples, ~30 min on CPU)
python rakshakai/train.py --num-samples 2000 --epochs 10

# Full training (8000 samples, class-weighted)
python rakshakai/train.py --num-samples 8000 --d-model 192 --num-layers 4 --epochs 25
```

### Training Results

| Run | Samples | Params | Epochs | Accuracy |
|-----|---------|--------|--------|----------|
| v1 | 2,000 | 1.56M | 10 | **70.0%** |
| v2 (target) | 8,000 | 3.5M | 25 | **85%+** |

## Dataset

The training dataset contains **10,100+** synthetic code samples covering 21 classes:

| Class | Samples | CWE |
|-------|---------|-----|
| SQL Injection | 9200+ | CWE-89 |
| XSS | 8000+ | CWE-79 |
| Command Injection | 5000+ | CWE-78 |
| Hardcoded Secrets | 6000+ | CWE-798 |
| Path Traversal | 4000+ | CWE-22 |
| Weak Crypto | 3500+ | CWE-327 |
| SSTI | 3000+ | CWE-94 |
| Insecure Deserialization | 3000+ | CWE-502 |
| JWT Vulnerability | 2000+ | CWE-347 |
| +12 more classes | | |
| **Clean Code** | 900+ | — |

## API

### POST /ml/scan

```json
{
  "code": "os.system(\"ping \" + user_input)",
  "language": "python",
  "filename": "test.py"
}
```

Response:
```json
{
  "issues": [{
    "type": "COMMAND_INJECTION",
    "severity": "critical",
    "confidence": 0.95,
    "line": 1,
    "message": "Command Injection Detected",
    "cwe": "CWE-78"
  }],
  "total_issues": 1,
  "scan_time_ms": 12.5
}
```

### GET /ml/health

```json
{"status": "ok", "engine": "lightweight", "labels": 21}
```

## Package Structure

```
RakshakAI/
├── rakshakai/              # Main Python package
│   ├── __init__.py
│   ├── model.py            # Lightweight Transformer
│   ├── tokenizer.py         # BPE Tokenizer
│   ├── train.py             # Training pipeline
│   ├── inference.py         # Inference engine
│   └── data.py              # Dataset generation
├── examples/                # Example scripts
│   ├── scan_file.py
│   └── api_client.py
├── colabs/                  # Jupyter notebooks
├── docs/                    # Documentation
├── server.py                # FastAPI inference server
├── pyproject.toml
├── requirements.txt
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

## License

Apache 2.0 — Made in India 🇮🇳

*This is not an official Google product.*
