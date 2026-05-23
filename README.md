# RakshakAI — India's First Security AI

**रक्षक AI** — Lightweight, high-accuracy ML model for code vulnerability detection. Built in India, for the world.

## Vision

A small-footprint, low-cost ML model that outperforms traditional static analysis tools — detecting SQL injection, XSS, command injection, hardcoded secrets, and 18+ vulnerability classes in real-time.

## Model Architecture

- Base: CodeBERT / DistilBERT
- Sequence classification for vulnerability detection
- Optimized for CPU inference (no GPU required)
- 21 vulnerability classes + clean code detection

## Dataset

| Class | Samples |
|-------|---------|
| SQL Injection | 9200+ |
| XSS | 8000+ |
| Command Injection | 5000+ |
| Hardcoded Secrets | 6000+ |
| Path Traversal | 4000+ |
| Weak Crypto | 3500+ |
| SSTI | 3000+ |
| Insecure Deserialization | 3000+ |
| JWT Vulnerability | 2000+ |
| ... and 12 more classes | |
| **Clean Code** | 900+ |
| **Total** | **10,100+** |

## Training

### Local (CPU)
```bash
pip install -r requirements.txt
python train.py
```

### Google Colab (GPU - recommended)
Upload the `RakshakAI/` folder to Colab and run:
```bash
!pip install -r requirements.txt
!python train.py
```

## Inference API

```bash
python server.py
# Server runs on http://0.0.0.0:8000
```

```bash
curl -X POST http://localhost:8000/ml/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")", "language": "python"}'
```

## Testing

```bash
python test.py
```

## Performance Target

- Model size: < 100MB
- Inference time: < 50ms per snippet on CPU
- Accuracy: > 95% on test set
- Cost: Runs on $5/mo VPS

## License

MIT — Made in India 🇮🇳
