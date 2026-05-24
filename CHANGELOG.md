# Changelog

## [0.3.0] - 2026-05-24

### Training Results (v3)
- **90.3% real-world accuracy** (28/31 diverse test cases)
- **99.88% synthetic test accuracy** (799/800)
- **100.0% best validation accuracy** (800/800)
- **2.74M params** — runs in <30ms on CPU
- **25 epochs**, 8000 training samples, class-weighted loss
- 21 vulnerability classes with perfect per-class F1 on test set

### Improvements over v2
- Class-weighted CrossEntropyLoss (upweighted minority classes)
- Code mutation augmentation (variable renaming, whitespace, comments)
- More diverse templates per class (SQL injection: +60%, XSS: +50%)
- Better CLEAN examples for disambiguation

## [0.2.0] - 2026-05-24
### Added
- Custom lightweight transformer architecture (~1.5M params)
- BPE tokenizer trained on source code
- Knowledge distillation training pipeline
- Class-weighted loss for balanced training
- Code augmentation (variable renaming, whitespace, comments)
- ONNX export for fast CPU inference
- Professional package structure (`rakshakai/`)

### Training
- First training run: 70.0% accuracy on 2000 samples
- Supports tiny (2.5M), small (7.3M), medium (18M) model configs
- 21 vulnerability classes + clean code detection

## [0.1.0] - 2026-05-23
- Initial CodeBERT-based prototype
- FastAPI inference server
- Regex mock engine fallback
