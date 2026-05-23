# Changelog

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
