# BENCHMARK_RESULTS.md

## Security Benchmark Results

Benchmark: `security_benchmark.jsonl` (31 locked samples, 20+ CWEs, 7 languages)

### Vulnerability Detection

| Metric | Base Qwen2.5-Coder | Phase A |
|--------|-------------------|---------|
| tp | 0 | 0 |
| fp | 0 | 0 |
| tn | 0 | 0 |
| fn | 0 | 0 |
| precision | 0.0000 | 0.0000 |
| recall | 0.0000 | 0.0000 |
| f1 | 0.0000 | 0.0000 |
| accuracy | 0.0000 | 0.0000 |
| false_positive_rate | 0.0000 | 0.0000 |
| false_negative_rate | 0.0000 | 0.0000 |

### CWE Classification

| Metric | Base Qwen2.5-Coder | Phase A |
|--------|-------------------|---------|
| Accuracy | 0.0000 | 0.0000 |
| Top-3 Accuracy | 0.0000 | 0.0000 |
| Parse Failures | 31 | 31 |

### Severity Prediction

| Exact Match Accuracy | 0.0000 | 0.0000 |

### Fix Quality

| Mean Quality Score | 0.3000 | 0.3000 |
| Pass Rate @ 0.6 | 0.0000 | 0.0000 |

### Per-CWE Performance

| CWE | N | Base F1 | Phase A F1 | Δ |
|-----|---|---------|-------------|-----|
| CWE-119 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-120 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-122 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-1333 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-190 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-20 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-200 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-287 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-295 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-327 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-347 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-352 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-416 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-434 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-444 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-502 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-601 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-611 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-74 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-78 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-79 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-798 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-862 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-89 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-918 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-94 | 1 | 0.0% | 0.0% | +0.0% |

### Most Improved Categories

No categories with statistically significant improvement detected.

### Weakest Categories

No categories regressed significantly.

### Inference Speed

| Model | Total Time | Avg/Sample |
|-------|------------|------------|
| Base Qwen2.5-Coder | 784.3s | 25.30s |
| Phase A (QLoRA) | 775.2s | 25.01s |
