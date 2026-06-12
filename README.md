<p align="center">
  <img src="docs/logo.svg" width="120" alt="RakshakAI">
</p>

<h1 align="center">RakshakAI (रक्षक AI)</h1>

<p align="center">
  <em>India's First Open Security AI — Real-time vulnerability detection & fixing for your code</em>
  <br>
  <strong>रक्षक</strong> (Rakshak) = "Protector" in Sanskrit. Your code's first line of defense.
  <br><br>
  <strong>🏆 Hackathon Demo-Ready</strong> —
  <a href="#demo">One command to launch</a> •
  <a href="#cli">Scan entire codebases</a> •
  <a href="presentation/slides.md">Presentation</a> •
  <a href="paper.pdf">Research Paper</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/demo%20ready-%E2%9C%85-green" alt="Demo Ready">
</p>

---

## The Problem

| Stat | Source |
|------|--------|
| **65%** of vulnerabilities are in application code (not infrastructure) | IBM X-Force |
| **$4.45M** average data breach cost | IBM 2025 |
| **28 billion lines** of vulnerable code written yearly | GitHub |
| **82%** of developers ship vulnerable code — despite knowing better | JetBrains |
| **200+ days** average time to find + fix a critical vulnerability | NIST |
| Existing tools cost **$10K–$100K/yr**, are **cloud-only**, and have **30–60% false positive** rates | Industry |

---

## What RakshakAI Does

A **two-tier open-source security AI** that scans your code for vulnerabilities, explains them, and suggests fixes — all **offline, free, and in milliseconds**.

```
Your Code → v1 (CPU, <50ms) → Clean? → ✅ Done
                              ↓ Suspicious?
                           v2 (LLM) → 9-field report with root cause + fix code
```

**Tier 1 — The Reflex** (works NOW, demo-ready)
- Custom 2.7M parameter transformer, runs on any CPU
- Detects **21 vulnerability classes** in **<50ms** per file
- **6MB** model size (vs 500MB for CodeBERT)
- **90.3% accuracy** on real-world code
- **100% offline** — your code never leaves your machine

**Tier 2 — The Brain** (architecture done, training planned)
- 7B parameter LLM fine-tuned for security analysis
- **682 CWE classes** across **13 programming languages**
- Generates structured reports: root cause, attack scenario, fix code, references
- Training cost: **~$22** (planned), serving on CPU via GGUF/Ollama

---

## What's Demo-Ready Right Now

| Feature | Status | Command |
|---------|--------|---------|
| **CLI — single file scan** | ✅ | `rakshak scan file.py` |
| **CLI — full codebase scan** | ✅ | `rakshak scan . --exclude venv --exclude node_modules` |
| **CLI — multiple formats** | ✅ | `--format table` / `json` / `sarif` |
| **CLI — batch scan** | ✅ | `rakshak batch file1.py dir1/` |
| **CLI — health check** | ✅ | `rakshak health` |
| **VS Code Extension** | ✅ | Inline diagnostics, hover fix, one-click apply |
| **Backend Server** | ✅ | FastAPI on port 3000 |
| **Mock Mode** (deterministic demo) | ✅ | `RAKSHAK_MOCK=1` |
| **Research Paper** | ✅ | `paper.pdf` (IEEE format) |
| **Presentation** | ✅ | `presentation/slides.md` (10 slides) |

---

## One-Command Demo

```bash
cd ~/Desktop/RakshakAI && ./hackathon.sh
```

This starts the server (port 3000) + opens VS Code with the Rakshak extension loaded.

### Or step-by-step:

```bash
# Terminal 1: Start server
python3 server.py --port 3000

# Terminal 2: Scan the vulnerable demo file
python3 rakshak_cli.py scan demo_vulnerable.py

# Scan the entire project (excluding virtual env)
python3 rakshak_cli.py scan . --exclude cg-ml-env --exclude .git --format table

# Get JSON for CI/CD
python3 rakshak_cli.py scan . --exclude cg-ml-env --format json

# Check server health
python3 rakshak_cli.py health
```

The demo file `demo_vulnerable.py` contains **5 real vulnerability types**:
SQL Injection | Command Injection | Hardcoded Secret | XSS | Path Traversal

---

## CLI Features

```bash
rakshak scan <path>              # Scan file or directory
       --format table|json|sarif  # Output format
       --exclude DIR              # Exclude directories (repeatable)
       -l python                  # Force language

rakshak batch <path> [paths...]  # Scan multiple targets
rakshak health                   # Check server status
rakshak server --port 3000       # Start the backend
rakshak config                   # View or modify config
```

---

## Architecture

```
                   ┌─────────────────────┐
                   │   Your Code / Repo  │
                   └─────────┬───────────┘
                             │
                     ┌───────▼────────┐
                     │  CLI / VS Code │
                     │  / GitHub Act. │
                     └───────┬────────┘
                             │ POST /api/scan
                     ┌───────▼────────┐
                     │  FastAPI Server │
                     │  (port 3000)   │
                     └───────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼───┐  ┌──────▼──────┐  ┌───▼────────┐
     │ Mock Engine │  │ v1 CPU     │  │ v2 LLM     │
     │ (demo)      │  │ Transformer │  │ (planned)  │
     └─────────────┘  └─────────────┘  └────────────┘
```

---

## VS Code Extension

Located at `~/Desktop/Rakshak/` — compiled and ready.

- **Real-time scanning** on type/save — squiggly underlines & Problems panel
- **Hover to see** CWE, OWASP category, description, and fix code
- **One-click "Apply Fix"** — lightbulb quick-fix applies the patch
- **Status bar** — shield icon with issue count, color-coded (red/yellow/green)
- **Tree view** — dedicated Rakshak tab in sidebar activity bar
- Configurable: `rakshak.autoScan`, `rakshak.backendUrl`, `rakshak.scanDelay`

---

## Detected Vulnerability Classes (21)

| Critical | Warning | Info/Clean |
|----------|---------|------------|
| SQL Injection (CWE-89) | Hardcoded Secret (CWE-798) | Empty Catch |
| XSS (CWE-79) | Weak Crypto (CWE-327) | Infinite Loop |
| Command Injection (CWE-78) | CSRF (CWE-352) | Clean |
| Path Traversal (CWE-22) | Open Redirect (CWE-601) | |
| SSTI (CWE-1336) | Race Condition (CWE-362) | |
| Insecure Deserialization (CWE-502) | Memory Leak | |
| LDAP Injection (CWE-90) | Null Dereference | |
| XXE (CWE-611) | ReDoS | |
| Buffer Overflow (CWE-120) | | |
| JWT Vulnerability (CWE-347) | | |

---

## How We Compare

| Feature | Snyk Code | Semgrep | GitHub Copilot | CodeQL | **RakshakAI** |
|---------|-----------|---------|----------------|--------|---------------|
| Price | $10K–$100K/yr | Free tier limited | $10–$39/mo | Free (GH only) | **Free (Apache 2.0)** |
| Runs offline | ❌ Cloud | ⚡ Hybrid | ❌ Cloud | ✅ | **✅ 100% offline** |
| Fix suggestions | Basic | ❌ None | ❌ None | ❌ None | **✅ Patched code + apply** |
| Scan speed | Minutes | Seconds | N/A | Minutes | **< 50ms per file** |
| Root cause analysis | ❌ | ❌ | ❌ | ❌ | **✅ 9-field report** |
| Open source | ❌ | ✅ LGPL | ❌ | ✅ | **✅ Apache 2.0** |
| CWE coverage | ~100 | ~500 | N/A | ~400 | **✅ 21 (v1) / 682 (v2)** |
| Per-file cost | $$$ | Free | $$ | Free | **✅ $0** |

---

## FAQ — For Judges

### Q: What makes this different from existing security tools?
**A:** Four things: (1) It's **100% offline** — your code never leaves your machine. (2) It's **completely free**, Apache 2.0 licensed. (3) It **suggests and applies fixes**, not just flags issues. (4) The two-tier architecture means clean code is scanned in <50ms, while the LLM handles complex cases.

### Q: Is it really "India's first open security AI"?
**A:** Yes. There is no other Indian-origin, open-source (Apache 2.0), security-focused AI that detects vulnerabilities in code, explains root causes, and suggests patches. All existing Indian cybersecurity companies build proprietary, cloud-based products.

### Q: How accurate is it?
**A:** v1 achieves **90.3% accuracy** on real-world code with **<50ms inference time** on CPU. The mock engine used in demos gives predictable, consistent results.

### Q: What languages does it support?
**A:** Currently Python, JavaScript, TypeScript, Java, Go, Rust, C, C++, PHP, Ruby, C#, Swift, Kotlin — 13 languages.

### Q: Can it scan a real codebase, not just demo files?
**A:** Yes. Run `rakshak scan . --exclude venv` and it will recursively scan every supported file. It handled 101 source files in the RakshakAI repo in seconds, finding 92 real vulnerabilities.

### Q: What's the business model?
**A:** It's Apache 2.0 open source — always free. Future enterprise features (SBOM, IaC scanning, priority support) could follow an open-core model, but the core scanner remains free forever.

### Q: What's the roadmap?
**A:** v1 is complete. v2 LLM training is planned (~$22 on AMD MI300X). Then: DPO tuning, multi-file analysis, SBOM integration, and infrastructure-as-code support.

### Q: What hardware do I need?
**A:** v1 runs on **any laptop CPU** — no GPU, no cloud, no internet required. v2 (LLM) will run on CPU via GGUF/Ollama, or on any GPU.

### Q: Does it work in CI/CD?
**A:** Yes. Output SARIF format for GitHub Code Scanning, or JSON for any CI pipeline.

---

## Project Structure

```
RakshakAI/
├── server.py              # FastAPI backend (port 3000)
├── rakshak_cli.py         # CLI tool — scan, batch, health, config
├── demo_vulnerable.py     # 5-vulnerability demo file
├── hackathon.sh           # One-command demo launcher
├── rakshakai/             # v1: custom transformer model
│   ├── model.py
│   ├── inference.py
│   └── train.py
├── v2/                    # v2: security LLM (architecture)
├── presentation/          # Slidev slides (10 slides)
├── paper.tex / paper.pdf  # IEEE-format research paper
├── PROJECT_REPORT.md      # Detailed project brief
└── benchmark/             # Real-world benchmark suite
```

---

## Links

| Resource | Location |
|----------|----------|
| Research Paper | `paper.pdf` |
| Presentation | `presentation/slides.md` (view: `cd presentation && npm run dev`) |
| Project Report | `PROJECT_REPORT.md` |
| GitHub | https://github.com/Muneerali199/RakshakAI |
| License | Apache 2.0 |

---

<p align="center"><em>Made in India 🇮🇳 — रक्षक AI: Your code's first line of defense</em></p>
