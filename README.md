# RakshakAI v3

Multi-model security CLI with a fine-tuned 7B vulnerability detection model.

```bash
pip install -e .
rakshakai
```

## Quick Start

```bash
# Interactive REPL
rakshakai

# CI mode (JSON output)
rakshak-ci scan path/to/file.py --format json

# Single-file scan
/scan exploit.c
```

The default model is `rakshak` (fine-tuned Qwen2.5-Coder-7B on 80K CWE examples).
If the inference endpoint isn't available yet, switch to another model:

```
/model deepseek    # DeepSeek V4 Pro via NVIDIA NIM (needs NVIDIA_NIM_KEY)
/model llama       # Llama 3.1 70B via NVIDIA NIM
/model gpt-4o      # GPT-4o (needs OPENAI_API_KEY)
```

## Commands

| Command | Description |
|---|---|
| `/scan <file>` | Scan for vulnerabilities |
| `/explain <file>` | Explain code |
| `/fix <desc>` | Generate fix |
| `/batch <dir>` | Scan directory |
| `/watch <dir>` | Watch for changes |
| `/diff` | Scan git diff |
| `/precommit` | Install/uninstall pre-commit hook |
| `/parallel` | Run all models in parallel |
| `/model <name>` | Switch active model |
| `/models` | List models |
| `/history [query]` | Search past analyses |
| `/stats` | Scan statistics |
| `/confirm <id>` | Mark finding as true-positive |
| `/dismiss <id>` | Mark as false-positive |
| `/cost` | Per-model usage stats |
| `/clear` | Clear terminal |
| `/help` | Show help |
| `/exit` | Exit |

## CI Mode

```bash
# JSON output
rakshak-ci scan src/ --format json

# SARIF output (GitHub Code Scanning)
rakshak-ci scan src/ --format sarif

# Pipe stdin
echo "code" | rakshak-ci scan -

# Select model
rakshak-ci scan --model deepseek src/
```

## MCP Mode

```bash
rkscan-mcp
```

Supports Cursor, Claude Code, and any MCP client.
Tools: `scan_file`, `explain_code`, `fix_vulnerability`, `list_models`.

## Models

| Key | Model | Provider | Requires |
|---|---|---|---|
| `rakshak` | Fine-tuned Qwen2.5-Coder-7B | Modal / HF Inference | — |
| `deepseek` | DeepSeek V4 Pro | NVIDIA NIM | `NVIDIA_NIM_KEY` |
| `llama` | Llama-3.1-70B | NVIDIA NIM | `NVIDIA_NIM_KEY` |
| `gpt-4o` | GPT-4o | OpenAI | `OPENAI_API_KEY` |
| `gpt-4o-mini` | GPT-4o Mini | OpenAI | `OPENAI_API_KEY` |

## Architecture

Three entry points sharing one scan function:

- `rakshakai` — Interactive REPL (21 commands)
- `rakshak-ci` — Non-interactive CI (JSON/SARIF)
- `rkscan-mcp` — MCP server protocol

Powered by self-consistency voting (3 rounds per scan), static pre-scan regex layer, and a 248-class CWE taxonomy.
