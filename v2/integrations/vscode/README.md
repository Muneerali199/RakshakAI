# RakshakAI — AI Security Code Review

AI-powered security scanner for VS Code. Detects vulnerabilities in real-time, generates one-click fixes, and syncs reports to Notion.

## Features

- **Real-time Scanning** — Code is scanned automatically on save
- **12+ LLM Providers** — Groq (1.3s), Nebius (Kimi K2.7, Qwen 3.5), Ollama, HuggingFace, Fireworks
- **One-click Fix** — Right-click → "Apply Suggested Patch" to fix vulnerabilities
- **Security Dashboard** — Interactive webview with stats, severity badges, and finding cards
- **Notion Integration** — Send vulnerability reports to your team's Notion Security Center
- **40+ Languages** — Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby, PHP, Solidity, and more
- **CWE Detection** — Maps findings to CWE taxonomy (CWE-78, CWE-89, CWE-798, etc.)

## Quick Start

1. Install the extension
2. Start the RakshakAI server: `python3 -m v2.deploy.server`
3. Open any supported file — scanning starts automatically

## Commands

| Command | Description |
|---|---|
| `Scan Current File` | Scan the active file for vulnerabilities |
| `Scan Workspace` | Scan all files in the workspace |
| `Open Security Dashboard` | Interactive dashboard with stats |
| `Choose Provider & Model` | Switch between LLM providers |
| `Apply Suggested Patch` | Apply AI-generated fix |
| `Create Notion Report` | Sync finding to Notion |
| `Export All to Notion` | Create a complete Notion report for every current finding |

## Provider Setup

### Groq (Recommended — Fast, Free)

1. Get a free API key at [console.groq.com](https://console.groq.com)
2. Set in settings: `rakshakai.provider` → `groq`
3. Set environment variable: `GROQ_API_KEY=gsk_your_key`

### Nebius (Best Accuracy)

1. Get API key at [nebius.ai](https://nebius.ai)
2. Set: `rakshakai.provider` → `nebius`
3. Set: `NEBIUS_API_KEY=your_key`

### Ollama (Local, Private)

1. Install Ollama: [ollama.ai](https://ollama.ai)
2. Pull a model: `ollama pull qwen2.5-coder:7b`
3. Set: `rakshakai.provider` → `ollama`

## Configuration

| Setting | Default | Description |
|---|---|---|
| `rakshakai.serverUrl` | `http://localhost:8080` | Server URL |
| `rakshakai.scanOnSave` | `true` | Auto-scan on save |
| `rakshakai.provider` | `groq` | LLM provider |
| `rakshakai.severityFilter` | `["critical","high","medium"]` | Severity filter |
| `rakshakai.minConfidence` | `0.6` | Min confidence threshold |
| `rakshakai.notionEnabled` | `false` | Enable Notion integration |
| `rakshakai.notionServerUrl` | `http://localhost:8080` | Server that exposes the Notion integration API |

## Notion setup and one-click export

1. Create a Notion integration, copy its token, and share the destination parent page with that integration.
2. Set `NOTION_TOKEN` (or `NOTION_API_KEY`) on the server, then call `POST /v2/notion/setup` once with the parent page ID. This creates the **RakshakAI Security Center** database.
3. Scan a file or workspace, then use **Export All to Notion** in the RakshakAI sidebar. One detailed page is created for every finding, including the severity, CWE, file and line, vulnerable code, root cause, attack scenario, proposed patch, references, and remediation checklist.

For a single finding, use the lightbulb action **Create Notion Report**. If Notion is temporarily unavailable, the extension tells you that the report was queued instead of claiming it was created.

## Requirements

- RakshakAI server running (`python3 -m v2.deploy.server`)
- Python 3.9+
- At least one LLM provider configured (Groq free tier recommended)

## Links

- [GitHub](https://github.com/Muneerali199/RakshakAI-Security)
- [Documentation](https://github.com/Muneerali199/RakshakAI-Security#readme)
- [Report Issues](https://github.com/Muneerali199/RakshakAI-Security/issues)
