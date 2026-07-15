"""World-class terminal UI with Rich components - inspired by opencode and kiro-cli."""
from __future__ import annotations
import os
import sys
import time
import shutil
import platform
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich.panel import Panel
from rich.rule import Rule
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.status import Status
from rich.align import Align
from rich.style import Style
from rich import box

# Console with paging support for long output
console = Console(highlight=False)
term_width = shutil.get_terminal_size().columns

MODEL_LABELS = {
    "ollama": "Ollama Local",
    "rakshak": "Rakshak",
    "deepseek": "DeepSeek V4 Pro",
    "llama": "Llama 3.1 70B",
    "mistral-nvidia": "Mistral Large",
    "nebius-llama-70b": "Llama 3.1 70B",
    "nebius-llama-8b": "Llama 3.1 8B",
    "nebius-qwen-72b": "Qwen 2.5 72B",
    "nebius-qwen-32b": "Qwen 2.5 32B",
    "nebius-mixtral": "Mixtral 8x22B",
    "nebius-deepseek": "DeepSeek V2.5",
    "fw-llama-70b": "Llama 3.1 70B",
    "fw-llama-8b": "Llama 3.1 8B",
    "fw-mixtral": "Mixtral 8x22B",
    "fw-qwen-72b": "Qwen 2.5 72B",
    "fw-deepseek-v3": "DeepSeek V3",
    "fw-phi-4": "Phi-4 14B",
    "tg-llama-70b": "Llama 3.1 70B Turbo",
    "tg-llama-8b": "Llama 3.1 8B Turbo",
    "tg-qwen-72b": "Qwen 2.5 72B Turbo",
    "tg-deepseek": "DeepSeek V3",
    "tg-mixtral": "Mixtral 8x22B",
    "groq-llama-70b": "Llama 3.1 70B",
    "groq-llama-8b": "Llama 3.1 8B",
    "groq-mixtral": "Mixtral 8x7B",
    "groq-gemma": "Gemma 2 9B",
    "groq-deepseek": "DeepSeek R1 Distill",
    "gpt-4o-mini": "GPT-4o Mini",
    "gpt-4o": "GPT-4o",
    "claude": "Claude Haiku",
    "claude-sonnet": "Claude Sonnet",
    # OpenRouter
    "or-gpt-4o": "GPT-4o (OR)",
    "or-gpt-4o-mini": "GPT-4o Mini (OR)",
    "or-claude-sonnet": "Claude Sonnet (OR)",
    "or-claude-haiku": "Claude Haiku (OR)",
    "or-deepseek-v3": "DeepSeek V3 (OR)",
    "or-llama-70b": "Llama 3.1 70B (OR)",
    "or-llama-8b": "Llama 3.1 8B (OR)",
    "or-mixtral": "Mixtral 8x22B (OR)",
    "or-gemini-2-flash": "Gemini 2.0 Flash (OR)",
    "or-qwen-72b": "Qwen 2.5 72B (OR)",
    "or-phi-4": "Phi-4 14B (OR)",
    "or-llama-3.2-3b": "Llama 3.2 3B (OR)",
    # Google Gemini
    "gemini-2-flash": "Gemini 2.0 Flash",
    "gemini-2-flash-lite": "Gemini 2.0 Flash Lite",
    "gemini-1.5-pro": "Gemini 1.5 Pro",
    "gemini-1.5-flash": "Gemini 1.5 Flash",
    # DeepSeek Native
    "ds-chat": "DeepSeek V3 Chat",
    "ds-reasoner": "DeepSeek R1 Reasoner",
    # Mistral AI
    "ms-large": "Mistral Large 2",
    "ms-small": "Mistral Small",
    "ms-codestral": "Codestral",
    # xAI Grok
    "grok-2": "Grok 2",
    # Perplexity
    "pplx-sonar": "Sonar Pro",
    "pplx-sonar-deep": "Sonar Deep",
    # DeepInfra
    "di-llama-70b": "Llama 3.1 70B (DI)",
    "di-llama-8b": "Llama 3.1 8B (DI)",
    "di-mixtral": "Mixtral 8x22B (DI)",
    "di-qwen-72b": "Qwen 2.5 72B (DI)",
    "di-deepseek": "DeepSeek V3 (DI)",
    # AI/ML API
    "aiml-gpt-4o": "GPT-4o (AI/ML)",
    "aiml-gpt-4o-mini": "GPT-4o Mini (AI/ML)",
    "aiml-claude-sonnet": "Claude Sonnet (AI/ML)",
    "aiml-llama-70b": "Llama 3.1 70B (AI/ML)",
    "aiml-deepseek": "DeepSeek V3 (AI/ML)",
}

MODEL_SHORT_LABELS = {
    "ollama": "ol",
    "rakshak": "rk",
    "deepseek": "ds",
    "llama": "l3-70b",
    "mistral-nvidia": "mx",
    "nebius-llama-70b": "nb-l3-70b",
    "nebius-llama-8b": "nb-l3-8b",
    "nebius-qwen-72b": "nb-qw-72b",
    "nebius-qwen-32b": "nb-qw-32b",
    "nebius-mixtral": "nb-mx",
    "nebius-deepseek": "nb-ds",
    "fw-llama-70b": "fw-l3-70b",
    "fw-llama-8b": "fw-l3-8b",
    "fw-mixtral": "fw-mx",
    "fw-qwen-72b": "fw-qw-72b",
    "fw-deepseek-v3": "fw-ds",
    "fw-phi-4": "fw-phi",
    "tg-llama-70b": "tg-l3-70b",
    "tg-llama-8b": "tg-l3-8b",
    "tg-qwen-72b": "tg-qw-72b",
    "tg-deepseek": "tg-ds",
    "tg-mixtral": "tg-mx",
    "groq-llama-70b": "gq-l3-70b",
    "groq-llama-8b": "gq-l3-8b",
    "groq-mixtral": "gq-mx",
    "groq-gemma": "gq-gm",
    "groq-deepseek": "gq-ds",
    "gpt-4o-mini": "gpt4m",
    "gpt-4o": "gpt4o",
    "claude": "cl",
    "claude-sonnet": "cl-sn",
    # OpenRouter
    "or-gpt-4o": "or-g4o",
    "or-gpt-4o-mini": "or-g4m",
    "or-claude-sonnet": "or-csn",
    "or-claude-haiku": "or-chk",
    "or-deepseek-v3": "or-ds",
    "or-llama-70b": "or-l3-70b",
    "or-llama-8b": "or-l3-8b",
    "or-mixtral": "or-mx",
    "or-gemini-2-flash": "or-gf",
    "or-qwen-72b": "or-qw72",
    "or-phi-4": "or-phi",
    "or-llama-3.2-3b": "or-l3-3b",
    # Google Gemini
    "gemini-2-flash": "gm-gf",
    "gemini-2-flash-lite": "gm-gfl",
    "gemini-1.5-pro": "gm-15p",
    "gemini-1.5-flash": "gm-15f",
    # DeepSeek Native
    "ds-chat": "ds-chat",
    "ds-reasoner": "ds-reas",
    # Mistral AI
    "ms-large": "ms-lg",
    "ms-small": "ms-sm",
    "ms-codestral": "ms-code",
    # xAI Grok
    "grok-2": "grk2",
    # Perplexity
    "pplx-sonar": "pplx-sn",
    "pplx-sonar-deep": "pplx-sd",
    # DeepInfra
    "di-llama-70b": "di-l3-70b",
    "di-llama-8b": "di-l3-8b",
    "di-mixtral": "di-mx",
    "di-qwen-72b": "di-qw72",
    "di-deepseek": "di-ds",
    # AI/ML API
    "aiml-gpt-4o": "ai-g4o",
    "aiml-gpt-4o-mini": "ai-g4m",
    "aiml-claude-sonnet": "ai-csn",
    "aiml-llama-70b": "ai-l3-70b",
    "aiml-deepseek": "ai-ds",
}

MODEL_COLORS = {
    "ollama": "yellow",
    "rakshak": "magenta",
    "deepseek": "cyan",
    "llama": "cyan",
    "mistral-nvidia": "blue",
    "nebius-llama-70b": "green",
    "nebius-llama-8b": "green",
    "nebius-qwen-72b": "green",
    "nebius-qwen-32b": "green",
    "nebius-mixtral": "green",
    "nebius-deepseek": "green",
    "fw-llama-70b": "red",
    "fw-llama-8b": "red",
    "fw-mixtral": "red",
    "fw-qwen-72b": "red",
    "fw-deepseek-v3": "red",
    "fw-phi-4": "red",
    "tg-llama-70b": "blue",
    "tg-llama-8b": "blue",
    "tg-qwen-72b": "blue",
    "tg-deepseek": "blue",
    "tg-mixtral": "blue",
    "groq-llama-70b": "yellow",
    "groq-llama-8b": "yellow",
    "groq-mixtral": "yellow",
    "groq-gemma": "yellow",
    "groq-deepseek": "yellow",
    "gpt-4o-mini": "white",
    "gpt-4o": "white",
    "claude": "blue",
    "claude-sonnet": "blue",
    # OpenRouter
    "or-gpt-4o": "cyan",
    "or-gpt-4o-mini": "cyan",
    "or-claude-sonnet": "cyan",
    "or-claude-haiku": "cyan",
    "or-deepseek-v3": "cyan",
    "or-llama-70b": "cyan",
    "or-llama-8b": "cyan",
    "or-mixtral": "cyan",
    "or-gemini-2-flash": "cyan",
    "or-qwen-72b": "cyan",
    "or-phi-4": "cyan",
    "or-llama-3.2-3b": "cyan",
    # Google Gemini
    "gemini-2-flash": "blue",
    "gemini-2-flash-lite": "blue",
    "gemini-1.5-pro": "blue",
    "gemini-1.5-flash": "blue",
    # DeepSeek Native
    "ds-chat": "magenta",
    "ds-reasoner": "magenta",
    # Mistral AI
    "ms-large": "green",
    "ms-small": "green",
    "ms-codestral": "green",
    # xAI Grok
    "grok-2": "white",
    # Perplexity
    "pplx-sonar": "yellow",
    "pplx-sonar-deep": "yellow",
    # DeepInfra
    "di-llama-70b": "red",
    "di-llama-8b": "red",
    "di-mixtral": "red",
    "di-qwen-72b": "red",
    "di-deepseek": "red",
    # AI/ML API
    "aiml-gpt-4o": "magenta",
    "aiml-gpt-4o-mini": "magenta",
    "aiml-claude-sonnet": "magenta",
    "aiml-llama-70b": "magenta",
    "aiml-deepseek": "magenta",
}

MODEL_DESCRIPTIONS = {
    "ollama": "Local models via Ollama (free, private)",
    "rakshak": "Fine-tuned Qwen2.5-Coder-7B on 80K CWE samples",
    "deepseek": "DeepSeek V4 Pro via NVIDIA NIM (fast, intelligent)",
    "llama": "Llama 3.1 70B via NVIDIA NIM (high accuracy)",
    "mistral-nvidia": "Mistral Large via NVIDIA NIM",
    "nebius-llama-70b": "Nebius AI Studio — Llama 3.1 70B",
    "nebius-llama-8b": "Nebius AI Studio — Llama 3.1 8B",
    "nebius-qwen-72b": "Nebius AI Studio — Qwen 2.5 72B",
    "nebius-qwen-32b": "Nebius AI Studio — Qwen 2.5 32B",
    "nebius-mixtral": "Nebius AI Studio — Mixtral 8x22B",
    "nebius-deepseek": "Nebius AI Studio — DeepSeek V2.5",
    "fw-llama-70b": "Fireworks AI — Llama 3.1 70B (fast inference)",
    "fw-llama-8b": "Fireworks AI — Llama 3.1 8B (fast inference)",
    "fw-mixtral": "Fireworks AI — Mixtral 8x22B (fast inference)",
    "fw-qwen-72b": "Fireworks AI — Qwen 2.5 72B (fast inference)",
    "fw-deepseek-v3": "Fireworks AI — DeepSeek V3 (best of open)",
    "fw-phi-4": "Fireworks AI — Phi-4 14B (Microsoft)",
    "tg-llama-70b": "Together AI — Llama 3.1 70B Turbo",
    "tg-llama-8b": "Together AI — Llama 3.1 8B Turbo",
    "tg-qwen-72b": "Together AI — Qwen 2.5 72B Turbo",
    "tg-deepseek": "Together AI — DeepSeek V3",
    "tg-mixtral": "Together AI — Mixtral 8x22B",
    "groq-llama-70b": "Groq — Llama 3.1 70B (LPU instant)",
    "groq-llama-8b": "Groq — Llama 3.1 8B (LPU instant)",
    "groq-mixtral": "Groq — Mixtral 8x7B (LPU instant)",
    "groq-gemma": "Groq — Gemma 2 9B (LPU instant)",
    "groq-deepseek": "Groq — DeepSeek R1 Distill Llama 70B",
    "gpt-4o-mini": "OpenAI GPT-4o Mini (fast, economical)",
    "gpt-4o": "OpenAI GPT-4o (best overall)",
    "claude": "Anthropic Claude Haiku (fast, affordable)",
    "claude-sonnet": "Anthropic Claude Sonnet 3.5 (top-tier code)",
    # OpenRouter
    "or-gpt-4o": "OpenRouter — GPT-4o (200+ models via single API)",
    "or-gpt-4o-mini": "OpenRouter — GPT-4o Mini",
    "or-claude-sonnet": "OpenRouter — Claude Sonnet 3.5",
    "or-claude-haiku": "OpenRouter — Claude Haiku 3.5",
    "or-deepseek-v3": "OpenRouter — DeepSeek V3",
    "or-llama-70b": "OpenRouter — Llama 3.1 70B",
    "or-llama-8b": "OpenRouter — Llama 3.1 8B",
    "or-mixtral": "OpenRouter — Mixtral 8x22B",
    "or-gemini-2-flash": "OpenRouter — Gemini 2.0 Flash",
    "or-qwen-72b": "OpenRouter — Qwen 2.5 72B",
    "or-phi-4": "OpenRouter — Phi-4 14B",
    "or-llama-3.2-3b": "OpenRouter — Llama 3.2 3B",
    # Google Gemini
    "gemini-2-flash": "Google Gemini 2.0 Flash (fast, multimodal)",
    "gemini-2-flash-lite": "Google Gemini 2.0 Flash Lite (cheapest)",
    "gemini-1.5-pro": "Google Gemini 1.5 Pro (1M context)",
    "gemini-1.5-flash": "Google Gemini 1.5 Flash (balanced)",
    # DeepSeek Native
    "ds-chat": "DeepSeek V3 Chat (native API, cost-effective)",
    "ds-reasoner": "DeepSeek R1 Reasoner (chain-of-thought)",
    # Mistral AI
    "ms-large": "Mistral Large 2 (top-tier European model)",
    "ms-small": "Mistral Small (fast, economical)",
    "ms-codestral": "Codestral (code-specialized Mistral)",
    # xAI Grok
    "grok-2": "xAI Grok 2 (real-time knowledge)",
    # Perplexity
    "pplx-sonar": "Perplexity Sonar Pro (online search augmented)",
    "pplx-sonar-deep": "Perplexity Sonar Deep (deep reasoning)",
    # DeepInfra
    "di-llama-70b": "DeepInfra — Llama 3.1 70B (serverless GPU)",
    "di-llama-8b": "DeepInfra — Llama 3.1 8B",
    "di-mixtral": "DeepInfra — Mixtral 8x22B",
    "di-qwen-72b": "DeepInfra — Qwen 2.5 72B",
    "di-deepseek": "DeepInfra — DeepSeek V3",
    # AI/ML API
    "aiml-gpt-4o": "AI/ML API — GPT-4o (cheaper OpenAI alternative)",
    "aiml-gpt-4o-mini": "AI/ML API — GPT-4o Mini",
    "aiml-claude-sonnet": "AI/ML API — Claude Sonnet 3.5",
    "aiml-llama-70b": "AI/ML API — Llama 3.1 70B",
    "aiml-deepseek": "AI/ML API — DeepSeek V3",
}

SEV_STYLES = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim white"}
SEV_ICONS = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️", "info": "💡"}

# Confidence-based color scale
def confidence_color(conf: float) -> str:
    """Return color based on confidence: 1.0=red, 0.67=yellow, <0.5=dim."""
    if conf >= 0.9:
        return "bold red"
    elif conf >= 0.7:
        return "red"
    elif conf >= 0.5:
        return "yellow"
    else:
        return "dim yellow"


# ── Streaming ──────────────────────────────────────────────

class StreamingPanel:
    """Stream tokens with live markdown rendering."""

    def __init__(self):
        self.buffer = ""
        self.live = Live(console=console, auto_refresh=True, refresh_per_second=10)

    def __enter__(self):
        self.live.start()
        return self

    def __exit__(self, *args):
        self.live.stop()
        if self.buffer.strip():
            console.print(Markdown(self.buffer))

    def update(self, text: str):
        """Update with new token - renders as markdown."""
        self.buffer += text
        # Only render complete lines for markdown
        if '\n' in text or len(self.buffer) > 80:
            try:
                self.live.update(Markdown(self.buffer))
            except:
                # Fallback for malformed markdown during streaming
                self.live.update(Text(self.buffer))


# ── Progress Bar ───────────────────────────────────────────

def create_scan_progress() -> Progress:
    """Create beautiful progress bar for batch scanning."""
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        "•",
        TextColumn("[dim]{task.fields[status]}"),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    )


# ── Output ─────────────────────────────────────────────────

def show_banner(model_name: str = "rakshak"):
    """Startup banner with logo."""
    if not model_name:
        model_name = "rakshak"
    model_color = MODEL_COLORS.get(model_name, "white")
    model_label = MODEL_LABELS.get(model_name, model_name)

    logo = """
[bold cyan]
    ██████╗  ██████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗
    ██╔══██╗██╔═══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║
    ██████╔╝███████║█████╔╝ ███████╗███████║███████║██║
    ██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██║
    ██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
[/bold cyan]"""

    console.print(logo)

    info = Text()
    info.append("  ")
    info.append(f"●", style=f"bold {model_color}")
    info.append(f" {model_label}", style=model_color)
    info.append("  ", style="dim")
    info.append("|", style="dim")
    info.append("  /help  ", style="bold")
    info.append("|", style="dim")
    info.append("  /models  ", style="bold")
    info.append("|", style="dim")
    info.append("  /scan", style="bold")

    console.print(Panel(
        info,
        subtitle="[dim]AI security scanner \u2014 150+ patterns, 65+ models[/dim]",
        border_style="#00e5ff",
        padding=(0, 2),
    ))
    console.print()


def show_status(text: str, style: str = "cyan"):
    """Enhanced status with icon and color."""
    icon = "●"
    console.print(f"[{style}]{icon}[/] {text}")


def show_error(text: str):
    """Error message with red X."""
    console.print(f"[red]✗[/] {text}")
    return False  # Return False for convenience in command handlers


def show_success(text: str):
    """Success message with green check."""
    console.print(f"[green]✓[/] {text}")
    return True  # Return True for convenience


def show_info_panel(title: str, content: str, border_color: str = "blue"):
    """Display info in a beautiful panel."""
    panel = Panel(
        content,
        title=f"[bold]{title}[/]",
        border_style=border_color,
        padding=(1, 2),
    )
    console.print(panel)


def show_response(content: str):
    """Render clean markdown response."""
    console.print(Markdown(content.strip()))


def show_model_response(name: str, text: str):
    """Inline model tag + markdown."""
    tag = MODEL_LABELS.get(name, name)
    color = MODEL_COLORS.get(name, "white")
    console.print(f"  [{color}]{tag}[/] {Markdown(text.strip())}")


def show_parallel_results(results: dict[str, str]):
    """Beautiful side-by-side model comparison."""
    if not results:
        return
    
    import json, re
    
    # Parse vulnerability counts from each model
    counts = {}
    for name, resp in results.items():
        match = re.search(r'```(?:json)?\n(.*?)\n```', resp, re.DOTALL)
        vulns = []
        if match:
            try:
                vulns = json.loads(match.group(1)).get("vulnerabilities", [])
            except Exception:
                pass
        counts[name] = {
            "total": len(vulns),
            "critical": sum(1 for v in vulns if v.get("severity", "").lower() == "critical"),
            "high": sum(1 for v in vulns if v.get("severity", "").lower() == "high"),
            "medium": sum(1 for v in vulns if v.get("severity", "").lower() == "medium"),
        }
    
    # Create comparison table
    table = Table(
        title="[bold]Multi-Model Comparison[/]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        padding=(0, 2),
    )
    
    table.add_column("Model", style="bold")
    table.add_column("Total", justify="center")
    table.add_column("Critical", justify="center")
    table.add_column("High", justify="center")
    table.add_column("Medium", justify="center")
    
    for name in results:
        model_color = MODEL_COLORS.get(name, "white")
        model_label = MODEL_LABELS.get(name, name)
        c = counts[name]
        
        table.add_row(
            f"[{model_color}]{model_label}[/]",
            str(c['total']),
            f"[red]{c['critical']}[/]" if c['critical'] > 0 else "[dim]0[/]",
            f"[red]{c['high']}[/]" if c['high'] > 0 else "[dim]0[/]",
            f"[yellow]{c['medium']}[/]" if c['medium'] > 0 else "[dim]0[/]",
        )
    
    console.print(table)


def show_vuln_table(vulns: list[dict]):
    """Beautiful vulnerability table with confidence-based coloring."""
    if not vulns:
        console.print(Panel("✅ [green bold]No vulnerabilities detected[/]", border_style="green"))
        return
    
    # Sort by severity and confidence
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulns, key=lambda v: (
        severity_order.get(v.get("severity", "").lower(), 99),
        -v.get("confidence", 0)
    ))
    
    table = Table(
        box=box.ROUNDED,
        padding=(0, 1),
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("CWE", style="cyan", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Conf.", justify="right", width=6)
    table.add_column("Location", width=20)
    table.add_column("Description", ratio=1)
    
    for v in sorted_vulns:
        sev = v.get("severity", "").lower()
        sev_style = SEV_STYLES.get(sev, "white")
        sev_icon = SEV_ICONS.get(sev, "")
        conf = v.get("confidence", 0.0)
        conf_style = confidence_color(conf)
        
        table.add_row(
            v.get("cwe", "CWE-???"),
            f"[{sev_style}]{sev_icon} {sev.upper()}[/]",
            f"[{conf_style}]{conf:.0%}[/]",
            (v.get("file", v.get("location", "?"))[:18]),
            v.get("description", "")[:80] + ("..." if len(v.get("description", "")) > 80 else ""),
        )
    
    console.print(table)


def show_scan_tree(results: list[dict]):
    """Beautiful batch scan tree with vulnerability breakdown."""
    vulns = [r for r in results if r.get("cwe")]
    clean = [r for r in results if not r.get("cwe") and r.get("status") == "done"]
    errors = [r for r in results if r.get("status") == "error"]
    
    # Summary panel
    summary_parts = []
    if vulns:
        summary_parts.append(f"[red bold]{len(vulns)} vulnerable[/]")
    if clean:
        summary_parts.append(f"[green]{len(clean)} clean[/]")
    if errors:
        summary_parts.append(f"[red]{len(errors)} errors[/]")
    
    summary = " • ".join(summary_parts) if summary_parts else "[green]All clean[/]"
    
    console.print(Panel(
        summary,
        title="[bold]Scan Results[/]",
        border_style="cyan",
        padding=(0, 2),
    ))
    
    if not vulns:
        return
    
    # Group by severity
    by_severity = {}
    for v in vulns:
        sev = v.get("severity", "unknown").lower()
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(v)
    
    # Display tree by severity
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev not in by_severity:
            continue
        
        items = by_severity[sev]
        sev_style = SEV_STYLES.get(sev, "white")
        sev_icon = SEV_ICONS.get(sev, "")
        
        tree = Tree(f"[{sev_style}]{sev_icon} {sev.upper()} ({len(items)})[/]")
        
        for v in items[:10]:  # Limit display to avoid clutter
            cwe = v.get("cwe", "CWE-???")
            file_path = v.get("file", "unknown")
            basename = os.path.basename(file_path)
            conf = v.get("confidence", 0.0)
            conf_style = confidence_color(conf)
            
            tree.add(f"[{conf_style}]{basename}[/] [dim]({cwe}, {conf:.0%})[/]")
        
        if len(items) > 10:
            tree.add(f"[dim]... and {len(items) - 10} more[/]")
        
        console.print(tree)


def show_diff_view(diff_text: str, language: str = "diff"):
    """Display syntax-highlighted unified diff."""
    if not diff_text.strip():
        show_status("No differences to display", "dim")
        return
    
    syntax = Syntax(
        diff_text,
        "diff",
        theme="monokai",
        line_numbers=True,
        word_wrap=False,
    )
    
    panel = Panel(
        syntax,
        title="[bold]Git Diff[/]",
        border_style="yellow",
        padding=(1, 2),
    )
    console.print(panel)


def show_code_comparison(original: str, fixed: str, language: str = "python"):
    """Side-by-side code comparison (before/after)."""
    cols = Columns([
        Panel(
            Syntax(original, language, theme="monokai", line_numbers=True),
            title="[red]Before[/]",
            border_style="red",
            padding=(0, 1),
        ),
        Panel(
            Syntax(fixed, language, theme="monokai", line_numbers=True),
            title="[green]After[/]",
            border_style="green",
            padding=(0, 1),
        ),
    ], equal=True, expand=True)
    console.print(cols)


def show_help():
    """Beautiful help table with all commands."""
    table = Table(
        title="[bold cyan]RakshakAI Commands[/]",
        box=box.ROUNDED,
        padding=(0, 2),
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
    )
    table.add_column("Command", style="green bold", width=24)
    table.add_column("Description")
    
    commands = [
        ("/scan <file>", "Scan a file for vulnerabilities"),
        ("/scan-project", "Scan entire project & AI-prioritize fixes"),
        ("/explain <file>", "Get detailed code explanation"),
        ("/fix <desc> [--test]", "Generate security fix & optionally run tests"),
        ("/batch <dir>", "Scan entire directory"),
        ("/watch <dir>", "Watch directory for changes"),
        ("/watch-stop", "Stop file watcher"),
        ("/diff", "Scan git changes"),
        ("/precommit [cmd]", "Manage git pre-commit hook"),
        ("/test [file]", "Auto-detect and run tests"),
        ("", ""),
        ("/index [dir]", "Index codebase for semantic search (NEW!)"),
        ("/search <query>", "Semantic search in codebase (NEW!)"),
        ("", ""),
        ("/def <file:line:col>", "Jump to symbol definition (LSP)"),
        ("/refs <file:line:col>", "Find all symbol references (LSP)"),
        ("/hover <file:line:col>", "Show type hints & docs (LSP)"),
        ("/rename <loc> <name>", "Rename symbol everywhere (LSP)"),
        ("", ""),
        ("/share [upload|export]", "Share session via URL or export to file"),
        ("/login", "Login via web browser"),
        ("/logout", "Logout and clear credentials"),
        ("/whoami", "Show current login status"),
        ("", ""),
        ("/model <name>", "Switch active model"),
        ("/models", "List all available models"),
        ("/parallel [models]", "Run multiple models in parallel"),
        ("", ""),
        ("/history <query>", "Search analysis history"),
        ("/log <file>", "Show file scan history"),
        ("/stats", "Show session statistics"),
        ("/cost", "Model usage and costs"),
        ("", ""),
        ("/confirm <id>", "Mark finding as true positive"),
        ("/dismiss <id>", "Mark finding as false positive"),
        ("", ""),
        ("/agent <task>", "Run autonomous agent"),
        ("/swarm <task>", "Multi-agent swarm (parallel subagents)"),
        ("/skills [name]", "List skills or show details / refresh"),
        ("", ""),
        ("/clear", "Clear conversation context"),
        ("/session", "Show session information"),
        ("/help", "Show this help"),
        ("/exit", "Exit RakshakAI"),
    ]
    
    for cmd, desc in commands:
        if not cmd:
            table.add_row("", "")
        else:
            table.add_row(cmd, desc)
    
    console.print(table)
    console.print("\n[bold cyan]NEW FEATURES:[/]")
    console.print("  • LSP integration for symbol navigation (/def, /refs, /hover, /rename)")
    console.print("  • Auto-test runner (/test, /fix --test)")
    console.print("  • Session sharing (/share upload)")
    console.print("  • Codebase indexing (/index, /search)")
    console.print("  • Headless JSON mode (--json flag)")
    console.print("\n[dim]Tip: Use Tab for auto-completion • Ctrl+C to cancel • Ctrl+D to exit[/]\n")


def show_model_list(models: dict, active_model: str):
    """Display models grouped by provider (opencode-style)."""
    providers: dict[str, list[str]] = {}
    for name, cfg in models.items():
        prov = cfg.provider or "other"
        providers.setdefault(prov, []).append(name)

    console.print()
    for prov, names in providers.items():
        console.print(f"  [bold white on #333333]  {prov.upper()}  [/]")
        for name in names:
            label = MODEL_LABELS.get(name, name)
            color = MODEL_COLORS.get(name, "white")
            mark = "[green]●[/]" if name == active_model else " "
            desc = MODEL_DESCRIPTIONS.get(name, "")
            console.print(
                f"  {mark}  [{color}]{label}[/]"
                f"{'  [dim]' + desc + '[/dim]' if desc else ''}"
            )
        console.print()


def show_stats_table(stats: dict):
    """Beautiful stats dashboard."""
    table = Table(
        title="[bold cyan]Statistics[/]",
        box=box.ROUNDED,
        show_header=False,
        padding=(0, 3),
        border_style="cyan",
    )
    table.add_column("Metric", style="bold", justify="right")
    table.add_column("Value", style="cyan")
    
    table.add_row("Sessions", str(stats.get("sessions", 0)))
    table.add_row("Analyses", str(stats.get("analyses", 0)))
    table.add_row("Files Scanned", str(stats.get("files_scanned", 0)))
    table.add_row("Cache Entries", str(stats.get("cache_entries", 0)))
    
    if stats.get("top_cwes"):
        cwes = ", ".join(f"{c['cwe']} ({c['count']})" for c in stats["top_cwes"][:5])
        table.add_row("Top CWEs", cwes)
    
    if stats.get("precision") is not None:
        precision = stats["precision"]
        color = "green" if precision > 0.8 else "yellow" if precision > 0.6 else "red"
        table.add_row(
            "Precision",
            f"[{color}]{precision:.1%}[/] ({stats['feedback_confirmed']}/{stats['feedback_total']})"
        )
    
    console.print(table)


def show_history_results(results: list[dict], search_term: str = ""):
    """Display search results with highlighting."""
    if not results:
        show_status(f"No results found for '{search_term}'", "yellow")
        return
    
    table = Table(
        title=f"[bold]Search Results: '{search_term}'[/]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        padding=(0, 1),
    )
    
    table.add_column("ID", style="dim", width=6)
    table.add_column("Time", style="dim", width=10)
    table.add_column("File", width=25)
    table.add_column("CWE", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Model", width=12)
    
    for r in results:
        ts = (r.get("timestamp") or "")[-8:]  # Last 8 chars (HH:MM:SS)
        file_path = r.get("file_path", "")
        basename = os.path.basename(file_path) if file_path else "unknown"
        
        # Highlight search term
        if search_term.lower() in basename.lower():
            basename = basename.replace(
                search_term,
                f"[yellow on black]{search_term}[/]"
            )
        
        cwe = r.get("cwe", "") or "[dim]none[/]"
        sev = r.get("severity", "") or "[dim]none[/]"
        model = r.get("model", "")
        
        # Color severity
        if sev and sev != "[dim]none[/]":
            sev_lower = sev.lower()
            sev_color = SEV_STYLES.get(sev_lower, "white")
            sev = f"[{sev_color}]{sev.upper()}[/]"
        
        table.add_row(
            f"#{r.get('id', '?')}",
            ts,
            basename,
            cwe,
            sev,
            f"[dim]{model}[/]",
        )
    
    console.print(table)


def show_session_summary(
    duration_seconds: float,
    files_scanned: int,
    vulnerabilities_found: int,
    models_used: list[str],
    total_cost: float = 0.0
):
    """Display beautiful session summary on exit."""
    
    hours = int(duration_seconds // 3600)
    minutes = int((duration_seconds % 3600) // 60)
    seconds = int(duration_seconds % 60)
    
    if hours > 0:
        time_str = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        time_str = f"{minutes}m {seconds}s"
    else:
        time_str = f"{seconds}s"
    
    summary_text = f"""
[bold cyan]Session Complete[/]

[bold]Duration:[/] {time_str}
[bold]Files Scanned:[/] {files_scanned}
[bold]Vulnerabilities:[/] {vulnerabilities_found}
[bold]Models Used:[/] {', '.join(models_used) if models_used else 'None'}
"""
    
    if total_cost > 0:
        summary_text += f"[bold]Estimated Cost:[/] ${total_cost:.4f}\n"
    
    panel = Panel(
        summary_text.strip(),
        title="[bold green]✓ Thank you for using RakshakAI[/]",
        border_style="green",
        padding=(1, 2),
    )
    
    console.print("\n")
    console.print(panel)
    console.print("\n[dim]Stay secure! 🛡️[/]\n")


def interactive_model_selector(models: dict, current_model: str) -> Optional[str]:
    """Interactive model selector — type number or name (like opencode)."""
    providers: dict[str, list[tuple[int, str]]] = {}
    numbered: list[str] = []
    idx = 0

    for name, cfg in models.items():
        idx += 1
        numbered.append(name)
        prov = cfg.provider or "other"
        providers.setdefault(prov, []).append((idx, name))

    console.print()
    for prov, items in providers.items():
        console.print(f"  [bold white on #333333]  {prov.upper()}  [/]")
        for num, name in items:
            label = MODEL_LABELS.get(name, name)
            color = MODEL_COLORS.get(name, "white")
            mark = "[green]●[/]" if name == current_model else " "
            desc = MODEL_DESCRIPTIONS.get(name, "")
            console.print(
                f"  {mark} [dim]{num}.[/] [{color}]{label}[/]"
                f"{'  [dim]' + desc + '[/dim]' if desc else ''}"
            )
    console.print()

    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.completion import FuzzyCompleter, WordCompleter
        from prompt_toolkit.validation import Validator

        word_comp = WordCompleter(list(models.keys()) + [str(i) for i in range(1, len(models) + 1)])

        choice = prompt(
            "  Select model (number or name): ",
            completer=FuzzyCompleter(word_comp),
            complete_while_typing=True,
        ).strip()
    except ImportError:
        choice = input("  Select model (number or name): ").strip()

    if not choice:
        return None

    if choice.isdigit():
        n = int(choice)
        if 1 <= n <= len(numbered):
            return numbered[n - 1]

    if choice in models:
        return choice

    # fuzzy match
    low = choice.lower()
    for name in models:
        label = MODEL_LABELS.get(name, name).lower()
        if low in label or low in name:
            return name

    show_error(f"Unknown model: {choice}")
    return None


# ── Action Display (claude-code style) ─────────────────────

def show_tool_call(name: str, args: dict, start_time: float = 0):
    """Display a tool call action line like claude-code: → action_name (params)"""
    params_str = ", ".join(f"{k}={v}" for k, v in args.items())
    show = f"  [bold cyan]→ {name}[/]"
    if params_str:
        show += f" [dim]({params_str})[/dim]"
    console.print(show)


def show_tool_result(result_summary: str):
    """Show a brief tool result after execution."""
    if result_summary:
        console.print(f"    [dim]{result_summary[:120]}[/dim]")


def show_thought_timing(start: float, end: float):
    """Show thought timing like claude-code: 'Thought: X.Xs'"""
    elapsed = end - start
    if elapsed >= 0.1:
        console.print(f"  [dim]Thought: {elapsed:.1f}s[/dim]")


def show_tool_error(name: str, error: str):
    """Show a tool error."""
    console.print(f"  [red]→ {name}[/] [red]Error:[/] [dim]{error}[/dim]")


def show_swarm_results(result: dict):
    """Display multi-agent swarm execution results."""
    from rich.tree import Tree

    success = result.get("fail_count", 0) == 0
    border = "green" if success else "yellow"
    title = "✓ Swarm Complete" if success else "⚠ Swarm Partial"

    tree = Tree(
        f"[bold]{result['task'][:80]}[/]",
        guide_style="dim cyan",
    )
    for sr in result.get("subtask_results", []):
        icon = "✓" if sr["success"] else "✗"
        color = "green" if sr["success"] else "red"
        label = (
            f"[bold {color}]{icon} {sr['id']}[/] "
            f"[dim]({sr['steps']} steps, {sr['elapsed_ms']}ms)[/dim]"
        )
        branch = tree.add(label)
        if sr.get("preview"):
            branch.add(f"[dim]{sr['preview'][:120]}[/dim]")
        if sr.get("error"):
            branch.add(f"[red]{sr['error'][:200]}[/red]")

    summary = (
        f"Sub-tasks: {result['subtask_count']} | "
        f"Succeeded: {result['success_count']} | "
        f"Failed: {result['fail_count']} | "
        f"Total wall time: {result['total_elapsed_ms']}ms"
    )

    panel = Panel(
        tree,
        title=f"[bold]{title}[/]",
        border_style=border,
        subtitle=f"[dim]{summary}[/dim]",
        padding=(1, 2),
    )
    console.print(panel)


def show_auth_status(state):
    """Display auth status panel."""
    if not state.logged_in:
        panel = Panel(
            "[yellow]Not logged in[/]\n\nUse [bold]/login[/] to authenticate via web browser.\nOr set [bold]RAKSHAKAI_TOKEN[/] env var.",
            title="Authentication",
            border_style="yellow",
            padding=(1, 2),
        )
        console.print(panel)
        return

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right", width=14)
    info.add_column(style="bold white")

    info.add_row("Email", state.email)
    info.add_row("Plan", f"[green]{state.plan.title()}[/green]")
    info.add_row("Logged in", f"[green]{state.elapsed} ago[/green]")

    panel = Panel(
        Align.center(info),
        title="[bold green]✓ Authenticated[/bold green]",
        border_style="green",
        padding=(1, 2),
    )
    console.print(panel)
