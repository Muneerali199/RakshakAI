"""World-class terminal UI with Rich components - inspired by opencode and kiro-cli."""
from __future__ import annotations
import os
import sys
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
    "rakshak": "Rakshak",
    "deepseek": "DeepSeek V4 Pro",
    "llama": "Llama 3.1 70B",
    "gpt-4o": "GPT-4o",
    "gpt-4o-mini": "GPT-4o Mini",
}

MODEL_SHORT_LABELS = {
    "rakshak": "rk",
    "deepseek": "ds",
    "llama": "llama",
    "gpt-4o": "gpt4",
    "gpt-4o-mini": "gpt4m",
}

MODEL_COLORS = {
    "rakshak": "magenta",
    "deepseek": "cyan",
    "llama": "cyan",
    "gpt-4o": "green",
    "gpt-4o-mini": "yellow",
}

MODEL_DESCRIPTIONS = {
    "rakshak": "Fine-tuned Qwen2.5-Coder-7B on 80K CWE samples",
    "deepseek": "DeepSeek V4 Pro via NVIDIA NIM (fast, intelligent)",
    "llama": "Llama 3.1 70B via NVIDIA NIM (high accuracy)",
    "gpt-4o": "OpenAI GPT-4o (most capable, costly)",
    "gpt-4o-mini": "OpenAI GPT-4o Mini (fast, economical)",
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
    """World-class startup banner - the most beautiful CLI you've ever seen."""
    
    # Epic RAKSHAKAI ASCII art
    banner_art = """
[bold cyan]
    ██████╗  ██████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗ █████╗ ██╗
    ██╔══██╗██╔═══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔══██╗██║
    ██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝ ███████║██║
    ██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗ ██╔══██║██║
    ██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗██║  ██║██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
[/bold cyan]
    [bold yellow]The World's Fastest & Most Intelligent Security AI - Mythos Edition[/bold yellow]
    """
    
    console.print(banner_art)
    
    # Epic features showcase
    features = Text()
    features.append("⚡ ", style="yellow bold")
    features.append("10x Faster", style="yellow")
    features.append(" • ", style="dim")
    features.append("🛡️ ", style="blue bold")
    features.append("Military Grade", style="blue")
    features.append(" • ", style="dim")
    features.append("🧠 ", style="magenta bold")
    features.append("Claude Mythos Intelligence", style="magenta")
    features.append(" • ", style="dim")
    features.append("💰 ", style="green bold")
    features.append("90% Token Savings", style="green")
    
    console.print(Align.center(features))
    console.print()
    
    # System info panel with enhanced styling
    model_color = MODEL_COLORS.get(model_name, "white")
    model_label = MODEL_LABELS.get(model_name, model_name)
    
    info_table = Table.grid(padding=(0, 3))
    info_table.add_column(style="bold cyan", justify="right", width=15)
    info_table.add_column(style="bold white")
    
    info_table.add_row("🔥 Version", "[yellow]v3.0 Quantum Edition[/yellow]")
    info_table.add_row("🤖 Active Model", f"[{model_color}]{model_label}[/{model_color}]")
    info_table.add_row("💻 Platform", f"[green]{platform.system()} {platform.machine()}[/green]")
    info_table.add_row("🐍 Python", f"[blue]{sys.version.split()[0]}[/blue]")
    info_table.add_row("⚡ Mode", "[yellow bold]ULTRA-FAST • Token Optimized[/yellow bold]")
    info_table.add_row("⚙️  Status", "[green bold]● ONLINE[/green bold]")
    
    panel = Panel(
        Align.center(info_table),
        title="[bold yellow]⚡ RAKSHAKAI QUANTUM CORE ⚡[/bold yellow]",
        subtitle="[dim]Type /help for superpowers • Mythos-level intelligence, minimal tokens[/dim]",
        border_style="bold cyan",
        padding=(1, 2),
    )
    console.print(panel)
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
    table.add_column("Command", style="green bold", width=22)
    table.add_column("Description")
    
    commands = [
        ("/scan <file>", "Scan a file for vulnerabilities"),
        ("/explain <file>", "Get detailed code explanation"),
        ("/fix <description>", "Generate security fix"),
        ("/batch <dir>", "Scan entire directory"),
        ("/watch <dir>", "Watch directory for changes"),
        ("/watch-stop", "Stop file watcher"),
        ("/diff", "Scan git changes"),
        ("/precommit [cmd]", "Manage git pre-commit hook"),
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
        ("/agent <task>", "Run autonomous agent on a task"),
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
    console.print("\n[dim]Tip: Use Tab for auto-completion • Ctrl+C to cancel • Ctrl+D to exit[/]\n")


def show_model_list(models: dict, active_model: str):
    """Display beautiful model selector."""
    table = Table(
        title="[bold cyan]Available Models[/]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        padding=(0, 2),
    )
    
    table.add_column("", width=3)
    table.add_column("Model", style="bold")
    table.add_column("Provider")
    table.add_column("Description")
    
    for name, cfg in models.items():
        is_active = name == active_model
        marker = "[green]●[/]" if is_active else "[dim]○[/]"
        model_color = MODEL_COLORS.get(name, "white")
        model_label = MODEL_LABELS.get(name, name)
        desc = MODEL_DESCRIPTIONS.get(name, f"{cfg.provider} / {cfg.model}")
        
        table.add_row(
            marker,
            f"[{model_color}]{model_label}[/]" if not is_active else f"[{model_color} bold]{model_label}[/]",
            cfg.provider,
            f"[dim]{desc}[/]" if not is_active else desc,
        )
    
    console.print(table)


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
    """Interactive model selector with arrow keys (like opencode/kiro-cli)."""
    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.shortcuts import radiolist_dialog
        from prompt_toolkit.formatted_text import HTML
    except ImportError:
        show_error("prompt_toolkit required for interactive selection")
        return None
    
    # Build choices
    choices = []
    for name, cfg in models.items():
        model_label = MODEL_LABELS.get(name, name)
        desc = MODEL_DESCRIPTIONS.get(name, f"{cfg.provider} / {cfg.model}")
        is_current = "(current)" if name == current_model else ""
        
        display_text = f"{model_label} - {desc} {is_current}"
        choices.append((name, display_text))
    
    try:
        result = radiolist_dialog(
            title="Select Model",
            text="Choose a security scanning model:",
            values=choices,
            default=current_model,
        ).run()
        
        return result
    except Exception:
        return None
