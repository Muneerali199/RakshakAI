"""Minimal, beautiful TUI output — sequential, no Live conflicts."""
from __future__ import annotations
import os, threading
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich.rule import Rule
from rich import box

console = Console()

MODEL_LABELS = {"deepseek": "llama", "gpt-4o": "gpt4", "gpt-4o-mini": "gpt4m", "rakshak": "rk"}
MODEL_COLORS = {"deepseek": "cyan", "gpt-4o": "green", "gpt-4o-mini": "yellow", "rakshak": "magenta"}
SEV_STYLES = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "white"}


class Display:
    """Clean sequential output — messages printed in order, no screen takeover."""

    def __init__(self):
        self._lock = threading.Lock()
        self._conversation: list[dict] = []  # {"role","content","model"}
        self.sidebar: dict = {}
        self.input_line = ""

    # ── public API ─────────────────────────────────────────

    def start(self):
        """Called at REPL start."""
        pass

    def stop(self):
        """Called at REPL exit."""
        pass

    def add_user_msg(self, text: str):
        self._conversation.append({"role": "user", "content": text})
        self._render()

    def add_assistant_msg(self, text: str, model: str = ""):
        self._conversation.append({"role": "assistant", "content": text, "model": model})
        self._render()

    def show_status(self, text: str, style: str = "cyan"):
        console.print(f"  [{style}]\u2219[/] {text}")

    def show_error(self, text: str):
        console.print(f"  [red]\u2716[/] {text}")

    def show_success(self, text: str):
        console.print(f"  [green]\u2713[/] {text}")

    def show_scan_tree(self, results: list[dict]):
        """Compact scan results."""
        vulns = [r for r in results if r.get("cwe")]
        clean = [r for r in results if not r.get("cwe") and r.get("status") == "done"]
        errors = [r for r in results if r.get("status") == "error"]
        parts = []
        if vulns:
            parts.append(f"[red]{len(vulns)} vuln[/]")
        if clean:
            parts.append(f"[dim]{len(clean)} clean[/]")
        if errors:
            parts.append(f"[red]{len(errors)} err[/]")
        if parts:
            console.print("  " + "  ".join(parts))
        for v in sorted(vulns, key=lambda x: SEV_STYLES.get(x.get("severity", "").lower(), "z")):
            c = SEV_STYLES.get(v.get("severity", "").lower(), "white")
            console.print(
                f"  [{c}]\u2502 {os.path.basename(v['file'])}[/]"
                f" [dim]{v.get('cwe','')} ({v.get('severity','?')})[/]"
            )

    def sidebar_update(self, **kwargs):
        self.sidebar.update(kwargs)

    def sidebar_render(self):
        """Render sidebar content as rich Panel."""
        items = []
        m = self.sidebar.get("model", "deepseek")
        c = MODEL_COLORS.get(m, "white")
        items.append(f"[{c}]\u25c6 {MODEL_LABELS.get(m,m).upper()}[/]\n")

        ctx = self.sidebar.get("context_tokens", 0)
        mx = self.sidebar.get("context_max", 32768) or 1
        items.append(f"[bold]Context[/]  {ctx:,} tok ({int(ctx/mx*100)}%)\n")

        mcp = self.sidebar.get("mcp", [])
        if mcp:
            items.append("[bold]MCP[/]")
            for s in mcp:
                d = "\u25cf" if s.get("connected") else "\u25cb"
                items.append(f"  {d} {s['name']}")
            items.append("")

        ls = self.sidebar.get("lsp", [])
        if ls:
            items.append("[bold]LSP[/]")
            for s in ls:
                items.append(f"  \u25cf {s}")
            items.append("")

        branch = self.sidebar.get("branch", "")
        if branch:
            items.append(f"[dim]{branch}[/]\n")

        cost = self.sidebar.get("cost", "0.00")
        items.append(f"cost: ${cost}")

        return "\n".join(items)

    def _render(self):
        """Called after each message — could be no-op for sequential mode."""
        pass

    def render_conversation(self):
        """Render all conversation messages."""
        for msg in self._conversation:
            if msg["role"] == "user":
                console.print(f"\n  [bold]\u276f {msg['content']}[/]")
            elif msg["role"] == "assistant":
                model = msg.get("model", "")
                if model:
                    c = MODEL_COLORS.get(model, "white")
                    console.print(f"  [{c}]\u2502 {MODEL_LABELS.get(model, model)}[/]")
                try:
                    console.print(Markdown(msg["content"].strip()))
                except Exception:
                    console.print(Text(msg["content"][:500]))
