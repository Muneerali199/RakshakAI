#!/usr/bin/env python3
"""rkscan — Security scan CLI (Phase 1).

Usage:
  rkscan scan <file>                          # Scan a file for vulns
  rkscan scan <file> --json                   # Output raw JSON
  rkscan scan <file> --model deepseek          # Use a specific model
  rkscan scan <file> --output sarif            # SARIF output format
  rkscan explain <file>                       # Explain what code does
  rkscan fix <file>                           # Generate a fix
  rkscan diff <file> --base main              # Scan changes vs git base
  rkscan models                               # List available models
  rkscan watch <dir>                          # Watch dir for file changes (Phase 2)

Integrations:
  Claude Code hook: set PostToolUse to run `rkscan scan $FILE`
  MCP server: run `rkscan mcp` to start MCP stdio server
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

# Ensure project root is on path
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

from v2.cli.llm import registry, stream_chat
from v2.cli.prompts import get_scan_messages, get_explain_messages, get_fix_messages

app = typer.Typer(name="rkscan", help="RakshakAI security scanner")
console = Console()

def _read_file(path: str) -> tuple[str, str]:
    """Read a file and return (content, language_hint)."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found: {path}[/]")
        raise typer.Exit(code=1)
    content = p.read_text(encoding="utf-8", errors="replace")
    ext = p.suffix.lower()
    lang_map = {
        ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".rs": "rust", ".go": "go",
        ".rb": "ruby", ".php": "php", ".swift": "swift",
        ".kt": "kotlin", ".cs": "csharp",
    }
    return content, lang_map.get(ext, "unknown")

def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON block from model response."""
    import re
    match = re.search(r'```(?:json)?\n(.*?)\n```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try parsing the whole thing as JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None

def _render_vuln_table(vulns: list[dict]):
    """Render vulnerabilities in a rich table."""
    if not vulns:
        console.print("[green]No vulnerabilities found.[/]")
        return
    table = Table(box=box.ROUNDED, title="Vulnerabilities", title_style="bold red", header_style="bold")
    table.add_column("CWE", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Location")
    table.add_column("Description", no_wrap=False)
    for v in vulns:
        sev = v.get("severity", "unknown").lower()
        sev_style = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
        table.add_row(
            v.get("cwe", "?"),
            f"[{sev_style}]{v.get('severity', '?').upper()}[/]",
            v.get("location", "?"),
            v.get("description", "")[:100],
        )
    console.print(table)

@app.callback()
def callback():
    """RakshakAI security scanner — scan code for vulnerabilities."""
    pass

@app.command()
def scan(
    file: str = typer.Argument(..., help="File to scan"),
    model: str = typer.Option("deepseek", "--model", "-m", help="Model to use"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table, json, sarif"),
):
    """Scan a file for security vulnerabilities."""
    content, lang = _read_file(file)
    cfg = registry.get(model)
    if not cfg:
        console.print(f"[red]Unknown model: {model}[/]")
        raise typer.Exit(code=1)

    console.print(f"[dim]Scanning {file} with {cfg.name}...[/]")

    messages = get_scan_messages(f"```{lang}\n{content}\n```", model)
    response = stream_chat(messages, cfg)

    data = _extract_json(response)

    if json_output or output == "json":
        if data:
            print(json.dumps(data, indent=2))
        else:
            print(response)
        return

    if output == "sarif":
        _output_sarif(data or {}, file)
        return

    # Default: pretty table
    if data:
        vulns = data.get("vulnerabilities", [])
        _render_vuln_table(vulns)
        summary = data.get("summary", "")
        if summary:
            console.print(f"\n[bold]Summary:[/] {summary}")
    else:
        console.print(Panel(Markdown(response), title="Scan Results", border_style="cyan"))

@app.command()
def explain(
    file: str = typer.Argument(..., help="File to explain"),
    model: str = typer.Option("deepseek", "--model", "-m", help="Model to use"),
):
    """Explain what a source file does."""
    content, lang = _read_file(file)
    cfg = registry.get(model)
    messages = get_explain_messages(f"```{lang}\n{content}\n```")
    console.print(f"[dim]Analyzing {file}...[/]")
    response = stream_chat(messages, cfg)
    console.print(Panel(Markdown(response), title=f"Analysis: {file}", border_style="blue"))

@app.command()
def fix(
    file: str = typer.Argument(..., help="File with vulnerability to fix"),
    model: str = typer.Option("deepseek", "--model", "-m", help="Model to use"),
):
    """Generate a fix for vulnerabilities in a file."""
    content, lang = _read_file(file)
    cfg = registry.get(model)
    messages = get_fix_messages(f"```{lang}\n{content}\n```")
    console.print(f"[dim]Generating fix for {file}...[/]")
    response = stream_chat(messages, cfg)
    console.print(Panel(Markdown(response), title=f"Fix: {file}", border_style="green"))

@app.command()
def models():
    """List available models."""
    table = Table(box=box.ROUNDED, title="Available Models")
    table.add_column("Name", style="cyan")
    table.add_column("Model", style="green")
    table.add_column("Provider", style="yellow")
    for name, cfg in registry.models.items():
        table.add_row(name, cfg.model, cfg.provider)
    console.print(table)

def _output_sarif(data: dict, file_path: str):
    """Convert findings to SARIF format."""
    vulns = data.get("vulnerabilities", [])
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RakshakAI",
                    "informationUri": "https://github.com/Muneerali199/RakshakAI",
                    "rules": []
                }
            },
            "results": [],
        }]
    }
    rule_ids = set()
    for v in vulns:
        rule_id = v.get("cwe", "CWE-unknown")
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": v.get("name", rule_id),
                "shortDescription": {"text": v.get("description", "")[:200]},
                "properties": {"severity": v.get("severity", "medium")},
            })
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "message": {"text": v.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"snippet": {"text": v.get("code", "")}},
                }
            }],
            "properties": {"fix": v.get("fix", "")},
        })
    print(json.dumps(sarif, indent=2))


@app.command()
def mcp():
    """Start the MCP stdio server for use with Cursor, Claude Code, etc."""
    from v2.cli.mcp_server import main as mcp_main
    mcp_main()

@app.command()
def watch(
    directory: str = typer.Argument(".", help="Directory to watch"),
    model: str = typer.Option("deepseek", "--model", "-m", help="Model to use"),
):
    """Watch a directory for new/modified files and scan them (Phase 2)."""
    console.print("[yellow]File watching not yet implemented (Phase 2). Coming soon.[/]")


def main():
    app()

if __name__ == "__main__":
    main()
