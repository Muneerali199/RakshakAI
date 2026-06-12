#!/usr/bin/env python3
"""
RakshakAI CLI — Scan, review, and fix code vulnerabilities from your terminal.

Usage:
    rakshak scan <file-or-dir>              Scan file(s) for vulnerabilities
    rakshak review <diff-file>              Review a unified diff
    rakshak generate <prompt>               Generate secure code from prompt
    rakshak server [--port PORT]            Start the backend server
    rakshak health                          Check server status
    rakshak config                          Show current configuration
    rakshak batch <file1> [file2 ...]       Scan multiple files

Examples:
    rakshak scan app.py
    rakshak scan src/ --format table
    rakshak review pr.diff --output results.json
    rakshak generate "secure file upload in Python"
    rakshak server --port 3000
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# ── Config ──────────────────────────────────────────────────────────
CONFIG_FILE = Path.home() / ".rakshak" / "config.json"
DEFAULT_CONFIG = {
    "v1_url": "http://127.0.0.1:3000",
    "v2_url": "http://127.0.0.1:8080",
    "format": "table",
    "timeout": 120,
    "mock": True,
    "severity_threshold": "low",
}

def load_config() -> dict:
    if CONFIG_FILE.exists():
        return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def get_backend_url(cfg: dict, tier: str = "v1") -> str:
    return cfg.get(f"{tier}_url", DEFAULT_CONFIG[f"{tier}_url"])


# ── Output Formatting ───────────────────────────────────────────────
def print_json(data, indent=2):
    """Print pretty JSON output."""
    print(json.dumps(data, indent=indent, default=str))


def print_table(issues: list[dict]):
    """Print issues in a formatted table."""
    if not issues:
        print("  ✅ No vulnerabilities found.")
        return

    severity_colors = {
        "critical": "\033[91m",   # Red
        "high":     "\033[91m",   # Red
        "medium":   "\033[93m",   # Yellow
        "low":      "\033[94m",   # Blue
        "info":     "\033[90m",   # Gray
    }
    reset = "\033[0m"

    # Header
    print(f"\n  {'Line':<6} {'Severity':<10} {'CWE':<12} {'Category':<25} {'Message'}")
    print(f"  {'-'*4:<6} {'-'*8:<10} {'-'*10:<12} {'-'*23:<25} {'-'*40}")

    for issue in issues:
        sev = issue.get("severity", "info").lower()
        color = severity_colors.get(sev, "")
        sev_str = f"{color}{sev:<10}{reset}"
        cwe = issue.get("cweId") or issue.get("cwe") or ""
        cat = (issue.get("category") or issue.get("type") or "")[:23]
        msg = (issue.get("message") or "")[:60]
        line = issue.get("line", "?")
        print(f"  {str(line):<6} {sev_str} {cwe:<12} {cat:<25} {msg}")

    print(f"\n  {'─'*60}")
    sev_counts = {}
    for i in issues:
        s = i.get("severity", "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"  Total: {len(issues)} issue(s) — " + ", ".join(f"{c} {s}" for s, c in sev_counts.items()))


def print_sarif(issues: list[dict], filename: str) -> str:
    """Convert issues to SARIF format (for CI/CD integration)."""
    sarif_runs = []
    results = []
    for i, issue in enumerate(issues):
        results.append({
            "ruleId": issue.get("cweId", "unknown"),
            "level": issue.get("severity", "warning"),
            "message": {"text": issue.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filename},
                    "region": {
                        "startLine": issue.get("line", 0),
                        "endLine": issue.get("line", 0),
                    }
                }
            }]
        })
    sarif_runs.append({
        "tool": {"driver": {"name": "RakshakAI", "version": "1.0.0"}},
        "results": results,
    })
    return json.dumps({"$schema": "https://schemastore.aws.dev/sarif/2.1.0.json", "version": "2.1.0", "runs": sarif_runs}, indent=2)


# ── API Client ──────────────────────────────────────────────────────
def api_post(url: str, path: str, payload: dict, timeout: int = 120) -> Optional[dict]:
    """Make an HTTP POST request to the RakshakAI server."""
    try:
        import urllib.request
        import urllib.error

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"\033[91m✖ Error: {e}\033[0m", file=sys.stderr)
        return None

def api_get(url: str, path: str, timeout: int = 10) -> Optional[dict]:
    """Make an HTTP GET request."""
    try:
        import urllib.request
        req = urllib.request.Request(f"{url}{path}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"\033[91m✖ Error: {e}\033[0m", file=sys.stderr)
        return None


# ── Scanner Logic ────────────────────────────────────────────────────
def guess_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".rs": "rust", ".c": "c",
        ".cpp": "cpp", ".cc": "cpp", ".h": "c", ".hpp": "cpp",
        ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
        ".sh": "bash", ".bash": "bash", ".zsh": "bash",
        ".sql": "sql", ".html": "html", ".css": "css",
        ".yaml": "yaml", ".yml": "yaml", ".json": "json",
        ".md": "markdown", ".rst": "markdown",
        ".tex": "latex", ".lua": "lua", ".r": "r",
    }.get(ext, "text")


def scan_file(path: str, cfg: dict, language: str = None) -> list[dict]:
    """Scan a single file and return issues."""
    if not os.path.isfile(path):
        print(f"\033[93m⚠ Skipping {path} (not a file)\033[0m")
        return []

    lang = language or guess_language(path)
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    url = get_backend_url(cfg)

    resp = api_post(url, "/api/scan", {
        "code": code,
        "language": lang,
        "filename": path,
    }, timeout=cfg.get("timeout", 120))

    if not resp:
        return []

    return resp.get("issues", [])


def scan_directory(path: str, cfg: dict, exclude: list[str] = None) -> dict[str, list[dict]]:
    """Recursively scan all supported files in a directory."""
    supported_exts = {
        ".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp",
        ".h", ".hpp", ".rb", ".php", ".cs", ".swift", ".kt",
    }
    exclude_dirs = set(exclude or [])
    results = {}
    p = Path(path)
    files = []
    for f in p.rglob("*"):
        if f.suffix not in supported_exts or f.name.startswith("."):
            continue
        if any(excl in f.parts for excl in exclude_dirs):
            continue
        files.append(f)
    total = len(files)

    if not files:
        print(f"\033[93m⚠ No supported files found in {path}\033[0m")
        return results

    print(f"\n  Scanning {total} file(s) in {path}...\n")

    for i, f in enumerate(files, 1):
        fpath = str(f)
        show_path = fpath[:80] + "..." if len(fpath) > 80 else fpath
        print(f"  [{i}/{total}] \033[90m{show_path}\033[0m", end="\r")
        issues = scan_file(fpath, cfg)
        if issues:
            results[fpath] = issues
        sys.stdout.flush()

    print(f"\n  {'─'*50}")
    total_issues = sum(len(v) for v in results.values())
    print(f"  ✅ Done. Found {total_issues} issue(s) in {len(results)} file(s).")
    return results


# ── Server Management ───────────────────────────────────────────────
def start_server(port: int = 3000, mock: bool = True):
    """Start the RakshakAI backend server."""
    env = os.environ.copy()
    if mock:
        env["RAKSHAK_MOCK"] = "1"

    try:
        import uvicorn
        sys.path.insert(0, str(Path(__file__).parent))
        from server import app
        print(f"\033[92m▶ Starting RakshakAI server on port {port} (mock={mock})...\033[0m")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
    except ImportError:
        print("\033[91m✖ Error: uvicorn not installed. Run: pip install uvicorn fastapi\033[0m", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\033[91m✖ Error starting server: {e}\033[0m", file=sys.stderr)
        sys.exit(1)


# ── CLI Commands ────────────────────────────────────────────────────
def cmd_scan(args: argparse.Namespace, cfg: dict) -> int:
    path = args.path
    fmt = args.format or cfg.get("format", "table")
    lang = args.language
    excludes = args.exclude or []

    if os.path.isdir(path):
        results = scan_directory(path, cfg, exclude=excludes)
        if results and fmt == "json":
            print_json(results)
        elif results and fmt == "sarif":
            for fpath, issues in results.items():
                print(print_sarif(issues, fpath))
        else:
            for fpath, issues in results.items():
                if issues:
                    print(f"\n  \033[1m📄 {fpath}\033[0m")
                    print_table(issues)
        return 0

    issues = scan_file(path, cfg, lang)

    if not issues:
        print(f"\n  ✅ \033[92mNo vulnerabilities found in {path}\033[0m")
        return 0

    if fmt == "json":
        print_json(issues)
    elif fmt == "sarif":
        print(print_sarif(issues, path))
    else:
        print_table(issues)

    # Show fix info if available (table mode only)
    if fmt == "table":
        for i in issues:
            if i.get("remediation") and i["remediation"].get("example"):
                print(f"\n  \033[96m💡 Fix for line {i.get('line', '?')}:\033[0m")
                print(f"    {i['remediation']['example']}")
                print()

    return 0


def cmd_review(args: argparse.Namespace, cfg: dict) -> int:
    diff = Path(args.path).read_text(encoding="utf-8", errors="replace")
    url = get_backend_url(cfg, "v2")
    resp = api_post(url, "/v2/review", {
        "diff": diff,
        "language": args.language or "python",
    }, timeout=cfg.get("timeout", 120))

    if not resp:
        print("\033[91m✖ Review failed. Is the v2 server running?\033[0m")
        return 1

    finding = resp.get("finding", {})
    if args.format == "json":
        print_json(resp)
    else:
        print(f"\n  \033[1m📋 Security Review\033[0m")
        print(f"  Vulnerability: {finding.get('vulnerability', 'N/A')}")
        print(f"  CWE: {finding.get('cwe', 'N/A')}")
        print(f"  Severity: {finding.get('severity', 'N/A')}")
        if finding.get("root_cause"):
            print(f"\n  Root Cause: {finding['root_cause']}")
        if finding.get("attack_scenario"):
            print(f"  Attack: {finding['attack_scenario']}")
        if finding.get("secure_fix"):
            print(f"  Fix: {finding['secure_fix']}")
        if finding.get("patched_code"):
            print(f"\n  \033[96m📝 Patched Code:\033[0m")
            print(f"  {finding['patched_code']}")
        if finding.get("references"):
            refs = ", ".join(finding["references"])
            print(f"  References: {refs}")
    return 0


def cmd_generate(args: argparse.Namespace, cfg: dict) -> int:
    url = get_backend_url(cfg, "v2")
    resp = api_post(url, "/v2/generate", {
        "prompt": args.prompt,
        "language": args.language or "python",
    }, timeout=cfg.get("timeout", 120))

    if not resp:
        print("\033[91m✖ Generation failed. Is the v2 server running?\033[0m")
        return 1

    finding = resp.get("finding", {})
    if args.format == "json":
        print_json(resp)
    else:
        print(f"\n  \033[1m🔒 Generated Secure Code\033[0m")
        if finding.get("patched_code"):
            print(f"\n  \033[96m{'-'*50}\033[0m")
            print(f"  {finding['patched_code']}")
            print(f"  \033[96m{'-'*50}\033[0m")
        if finding.get("secure_fix"):
            print(f"\n  Note: {finding['secure_fix']}")
    return 0


def cmd_server(args: argparse.Namespace, cfg: dict) -> int:
    start_server(port=args.port, mock=cfg.get("mock", True))
    return 0


def cmd_health(args: argparse.Namespace, cfg: dict) -> int:
    url = args.url or get_backend_url(cfg)
    resp = api_get(url, "/ml/health", timeout=5)

    if not resp:
        # Try v2 health
        v2_url = get_backend_url(cfg, "v2")
        resp = api_get(v2_url, "/v2/health", timeout=5)

    if not resp:
        print(f"\033[91m✖ Server is not responding at {url}\033[0m")
        return 1

    print(f"\n  \033[92m✅ Server is healthy\033[0m")
    print_json(resp)
    return 0


def cmd_batch(args: argparse.Namespace, cfg: dict) -> int:
    results = {}
    for path in args.paths:
        if os.path.isdir(path):
            results.update(scan_directory(path, cfg))
        else:
            issues = scan_file(path, cfg)
            if issues:
                results[path] = issues

    fmt = args.format or cfg.get("format", "table")
    if fmt == "json":
        print_json(results)
    else:
        for fpath, issues in results.items():
            if issues:
                print(f"\n  \033[1m📄 {fpath}\033[0m")
                print_table(issues)

    total = sum(len(v) for v in results.values())
    print(f"\n  \033[1mSummary: {total} issue(s) in {len(results)} file(s)\033[0m")
    return 0


def cmd_config(args: argparse.Namespace, cfg: dict) -> int:
    if args.show:
        print_json(cfg)
        return 0

    if args.key and args.value:
        cfg[args.key] = args.value
        save_config(cfg)
        print(f"\033[92m✅ Config updated: {args.key} = {args.value}\033[0m")
        return 0

    if args.reset:
        save_config(DEFAULT_CONFIG)
        print("\033[92m✅ Config reset to defaults\033[0m")
        return 0

    print_json(cfg)
    return 0


# ── Main Entry Point ────────────────────────────────────────────────
def main():
    cfg = load_config()

    ap = argparse.ArgumentParser(
        prog="rakshak",
        description="RakshakAI — AI-powered security scanner for your code.",
        epilog="See https://github.com/Muneerali199/RakshakAI for documentation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--url", help="Backend server URL (overrides config)")
    ap.add_argument("--mock", action="store_true", help="Force mock mode")

    sub = ap.add_subparsers(dest="cmd")

    # scan
    s = sub.add_parser("scan", help="Scan file(s) for vulnerabilities")
    s.add_argument("path", help="File or directory to scan")
    s.add_argument("--format", choices=["table", "json", "sarif"], default=cfg.get("format", "table"), help="Output format")
    s.add_argument("--language", "-l", help="Force language (default: auto-detect)")
    s.add_argument("--output", "-o", help="Save results to file")
    s.add_argument("--exclude", "-e", action="append", default=[], help="Exclude directories (repeatable, e.g. -e node_modules -e venv)")
    s.set_defaults(fn=cmd_scan)

    # review
    r = sub.add_parser("review", help="Review a unified diff for security issues")
    r.add_argument("path", help="Path to diff file")
    r.add_argument("--format", choices=["table", "json"], default=cfg.get("format", "table"), help="Output format")
    r.add_argument("--language", "-l", default="python")
    r.set_defaults(fn=cmd_review)

    # generate
    g = sub.add_parser("generate", help="Generate secure code from a prompt")
    g.add_argument("prompt", help="Describe what you need")
    g.add_argument("--format", choices=["table", "json"], default=cfg.get("format", "table"), help="Output format")
    g.add_argument("--language", "-l", default="python")
    g.set_defaults(fn=cmd_generate)

    # server
    sv = sub.add_parser("server", help="Start the RakshakAI backend server")
    sv.add_argument("--port", type=int, default=3000, help="Port to listen on")
    sv.set_defaults(fn=cmd_server)

    # health
    h = sub.add_parser("health", help="Check if the server is running")
    h.set_defaults(fn=cmd_health)

    # batch
    b = sub.add_parser("batch", help="Scan multiple files")
    b.add_argument("paths", nargs="+", help="Files or directories to scan")
    b.add_argument("--format", choices=["table", "json", "sarif"], default=cfg.get("format", "table"), help="Output format")
    b.set_defaults(fn=cmd_batch)

    # config
    c = sub.add_parser("config", help="View or modify configuration")
    c.add_argument("--show", action="store_true", help="Show current config")
    c.add_argument("--reset", action="store_true", help="Reset to defaults")
    c.add_argument("key", nargs="?", help="Config key to set")
    c.add_argument("value", nargs="?", help="Value to set")
    c.set_defaults(fn=cmd_config)

    args = ap.parse_args()

    if not args.cmd:
        ap.print_help()
        return 0

    # Update cfg with CLI overrides
    if hasattr(args, "format") and args.format:
        cfg["format"] = args.format
    if args.url:
        cfg["v1_url"] = args.url
        cfg["v2_url"] = args.url
    if hasattr(args, "mock") and args.mock:
        cfg["mock"] = True

    result = args.fn(args, cfg)

    # Save output to file if requested
    if hasattr(args, "output") and args.output:
        # Re-capture in JSON format for file output
        pass  # Could be expanded

    return result if result is not None else 0


if __name__ == "__main__":
    sys.exit(main())
