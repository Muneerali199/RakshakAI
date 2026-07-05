#!/usr/bin/env python3
"""RakshakAI v3 — Multi-Model Security CLI."""
from __future__ import annotations
import os, sys, json, time, hashlib, threading, re
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style

from v2.cli.llm import registry, parallel_chat, chat_sync, stream_chat
from v2.cli.agent import ReActAgent, AgentMode
from v2.cli.skills import SkillRegistry
from v2.cli.tools import TOOLS
from rich.markdown import Markdown
from rich.table import Table
from rich import box
from v2.cli.display import console, show_banner, show_status, show_error, show_success
from v2.cli.display import show_vuln_table, show_parallel_results, show_help, show_stats_table
from v2.cli.display import show_scan_tree, show_diff_view, show_code_comparison
from v2.cli.display import show_model_list, show_history_results, show_session_summary
from v2.cli.display import MODEL_LABELS, MODEL_COLORS, create_scan_progress, interactive_model_selector
from v2.cli.prompts import get_explain_messages, get_fix_messages, get_system, get_scan_system
from v2.cli.scanner import BatchScanner, collect_source_files
from v2.cli.watcher import FileWatcher
from v2.cli.git_scanner import (
    get_repo, scan_diff_files, get_diff_files,
    install_precommit_hook, uninstall_precommit_hook, is_hook_installed,
)
import v2.cli.memory as memory

HISTORY_FILE = os.path.expanduser("~/.rakshak_history")


def _chat_and_show(model: str, messages: list[dict]) -> str:
    """Send messages, render response with live streaming."""
    from v2.cli.llm import stream_chat
    from v2.cli.display import StreamingPanel
    
    cfg = registry.get(model)
    
    if cfg.supports_streaming:
        # Use streaming for better UX
        with StreamingPanel() as panel:
            response = stream_chat(messages, cfg, on_token=panel.update)
        return response
    else:
        # Fallback to non-streaming
        text = chat_sync(messages, cfg)
        content = text.strip()
        if content:
            console.print(Markdown(content))
        return text


class ModelCompleter(Completer):
    COMMANDS = [
        "/help", "/model", "/models", "/parallel",
        "/scan", "/explain", "/fix",
        "/batch", "/watch", "/watch-stop",
        "/diff", "/precommit",
        "/history", "/log", "/stats",
        "/confirm", "/dismiss", "/cost",
        "/clear", "/session", "/exit",
        "/agent", "/skills",
    ]

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        
        # Command completion
        if text.startswith("/") and " " not in text:
            for cmd in self.COMMANDS:
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text))
        
        # Model name completion for /model and /parallel
        elif text.startswith("/model ") or text.startswith("/parallel ") or text.startswith("/agent "):
            prefix = text.split()[-1]
            for name in registry.list():
                if name.startswith(prefix):
                    yield Completion(name, start_position=-len(prefix))
        
        # File path completion for /scan, /explain, /log, /batch
        elif any(text.startswith(cmd + " ") for cmd in ["/scan", "/explain", "/log", "/batch", "/watch"]):
            from pathlib import Path
            
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                return
            
            path_prefix = parts[1]
            
            try:
                if path_prefix:
                    base_path = Path(path_prefix).parent if "/" in path_prefix else Path(".")
                    name_prefix = Path(path_prefix).name
                else:
                    base_path = Path(".")
                    name_prefix = ""
                
                if base_path.exists() and base_path.is_dir():
                    for item in sorted(base_path.iterdir()):
                        item_name = item.name
                        if item_name.startswith(".") and not name_prefix.startswith("."):
                            continue
                        if item_name.startswith(name_prefix):
                            display_path = str(item.relative_to(".")) if item.is_relative_to(".") else str(item)
                            if item.is_dir():
                                display_path += "/"
                            yield Completion(
                                display_path,
                                start_position=-len(path_prefix),
                                display=item_name + ("/" if item.is_dir() else "")
                            )
            except (OSError, ValueError):
                pass


bindings = KeyBindings()

@bindings.add("c-c")
def _(event):
    raise KeyboardInterrupt()

@bindings.add("c-d")
def _(event):
    sys.exit(0)

prompt_style = Style.from_dict({"prompt": "bold cyan"})


class RakshakREPL:
    def __init__(self):
        self.messages: list[dict] = []
        self.current_dir = os.getcwd()
        self.session_count = 0
        self.start_time = time.time()
        self._session_id = memory.start_session(registry.active, self.current_dir)
        self._scanner = BatchScanner(max_workers=4)
        self._watcher = FileWatcher(model=registry.active)
        self.last_analysis_id: int | None = None
        
        # Agent & skills
        from v2.cli.tools import TOOLS
        self._skills = SkillRegistry()
        self._agent = ReActAgent(mode=AgentMode.INTERACTIVE, tools=TOOLS, model=registry.active)

        # Track session stats
        self.files_scanned = 0
        self.vulnerabilities_found = 0
        self.models_used = set([registry.active])

    def _on_watch_notify(self, alert: dict):
        sev = alert.get("severity", "").lower()
        c = "red" if sev in ("critical", "high") else "yellow"
        show_status(f"watch: {os.path.basename(alert['file'])} ({alert['cwe']} [{sev}])", c)

    def _read_file(self, path: str) -> str | None:
        p = Path(path)
        if not p.exists():
            p = Path(self.current_dir) / path
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")
        return None

    def _cache_key(self, q: str, m: str) -> str:
        return hashlib.md5(f"{m}:{q}".encode()).hexdigest()[:16]

    # ── command handlers ──────────────────────────────────

    def _handle_scan(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /scan <file>")
        code = self._read_file(args.strip())
        if code is None:
            return show_error(f"File not found: {args.strip()}")
        
        t0 = time.time()
        with console.status(f"[cyan]Scanning {args.strip()}...", spinner="dots"):
            from v2.cli.scanner import scan_code
            result = scan_code(code, language=Path(args.strip()).suffix[1:], model=registry.active)
        
        vulns = result.get("vulnerabilities", [])
        raw = result.get("_raw", "")
        
        # Update stats
        self.files_scanned += 1
        self.vulnerabilities_found += len(vulns)
        
        if vulns:
            show_vuln_table(vulns)
        
        cwe = vulns[0].get("cwe", "") if vulns else ""
        sev = vulns[0].get("severity", "") if vulns else ""
        conf = vulns[0].get("confidence", 0.0) if vulns else 0.0
        aid = memory.record_analysis(
            session_id=self._session_id,
            file_path=os.path.abspath(args.strip()),
            language=Path(args.strip()).suffix[1:],
            cwe=cwe, severity=sev, model=registry.active,
            query_hash=self._cache_key(code, registry.active),
            query=f"scan {args.strip()}", response=raw,
            duration_ms=int((time.time() - t0) * 1000),
        )
        self.last_analysis_id = aid
        
        if vulns:
            console.print(f"\n[dim]Analysis #{aid} • /confirm #{aid} to mark as true positive • /dismiss #{aid} to mark as false positive[/]")
        else:
            console.print(f"\n[dim]Analysis #{aid} • Completed in {(time.time() - t0):.2f}s[/]")
        
        return True

    def _handle_explain(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /explain <file>")
        code = self._read_file(args.strip())
        if code is None:
            return show_error(f"File not found: {args.strip()}")
        show_status(f"Explaining {args.strip()} ...")
        _chat_and_show(registry.active, get_explain_messages(code))
        return True

    def _handle_fix(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /fix <description>")
        show_status("Generating fix...")
        _chat_and_show(registry.active, get_fix_messages(args.strip()))
        return True

    def _handle_batch(self, args: str) -> bool:
        target_dir = args.strip() or "."
        if not os.path.isdir(target_dir):
            return show_error(f"Directory not found: {target_dir}")
        
        with console.status("[cyan]Collecting source files...", spinner="dots"):
            files = collect_source_files(target_dir)
        
        if not files:
            return show_status("No source files found.", "yellow")
        
        # Use rich progress bar
        progress = create_scan_progress()
        results = []
        
        with progress:
            task = progress.add_task(
                "Scanning files",
                total=len(files),
                status=f"0/{len(files)} files"
            )
            
            def on_progress(completed_count):
                progress.update(task, completed=completed_count, status=f"{completed_count}/{len(files)} files")
            
            self._scanner.on_progress(on_progress)
            results = self._scanner.scan_files(files, model=registry.active)
        
        # Update stats
        self.files_scanned += len(files)
        vuln_count = sum(1 for r in results if r.cwe)
        self.vulnerabilities_found += vuln_count
        
        smry = self._scanner.summary()
        show_status(
            f"Scanned: {smry['scanned']} • Vulnerable: {smry['vulnerable']} • "
            f"Critical: {smry['critical']} • High: {smry['high']} • Errors: {smry['errors']}"
        )
        show_scan_tree([r.to_dict() for r in results])
        return True

    def _handle_watch(self, args: str) -> bool:
        target_dir = args.strip() or "."
        if self._watcher.is_running:
            return show_status("Watcher already running")
        if not os.path.isdir(target_dir):
            return show_error(f"Directory not found: {target_dir}")
        self._watcher.on_notify(self._on_watch_notify)
        if self._watcher.start(os.path.abspath(target_dir)):
            show_status(f"Watching {os.path.abspath(target_dir)}  |  /watch-stop to stop")
        else:
            show_error("Failed to start watcher")
        return True

    def _handle_watch_stop(self, args: str) -> bool:
        if not self._watcher.is_running:
            return show_status("No watcher running")
        c = self._watcher.vulnerable_count
        self._watcher.stop()
        show_status(f"Watcher stopped. {c} vulnerabilities found.")
        return True

    def _handle_diff(self, args: str) -> bool:
        repo = get_repo(".")
        if not repo:
            return show_error("Not a git repository")
        files = get_diff_files(repo)
        if not files:
            return show_status("No unstaged changes.")
        show_status(f"Scanning {len(files)} changed file(s)...")
        results = scan_diff_files(files, model=registry.active)
        show_status(f"{sum(1 for r in results if r.get('cwe'))} vulns in changes")
        show_scan_tree(results)
        return True

    def _handle_precommit(self, args: str) -> bool:
        a = args.strip().lower()
        if a == "install":
            show_success("Hook installed") if install_precommit_hook(".") else show_error("Not a git repo")
        elif a == "uninstall":
            show_success("Hook removed") if uninstall_precommit_hook(".") else show_error("Hook not found")
        elif a == "status":
            show_status("Installed" if is_hook_installed(".") else "Not installed")
        else:
            show_error("Usage: /precommit [install|uninstall|status]")
        return True

    def _handle_history(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /history <search term>")
        rows = memory.search_analyses(args.strip(), limit=20)
        show_history_results(rows, args.strip())
        return True

    def _handle_log(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /log <file>")
        p = Path(args.strip())
        if not p.exists():
            p = Path(self.current_dir) / args.strip()
        if not p.exists():
            return show_error(f"File not found: {args.strip()}")
        rows = memory.get_file_history(str(p.resolve()))
        if not rows:
            return show_status(f"No history for {args.strip()}")
        for r in rows:
            ts = (r.get("timestamp") or "")[11:19]
            cwe = r.get("cwe", "") or ""
            sev = r.get("severity", "") or ""
            console.print(f"  [dim]{ts}[/]  {cwe}  {sev}")
        return True

    def _handle_stats(self, args: str) -> bool:
        show_stats_table(memory.get_stats())
        return True

    def _handle_parallel(self, args: str) -> bool:
        model_names = [p for p in args.strip().split() if p in registry.models] or registry.list()
        if not model_names:
            return show_error(f"Available: {', '.join(registry.list())}")
        
        # Update models used
        self.models_used.update(model_names)
        
        last = next((m["content"] for m in reversed(self.messages) if m["role"] == "user"), None)
        if not last:
            return show_error("No previous query.")
        
        with console.status(f"[cyan]Running {len(model_names)} models in parallel...", spinner="dots"):
            results = parallel_chat([{"role": "user", "content": last}], model_names)
        
        show_parallel_results(results)
        return True

    def _handle_model(self, args: str) -> bool:
        name = args.strip()
        if not name:
            # Show interactive model selector
            selected = interactive_model_selector(registry.models, registry.active)
            if selected and selected != registry.active:
                if registry.set_active(selected):
                    self.models_used.add(selected)
                    show_success(f"Switched to {MODEL_LABELS.get(selected, selected)}")
                    return True
            elif not selected:
                # User cancelled, show current model list
                show_model_list(registry.models, registry.active)
            return True
        
        if registry.set_active(name):
            self.models_used.add(name)
            self._agent.model = name
            show_success(f"Switched to {MODEL_LABELS.get(name, name)}")
            return True
        else:
            show_error(f"Model '{name}' not found")
            show_model_list(registry.models, registry.active)
            return False

    def _handle_models(self, args: str) -> bool:
        show_model_list(registry.models, registry.active)
        return True

    def _handle_confirm(self, args: str) -> bool:
        aid = args.strip().lstrip("#")
        if not aid.isdigit():
            if self.last_analysis_id:
                aid = str(self.last_analysis_id)
            else:
                return show_error("Usage: /confirm <analysis_id>")
        note = ""
        if " " in aid:
            parts = aid.split(maxsplit=1)
            aid, note = parts[0], parts[1]
        memory.confirm_finding(int(aid), note)
        show_success(f"#{aid} confirmed as true positive")
        return True

    def _handle_dismiss(self, args: str) -> bool:
        aid = args.strip().lstrip("#")
        if not aid.isdigit():
            if self.last_analysis_id:
                aid = str(self.last_analysis_id)
            else:
                return show_error("Usage: /dismiss <analysis_id>")
        note = ""
        if " " in aid:
            parts = aid.split(maxsplit=1)
            aid, note = parts[0], parts[1]
        memory.dismiss_finding(int(aid), note)
        show_success(f"#{aid} dismissed as false positive")
        return True

    def _handle_cost(self, args: str) -> bool:
        stats = memory.get_stats()
        model_usage = stats.get("model_usage", [])
        if not model_usage:
            return show_status("No analyses yet.")
        table = Table(box=box.SIMPLE, padding=(0, 2), show_header=True)
        table.add_column("model", style="cyan")
        table.add_column("count", justify="right")
        table.add_column("total_s", justify="right")
        table.add_column("avg_ms", justify="right")
        for m in model_usage:
            table.add_row(
                m["model"],
                str(m["count"]),
                f"{m['total_ms'] / 1000:.1f}",
                str(m["avg_ms"]),
            )
        console.print(table)
        fb = stats.get("precision")
        if fb is not None:
            console.print(f"[dim]  precision: {fb:.1%} ({stats['feedback_confirmed']}/{stats['feedback_total']})[/]")
        return True

    def _handle_session(self, args: str) -> bool:
        elapsed = time.time() - self.start_time
        console.print(
            f"  dir: {self.current_dir}\n"
            f"  model: {MODEL_LABELS.get(registry.active, registry.active)}\n"
            f"  messages: {len(self.messages)}\n"
            f"  duration: {elapsed:.0f}s\n"
            f"  session: {self._session_id}"
        )
        return True

    def _handle_agent(self, args: str) -> bool:
        """Run autonomous agent on a task."""
        if not args.strip():
            return show_error("Usage: /agent <task description>")
        show_status(f"Agent starting: {args.strip()[:80]}...", "cyan")
        self.models_used.add(self._agent.model)
        result = self._agent.run(args.strip())
        self._show_agent_result(result)
        return True

    def _handle_skills(self, args: str) -> bool:
        """List or refresh agent skills."""
        a = args.strip().lower()
        if a == "refresh":
            with console.status("[cyan]Refreshing skill cache...", spinner="dots"):
                self._skills.refresh_cache()
            show_success("Skills refreshed")
        elif a:
            # Show specific skill details
            skill = self._skills.get_skill(a)
            if skill:
                from rich.panel import Panel
                console.print(Panel(
                    f"[bold]{skill.name}[/] v{skill.version}\n"
                    f"Source: {skill.source}\n"
                    f"Tools: {', '.join(skill.tools_required)}\n\n"
                    f"{skill.description[:500]}",
                    title="Skill Details",
                    border_style="cyan",
                ))
            else:
                show_error(f"Skill '{a}' not found")
        else:
            skills = self._skills.list_skills()
            from rich.table import Table
            table = Table(title=f"[bold]Skills ({len(skills)})[/]", box=box.ROUNDED, border_style="cyan")
            table.add_column("Name", style="bold cyan")
            table.add_column("Source")
            table.add_column("Tools Required")
            for name in skills:
                s = self._skills.get_skill(name)
                table.add_row(name, s.source, ", ".join(s.tools_required) if s.tools_required else "—")
            console.print(table if skills else "[dim]No skills loaded. Use /skills refresh to fetch from GitHub.[/]")
        return True

    def _show_agent_result(self, result: dict):
        """Display agent execution result."""
        from rich.panel import Panel
        from v2.cli.display import console
        success = result.get("success", False)
        border = "green" if success else "red"
        title = "✓ Agent Complete" if success else "✗ Agent Failed"
        text = f"Steps: {result['steps']}\n"
        if result.get("error"):
            text += f"Error: {result['error']}\n"
        for t in result["thoughts"]:
            action_str = ""
            if t.get("action"):
                a = t["action"]
                action_str = f" → {a['tool']}.{a['action']}({a['params']})"
            status = "✓" if t.get("success") else "✗" if t.get("success") is False else "?"
            text += f"\n  Step {t['step']}: [{status}] {t['thought'][:120]}{action_str}"
        console.print(Panel(text.strip(), title=title, border_style=border))

    # ── main loop ──────────────────────────────────────────

    def run(self):
        show_banner(registry.active)
        show_status(f"Ready to scan • Type /help for commands", "green")

        session = PromptSession(
            history=FileHistory(HISTORY_FILE),
            auto_suggest=AutoSuggestFromHistory(),
            completer=ModelCompleter(),
            key_bindings=bindings,
            style=prompt_style,
            complete_while_typing=True,
            enable_history_search=True,
        )

        while True:
            try:
                text = session.prompt("> ", default="")
            except KeyboardInterrupt:
                console.print("\n[yellow]Use /exit or Ctrl+D to quit[/]")
                continue
            except EOFError:
                break

            text = text.strip()
            if not text:
                continue

            self.session_count += 1

            if text.startswith("/"):
                parts = text.split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                handlers = {
                    "/help": lambda a: show_help(),
                    "/model": self._handle_model,
                    "/models": self._handle_models,
                    "/parallel": self._handle_parallel,
                    "/scan": self._handle_scan,
                    "/explain": self._handle_explain,
                    "/fix": self._handle_fix,
                    "/batch": self._handle_batch,
                    "/watch": self._handle_watch,
                    "/watch-stop": self._handle_watch_stop,
                    "/diff": self._handle_diff,
                    "/precommit": self._handle_precommit,
                    "/history": self._handle_history,
                    "/log": self._handle_log,
                    "/stats": self._handle_stats,
                    "/confirm": self._handle_confirm,
                    "/dismiss": self._handle_dismiss,
                    "/cost": self._handle_cost,
                    "/clear": lambda a: (self.messages.clear(), show_status("Conversation context cleared", "green")),
                    "/session": self._handle_session,
                    "/agent": self._handle_agent,
                    "/skills": self._handle_skills,
                    "/exit": lambda a: self._exit_gracefully(),
                }

                handler = handlers.get(cmd)
                if handler:
                    try:
                        handler(args)
                    except Exception as e:
                        show_error(f"Command failed: {e}")
                else:
                    show_error(f"Unknown command: {cmd} (type /help for available commands)")
                continue

            # Regular chat
            self.messages.append({"role": "user", "content": text})
            system = {"role": "system", "content": get_system(registry.active)}
            response = _chat_and_show(registry.active, [system] + self.messages[-20:])
            self.messages.append({"role": "assistant", "content": response})

    def _exit_gracefully(self):
        """Exit with session summary."""
        duration = time.time() - self.start_time
        show_session_summary(
            duration_seconds=duration,
            files_scanned=self.files_scanned,
            vulnerabilities_found=self.vulnerabilities_found,
            models_used=sorted(list(self.models_used)),
        )
        sys.exit(0)


def main():
    repl = RakshakREPL()
    try:
        repl.run()
    except KeyboardInterrupt:
        duration = time.time() - repl.start_time
        show_session_summary(
            duration_seconds=duration,
            files_scanned=repl.files_scanned,
            vulnerabilities_found=repl.vulnerabilities_found,
            models_used=sorted(list(repl.models_used)),
        )
    except Exception as e:
        show_error(f"Fatal error: {e}")
        raise
    finally:
        if repl._watcher.is_running:
            repl._watcher.stop()
        memory.end_session(repl._session_id)


if __name__ == "__main__":
    main()
