"""Autonomous Agent Core - ReAct Pattern Implementation.

ReAct = Reasoning + Acting
The agent uses the LLM to reason, calls tools, observes results, and iterates.
"""
from __future__ import annotations
import json
import re
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

from v2.cli.llm import registry, chat_sync
from v2.cli.prompts import get_agent_messages


class AgentMode(Enum):
    AUTONOMOUS = "autonomous"
    INTERACTIVE = "interactive"
    PASSIVE = "passive"


@dataclass
class AgentAction:
    tool: str
    action: str
    params: dict[str, Any]
    reasoning: str


@dataclass
class AgentObservation:
    success: bool
    result: Any
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentThought:
    step: int
    thought: str
    action: Optional[AgentAction] = None
    observation: Optional[AgentObservation] = None


class ReActAgent:
    """Autonomous ReAct agent that uses the LLM for reasoning."""

    def __init__(
        self,
        mode: AgentMode = AgentMode.INTERACTIVE,
        max_iterations: int = 10,
        tools: Optional[dict[str, Callable]] = None,
        model: str = "deepseek",
    ):
        self.mode = mode
        self.max_iterations = max_iterations
        self.tools = tools or {}
        self.model = model
        self.thought_chain: list[AgentThought] = []
        self.context = {}

    def think(self, task: str, context: Optional[dict] = None) -> AgentThought:
        """Use the LLM to generate the next thought and action."""
        step = len(self.thought_chain) + 1
        history = self._format_history()
        tools_context = self._format_tools_context()
        messages = get_agent_messages(task, history, tools_context)

        thought_text = chat_sync(messages, registry.get(self.model))
        action = self._parse_action(thought_text)

        return AgentThought(step=step, thought=thought_text, action=action)

    def act(self, action: AgentAction) -> AgentObservation:
        """Execute a tool action."""
        if action.tool not in self.tools:
            return AgentObservation(
                success=False,
                error=f"Tool '{action.tool}' not available. Available: {', '.join(self.tools)}",
            )

        try:
            tool_obj = self.tools[action.tool]
            method = getattr(tool_obj, action.action, None)
            if method is None:
                return AgentObservation(
                    success=False,
                    error=f"Action '{action.action}' not found on tool '{action.tool}'. Available: {[m for m in dir(tool_obj) if not m.startswith('_')]}",
                )

            result = method(**action.params)
            return AgentObservation(
                success=True,
                result=result,
                metadata={"tool": action.tool, "action": action.action},
            )
        except TypeError as e:
            return AgentObservation(
                success=False, error=f"Bad params for {action.action}: {e}"
            )
        except Exception as e:
            return AgentObservation(
                success=False, error=str(e),
                metadata={"tool": action.tool, "action": action.action},
            )

    def run(self, task: str, context: Optional[dict] = None) -> dict:
        """Execute ReAct loop until task completion."""
        self.thought_chain = []
        self.context = context or {}

        for i in range(self.max_iterations):
            thought = self.think(task, self.context)
            self.thought_chain.append(thought)

            if self._is_complete(thought):
                return self._build_result(success=True)

            if not thought.action:
                return self._build_result(
                    success=False, error="Agent could not determine next action"
                )

            if self.mode == AgentMode.INTERACTIVE:
                if not self._get_user_permission(thought):
                    return self._build_result(
                        success=False, error="User cancelled"
                    )

            if self.mode != AgentMode.PASSIVE:
                observation = self.act(thought.action)
                thought.observation = observation
                result_text = str(observation.result)[:500] if observation.success else f"ERROR: {observation.error}"
                self.context[f"step_{i}_result"] = result_text

        return self._build_result(
            success=False, error=f"Max iterations ({self.max_iterations}) reached"
        )

    def _parse_action(self, thought: str) -> Optional[AgentAction]:
        """Extract ACTION[tool:action](params) from LLM output."""
        pattern = r'ACTION\[(\w+):(\w+)\]\((.*?)\)'
        match = re.search(pattern, thought, re.DOTALL)
        if not match:
            return None

        tool, action_name, params_str = match.groups()
        params = {}
        if params_str.strip():
            for pair in params_str.split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    k, v = k.strip(), v.strip().strip('"\'')
                    if v.isdigit():
                        v = int(v)
                    elif v.lower() == 'true':
                        v = True
                    elif v.lower() == 'false':
                        v = False
                    params[k] = v

        return AgentAction(tool=tool, action=action_name, params=params, reasoning=thought)

    def _is_complete(self, thought: AgentThought) -> bool:
        return "DONE" in thought.thought.upper()

    def _format_history(self) -> str:
        if not self.thought_chain:
            return "No previous actions."
        lines = []
        for t in self.thought_chain[-5:]:
            lines.append(f"Step {t.step}: {t.thought[:200]}")
            if t.observation:
                status = "✓" if t.observation.success else "✗"
                lines.append(f"  → {status}")
        return "\n".join(lines)

    def _format_tools_context(self) -> str:
        if not self.tools:
            return ""
        parts = []
        for name, obj in self.tools.items():
            methods = [m for m in dir(obj) if not m.startswith('_') and callable(getattr(obj, m))]
            parts.append(f"- {name}: {', '.join(methods)}")
        return "Tools:\n" + "\n".join(parts)

    def _get_user_permission(self, thought: AgentThought) -> bool:
        if not thought.action:
            return True
        from rich.prompt import Confirm
        from v2.cli.display import console

        console.print(f"\n[bold cyan]Agent[/] wants to use [bold]{thought.action.tool}.{thought.action.action}[/]")
        if thought.action.params:
            console.print(f"  Params: {thought.action.params}")
        console.print(f"  Reason: {thought.action.reasoning[:200]}\n")
        return Confirm.ask("Allow?")

    def _build_result(self, success: bool, error: Optional[str] = None) -> dict:
        return {
            "success": success,
            "error": error,
            "steps": len(self.thought_chain),
            "thoughts": [
                {
                    "step": t.step,
                    "thought": t.thought,
                    "action": {"tool": t.action.tool, "action": t.action.action, "params": t.action.params} if t.action else None,
                    "success": t.observation.success if t.observation else None,
                    "result_preview": str(t.observation.result)[:100] if t.observation and t.observation.success else None,
                }
                for t in self.thought_chain
            ],
        }
