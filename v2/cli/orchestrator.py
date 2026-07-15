"""Multi-agent orchestration — decompose tasks, spawn subagents in parallel, synthesize results."""
from __future__ import annotations
import json
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import Any, Optional

from v2.cli.agent import ReActAgent, AgentMode
from v2.cli.llm import registry
from v2.cli.tools import TOOLS


@dataclass
class SubTask:
    """A unit of work for a subagent."""
    id: str
    description: str
    tool_restrictions: str = "all"


@dataclass
class SubAgentResult:
    """Result from a single subagent execution."""
    subtask_id: str
    success: bool
    result: dict
    steps: int
    elapsed_ms: float


class OrchestratorAgent:
    """Decomposes high-level tasks into parallel subtasks and synthesizes results.

    Uses the LLM to reason about how to break down a complex task,
    spawns ReActAgent subagents in parallel via ThreadPoolExecutor,
    and collects results for synthesis.
    """

    def __init__(
        self,
        model: str = "deepseek",
        max_subagents: int = 5,
        max_iterations: int = 10,
    ):
        self.model = model
        self.max_subagents = max_subagents
        self.max_iterations = max_iterations

    def decompose(self, task: str) -> list[SubTask]:
        """Use LLM to break a task into independent parallel subtasks."""
        prompt = (
            f"You are a task decomposition agent. Break this task into at most {self.max_subagents} "
            f"independent subtasks that can run in parallel:\n\n{task}\n\n"
            "Return a JSON array of objects with keys: id, description, tool_restrictions.\n"
            "tool_restrictions: comma-separated tool names or 'all'.\n"
            "Tools available: file_ops (read/write/search), shell, web_search, http, github.\n"
            "Example: [{\"id\": \"scan_backend\", \"description\": \"Scan src/backend for SQL injection\", \"tool_restrictions\": \"file_ops\"}]\n"
            "Return ONLY the JSON array, no markdown."
        )
        cfg = registry.get(self.model)
        try:
            client = cfg.client
            r = client.chat.completions.create(
                model=cfg.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2048,
            )
            text = r.choices[0].message.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                if text.endswith("```"):
                    text = text[:-3]
            text = text.strip()
            data = json.loads(text)
            if isinstance(data, dict):
                data = [data]
            return [SubTask(**t) for t in data[:self.max_subagents]]
        except Exception:
            return [SubTask(id="main", description=task, tool_restrictions="all")]

    def _run_single(self, subtask: SubTask) -> SubAgentResult:
        """Spawn a ReActAgent for one subtask."""
        start = time.time()
        agent = ReActAgent(
            mode=AgentMode.AUTONOMOUS,
            max_iterations=self.max_iterations,
            tools=TOOLS,
            model=self.model,
        )
        result = agent.run(subtask.description)
        elapsed = (time.time() - start) * 1000
        return SubAgentResult(
            subtask_id=subtask.id,
            success=result.get("success", False),
            result=result,
            steps=result.get("steps", 0),
            elapsed_ms=round(elapsed, 1),
        )

    def run(self, task: str) -> dict:
        """Decompose task, spawn subagents in parallel, return synthesized results."""
        subtasks = self.decompose(task)
        n = len(subtasks)

        results: list[SubAgentResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            futures = {pool.submit(self._run_single, st): st for st in subtasks}
            for future in concurrent.futures.as_completed(futures):
                st = futures[future]
                try:
                    r = future.result()
                    results.append(r)
                except Exception as e:
                    results.append(SubAgentResult(
                        subtask_id=st.id, success=False,
                        result={"error": str(e)}, steps=0, elapsed_ms=0,
                    ))

        results.sort(key=lambda r: r.subtask_id)
        successes = sum(1 for r in results if r.success)
        total_ms = sum(r.elapsed_ms for r in results)

        thoughts = []
        for r in results:
            steps = r.result.get("thoughts", [])
            preview = ""
            if steps:
                last = steps[-1]
                preview = last.get("thought", "")[:200]
            thoughts.append({
                "id": r.subtask_id,
                "success": r.success,
                "steps": r.steps,
                "elapsed_ms": r.elapsed_ms,
                "preview": preview,
                "error": r.result.get("error") if not r.success else None,
            })

        return {
            "task": task,
            "subtask_count": n,
            "success_count": successes,
            "fail_count": n - successes,
            "total_elapsed_ms": round(total_ms, 1),
            "subtask_results": thoughts,
        }


def run_swarm(task: str, model: str = "deepseek", max_agents: int = 5) -> dict:
    """Convenience: create orchestrator and run task."""
    orch = OrchestratorAgent(model=model, max_subagents=max_agents)
    return orch.run(task)
