"""Replay agent: a scripted stand-in for the LLM that drives the demo through MCP tools.

It emits the same one-`{"tool": .., "args": ..}`-per-turn actions the LLM loop uses, so it is
the fallback when no GPU/model is available and the reference for the canonical trace.
IDs (`simulation_id`, `commit_id`) are read from the previous tool outputs.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..state import DEMO_ATTACK_INTERFACE, DEMO_ATTACKER_IP

Action = dict[str, Any]
CallTool = Callable[[str, dict[str, Any]], Awaitable[str]]
Scenario = Literal["canonical", "bonus"]

SIM_ID_RE = re.compile(r"Simulation `(sim-[0-9a-f]+)`")
COMMIT_ID_RE = re.compile(r"Commit `(commit-[0-9a-f]+)`")
MIN_PRIORITY_RE = re.compile(r"Minimum safe priority: (\d+)")


class ToolCallError(Exception):
    """A tool returned an error result (the server rejected the call)."""


@dataclass
class TraceStep:
    tool: str
    args: dict[str, Any]
    output: str
    is_error: bool = False


def _last(pattern: re.Pattern[str], trace: list[TraceStep]) -> str:
    for step in reversed(trace):
        m = pattern.search(step.output)
        if m:
            return m.group(1)
    raise RuntimeError(f"replay: no match for {pattern.pattern!r} in previous outputs")


def _deny_attacker(priority: int) -> Action:
    args = {"src_cidr": f"{DEMO_ATTACKER_IP}/32", "action": "deny", "priority": priority}
    return {"tool": "simulate_flow_impact", "args": args}


# Each step maps the trace so far to the next action.
CANONICAL: tuple[Callable[[list[TraceStep]], Action], ...] = (
    lambda t: {"tool": "get_traffic_anomalies", "args": {"window_s": 60}},
    lambda t: {"tool": "detect_network_drift", "args": {"interface": DEMO_ATTACK_INTERFACE}},
    # The naive fix: prio 40 is SHADOWED by rule #10 (prio 100 ALLOW 10.10.20.0/24).
    lambda t: _deny_attacker(40),
    # Apply the simulator's fix with headroom (>= minimum safe priority).
    lambda t: _deny_attacker(max(150, int(_last(MIN_PRIORITY_RE, t)))),
    lambda t: {
        "tool": "push_safe_sdn_policy",
        "args": {"simulation_id": _last(SIM_ID_RE, t), "timeout_s": 30},
    },
    lambda t: {"tool": "confirm_commit", "args": {"commit_id": _last(COMMIT_ID_RE, t)}},
)


def bonus_steps(timeout_s: int = 10) -> tuple[Callable[[list[TraceStep]], Action], ...]:
    """Dead-man's switch: a PASS rule is pushed and deliberately never confirmed."""
    return (
        lambda t: {"tool": "list_flow_rules", "args": {}},
        lambda t: {
            "tool": "simulate_flow_impact",
            "args": {
                "src_cidr": "10.10.20.0/24",
                "dst_cidr": "10.10.40.0/24",
                "action": "deny",
                "priority": 200,
            },
        },
        lambda t: {
            "tool": "push_safe_sdn_policy",
            "args": {"simulation_id": _last(SIM_ID_RE, t), "timeout_s": timeout_s},
        },
        lambda t: {"tool": "wait", "args": {"seconds": _bonus_wait(t, timeout_s)}},
        lambda t: {"tool": "get_commit_status", "args": {"commit_id": _last(COMMIT_ID_RE, t)}},
        lambda t: {"tool": "list_flow_rules", "args": {}},
    )


def _bonus_wait(trace: list[TraceStep], timeout_s: int) -> float:
    m = re.search(r"Auto-rollback in (\d+) s", trace[-1].output)
    return (int(m.group(1)) if m else timeout_s) + 1.5


@dataclass
class ReplayAgent:
    scenario: Scenario = "canonical"
    bonus_timeout_s: int = 10
    trace: list[TraceStep] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.steps = (
            CANONICAL if self.scenario == "canonical" else bonus_steps(self.bonus_timeout_s)
        )

    def next_action(self) -> Action | None:
        """The next `{"tool", "args"}` action, or None when the script is done."""
        if len(self.trace) >= len(self.steps):
            return None
        return self.steps[len(self.trace)](self.trace)

    def observe(self, action: Action, output: str, is_error: bool = False) -> None:
        self.trace.append(TraceStep(action["tool"], action["args"], output, is_error))

    async def run(self, call_tool: CallTool, wait_scale: float = 1.0) -> list[TraceStep]:
        """Drive the scenario to the end. A `wait` action sleeps locally (not an MCP tool)."""
        while (action := self.next_action()) is not None:
            if action["tool"] == "wait":
                seconds = float(action["args"]["seconds"]) * wait_scale
                await asyncio.sleep(seconds)
                self.observe(action, f"Waited {seconds:.1f} s.")
                continue
            try:
                output, is_error = await call_tool(action["tool"], action["args"]), False
            except ToolCallError as exc:
                output, is_error = str(exc), True
            self.observe(action, output, is_error)
            if is_error:
                break
        return self.trace


def mcp_call_tool(client: Any) -> CallTool:
    """Adapt an `mcp.Client` to the `CallTool` signature (text content joined)."""

    async def call(name: str, args: dict[str, Any]) -> str:
        result = await client.call_tool(name, args)
        text = "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")
        if result.is_error:
            raise ToolCallError(text)
        return text

    return call


def format_trace(trace: list[TraceStep]) -> str:
    out = []
    for i, step in enumerate(trace, 1):
        args = ", ".join(f"{k}={v!r}" for k, v in step.args.items())
        flag = " [error]" if step.is_error else ""
        out.append(f"### {i}. {step.tool}({args}){flag}\n{step.output}")
    return "\n\n".join(out)


def server_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Env for the server subprocess: make this package importable even without the
    editable install's .pth (macOS may mark it hidden, and the default env drops PYTHONPATH)."""
    pkg_root = str(Path(__file__).resolve().parents[2])
    path = os.pathsep.join(p for p in (pkg_root, os.environ.get("PYTHONPATH", "")) if p)
    return {"PYTHONPATH": path, **(extra or {})}


async def run_over_stdio(
    scenario: Scenario = "canonical",
    reset: bool = True,
    env: dict[str, str] | None = None,
    bonus_timeout_s: int = 10,
) -> list[TraceStep]:
    """Spawn the MCP server as a subprocess and replay a scenario against it."""
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    args = ["-m", "sdn_guardian.mcp_server"] + (["--reset"] if reset else [])
    params = StdioServerParameters(command=sys.executable, args=args, env=server_env(env))
    async with Client(params) as client:
        return await ReplayAgent(scenario, bonus_timeout_s).run(mcp_call_tool(client))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Replay the SDN Guardian demo over MCP stdio.")
    parser.add_argument("--scenario", choices=["canonical", "bonus", "both"], default="both")
    args = parser.parse_args(argv)

    async def go() -> None:
        env = {k: v for k, v in os.environ.items() if k.startswith("SDN_GUARDIAN_")}
        scenarios: list[Scenario] = (
            ["canonical", "bonus"] if args.scenario == "both" else [args.scenario]
        )
        for i, sc in enumerate(scenarios):
            print(f"## Scenario: {sc}\n")
            print(format_trace(await run_over_stdio(sc, reset=i == 0, env=env or None)) + "\n")

    asyncio.run(go())


if __name__ == "__main__":
    main()
