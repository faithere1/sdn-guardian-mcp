"""ReAct loop: the LLM emits one `{"tool": .., "args": ..}` JSON per turn, the loop runs it
over MCP and feeds the Markdown output back as the next observation.

Malformed replies get a corrective message and are retried a bounded number of times. Tool
errors (e.g. a rejected push) are observations, not crashes, so the model can recover. The
loop ends on the `finish` pseudo-tool, the turn limit, or exhausted parse retries.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from .llm_backend import ChatBackend, Message, load_backend
from .replay_agent import (
    Action,
    CallTool,
    ReplayAgent,
    ToolCallError,
    TraceStep,
    mcp_call_tool,
    server_env,
)

FINISH_TOOL = "finish"
StopReason = Literal["finished", "max_turns", "parse_error", "backend_error", "replay"]

SYSTEM_PROMPT = """You are SDN Guardian, a network security agent. You defend the network by \
calling tools. Every change is dry-run first; only PASS simulations can be pushed, and every \
push must be confirmed or it rolls back automatically.

Workflow: get_traffic_anomalies -> detect_network_drift on the attack interface -> \
simulate_flow_impact a deny for the attacker (/32) -> if FAIL, re-simulate with the suggested \
"Minimum safe priority" or higher -> push_safe_sdn_policy with the PASS simulation_id -> \
confirm_commit with the commit_id -> finish.

Tools:
{tools}
- {finish}(summary: string): end the task with a short summary.

Reply with exactly ONE JSON object and nothing else, for example:
{{"tool": "get_traffic_anomalies", "args": {{"window_s": 60}}}}
Copy IDs (sim-..., commit-...) exactly from previous tool outputs."""

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class ActionParseError(ValueError):
    """The model reply is not a single valid tool action."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]

    def signature(self) -> str:
        props = self.input_schema.get("properties", {})
        required = set(self.input_schema.get("required", []))
        params = []
        for pname, schema in props.items():
            ptype = _schema_type(schema)
            params.append(f"{pname}: {ptype}" + ("" if pname in required else "?"))
        desc = " ".join(self.description.split())
        return f"- {self.name}({', '.join(params)}): {desc}"


def _schema_type(schema: dict[str, Any]) -> str:
    if "enum" in schema:
        return "|".join(json.dumps(v) for v in schema["enum"])
    if "anyOf" in schema:
        return "|".join(_schema_type(s) for s in schema["anyOf"] if s.get("type") != "null")
    return str(schema.get("type", "any"))


def build_system_prompt(tools: list[ToolSpec]) -> str:
    return SYSTEM_PROMPT.format(tools="\n".join(t.signature() for t in tools), finish=FINISH_TOOL)


def _json_objects(text: str) -> list[str]:
    """Every balanced `{...}` span in text (outermost first per start), honoring JSON strings."""
    spans = []
    start = text.find("{")
    while start != -1:
        depth, in_str, escaped = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    spans.append(text[start : i + 1])
                    break
        start = text.find("{", start + 1)
    return spans


def parse_action(text: str, tool_names: set[str]) -> Action:
    """Extract and validate one `{"tool": str, "args": dict}` action from a model reply.
    The first JSON object with a "tool" key wins; prose and code fences around it are ignored."""
    fenced = _FENCE_RE.search(text)
    candidates = _json_objects(fenced.group(1) if fenced else text)
    if not candidates:
        raise ActionParseError("no JSON object found")
    obj: Any = None
    first_error = ""
    for cand in candidates:
        try:
            parsed = json.loads(cand)
        except json.JSONDecodeError as exc:
            first_error = first_error or f"invalid JSON: {exc.msg}"
            continue
        if isinstance(parsed, dict) and "tool" in parsed:
            obj = parsed
            break
        first_error = first_error or 'missing string field "tool"'
    if obj is None:
        raise ActionParseError(first_error)
    tool = obj["tool"]
    if not isinstance(tool, str):
        raise ActionParseError('missing string field "tool"')
    if tool not in tool_names and tool != FINISH_TOOL:
        raise ActionParseError(f"unknown tool {tool!r}")
    args = obj.get("args") or {}
    if not isinstance(args, dict):
        raise ActionParseError('"args" must be a JSON object')
    return {"tool": tool, "args": args}


@dataclass
class AgentResult:
    trace: list[TraceStep]
    stop_reason: StopReason
    summary: str = ""
    backend: str = ""
    messages: list[Message] = field(default_factory=list)


@dataclass
class ReactAgent:
    backend: ChatBackend
    tools: list[ToolSpec]
    max_turns: int = 12
    max_parse_retries: int = 2
    task: str = "Investigate current traffic anomalies and safely mitigate any attack."

    async def run(self, call_tool: CallTool) -> AgentResult:
        names = {t.name for t in self.tools}
        messages: list[Message] = [
            {"role": "system", "content": build_system_prompt(self.tools)},
            {"role": "user", "content": self.task},
        ]
        trace: list[TraceStep] = []
        result = AgentResult(trace, "max_turns", backend=self.backend.name, messages=messages)

        for _ in range(self.max_turns):
            action = await self._next_action(messages, names)
            if isinstance(action, str):  # a stop reason
                result.stop_reason = action  # type: ignore[assignment]
                return result
            if action["tool"] == FINISH_TOOL:
                result.stop_reason = "finished"
                result.summary = str(action["args"].get("summary", ""))
                return result
            try:
                output, is_error = await call_tool(action["tool"], action["args"]), False
            except ToolCallError as exc:
                output, is_error = str(exc), True
            trace.append(TraceStep(action["tool"], action["args"], output, is_error))
            label = "Error from" if is_error else "Output of"
            messages.append({"role": "user", "content": f"{label} {action['tool']}:\n{output}"})
        return result

    async def _next_action(self, messages: list[Message], names: set[str]) -> Action | str:
        """Generate and parse the next action, retrying malformed replies. Returns a stop
        reason string when the backend fails or retries run out."""
        for attempt in range(self.max_parse_retries + 1):
            try:
                reply = await asyncio.to_thread(self.backend.generate, list(messages))
            except Exception:  # noqa: BLE001 - surfaced as a stop reason
                return "backend_error"
            messages.append({"role": "assistant", "content": reply})
            try:
                return parse_action(reply, names)
            except ActionParseError as exc:
                if attempt == self.max_parse_retries:
                    return "parse_error"
                messages.append(
                    {
                        "role": "user",
                        "content": f"Invalid reply ({exc}). Reply with exactly one JSON "
                        'object: {"tool": "<name>", "args": {...}}.',
                    }
                )
        return "parse_error"


async def list_tool_specs(client: Any) -> list[ToolSpec]:
    tools = (await client.list_tools()).tools
    return [ToolSpec(t.name, t.description or "", dict(t.input_schema)) for t in tools]


async def run_agent(client: Any, backend: ChatBackend | None, max_turns: int = 12) -> AgentResult:
    """Run the LLM loop against a connected `mcp.Client`. With no backend, or if the backend
    fails before any tool ran, the canonical replay runs instead."""
    call = mcp_call_tool(client)
    if backend is not None:
        agent = ReactAgent(backend, await list_tool_specs(client), max_turns=max_turns)
        result = await agent.run(call)
        if not (result.stop_reason == "backend_error" and not result.trace):
            return result
    trace = await ReplayAgent("canonical").run(call)
    return AgentResult(trace, "replay", backend="replay")


async def run_over_stdio(
    backend: ChatBackend | None = None,
    load: bool = True,
    reset: bool = True,
    env: dict[str, str] | None = None,
    max_turns: int = 12,
) -> AgentResult:
    """Spawn the MCP server over stdio and run the agent; loads the GPU-tier backend when
    `backend` is None and `load` is True."""
    import sys

    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    if backend is None and load:
        backend, _ = load_backend()
    args = ["-m", "sdn_guardian.mcp_server"] + (["--reset"] if reset else [])
    params = StdioServerParameters(command=sys.executable, args=args, env=server_env(env))
    async with Client(params) as client:
        return await run_agent(client, backend, max_turns)
