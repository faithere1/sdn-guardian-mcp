"""Phase 7: GPU tier selection, action parser, and the ReAct loop driven by a fake LLM."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import pytest
from mcp import Client

from sdn_guardian.agent.llm_backend import GPUInfo, select_tier
from sdn_guardian.agent.react_loop import (
    FINISH_TOOL,
    ActionParseError,
    ReactAgent,
    ToolSpec,
    build_system_prompt,
    list_tool_specs,
    parse_action,
    run_agent,
    unsupported_claims,
)
from sdn_guardian.agent.replay_agent import TraceStep
from sdn_guardian.config import Settings
from sdn_guardian.mcp_server import create_server

TOOLS = {"get_traffic_anomalies", "simulate_flow_impact", "push_safe_sdn_policy"}

T4 = GPUInfo("Tesla T4", 14.7, (7, 5))
L4 = GPUInfo("NVIDIA L4", 22.0, (8, 9))
A100 = GPUInfo("NVIDIA A100-SXM4-40GB", 39.4, (8, 0))
SMALL = GPUInfo("Tiny GPU", 4.0, (7, 5))


# --- tier selection ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("requested", "gpu", "vllm", "tier"),
    [
        ("auto", None, False, "replay"),
        ("auto", T4, False, "4bit"),
        ("auto", L4, True, "bf16"),
        ("auto", A100, False, "bf16"),
        ("auto", A100, True, "vllm"),
        ("auto", SMALL, False, "replay"),
        ("replay", A100, True, "replay"),
        ("bf16", None, False, "replay"),
        ("4bit", A100, False, "4bit"),
        ("vllm", T4, False, "4bit"),  # vLLM missing -> auto
    ],
)
def test_select_tier(requested, gpu, vllm, tier):
    assert select_tier(requested, gpu, vllm_available=vllm).tier == tier


# --- parser -------------------------------------------------------------------------------


def test_parse_plain_json():
    a = parse_action('{"tool": "get_traffic_anomalies", "args": {"window_s": 60}}', TOOLS)
    assert a == {"tool": "get_traffic_anomalies", "args": {"window_s": 60}}


def test_parse_fenced_with_prose_and_braces_in_strings():
    text = (
        "Thought: the attacker {maybe} is 10.10.20.45.\n```json\n"
        '{"tool": "simulate_flow_impact", "args": {"src_cidr": "10.10.20.45/32", '
        '"action": "deny", "priority": 40, "note": "a } brace"}}\n```\nDone.'
    )
    a = parse_action(text, TOOLS)
    assert a["tool"] == "simulate_flow_impact" and a["args"]["note"] == "a } brace"


def test_parse_skips_non_json_brace_then_finds_action():
    a = parse_action('{oops} {"tool": "finish", "args": null}', TOOLS)
    assert a == {"tool": FINISH_TOOL, "args": {}}


@pytest.mark.parametrize(
    ("text", "msg"),
    [
        ("I will call a tool now.", "no JSON object"),
        ('{"tool": "get_traffic_anomalies", "args": {"window_s": 60}', '"tool"'),  # truncated
        ('{"tool": "rm_rf", "args": {}}', "unknown tool"),
        ('{"args": {}}', '"tool"'),
        ('{"tool": "push_safe_sdn_policy", "args": ["sim-1"]}', '"args"'),
        ("{'tool': 'finish'}", "invalid JSON"),
    ],
)
def test_parse_errors(text, msg):
    with pytest.raises(ActionParseError, match=re.escape(msg)):
        parse_action(text, TOOLS)


def test_system_prompt_lists_tool_signatures():
    spec = ToolSpec(
        "simulate_flow_impact",
        "Dry-run a rule.",
        {
            "properties": {
                "src_cidr": {"type": "string"},
                "action": {"enum": ["allow", "deny"]},
                "dst_port_range": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            },
            "required": ["src_cidr", "action"],
        },
    )
    prompt = build_system_prompt([spec])
    assert (
        '- simulate_flow_impact(src_cidr: string, action: "allow"|"deny", '
        "dst_port_range: string?): Dry-run a rule." in prompt
    )
    assert "- finish(summary: string)" in prompt


# --- loop with a fake LLM -------------------------------------------------------------------

Reply = str | Callable[[str], str]


class FakeLLM:
    """Scripted replies; a callable reply gets the full conversation text to read IDs from."""

    name = "fake"

    def __init__(self, replies: list[Reply]) -> None:
        self.replies = list(replies)
        self.calls = 0

    def generate(self, messages):
        self.calls += 1
        reply = self.replies.pop(0)
        if callable(reply):
            return reply("\n".join(m["content"] for m in messages))
        return reply


def act(tool: str, **args) -> str:
    return json.dumps({"tool": tool, "args": args})


def last_id(pattern: str) -> Callable[[str], str]:
    def pick(convo: str) -> str:
        return re.findall(pattern, convo)[-1]

    return pick


def canonical_replies() -> list[Reply]:
    sim = last_id(r"Simulation `(sim-[0-9a-f]+)`")
    commit = last_id(r"Commit `(commit-[0-9a-f]+)`")
    deny = {"src_cidr": "10.10.20.45/32", "action": "deny"}
    return [
        "Let me look first.\n" + act("get_traffic_anomalies", window_s=60),
        "```json\n" + act("detect_network_drift", interface="Gi0/2") + "\n```",
        act("simulate_flow_impact", priority=40, **deny),
        "not json at all",  # one malformed reply, retried
        act("simulate_flow_impact", priority=150, **deny),
        lambda c: act("push_safe_sdn_policy", simulation_id=sim(c), timeout_s=30),
        lambda c: act("confirm_commit", commit_id=commit(c)),
        act(FINISH_TOOL, summary="Attacker blocked at prio 150, committed."),
    ]


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "guardian.db"), commit_timeout_s=30)


async def test_react_loop_runs_canonical_trace(settings):
    llm = FakeLLM(canonical_replies())
    async with Client(create_server(settings)) as client:
        result = await run_agent(client, llm)
        flows = await client.call_tool("list_flow_rules", {})

    assert result.stop_reason == "finished" and result.backend == "fake"
    assert result.summary.startswith("Attacker blocked")
    assert result.summary_warnings == []
    assert [s.tool for s in result.trace] == [
        "get_traffic_anomalies",
        "detect_network_drift",
        "simulate_flow_impact",
        "simulate_flow_impact",
        "push_safe_sdn_policy",
        "confirm_commit",
    ]
    assert "SYN_FLOOD" in result.trace[0].output
    assert "Minimum safe priority: 101" in result.trace[2].output
    assert "PASS" in result.trace[3].output
    assert "COMMITTED" in result.trace[5].output
    assert not any(s.is_error for s in result.trace)
    assert any("Invalid reply (no JSON object" in m["content"] for m in result.messages)
    assert "prio 150 DENY" in "\n".join(c.text for c in flows.content)


async def test_tool_error_is_observed_and_model_recovers(settings):
    llm = FakeLLM(
        [
            act("push_safe_sdn_policy", simulation_id="sim-deadbeef"),
            act("list_flow_rules"),
            act(FINISH_TOOL, summary="nothing pushed"),
        ]
    )
    async with Client(create_server(settings)) as client:
        result = await run_agent(client, llm)
    assert result.stop_reason == "finished"
    assert result.trace[0].is_error and "Unknown simulation" in result.trace[0].output
    assert any(m["content"].startswith("Error from push_safe_sdn_policy") for m in result.messages)
    assert "v1: 3 rules" in result.trace[1].output


async def test_parse_retries_exhausted_stops():
    llm = FakeLLM(["nope", "still nope", "nope again"])
    calls = []

    async def call_tool(name, args):
        calls.append(name)
        return ""

    agent = ReactAgent(llm, [ToolSpec("list_flow_rules", "", {})], max_parse_retries=2)
    result = await agent.run(call_tool)
    assert result.stop_reason == "parse_error" and llm.calls == 3 and calls == []


async def test_max_turns_stops():
    llm = FakeLLM([act("list_flow_rules")] * 3)

    async def call_tool(name, args):
        return "ok"

    agent = ReactAgent(llm, [ToolSpec("list_flow_rules", "", {})], max_turns=3)
    result = await agent.run(call_tool)
    assert result.stop_reason == "max_turns" and len(result.trace) == 3


class BrokenLLM:
    name = "broken"

    def generate(self, messages):
        raise RuntimeError("CUDA out of memory")


async def test_backend_failure_falls_back_to_replay(settings):
    async with Client(create_server(settings)) as client:
        result = await run_agent(client, BrokenLLM())
    assert result.stop_reason == "replay" and result.backend == "replay"
    assert result.trace[-1].tool == "confirm_commit"
    assert "COMMITTED" in result.trace[-1].output


async def test_no_backend_runs_replay(settings):
    async with Client(create_server(settings)) as client:
        specs = await list_tool_specs(client)
        result = await run_agent(client, None)
    assert {s.name for s in specs} >= TOOLS
    assert result.stop_reason == "replay" and len(result.trace) == 6


# --- prompt guidance and summary grounding (Colab run 2) --------------------------------------


def test_system_prompt_steers_scope_timeout_and_honest_summary():
    prompt = build_system_prompt([])
    assert "ALL traffic from the attacker" in prompt
    assert '"args": {"src_cidr": "10.10.20.45/32", "action": "deny", "priority": 100}' in prompt
    assert "Do not send timeout_s" in prompt
    assert "never claim it was fixed" in prompt


COMMITTED_TRACE = [
    TraceStep("detect_network_drift", {}, "- HIGH GigabitEthernet0/2: vlan SoT 20, live 99"),
    TraceStep("confirm_commit", {}, "**Commit `commit-1`: COMMITTED**"),
]
ROLLED_BACK_TRACE = [TraceStep("get_commit_status", {}, "**Commit `commit-1`: ROLLED_BACK**")]

# The real summary from Colab run 2 (docs/COLAB_VALIDATION.md §6).
RUN2_SUMMARY = (
    "SYN flood from 10.10.20.45 mitigated successfully. VLAN drift on GigabitEthernet0/2 "
    "reconciled. Rule #21 priority 101 DENY applied and committed."
)


def test_run2_summary_flags_only_the_drift_claim():
    warnings = unsupported_claims(RUN2_SUMMARY, COMMITTED_TRACE)
    assert len(warnings) == 1
    assert "drift was only reported" in warnings[0] and "reconciled" in warnings[0]


@pytest.mark.parametrize(
    "summary",
    [
        "Attacker blocked at prio 150, committed.",
        "VLAN drift on Gi0/2 found (SoT 20, live 99); recommend reconciling the port.",
        "Drift is not fixed and needs a manual change.",
    ],
)
def test_grounded_summaries_pass(summary):
    assert unsupported_claims(summary, COMMITTED_TRACE) == []


def test_block_claim_without_commit_is_flagged():
    warnings = unsupported_claims("Attacker blocked.", ROLLED_BACK_TRACE)
    assert len(warnings) == 1 and "no confirm_commit returned COMMITTED" in warnings[0]


def test_empty_summary_is_flagged():
    assert unsupported_claims("  ", COMMITTED_TRACE) == ["No summary given."]
