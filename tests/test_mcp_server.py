"""Phase 5: MCP server tools/resource, safety rejections, and the stdio end-to-end trace."""

from __future__ import annotations

import pytest
from mcp import Client

from sdn_guardian.agent.replay_agent import (
    COMMIT_ID_RE,
    SIM_ID_RE,
    ReplayAgent,
    mcp_call_tool,
    run_over_stdio,
)
from sdn_guardian.config import Settings
from sdn_guardian.mcp_server import create_server

EXPECTED_TOOLS = {
    "get_traffic_anomalies",
    "detect_network_drift",
    "simulate_flow_impact",
    "push_safe_sdn_policy",
    "confirm_commit",
    "get_commit_status",
    "list_flow_rules",
}


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "guardian.db"), commit_timeout_s=30)


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if c.type == "text")


async def test_tools_and_resource_are_registered(settings):
    async with Client(create_server(settings)) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert tools == EXPECTED_TOOLS
        resources = {str(r.uri) for r in (await client.list_resources()).resources}
        assert "sdn://flows" in resources
        res = await client.read_resource("sdn://flows")
        body = res.contents[0].text
        assert body.startswith("**Flow table v1: 3 rules**")
        assert "#10 prio 100 ALLOW" in body


async def test_push_rejects_fail_and_unknown_simulations(settings):
    async with Client(create_server(settings)) as client:
        sim = await client.call_tool(
            "simulate_flow_impact",
            {"src_cidr": "10.10.20.45/32", "action": "deny", "priority": 40},
        )
        assert "FAIL" in _text(sim) and "Minimum safe priority: 101" in _text(sim)
        sim_id = SIM_ID_RE.search(_text(sim)).group(1)

        push = await client.call_tool("push_safe_sdn_policy", {"simulation_id": sim_id})
        assert push.is_error and "only PASS can be pushed" in _text(push)

        push = await client.call_tool("push_safe_sdn_policy", {"simulation_id": "sim-nope"})
        assert push.is_error and "Unknown simulation" in _text(push)

        flows = await client.call_tool("list_flow_rules", {})
        assert "v1: 3 rules" in _text(flows)  # nothing was installed


async def test_mgmt_lockout_cannot_be_pushed(settings):
    async with Client(create_server(settings)) as client:
        sim = await client.call_tool(
            "simulate_flow_impact",
            {"src_cidr": "10.10.10.0/24", "action": "deny", "priority": 2000},
        )
        text = _text(sim)
        assert "FAIL" in text and "MGMT_LOCKOUT" in text
        push = await client.call_tool(
            "push_safe_sdn_policy", {"simulation_id": SIM_ID_RE.search(text).group(1)}
        )
        assert push.is_error


async def test_invalid_input_is_a_tool_error(settings):
    async with Client(create_server(settings)) as client:
        bad = await client.call_tool(
            "simulate_flow_impact",
            {"src_cidr": "10.10.20.0/24", "action": "deny", "priority": 150,
             "dst_port_range": "22"},
        )  # fmt: skip
        assert bad.is_error and "Invalid rule" in _text(bad)
        bad = await client.call_tool("confirm_commit", {"commit_id": "commit-nope"})
        assert bad.is_error and "Unknown commit" in _text(bad)
        bad = await client.call_tool("push_safe_sdn_policy", {"simulation_id": "x", "timeout_s": 0})
        assert bad.is_error


async def test_second_push_rejected_while_pending(settings):
    async with Client(create_server(settings)) as client:
        call = mcp_call_tool(client)
        ids = []
        for prio in (150, 160):
            out = await call(
                "simulate_flow_impact",
                {"src_cidr": "10.10.20.45/32", "action": "deny", "priority": prio},
            )
            ids.append(SIM_ID_RE.search(out).group(1))
        first = await call("push_safe_sdn_policy", {"simulation_id": ids[0]})
        assert "PENDING" in first
        second = await client.call_tool("push_safe_sdn_policy", {"simulation_id": ids[1]})
        assert second.is_error and "still PENDING" in _text(second)
        commit_id = COMMIT_ID_RE.search(first).group(1)
        assert "COMMITTED" in await call("confirm_commit", {"commit_id": commit_id})


async def test_bonus_rollback_in_process(settings):
    async with Client(create_server(settings)) as client:
        trace = await ReplayAgent("bonus", bonus_timeout_s=1).run(mcp_call_tool(client))
    before, after = trace[0].output, trace[-1].output
    assert "ROLLED_BACK" in trace[4].output
    assert "not confirmed before the deadline" in trace[4].output
    # Same rules as before the push (only the version counter moved).
    assert before.splitlines()[1:] == after.splitlines()[1:]


async def test_stdio_end_to_end_canonical_trace(tmp_path):
    env = {"SDN_GUARDIAN_DB": str(tmp_path / "e2e.db"), "SDN_GUARDIAN_MODE": "mock"}
    trace = await run_over_stdio("canonical", reset=True, env=env)

    assert [s.tool for s in trace] == [
        "get_traffic_anomalies",
        "detect_network_drift",
        "simulate_flow_impact",
        "simulate_flow_impact",
        "push_safe_sdn_policy",
        "confirm_commit",
    ]
    assert not any(s.is_error for s in trace)
    anomalies, drift, shadowed, passed, push, confirm = (s.output for s in trace)
    assert "SYN_FLOOD 10.10.20.45 on GigabitEthernet0/2" in anomalies
    assert "vlan SoT 20, live 99" in drift
    assert trace[2].args["priority"] == 40
    assert "FAIL" in shadowed and "SHADOWED" in shadowed and "#10 prio 100" in shadowed
    assert "Minimum safe priority: 101" in shadowed
    assert trace[3].args["priority"] == 150 and ": PASS**" in passed
    assert trace[4].args["simulation_id"] == SIM_ID_RE.search(passed).group(1)
    assert "PENDING" in push and "Auto-rollback in 30 s" in push
    assert trace[5].args["commit_id"] == COMMIT_ID_RE.search(push).group(1)
    assert "COMMITTED" in confirm and "health check passed" in confirm
    assert all(len(s.output.splitlines()) <= 15 for s in trace)

    # A second process sees the persisted, committed rule (state survives restarts).
    bonus = await run_over_stdio("bonus", reset=False, env=env, bonus_timeout_s=1)
    assert "#21 prio 150 DENY any 10.10.20.45/32" in bonus[0].output
    assert "ROLLED_BACK" in bonus[4].output
    assert bonus[0].output.splitlines()[1:] == bonus[-1].output.splitlines()[1:]
