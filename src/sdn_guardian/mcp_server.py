"""MCP server: exposes the Observe/Orient/Decide/Act tools over stdio.

Every tool returns compact Markdown. Safety is enforced below the tool layer:
`push_safe_sdn_policy` only takes a `simulation_id` (the rule is loaded from the stored PASS
simulation), and `confirm_commit` runs the health check itself.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from .adapters.base_adapter import SDNAdapter
from .adapters.cisco_iosxe_adapter import CiscoIOSXEAdapter
from .adapters.mock_sdn_adapter import MockSDNAdapter
from .config import Settings
from .engine.conflict_simulator import ConflictSimulator, SimulationRejected
from .engine.drift_detector import DriftDetector
from .engine.rollback_manager import CommitRejected, RollbackManager
from .engine.telemetry_summarizer import TelemetrySummarizer
from .models import CommitRecord, CommitStatus, FlowRule, sort_by_precedence
from .state import StateStore, demo_telemetry

log = logging.getLogger("sdn_guardian")

MAX_RULES_SHOWN = 12
MAX_TIMEOUT_S = 300

INSTRUCTIONS = (
    "SDN Guardian: closed-loop defense. Observe with get_traffic_anomalies and "
    "detect_network_drift, dry-run a fix with simulate_flow_impact, then "
    "push_safe_sdn_policy(simulation_id) and confirm_commit(commit_id) before the deadline. "
    "Only PASS simulations can be pushed; unconfirmed commits roll back automatically."
)


@dataclass
class Guardian:
    """All engines wired to one adapter and state store (the server's lifespan context)."""

    settings: Settings
    store: StateStore
    adapter: SDNAdapter
    telemetry: TelemetrySummarizer
    drift: DriftDetector
    simulator: ConflictSimulator
    rollback: RollbackManager

    @classmethod
    async def open(cls, settings: Settings, reset: bool = False) -> Guardian:
        store = StateStore(settings.db_path)
        adapter = _make_adapter(settings, store)
        if settings.mode == "mock":
            now = time.time()
            if not store.seed_demo_scenario(now=now, force=reset) and not store.get_telemetry(
                since=now - 60
            ):
                # The emulated attack is ongoing: refresh telemetry relative to "now".
                store.add_telemetry(demo_telemetry(now))
        simulator = ConflictSimulator(adapter, store)
        guardian = cls(
            settings=settings,
            store=store,
            adapter=adapter,
            telemetry=TelemetrySummarizer(adapter),
            drift=DriftDetector(adapter, store),
            simulator=simulator,
            rollback=RollbackManager(adapter, store, simulator, settings.commit_timeout_s),
        )
        for rec in await guardian.rollback.recover():
            log.warning("recover: %s is %s", rec.commit_id, rec.status.value)
        return guardian

    async def aclose(self) -> None:
        await self.rollback.aclose()
        await self.adapter.aclose()
        self.store.close()


def _make_adapter(settings: Settings, store: StateStore) -> SDNAdapter:
    if settings.mode == "mock":
        return MockSDNAdapter(store, settings.controller_ip, settings.protected_subnets)
    return CiscoIOSXEAdapter(
        settings.iosxe, store, settings.controller_ip, settings.protected_subnets
    )


# --- Markdown rendering -----------------------------------------------------------------------


def render_flow_table(rules: list[FlowRule], version: int) -> str:
    ordered = sort_by_precedence(rules)
    lines = [f"**Flow table v{version}: {len(ordered)} rules** (highest priority first)"]
    lines += [f"- {r.describe()}" for r in ordered[:MAX_RULES_SHOWN]]
    if len(ordered) > MAX_RULES_SHOWN:
        lines.append(f"- … {len(ordered) - MAX_RULES_SHOWN} more")
    return "\n".join(lines)


def render_commit(rec: CommitRecord, now: float | None = None) -> str:
    lines = [f"**Commit `{rec.commit_id}`: {rec.status.value}**", f"Rule: {rec.rule.describe()}"]
    if rec.status is CommitStatus.PENDING:
        left = max(0.0, rec.expires_at - (time.time() if now is None else now))
        lines.append(
            f"Auto-rollback in {left:.0f} s unless confirmed. "
            f"Next: confirm_commit(commit_id=`{rec.commit_id}`)"
        )
    elif rec.detail:
        lines.append(f"Detail: {rec.detail}")
    return "\n".join(lines)


# --- Server -----------------------------------------------------------------------------------


def create_server(settings: Settings | None = None, reset: bool = False) -> MCPServer[Guardian]:
    settings = settings or Settings.from_env()

    # Static resources get no Context, so every handler reads the lifespan's Guardian from here.
    live: list[Guardian] = []

    @asynccontextmanager
    async def lifespan(_: MCPServer[Guardian]) -> AsyncIterator[Guardian]:
        guardian = await Guardian.open(settings, reset=reset)
        live.append(guardian)
        try:
            yield guardian
        finally:
            live.remove(guardian)
            await guardian.aclose()

    mcp = MCPServer("sdn-guardian", instructions=INSTRUCTIONS, lifespan=lifespan)

    def g() -> Guardian:
        if not live:
            raise ToolError("Server is not initialized.")
        return live[-1]

    @mcp.tool(structured_output=False)
    async def get_traffic_anomalies(window_s: int = 60) -> str:
        """Summarize recent telemetry per source IP and flag SYN floods / high-rate sources."""
        if not 1 <= window_s <= 3600:
            raise ToolError("window_s must be between 1 and 3600.")
        return (await g().telemetry.summarize(window_s)).to_markdown()

    @mcp.tool(structured_output=False)
    async def detect_network_drift(interface: str | None = None) -> str:
        """Compare live switchport state (VLAN, enabled, description) with the Source of Truth."""
        return (await g().drift.detect(interface)).to_markdown()

    @mcp.tool(structured_output=False)
    async def simulate_flow_impact(
        src_cidr: str,
        action: Literal["allow", "deny"],
        priority: int,
        dst_cidr: str = "any",
        protocol: Literal["any", "tcp", "udp", "icmp"] = "any",
        dst_port_range: str | None = None,
    ) -> str:
        """Dry-run a candidate rule against the flow table. Returns PASS/FAIL, conflicts,
        a concrete fix on FAIL, and the simulation_id needed to push. Higher priority wins."""
        guardian = g()
        try:
            rule = FlowRule(
                rule_id=await guardian.simulator.next_rule_id(),
                priority=priority,
                src_cidr=src_cidr,
                dst_cidr=dst_cidr,
                protocol=protocol,
                dst_port_range=dst_port_range,
                action=action,
            )
        except (ValidationError, ValueError) as exc:
            raise ToolError(f"Invalid rule: {_first_error(exc)}") from None
        record, _ = await guardian.simulator.simulate(rule)
        return record.report

    @mcp.tool(structured_output=False)
    async def push_safe_sdn_policy(simulation_id: str, timeout_s: int | None = None) -> str:
        """Install the rule of a PASS simulation provisionally. It rolls back automatically
        unless confirm_commit is called within timeout_s (default from settings)."""
        if timeout_s is not None and not 1 <= timeout_s <= MAX_TIMEOUT_S:
            raise ToolError(f"timeout_s must be between 1 and {MAX_TIMEOUT_S}.")
        try:
            rec = await g().rollback.push(simulation_id, timeout_s)
        except (SimulationRejected, CommitRejected) as exc:
            raise ToolError(f"Push rejected: {exc}") from None
        return render_commit(rec)

    @mcp.tool(structured_output=False)
    async def confirm_commit(commit_id: str) -> str:
        """Run the health check; make the commit permanent if healthy, otherwise roll back."""
        try:
            rec = await g().rollback.confirm(commit_id)
        except CommitRejected as exc:
            raise ToolError(f"Confirm rejected: {exc}") from None
        return render_commit(rec)

    @mcp.tool(structured_output=False)
    async def get_commit_status(commit_id: str) -> str:
        """Show a commit's status (PENDING, COMMITTED, ROLLED_BACK, FAILED)."""
        try:
            return render_commit(g().rollback.status(commit_id))
        except CommitRejected as exc:
            raise ToolError(str(exc)) from None

    @mcp.tool(structured_output=False)
    async def list_flow_rules() -> str:
        """List the current flow table, highest priority first."""
        snap = await g().adapter.snapshot()
        return render_flow_table(list(snap.rules), snap.version)

    @mcp.resource("sdn://flows", name="flows", mime_type="text/markdown")
    async def flows_resource() -> str:
        """The current flow table as Markdown."""
        snap = await g().adapter.snapshot()
        return render_flow_table(list(snap.rules), snap.version)

    return mcp


def _first_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        err = exc.errors()[0]
        loc = ".".join(str(p) for p in err.get("loc", ()))
        return f"{loc}: {err['msg']}" if loc else err["msg"]
    return str(exc)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sdn-guardian-mcp", description=__doc__)
    parser.add_argument("--reset", action="store_true", help="re-seed the mock demo scenario")
    args = parser.parse_args(argv)
    # stdout carries the MCP protocol; logs go to stderr.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    create_server(reset=args.reset).run("stdio")


if __name__ == "__main__":
    main()
