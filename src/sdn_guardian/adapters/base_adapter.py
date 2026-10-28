"""Adapter contract every network backend (mock emulator, Cisco IOS-XE) implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv4Network

from ..models import (
    Action,
    CheckResult,
    FlowRule,
    FlowTableSnapshot,
    HealthReport,
    InterfaceState,
    Packet,
    Protocol,
    TelemetrySample,
    first_match,
)

# Management ports the controller must keep reaching: SSH, HTTPS/RESTCONF, NETCONF.
MGMT_PORTS: tuple[int, ...] = (22, 443, 830)


class SDNAdapter(ABC):
    """Async interface to a network device or emulator.

    Write semantics follow NETCONF confirmed-commit: `install_rule(..., confirm_timeout_s)`
    applies the rule provisionally, `confirm()` makes it permanent, and `restore(snapshot)`
    reverts the flow table to an earlier snapshot.
    """

    name: str = "base"

    def __init__(
        self,
        controller_ip: IPv4Address | str,
        protected_subnets: tuple[IPv4Network, ...],
    ) -> None:
        self.controller_ip = IPv4Address(str(controller_ip))
        self.protected_subnets = protected_subnets

    # -- reads --

    @abstractmethod
    async def get_flow_rules(self) -> list[FlowRule]: ...

    @abstractmethod
    async def get_flow_table_version(self) -> int: ...

    @abstractmethod
    async def snapshot(self) -> FlowTableSnapshot: ...

    @abstractmethod
    async def get_interfaces(self) -> list[InterfaceState]:
        """Live switchport state (compared against the Source of Truth for drift)."""

    @abstractmethod
    async def get_telemetry(self, window_s: int = 60) -> list[TelemetrySample]: ...

    # -- writes --

    @abstractmethod
    async def install_rule(self, rule: FlowRule, confirm_timeout_s: int | None = None) -> int:
        """Apply `rule`; returns the new flow-table version."""

    @abstractmethod
    async def confirm(self) -> None:
        """Make the provisionally installed change permanent (no-op where not applicable)."""

    @abstractmethod
    async def restore(self, snapshot: FlowTableSnapshot) -> int:
        """Revert the flow table to `snapshot`; returns the new flow-table version."""

    async def aclose(self) -> None:
        """Release connections (no-op by default)."""
        return None

    # -- health --

    async def health_check(self) -> HealthReport:
        """Default check: management traffic from protected subnets still reaches the controller."""
        rules = await self.get_flow_rules()
        return HealthReport(checks=self._mgmt_reachability_checks(rules))

    def _mgmt_reachability_checks(self, rules: list[FlowRule]) -> list[CheckResult]:
        checks: list[CheckResult] = []
        for subnet in self.protected_subnets:
            # Probe from a host in the subnet other than the controller itself when possible.
            src = next(
                (h for h in subnet.hosts() if h != self.controller_ip), subnet.network_address
            )
            for port in MGMT_PORTS:
                pkt = Packet(
                    src_ip=src, dst_ip=self.controller_ip, protocol=Protocol.TCP, dst_port=port
                )
                hit = first_match(rules, pkt)
                blocked = hit is not None and hit.action is Action.DENY
                checks.append(
                    CheckResult(
                        name=f"mgmt {src}->{self.controller_ip}:{port}",
                        ok=not blocked,
                        detail=f"blocked by {hit.describe()}" if blocked and hit else "reachable",
                    )
                )
        return checks
