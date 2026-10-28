"""SQLite-backed SDN emulator. Works offline (local, CI, Colab)."""

from __future__ import annotations

import time
from ipaddress import IPv4Address, IPv4Network

from ..models import FlowRule, FlowTableSnapshot, InterfaceState, TelemetrySample
from ..state import StateStore
from .base_adapter import SDNAdapter


class MockSDNAdapter(SDNAdapter):
    name = "mock"

    def __init__(
        self,
        store: StateStore,
        controller_ip: IPv4Address | str = "10.10.10.10",
        protected_subnets: tuple[IPv4Network, ...] = (IPv4Network("10.10.10.0/24"),),
    ) -> None:
        super().__init__(controller_ip, protected_subnets)
        self.store = store

    async def get_flow_rules(self) -> list[FlowRule]:
        return self.store.get_flow_rules()

    async def get_flow_table_version(self) -> int:
        return self.store.flow_table_version()

    async def snapshot(self) -> FlowTableSnapshot:
        return self.store.snapshot()

    async def get_interfaces(self) -> list[InterfaceState]:
        return self.store.get_live_interfaces()

    async def get_telemetry(self, window_s: int = 60) -> list[TelemetrySample]:
        return self.store.get_telemetry(since=time.time() - window_s)

    async def install_rule(self, rule: FlowRule, confirm_timeout_s: int | None = None) -> int:
        # The emulator has no device-side timer; the rollback manager owns the deadline.
        return self.store.add_flow_rule(rule)

    async def confirm(self) -> None:
        return None

    async def restore(self, snapshot: FlowTableSnapshot) -> int:
        return self.store.replace_flow_table(snapshot.rules)
