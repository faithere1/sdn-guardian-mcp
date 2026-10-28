"""Orient: compare live switchport state against the Source of Truth.

Reports per-field differences (VLAN, admin state, description) plus interfaces that exist
only on one side. VLAN and admin-state drift are high severity because they move traffic
out of the scope that the policy was written for.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..adapters.base_adapter import SDNAdapter
from ..models import InterfaceState
from ..state import StateStore

MAX_DRIFTS_SHOWN = 10
_HIGH_FIELDS = {"vlan", "enabled", "presence"}


@dataclass(frozen=True)
class Drift:
    interface: str
    field: str  # "vlan" | "enabled" | "description" | "presence"
    expected: str
    actual: str

    @property
    def severity(self) -> str:
        return "high" if self.field in _HIGH_FIELDS else "low"

    def describe(self) -> str:
        if self.field == "presence":
            return f"{self.interface}: {self.expected} in SoT, {self.actual} live"
        return f"{self.interface}: {self.field} SoT {self.expected}, live {self.actual}"


@dataclass
class DriftReport:
    checked: int
    drifts: list[Drift]
    interface: str | None = None

    @property
    def ok(self) -> bool:
        return not self.drifts

    def to_markdown(self) -> str:
        scope = f"`{self.interface}`" if self.interface else f"{self.checked} interfaces"
        if self.ok:
            return f"**Drift: none** ({scope} match the Source of Truth)"
        n = len({d.interface for d in self.drifts})
        lines = [f"**Drift: {n} interface(s) differ from Source of Truth** (checked {scope})"]
        ordered = sorted(self.drifts, key=lambda d: (d.severity != "high", d.interface))
        for d in ordered[:MAX_DRIFTS_SHOWN]:
            lines.append(f"- {d.severity.upper()} {d.describe()}")
        if len(ordered) > MAX_DRIFTS_SHOWN:
            lines.append(f"- … {len(ordered) - MAX_DRIFTS_SHOWN} more")
        vlan = [d for d in self.drifts if d.field == "vlan"]
        if vlan:
            lines.append(
                "Impact: VLAN-scoped policy may not apply on "
                + ", ".join(f"{d.interface} (VLAN {d.actual})" for d in vlan[:3])
                + "; prefer IP-based rules and reconcile the port config."
            )
        return "\n".join(lines)


def detect_drift(
    sot: Iterable[InterfaceState],
    live: Iterable[InterfaceState],
    interface: str | None = None,
) -> DriftReport:
    """Pure diff of SoT vs live. `interface` limits the check to one port."""
    want = {i.name: i for i in sot}
    have = {i.name: i for i in live}
    names = sorted(want.keys() | have.keys())
    if interface is not None:
        names = [n for n in names if n == interface]
    drifts: list[Drift] = []
    for name in names:
        exp, act = want.get(name), have.get(name)
        if exp is None:
            drifts.append(Drift(name, "presence", "absent", "present"))
            continue
        if act is None:
            drifts.append(Drift(name, "presence", "present", "absent"))
            continue
        for fld in ("vlan", "enabled", "description"):
            a, b = getattr(exp, fld), getattr(act, fld)
            if a != b:
                drifts.append(Drift(name, fld, str(a), str(b)))
    return DriftReport(checked=len(names), drifts=drifts, interface=interface)


class DriftDetector:
    def __init__(self, adapter: SDNAdapter, store: StateStore) -> None:
        self.adapter = adapter
        self.store = store

    async def detect(self, interface: str | None = None) -> DriftReport:
        live = await self.adapter.get_interfaces()
        return detect_drift(self.store.get_sot_interfaces(), live, interface)
