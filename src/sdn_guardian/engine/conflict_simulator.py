"""Decide: dry-run a candidate rule against the current flow table and store the verdict.

Pairwise anomaly classification (after Al-Shaer & Hamed), adapted to "higher priority wins".
`E` is an existing rule, `N` the candidate; "E wins" means E has higher precedence on overlap.

| relation of N to E | same action                    | different action          |
|--------------------|--------------------------------|---------------------------|
| E wins, N <= E     | REDUNDANT (N adds nothing)     | SHADOWED (N never fires)  |
| E wins, N > E      | -                              | GENERALIZATION (info)     |
| N wins, N >= E     | REDUNDANT (E becomes dead)     | OVERRIDES (E becomes dead)|
| N wins, N < E      | REDUNDANT if nothing in between| GENERALIZATION (info)     |
| partial overlap    | -                              | CORRELATION               |

MGMT_LOCKOUT is checked separately: a DENY that becomes first match for management traffic
from a protected subnet to the controller. SHADOWED and MGMT_LOCKOUT fail the simulation;
everything else is reported but still PASSes.

Limitation: shadowing is detected per rule pair, so a candidate covered only by the union of
several higher rules is not reported as SHADOWED.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network

from ..adapters.base_adapter import MGMT_PORTS, SDNAdapter
from ..models import (
    Action,
    FlowRule,
    FlowTableSnapshot,
    Packet,
    Protocol,
    SimulationRecord,
    first_match,
)
from ..state import StateStore

MAX_PRIORITY = 65535
PASS = "PASS"
FAIL = "FAIL"


class ConflictType(str, Enum):
    SHADOWED = "SHADOWED"
    OVERRIDES = "OVERRIDES"
    GENERALIZATION = "GENERALIZATION"
    CORRELATION = "CORRELATION"
    REDUNDANT = "REDUNDANT"
    MGMT_LOCKOUT = "MGMT_LOCKOUT"


class Severity(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


SEVERITY: dict[ConflictType, Severity] = {
    ConflictType.SHADOWED: Severity.BLOCK,
    ConflictType.MGMT_LOCKOUT: Severity.BLOCK,
    ConflictType.OVERRIDES: Severity.WARN,
    ConflictType.CORRELATION: Severity.WARN,
    ConflictType.REDUNDANT: Severity.WARN,
    ConflictType.GENERALIZATION: Severity.INFO,
}


class Relation(str, Enum):
    DISJOINT = "disjoint"
    EQUAL = "equal"
    SUBSET = "subset"  # candidate strictly inside existing
    SUPERSET = "superset"  # candidate strictly contains existing
    PARTIAL = "partial"


@dataclass(frozen=True)
class Conflict:
    type: ConflictType
    other: FlowRule | None
    detail: str
    fix: str = ""

    @property
    def severity(self) -> Severity:
        return SEVERITY[self.type]


@dataclass(frozen=True)
class SimulationResult:
    rule: FlowRule
    flow_table_version: int
    conflicts: list[Conflict] = field(default_factory=list)
    min_safe_priority: int | None = None

    @property
    def verdict(self) -> str:
        return FAIL if any(c.severity is Severity.BLOCK for c in self.conflicts) else PASS

    def types(self) -> set[ConflictType]:
        return {c.type for c in self.conflicts}

    def to_markdown(self, simulation_id: str) -> str:
        lines = [
            f"**Simulation `{simulation_id}`: {self.verdict}**"
            f" (flow table v{self.flow_table_version})",
            f"Rule: {self.rule.describe()}",
        ]
        order = list(SEVERITY)
        shown = sorted(self.conflicts, key=lambda c: order.index(c.type))
        for c in shown[:8]:
            lines.append(f"- {c.type.value} ({c.severity.value}): {c.detail}")
        if len(shown) > 8:
            lines.append(f"- … {len(shown) - 8} more")
        if not self.conflicts:
            lines.append("- No conflicts with existing rules.")
        fixes = list(dict.fromkeys(c.fix for c in shown if c.fix and c.severity is Severity.BLOCK))
        for fix in fixes[:3]:
            lines.append(f"Fix: {fix}")
        if self.verdict == PASS:
            lines.append(f"Next: push_safe_sdn_policy(simulation_id=`{simulation_id}`)")
        return "\n".join(lines)


# --- match-space algebra ---------------------------------------------------------------------


def _net_rel(a: IPv4Network, b: IPv4Network) -> Relation:
    if a == b:
        return Relation.EQUAL
    if a.subnet_of(b):
        return Relation.SUBSET
    if a.supernet_of(b):
        return Relation.SUPERSET
    # Two CIDR blocks either nest or are disjoint.
    return Relation.DISJOINT


def _proto_rel(a: Protocol, b: Protocol) -> Relation:
    if a is b:
        return Relation.EQUAL
    if b is Protocol.ANY:
        return Relation.SUBSET
    if a is Protocol.ANY:
        return Relation.SUPERSET
    return Relation.DISJOINT


def _port_rel(a: tuple[int, int] | None, b: tuple[int, int] | None) -> Relation:
    # `None` means "any port, including port-less packets", so it contains every range.
    if a == b:
        return Relation.EQUAL
    if b is None:
        return Relation.SUBSET
    if a is None:
        return Relation.SUPERSET
    (alo, ahi), (blo, bhi) = a, b
    if ahi < blo or bhi < alo:
        return Relation.DISJOINT
    if blo <= alo and ahi <= bhi:
        return Relation.SUBSET
    if alo <= blo and bhi <= ahi:
        return Relation.SUPERSET
    return Relation.PARTIAL


def match_relation(a: FlowRule, b: FlowRule) -> Relation:
    """Relation of `a`'s match space to `b`'s, as a product over all header dimensions."""
    dims = [
        _net_rel(a.src_net, b.src_net),
        _net_rel(a.dst_net, b.dst_net),
        _proto_rel(a.protocol, b.protocol),
        _port_rel(a.dst_port_range, b.dst_port_range),
    ]
    if Relation.DISJOINT in dims:
        return Relation.DISJOINT
    has_sub = any(d in (Relation.SUBSET, Relation.PARTIAL) for d in dims)
    has_sup = any(d in (Relation.SUPERSET, Relation.PARTIAL) for d in dims)
    if has_sub and has_sup:
        return Relation.PARTIAL
    if has_sub:
        return Relation.SUBSET
    if has_sup:
        return Relation.SUPERSET
    return Relation.EQUAL


def _wins(a: FlowRule, b: FlowRule) -> bool:
    """True if `a` is evaluated before `b` (same order as `models.sort_by_precedence`)."""
    return (-a.priority, a.rule_id) < (-b.priority, b.rule_id)


# --- analysis ---------------------------------------------------------------------------------


def _pairwise(rule: FlowRule, rules: Sequence[FlowRule]) -> list[Conflict]:
    out: list[Conflict] = []
    for other in rules:
        rel = match_relation(rule, other)
        if rel is Relation.DISJOINT:
            continue
        same = rule.action is other.action
        o = other.describe()
        if _wins(other, rule):
            if rel in (Relation.EQUAL, Relation.SUBSET):
                if same:
                    out.append(Conflict(
                        ConflictType.REDUNDANT, other,
                        f"already enforced by {o}; the new rule never takes effect.",
                        f"Drop the rule; #{other.rule_id} already {other.action.value}s it.",
                    ))  # fmt: skip
                else:
                    out.append(Conflict(
                        ConflictType.SHADOWED, other,
                        f"fully covered by higher-precedence {o}; the new rule never matches.",
                        f"Minimum safe priority: {other.priority + 1}",
                    ))  # fmt: skip
            elif rel is Relation.SUPERSET and not same:
                out.append(Conflict(
                    ConflictType.GENERALIZATION, other,
                    f"{o} stays an exception inside the new, broader rule.",
                ))  # fmt: skip
            elif rel is Relation.PARTIAL and not same:
                out.append(Conflict(
                    ConflictType.CORRELATION, other,
                    f"partially overlaps {o}, which wins on the overlap.",
                    f"Priority {other.priority + 1}+ makes the new rule win the overlap.",
                ))  # fmt: skip
        else:
            if rel in (Relation.EQUAL, Relation.SUPERSET):
                if same:
                    out.append(Conflict(
                        ConflictType.REDUNDANT, other,
                        f"{o} becomes redundant (fully covered by the new rule).",
                    ))  # fmt: skip
                else:
                    out.append(Conflict(
                        ConflictType.OVERRIDES, other,
                        f"overrides {o} entirely; that rule will never match again.",
                    ))  # fmt: skip
            elif rel is Relation.SUBSET:
                if not same:
                    out.append(Conflict(
                        ConflictType.GENERALIZATION, other,
                        f"carves a {rule.action.value.upper()} exception out of {o}.",
                    ))  # fmt: skip
                elif not _conflicting_between(rule, other, rules):
                    out.append(Conflict(
                        ConflictType.REDUNDANT, other,
                        f"duplicates {o} for this traffic.",
                    ))  # fmt: skip
            elif not same:
                out.append(Conflict(
                    ConflictType.CORRELATION, other,
                    f"partially overlaps {o} and wins on the overlap.",
                ))  # fmt: skip
    return out


def _conflicting_between(rule: FlowRule, lower: FlowRule, rules: Sequence[FlowRule]) -> bool:
    """A rule ranked between `rule` and `lower` overlaps `rule` with a different action."""
    return any(
        _wins(r, lower)
        and not _wins(r, rule)
        and r.action is not rule.action
        and match_relation(rule, r) is not Relation.DISJOINT
        for r in rules
        if r is not lower
    )


def _representative_host(a: IPv4Network, b: IPv4Network, avoid: IPv4Address) -> IPv4Address:
    """A host inside the intersection of two overlapping CIDRs, preferring one != `avoid`."""
    net = a if a.prefixlen >= b.prefixlen else b
    if net.num_addresses <= 2:
        return net.network_address
    return next((h for h in net.hosts() if h != avoid), net.network_address)


def _lockout(
    rule: FlowRule,
    rules: Sequence[FlowRule],
    controller_ip: IPv4Address,
    protected_subnets: Sequence[IPv4Network],
) -> list[Conflict]:
    if rule.action is not Action.DENY or controller_ip not in rule.dst_net:
        return []
    candidate = [*rules, rule]
    out: list[Conflict] = []
    for subnet in protected_subnets:
        if not rule.src_net.overlaps(subnet):
            continue
        src = _representative_host(rule.src_net, subnet, controller_ip)
        blocked = []
        for port in MGMT_PORTS:
            pkt = Packet(src_ip=src, dst_ip=controller_ip, protocol=Protocol.TCP, dst_port=port)
            if first_match(candidate, pkt) == rule:
                blocked.append(str(port))
        if blocked:
            out.append(Conflict(
                ConflictType.MGMT_LOCKOUT, None,
                f"blocks management {src} -> {controller_ip} on tcp/{','.join(blocked)} "
                f"(protected subnet {subnet}).",
                f"Exclude protected subnet {subnet} from the rule's source.",
            ))  # fmt: skip
    return out


def analyze(
    rule: FlowRule,
    table: FlowTableSnapshot,
    controller_ip: IPv4Address | str,
    protected_subnets: Sequence[IPv4Network],
) -> SimulationResult:
    """Pure dry-run of `rule` against `table`. Does not touch the device or the store."""
    if any(r.rule_id == rule.rule_id for r in table.rules):
        raise ValueError(f"rule_id {rule.rule_id} already exists in the flow table")
    conflicts = _pairwise(rule, table.rules)
    conflicts += _lockout(rule, table.rules, IPv4Address(str(controller_ip)), protected_subnets)
    blockers = [c.other for c in conflicts if c.type is ConflictType.SHADOWED and c.other]
    min_safe = None
    if blockers:
        min_safe = max(r.priority for r in blockers) + 1
        if min_safe > MAX_PRIORITY:
            min_safe = None
    return SimulationResult(rule, table.version, conflicts, min_safe)


# --- simulator + simulation store -------------------------------------------------------------


class SimulationRejected(Exception):
    """A simulation cannot authorize a push (unknown, not PASS, or stale)."""


class ConflictSimulator:
    def __init__(self, adapter: SDNAdapter, store: StateStore) -> None:
        self.adapter = adapter
        self.store = store

    async def next_rule_id(self) -> int:
        rules = await self.adapter.get_flow_rules()
        return max((r.rule_id for r in rules), default=0) + 1

    async def simulate(self, rule: FlowRule) -> tuple[SimulationRecord, SimulationResult]:
        table = await self.adapter.snapshot()
        result = analyze(rule, table, self.adapter.controller_ip, self.adapter.protected_subnets)
        sim_id = f"sim-{uuid.uuid4().hex[:12]}"
        record = SimulationRecord(
            simulation_id=sim_id,
            rule=rule,
            rule_hash=rule.fingerprint(),
            flow_table_version=table.version,
            verdict=result.verdict,
            report=result.to_markdown(sim_id),
            created_at=time.time(),
        )
        self.store.save_simulation(record)
        return record, result

    async def load_pushable(self, simulation_id: str) -> SimulationRecord:
        """Return the stored simulation if it may authorize a push; else SimulationRejected."""
        sim = self.store.get_simulation(simulation_id)
        if sim is None:
            raise SimulationRejected(f"Unknown simulation `{simulation_id}`. Run simulate first.")
        if sim.verdict != PASS:
            raise SimulationRejected(
                f"Simulation `{simulation_id}` is {sim.verdict}; only PASS can be pushed."
            )
        if sim.rule.fingerprint() != sim.rule_hash:
            raise SimulationRejected(f"Simulation `{simulation_id}` rule hash mismatch.")
        current = await self.adapter.get_flow_table_version()
        if current != sim.flow_table_version:
            raise SimulationRejected(
                f"Simulation `{simulation_id}` is stale (flow table v{sim.flow_table_version}, "
                f"now v{current}). Re-run the simulation."
            )
        return sim
