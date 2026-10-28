"""Domain models shared by the state store, adapters and engines."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from enum import Enum
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ANY_CIDR = "0.0.0.0/0"


class Protocol(str, Enum):
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class FlowRule(BaseModel):
    """One flow/ACL entry. Higher `priority` wins (OpenFlow semantics)."""

    model_config = ConfigDict(frozen=True)

    rule_id: int = Field(ge=1)
    priority: int = Field(ge=0, le=65535)
    src_cidr: str = ANY_CIDR
    dst_cidr: str = ANY_CIDR
    protocol: Protocol = Protocol.ANY
    dst_port_range: tuple[int, int] | None = None
    action: Action

    @field_validator("src_cidr", "dst_cidr")
    @classmethod
    def _normalize_cidr(cls, v: str) -> str:
        v = v.strip()
        if v.lower() == "any":
            return ANY_CIDR
        return str(IPv4Network(v, strict=False))

    @field_validator("dst_port_range", mode="before")
    @classmethod
    def _coerce_ports(cls, v: object) -> object:
        if isinstance(v, int):
            return (v, v)
        if isinstance(v, str):
            if v.strip().lower() in ("", "any"):  # like dst_cidr/protocol "any": all ports
                return None
            lo, _, hi = v.partition("-")
            return (int(lo), int(hi or lo))
        return v

    @model_validator(mode="after")
    def _check_ports(self) -> FlowRule:
        if self.dst_port_range is None:
            return self
        lo, hi = self.dst_port_range
        if not (0 <= lo <= hi <= 65535):
            raise ValueError(f"invalid dst_port_range {self.dst_port_range}")
        if self.protocol not in (Protocol.TCP, Protocol.UDP):
            raise ValueError(
                "dst_port_range requires protocol tcp or udp; omit dst_port_range to match "
                "all ports"
            )
        return self

    @property
    def src_net(self) -> IPv4Network:
        return IPv4Network(self.src_cidr)

    @property
    def dst_net(self) -> IPv4Network:
        return IPv4Network(self.dst_cidr)

    def normalized(self) -> dict[str, object]:
        """Canonical, order-stable form used for hashing and comparison."""
        return {
            "rule_id": self.rule_id,
            "priority": self.priority,
            "src_cidr": self.src_cidr,
            "dst_cidr": self.dst_cidr,
            "protocol": self.protocol.value,
            "dst_port_range": list(self.dst_port_range) if self.dst_port_range else None,
            "action": self.action.value,
        }

    def fingerprint(self) -> str:
        """sha256 of the normalized rule."""
        blob = json.dumps(self.normalized(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def matches(self, packet: Packet) -> bool:
        if packet.src_ip not in self.src_net or packet.dst_ip not in self.dst_net:
            return False
        if self.protocol is not Protocol.ANY and packet.protocol is not self.protocol:
            return False
        if self.dst_port_range is not None:
            if packet.dst_port is None:
                return False
            lo, hi = self.dst_port_range
            return lo <= packet.dst_port <= hi
        return True

    def describe(self) -> str:
        ports = ""
        if self.dst_port_range:
            lo, hi = self.dst_port_range
            ports = f" port {lo}" if lo == hi else f" ports {lo}-{hi}"
        return (
            f"#{self.rule_id} prio {self.priority} {self.action.value.upper()} "
            f"{self.protocol.value} {self.src_cidr} -> {self.dst_cidr}{ports}"
        )


class Packet(BaseModel):
    """A single flow probe used for rule evaluation and health checks."""

    model_config = ConfigDict(frozen=True)

    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Protocol = Protocol.TCP
    dst_port: int | None = None


def sort_by_precedence(rules: Iterable[FlowRule]) -> list[FlowRule]:
    """Highest priority first; ties broken by lower rule_id."""
    return sorted(rules, key=lambda r: (-r.priority, r.rule_id))


def first_match(rules: Iterable[FlowRule], packet: Packet) -> FlowRule | None:
    for rule in sort_by_precedence(rules):
        if rule.matches(packet):
            return rule
    return None


def table_fingerprint(rules: Iterable[FlowRule]) -> str:
    blob = json.dumps(
        [r.normalized() for r in sorted(rules, key=lambda r: r.rule_id)],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode()).hexdigest()


class FlowTableSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: int
    rules: tuple[FlowRule, ...]

    @property
    def fingerprint(self) -> str:
        return table_fingerprint(self.rules)


class InterfaceState(BaseModel):
    """Switchport state, used both for Source of Truth and live state."""

    model_config = ConfigDict(frozen=True)

    name: str
    vlan: int = Field(ge=1, le=4094)
    enabled: bool = True
    description: str = ""


class TelemetrySample(BaseModel):
    model_config = ConfigDict(frozen=True)

    ts: float
    interface: str
    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Protocol
    dst_port: int | None = None
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)
    syn: int = Field(default=0, ge=0)
    syn_ack: int = Field(default=0, ge=0)


class CheckResult(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class HealthReport(BaseModel):
    checks: list[CheckResult]

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.ok]


class CommitStatus(str, Enum):
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class CommitRecord(BaseModel):
    commit_id: str
    simulation_id: str | None
    rule: FlowRule
    snapshot: FlowTableSnapshot
    status: CommitStatus
    created_at: float
    expires_at: float
    resolved_at: float | None = None
    detail: str = ""


class SimulationRecord(BaseModel):
    simulation_id: str
    rule: FlowRule
    rule_hash: str
    flow_table_version: int
    verdict: str
    report: str
    created_at: float
