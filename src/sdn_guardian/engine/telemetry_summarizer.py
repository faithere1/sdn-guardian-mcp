"""Observe: condense raw flow telemetry into a short list of per-source anomalies.

Samples are aggregated per source IP over the window. A source is flagged as:
- SYN_FLOOD when its SYN rate is high and few SYNs are answered (SYN:SYN-ACK ratio),
- HIGH_RATE when its packet rate is high without a SYN imbalance.
The Markdown output stays within ~15 lines regardless of how many samples come in.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from ..adapters.base_adapter import SDNAdapter
from ..models import TelemetrySample

SYN_RATE_THRESHOLD = 100.0  # SYN/s from one source
SYN_RATIO_THRESHOLD = 3.0  # SYN per answered SYN-ACK
HIGH_RATE_PPS = 1000.0  # packets/s from one source
CRITICAL_SYN_RATE = 1000.0
MAX_ANOMALIES_SHOWN = 5
MAX_TALKERS_SHOWN = 3


class AnomalyType(str, Enum):
    SYN_FLOOD = "SYN_FLOOD"
    HIGH_RATE = "HIGH_RATE"


@dataclass
class SourceStats:
    src_ip: str
    packets: int = 0
    bytes: int = 0
    syn: int = 0
    syn_ack: int = 0
    by_interface: Counter[str] = field(default_factory=Counter)
    by_target: Counter[str] = field(default_factory=Counter)

    def add(self, s: TelemetrySample) -> None:
        self.packets += s.packets
        self.bytes += s.bytes
        self.syn += s.syn
        self.syn_ack += s.syn_ack
        self.by_interface[s.interface] += s.packets
        port = f"/{s.dst_port}" if s.dst_port is not None else ""
        self.by_target[f"{s.dst_ip} {s.protocol.value}{port}"] += s.packets

    @property
    def interface(self) -> str:
        return self.by_interface.most_common(1)[0][0]

    @property
    def target(self) -> str:
        return self.by_target.most_common(1)[0][0]

    @property
    def syn_ratio(self) -> float:
        return self.syn / max(self.syn_ack, 1)


@dataclass(frozen=True)
class Anomaly:
    type: AnomalyType
    severity: str  # "critical" | "high"
    src_ip: str
    interface: str
    target: str
    pps: float
    syn_rate: float
    syn_ratio: float
    share: float  # fraction of all packets in the window

    def describe(self) -> str:
        head = f"{self.severity.upper()} {self.type.value} {self.src_ip} on {self.interface}"
        head += f" -> {self.target}"
        if self.type is AnomalyType.SYN_FLOOD:
            body = (
                f"{self.syn_rate:,.0f} SYN/s, SYN:SYN-ACK {self.syn_ratio:,.0f}:1, "
                f"{self.pps:,.0f} pps ({self.share:.0%} of packets)"
            )
        else:
            body = f"{self.pps:,.0f} pps ({self.share:.0%} of packets)"
        return f"{head}: {body}"


@dataclass
class TelemetrySummary:
    window_s: int
    sample_count: int
    sources: list[SourceStats]
    anomalies: list[Anomaly]

    @property
    def total_packets(self) -> int:
        return sum(s.packets for s in self.sources)

    def to_markdown(self) -> str:
        lines = [
            f"**Traffic anomalies (last {self.window_s} s, {self.sample_count} samples, "
            f"{len(self.sources)} sources): {len(self.anomalies)} found**"
        ]
        if not self.sample_count:
            lines.append("- No telemetry in this window.")
            return "\n".join(lines)
        for a in self.anomalies[:MAX_ANOMALIES_SHOWN]:
            lines.append(f"- {a.describe()}")
        if len(self.anomalies) > MAX_ANOMALIES_SHOWN:
            lines.append(f"- … {len(self.anomalies) - MAX_ANOMALIES_SHOWN} more")
        if not self.anomalies:
            lines.append("- No anomalies; traffic is within baseline thresholds.")
        talkers = sorted(self.sources, key=lambda s: -s.packets)[:MAX_TALKERS_SHOWN]
        lines.append(
            "Top talkers: "
            + " · ".join(f"{s.src_ip} {s.packets / self.window_s:,.0f} pps" for s in talkers)
        )
        if self.anomalies:
            top = self.anomalies[0]
            lines.append(
                f"Next: detect_network_drift(interface=`{top.interface}`), then "
                f"simulate_flow_impact with a DENY for {top.src_ip}/32."
            )
        return "\n".join(lines)


def summarize(samples: Iterable[TelemetrySample], window_s: int = 60) -> TelemetrySummary:
    """Pure aggregation + anomaly classification over one window of samples."""
    if window_s <= 0:
        raise ValueError("window_s must be > 0")
    stats: dict[str, SourceStats] = {}
    count = 0
    for s in samples:
        count += 1
        key = str(s.src_ip)
        stats.setdefault(key, SourceStats(key)).add(s)
    total = sum(st.packets for st in stats.values()) or 1

    anomalies: list[Anomaly] = []
    for st in stats.values():
        pps = st.packets / window_s
        syn_rate = st.syn / window_s
        if syn_rate >= SYN_RATE_THRESHOLD and st.syn_ratio >= SYN_RATIO_THRESHOLD:
            kind = AnomalyType.SYN_FLOOD
            severity = "critical" if syn_rate >= CRITICAL_SYN_RATE else "high"
        elif pps >= HIGH_RATE_PPS:
            kind, severity = AnomalyType.HIGH_RATE, "high"
        else:
            continue
        anomalies.append(Anomaly(
            kind, severity, st.src_ip, st.interface, st.target,
            pps, syn_rate, st.syn_ratio, st.packets / total,
        ))  # fmt: skip
    anomalies.sort(key=lambda a: (a.severity != "critical", -a.pps))
    return TelemetrySummary(window_s, count, list(stats.values()), anomalies)


class TelemetrySummarizer:
    def __init__(self, adapter: SDNAdapter) -> None:
        self.adapter = adapter

    async def summarize(self, window_s: int = 60) -> TelemetrySummary:
        samples = await self.adapter.get_telemetry(window_s)
        return summarize(samples, window_s)
