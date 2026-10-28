import time

import pytest

from sdn_guardian.adapters.mock_sdn_adapter import MockSDNAdapter
from sdn_guardian.engine.drift_detector import DriftDetector, detect_drift
from sdn_guardian.engine.telemetry_summarizer import (
    MAX_ANOMALIES_SHOWN,
    AnomalyType,
    TelemetrySummarizer,
    summarize,
)
from sdn_guardian.models import InterfaceState, Protocol, TelemetrySample
from sdn_guardian.state import (
    DEMO_ATTACK_INTERFACE,
    DEMO_ATTACKER_IP,
    DEMO_LIVE_INTERFACES,
    DEMO_SOT_INTERFACES,
    StateStore,
    demo_telemetry,
)

MAX_LINES = 15


@pytest.fixture
def store() -> StateStore:
    s = StateStore(":memory:")
    s.seed_demo_scenario(now=time.time())
    yield s
    s.close()


def _sample(src: str, packets: int, syn: int = 0, syn_ack: int = 0) -> TelemetrySample:
    return TelemetrySample(
        ts=0.0, interface="GigabitEthernet0/9", src_ip=src, dst_ip="10.10.40.5",
        protocol=Protocol.TCP, dst_port=80, packets=packets, bytes=packets * 60,
        syn=syn, syn_ack=syn_ack,
    )  # fmt: skip


# --- telemetry ---


def test_demo_syn_flood_is_the_only_anomaly() -> None:
    summary = summarize(demo_telemetry(now=1_000_000.0), window_s=60)
    assert [a.src_ip for a in summary.anomalies] == [DEMO_ATTACKER_IP]
    a = summary.anomalies[0]
    assert a.type is AnomalyType.SYN_FLOOD
    assert a.severity == "critical"
    assert a.interface == DEMO_ATTACK_INTERFACE
    assert a.target == "10.10.10.10 tcp/443"
    assert a.pps == pytest.approx(4800)
    assert a.share > 0.95


def test_demo_markdown_is_compact_and_points_to_next_step() -> None:
    md = summarize(demo_telemetry(now=1_000_000.0), window_s=60).to_markdown()
    assert len(md.splitlines()) <= MAX_LINES
    assert "SYN_FLOOD 10.10.20.45 on GigabitEthernet0/2" in md
    assert "detect_network_drift(interface=`GigabitEthernet0/2`)" in md
    assert "10.10.20.45/32" in md
    assert "{" not in md  # no raw JSON


def test_high_rate_without_syn_imbalance() -> None:
    summary = summarize([_sample("10.10.30.7", packets=120_000, syn=50, syn_ack=50)], 60)
    assert [a.type for a in summary.anomalies] == [AnomalyType.HIGH_RATE]


def test_balanced_baseline_has_no_anomalies() -> None:
    summary = summarize([_sample("10.10.30.7", 600, syn=10, syn_ack=10)], 60)
    assert summary.anomalies == []
    assert "No anomalies" in summary.to_markdown()


def test_empty_window() -> None:
    md = summarize([], 60).to_markdown()
    assert "No telemetry" in md


def test_many_anomalies_stay_within_line_budget() -> None:
    samples = [_sample(f"10.0.0.{i}", 600_000, syn=500_000, syn_ack=10) for i in range(1, 40)]
    summary = summarize(samples, 60)
    assert len(summary.anomalies) == 39
    md = summary.to_markdown()
    assert len(md.splitlines()) <= MAX_LINES
    assert f"… {39 - MAX_ANOMALIES_SHOWN} more" in md


def test_invalid_window() -> None:
    with pytest.raises(ValueError):
        summarize([], 0)


async def test_summarizer_reads_from_adapter(store: StateStore) -> None:
    summary = await TelemetrySummarizer(MockSDNAdapter(store)).summarize(60)
    assert summary.sample_count > 0
    assert summary.anomalies[0].src_ip == DEMO_ATTACKER_IP


# --- drift ---


def test_demo_drift_on_gi0_2() -> None:
    report = detect_drift(DEMO_SOT_INTERFACES, DEMO_LIVE_INTERFACES)
    assert report.checked == 3
    assert [(d.interface, d.field, d.expected, d.actual) for d in report.drifts] == [
        ("GigabitEthernet0/2", "vlan", "20", "99")
    ]
    md = report.to_markdown()
    assert len(md.splitlines()) <= MAX_LINES
    assert "HIGH GigabitEthernet0/2: vlan SoT 20, live 99" in md
    assert "VLAN 99" in md


def test_no_drift_when_equal() -> None:
    report = detect_drift(DEMO_SOT_INTERFACES, DEMO_SOT_INTERFACES)
    assert report.ok
    assert "none" in report.to_markdown()


def test_filter_to_one_interface() -> None:
    report = detect_drift(DEMO_SOT_INTERFACES, DEMO_LIVE_INTERFACES, "GigabitEthernet0/1")
    assert report.checked == 1 and report.ok


def test_presence_enabled_and_description_drift() -> None:
    sot = [
        InterfaceState(name="Gi1", vlan=10),
        InterfaceState(name="Gi2", vlan=20, description="a"),
    ]
    live = [
        InterfaceState(name="Gi2", vlan=20, enabled=False, description="b"),
        InterfaceState(name="Gi3", vlan=30),
    ]
    found = {(d.interface, d.field, d.severity) for d in detect_drift(sot, live).drifts}
    assert found == {
        ("Gi1", "presence", "high"),
        ("Gi2", "enabled", "high"),
        ("Gi2", "description", "low"),
        ("Gi3", "presence", "high"),
    }


def test_many_drifts_stay_within_line_budget() -> None:
    sot = [InterfaceState(name=f"Gi{i}", vlan=10) for i in range(50)]
    live = [InterfaceState(name=f"Gi{i}", vlan=11) for i in range(50)]
    md = detect_drift(sot, live).to_markdown()
    assert len(md.splitlines()) <= MAX_LINES


async def test_detector_uses_store_sot_and_adapter_live(store: StateStore) -> None:
    report = await DriftDetector(MockSDNAdapter(store), store).detect()
    assert [d.interface for d in report.drifts] == ["GigabitEthernet0/2"]
