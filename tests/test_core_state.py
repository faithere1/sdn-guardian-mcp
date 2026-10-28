from ipaddress import IPv4Address, IPv4Network

import pytest
from pydantic import ValidationError

from sdn_guardian.adapters.mock_sdn_adapter import MockSDNAdapter
from sdn_guardian.config import Settings
from sdn_guardian.models import (
    Action,
    CommitRecord,
    CommitStatus,
    FlowRule,
    Packet,
    Protocol,
    SimulationRecord,
    first_match,
)
from sdn_guardian.state import DEMO_ATTACKER_IP, StateStore


@pytest.fixture
def store() -> StateStore:
    s = StateStore(":memory:")
    s.seed_demo_scenario(now=1_000_000.0)
    yield s
    s.close()


@pytest.fixture
def adapter(store: StateStore) -> MockSDNAdapter:
    return MockSDNAdapter(store)


def deny_host(rule_id: int, priority: int, cidr: str = f"{DEMO_ATTACKER_IP}/32") -> FlowRule:
    return FlowRule(rule_id=rule_id, priority=priority, src_cidr=cidr, action=Action.DENY)


# -- config --


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SDN_GUARDIAN_MODE", "mock")
    monkeypatch.setenv("SDN_GUARDIAN_COMMIT_TIMEOUT", "10")
    monkeypatch.setenv("SDN_GUARDIAN_PROTECTED_SUBNETS", "10.10.10.0/24, 192.168.0.1/16")
    monkeypatch.setenv("IOSXE_VERIFY_TLS", "true")
    s = Settings.from_env(dotenv=False)
    assert s.commit_timeout_s == 10
    assert s.protected_subnets == (IPv4Network("10.10.10.0/24"), IPv4Network("192.168.0.0/16"))
    assert s.controller_ip == IPv4Address("10.10.10.10")
    assert s.iosxe.verify_tls is True


def test_settings_rejects_bad_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SDN_GUARDIAN_MODE", "prod")
    with pytest.raises(ValueError):
        Settings.from_env(dotenv=False)


# -- models --


def test_flow_rule_normalization_and_fingerprint() -> None:
    a = FlowRule(rule_id=5, priority=10, src_cidr="10.10.20.45", dst_cidr="any",
                 protocol="tcp", dst_port_range=443, action="deny")  # fmt: skip
    b = FlowRule(rule_id=5, priority=10, src_cidr="10.10.20.45/32", dst_cidr="0.0.0.0/0",
                 protocol=Protocol.TCP, dst_port_range="443", action=Action.DENY)  # fmt: skip
    assert a == b
    assert a.fingerprint() == b.fingerprint()
    assert a.src_cidr == "10.10.20.45/32"
    assert a.fingerprint() != a.model_copy(update={"priority": 11}).fingerprint()


def test_flow_rule_validation() -> None:
    with pytest.raises(ValidationError):
        FlowRule(rule_id=1, priority=1, dst_port_range=(80, 80), action="allow")  # no protocol
    with pytest.raises(ValidationError):
        FlowRule(rule_id=1, priority=1, protocol="tcp", dst_port_range=(90, 80), action="allow")
    with pytest.raises(ValidationError):
        FlowRule(rule_id=1, priority=1, src_cidr="not-an-ip", action="allow")


def test_first_match_uses_highest_priority(store: StateStore) -> None:
    pkt = Packet(src_ip=DEMO_ATTACKER_IP, dst_ip="10.10.10.10", dst_port=443)
    rules = store.get_flow_rules()
    assert first_match(rules, pkt).rule_id == 10
    rules.append(deny_host(50, 40))
    assert first_match(rules, pkt).rule_id == 10  # shadowed by #10
    rules.append(deny_host(51, 150))
    assert first_match(rules, pkt).rule_id == 51


# -- seed --


def test_seed_demo_scenario(store: StateStore) -> None:
    rules = {r.rule_id: r for r in store.get_flow_rules()}
    trap = rules[10]
    assert (trap.src_cidr, trap.priority, trap.action) == ("10.10.20.0/24", 100, Action.ALLOW)

    sot = {i.name: i.vlan for i in store.get_sot_interfaces()}
    live = {i.name: i.vlan for i in store.get_live_interfaces()}
    assert sot["GigabitEthernet0/2"] == 20
    assert live["GigabitEthernet0/2"] == 99
    assert {k for k in sot if sot[k] != live[k]} == {"GigabitEthernet0/2"}

    attack = [s for s in store.get_telemetry() if str(s.src_ip) == DEMO_ATTACKER_IP]
    assert attack and all(s.interface == "GigabitEthernet0/2" for s in attack)
    assert all(s.syn > 100 * max(s.syn_ack, 1) for s in attack)


def test_seed_is_idempotent(store: StateStore) -> None:
    version = store.flow_table_version()
    n = len(store.get_telemetry())
    assert store.seed_demo_scenario() is False
    assert store.flow_table_version() == version
    assert len(store.get_telemetry()) == n
    assert store.seed_demo_scenario(force=True) is True
    assert len(store.get_telemetry()) == n


def test_state_persists_on_disk(tmp_path) -> None:
    path = tmp_path / "s.db"
    s = StateStore(path)
    s.seed_demo_scenario()
    s.add_flow_rule(deny_host(50, 150))
    version = s.flow_table_version()
    s.close()
    s2 = StateStore(path)
    assert s2.is_seeded()
    assert s2.flow_table_version() == version
    assert s2.get_flow_rule(50) is not None
    s2.close()


def test_flow_table_versioning(store: StateStore) -> None:
    v0 = store.flow_table_version()
    assert store.add_flow_rule(deny_host(50, 150)) == v0 + 1
    with pytest.raises(ValueError):
        store.add_flow_rule(deny_host(50, 150))
    assert store.flow_table_version() == v0 + 1
    assert store.remove_flow_rule(50) == v0 + 2
    assert store.next_rule_id() == 21


def test_simulation_and_commit_roundtrip(store: StateStore) -> None:
    rule = deny_host(50, 150)
    snap = store.snapshot()
    store.save_simulation(SimulationRecord(
        simulation_id="sim-1", rule=rule, rule_hash=rule.fingerprint(),
        flow_table_version=snap.version, verdict="PASS", report="ok", created_at=1.0,
    ))  # fmt: skip
    assert store.get_simulation("sim-1").rule == rule
    assert store.get_simulation("nope") is None

    store.save_commit(CommitRecord(
        commit_id="c-1", simulation_id="sim-1", rule=rule, snapshot=snap,
        status=CommitStatus.PENDING, created_at=1.0, expires_at=31.0,
    ))  # fmt: skip
    assert [c.commit_id for c in store.list_commits(CommitStatus.PENDING)] == ["c-1"]
    assert store.get_commit("c-1").snapshot == snap
    assert store.resolve_commit("c-1", CommitStatus.COMMITTED, "health OK") is True
    assert store.resolve_commit("c-1", CommitStatus.ROLLED_BACK) is False  # already resolved
    rec = store.get_commit("c-1")
    assert rec.status is CommitStatus.COMMITTED and rec.resolved_at is not None


# -- mock adapter --


async def test_adapter_reads(adapter: MockSDNAdapter, store: StateStore) -> None:
    assert await adapter.get_flow_rules() == store.get_flow_rules()
    assert await adapter.get_flow_table_version() == store.flow_table_version()
    assert {i.name: i.vlan for i in await adapter.get_interfaces()}["GigabitEthernet0/2"] == 99


async def test_adapter_telemetry_window(store: StateStore) -> None:
    fresh = StateStore(":memory:")
    fresh.seed_demo_scenario()  # timestamps relative to now
    adapter = MockSDNAdapter(fresh)
    assert len(await adapter.get_telemetry(window_s=120)) == len(fresh.get_telemetry())
    assert await MockSDNAdapter(store).get_telemetry(window_s=60) == []  # seeded long ago
    fresh.close()


async def test_adapter_install_and_restore_exact_snapshot(adapter: MockSDNAdapter) -> None:
    snap = await adapter.snapshot()
    v = await adapter.install_rule(deny_host(50, 150), confirm_timeout_s=30)
    assert v == snap.version + 1
    assert len(await adapter.get_flow_rules()) == len(snap.rules) + 1
    await adapter.confirm()
    v2 = await adapter.restore(snap)
    assert v2 > v
    after = await adapter.snapshot()
    assert after.rules == snap.rules
    assert after.fingerprint == snap.fingerprint


async def test_adapter_health_check(adapter: MockSDNAdapter) -> None:
    assert (await adapter.health_check()).ok
    # Bonus scenario: denying the management subnet above rule #1 locks out the controller.
    await adapter.install_rule(deny_host(60, 2000, cidr="10.10.10.0/24"))
    report = await adapter.health_check()
    assert not report.ok
    assert "#60" in report.failures()[0].detail
