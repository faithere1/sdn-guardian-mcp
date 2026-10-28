from ipaddress import IPv4Network

import pytest

from sdn_guardian.adapters.mock_sdn_adapter import MockSDNAdapter
from sdn_guardian.engine.conflict_simulator import (
    FAIL,
    PASS,
    ConflictSimulator,
    ConflictType,
    Relation,
    SimulationRejected,
    analyze,
    match_relation,
)
from sdn_guardian.models import Action, FlowRule, Protocol
from sdn_guardian.state import DEMO_ATTACKER_IP, DEMO_CONTROLLER_IP, StateStore

PROTECTED = (IPv4Network("10.10.10.0/24"),)


@pytest.fixture
def store() -> StateStore:
    s = StateStore(":memory:")
    s.seed_demo_scenario(now=1_000_000.0)
    yield s
    s.close()


@pytest.fixture
def sim(store: StateStore) -> ConflictSimulator:
    return ConflictSimulator(MockSDNAdapter(store), store)


def run(store: StateStore, **fields):
    rule = FlowRule(rule_id=store.next_rule_id(), **fields)
    return analyze(rule, store.snapshot(), DEMO_CONTROLLER_IP, PROTECTED)


def test_match_relation() -> None:
    def r(**kw) -> FlowRule:
        return FlowRule(rule_id=1, priority=1, action=Action.DENY, **kw)

    host = r(src_cidr="10.10.20.45/32")
    subnet = r(src_cidr="10.10.20.0/24")
    assert match_relation(host, subnet) is Relation.SUBSET
    assert match_relation(subnet, host) is Relation.SUPERSET
    assert match_relation(subnet, subnet) is Relation.EQUAL
    https = r(protocol=Protocol.TCP, dst_port_range=443)
    ssh = r(protocol=Protocol.TCP, dst_port_range=22)
    assert match_relation(https, ssh) is Relation.DISJOINT
    # Narrower source but wider ports: neither contains the other.
    assert match_relation(r(src_cidr="10.10.20.45/32", protocol="tcp", dst_port_range=443),
                          r(src_cidr="10.10.20.0/24", protocol="tcp", dst_port_range=(400, 500))
                          ) is Relation.SUBSET  # fmt: skip
    host_any = r(src_cidr="10.10.20.45/32")
    subnet_tcp = r(src_cidr="10.10.20.0/24", protocol="tcp")
    assert match_relation(host_any, subnet_tcp) is Relation.PARTIAL


def test_shadowed_by_rule_10_with_fix(store: StateStore) -> None:
    res = run(store, priority=40, src_cidr=f"{DEMO_ATTACKER_IP}/32", action=Action.DENY)
    assert res.verdict == FAIL
    assert ConflictType.SHADOWED in res.types()
    assert res.min_safe_priority == 101
    md = res.to_markdown("sim-x")
    assert "Minimum safe priority: 101" in md and "#10" in md
    assert len(md.splitlines()) <= 15


def test_demo_fix_passes_as_exception(store: StateStore) -> None:
    res = run(store, priority=150, src_cidr=f"{DEMO_ATTACKER_IP}/32", action=Action.DENY)
    assert res.verdict == PASS
    assert res.types() == {ConflictType.GENERALIZATION}


def test_override(store: StateStore) -> None:
    res = run(store, priority=200, src_cidr="10.10.20.0/24", action=Action.DENY)
    assert res.verdict == PASS
    assert [c.other.rule_id for c in res.conflicts if c.type is ConflictType.OVERRIDES] == [10]


def test_mgmt_lockout(store: StateStore) -> None:
    res = run(store, priority=2000, src_cidr="10.10.10.0/24", action=Action.DENY)
    assert res.verdict == FAIL
    assert {ConflictType.MGMT_LOCKOUT, ConflictType.OVERRIDES} <= res.types()
    assert "Exclude protected subnet 10.10.10.0/24" in res.to_markdown("sim-x")


def test_lockout_by_single_host_is_detected(store: StateStore) -> None:
    res = run(store, priority=2000, src_cidr="10.10.10.77/32", dst_cidr=DEMO_CONTROLLER_IP,
              protocol=Protocol.TCP, dst_port_range=830, action=Action.DENY)  # fmt: skip
    assert ConflictType.MGMT_LOCKOUT in res.types()


def test_lockout_shadowed_below_rule_1_is_not_lockout(store: StateStore) -> None:
    res = run(store, priority=500, src_cidr="10.10.10.0/24", action=Action.DENY)
    assert ConflictType.MGMT_LOCKOUT not in res.types()
    assert ConflictType.SHADOWED in res.types()


def test_redundant(store: StateStore) -> None:
    # Already allowed by #10 at higher priority.
    res = run(store, priority=50, src_cidr="10.10.20.7/32", action=Action.ALLOW)
    assert res.verdict == PASS
    assert ConflictType.REDUNDANT in res.types()
    # A broader, higher allow makes #20 redundant.
    res = run(store, priority=95, src_cidr="10.10.30.0/24", dst_cidr="10.10.40.0/24",
              protocol=Protocol.TCP, dst_port_range=(1, 1024), action=Action.ALLOW)  # fmt: skip
    assert [c.other.rule_id for c in res.conflicts if c.type is ConflictType.REDUNDANT] == [20]


def test_correlation(store: StateStore) -> None:
    res = run(store, priority=120, src_cidr="10.10.30.0/24", dst_cidr="any",
              protocol=Protocol.TCP, dst_port_range=(400, 500), action=Action.DENY)  # fmt: skip
    assert ConflictType.CORRELATION not in res.types()  # #20 fully inside -> OVERRIDES
    assert ConflictType.OVERRIDES in res.types()
    res = run(store, priority=120, src_cidr="10.10.30.5/32", dst_cidr="10.10.40.0/16",
              protocol=Protocol.TCP, action=Action.DENY)  # fmt: skip
    assert ConflictType.CORRELATION in res.types()


def test_port_disjoint_passes_clean(store: StateStore) -> None:
    res = run(store, priority=50, src_cidr="10.10.30.0/24", dst_cidr="10.10.40.0/24",
              protocol=Protocol.TCP, dst_port_range=22, action=Action.DENY)  # fmt: skip
    assert res.verdict == PASS
    assert res.conflicts == []
    assert "No conflicts" in res.to_markdown("sim-x")


def test_duplicate_rule_id_rejected(store: StateStore) -> None:
    rule = FlowRule(rule_id=10, priority=1, action=Action.DENY)
    with pytest.raises(ValueError):
        analyze(rule, store.snapshot(), DEMO_CONTROLLER_IP, PROTECTED)


# -- simulator + store --


async def test_simulate_persists_and_authorizes_push(sim: ConflictSimulator, store) -> None:
    rule = FlowRule(rule_id=await sim.next_rule_id(), priority=150,
                    src_cidr=DEMO_ATTACKER_IP, action=Action.DENY)  # fmt: skip
    rec, res = await sim.simulate(rule)
    assert rec.verdict == PASS == res.verdict
    assert rec.simulation_id.startswith("sim-")
    assert store.get_simulation(rec.simulation_id) == rec
    assert (await sim.load_pushable(rec.simulation_id)).rule == rule


async def test_load_pushable_rejects_fail_unknown_and_stale(sim: ConflictSimulator, store) -> None:
    with pytest.raises(SimulationRejected, match="Unknown"):
        await sim.load_pushable("sim-nope")

    bad = FlowRule(rule_id=await sim.next_rule_id(), priority=40,
                   src_cidr=DEMO_ATTACKER_IP, action=Action.DENY)  # fmt: skip
    rec, _ = await sim.simulate(bad)
    with pytest.raises(SimulationRejected, match="FAIL"):
        await sim.load_pushable(rec.simulation_id)

    good = bad.model_copy(update={"priority": 150})
    rec, _ = await sim.simulate(good)
    store.add_flow_rule(FlowRule(rule_id=99, priority=5, src_cidr="10.99.0.0/16",
                                 action=Action.DENY))  # fmt: skip
    with pytest.raises(SimulationRejected, match="stale"):
        await sim.load_pushable(rec.simulation_id)
