import asyncio

import pytest

from sdn_guardian.adapters.mock_sdn_adapter import MockSDNAdapter
from sdn_guardian.engine.conflict_simulator import ConflictSimulator
from sdn_guardian.engine.rollback_manager import (
    CommitRejected,
    RollbackManager,
    SimulationRejected,
)
from sdn_guardian.models import (
    Action,
    CheckResult,
    CommitStatus,
    FlowRule,
    HealthReport,
    table_fingerprint,
)
from sdn_guardian.state import DEMO_ATTACKER_IP, StateStore


class FlakyHealthAdapter(MockSDNAdapter):
    """Mock adapter whose health check can be forced to fail."""

    healthy = True

    async def health_check(self) -> HealthReport:
        if self.healthy:
            return await super().health_check()
        return HealthReport(checks=[CheckResult(name="bgp", ok=False, detail="neighbor down")])


@pytest.fixture
def store() -> StateStore:
    s = StateStore(":memory:")
    s.seed_demo_scenario(now=1_000_000.0)
    yield s
    s.close()


@pytest.fixture
def adapter(store: StateStore) -> FlakyHealthAdapter:
    return FlakyHealthAdapter(store)


@pytest.fixture
def sim(adapter: FlakyHealthAdapter, store: StateStore) -> ConflictSimulator:
    return ConflictSimulator(adapter, store)


@pytest.fixture
async def mgr(adapter: FlakyHealthAdapter, store: StateStore, sim: ConflictSimulator):
    m = RollbackManager(adapter, store, sim, timeout_s=30)
    yield m
    await m.aclose()


def deny_attacker(store: StateStore, priority: int) -> FlowRule:
    return FlowRule(
        rule_id=store.next_rule_id(),
        priority=priority,
        src_cidr=f"{DEMO_ATTACKER_IP}/32",
        dst_cidr="any",
        action=Action.DENY,
    )


async def pass_sim_id(sim: ConflictSimulator, store: StateStore) -> str:
    record, result = await sim.simulate(deny_attacker(store, 150))
    assert result.verdict == "PASS"
    return record.simulation_id


async def test_timer_restores_exact_snapshot(mgr, sim, store) -> None:
    before = table_fingerprint(store.get_flow_rules())
    rec = await mgr.push(await pass_sim_id(sim, store), timeout_s=1)
    assert rec.status is CommitStatus.PENDING
    assert table_fingerprint(store.get_flow_rules()) != before
    await asyncio.sleep(1.3)
    done = mgr.status(rec.commit_id)
    assert done.status is CommitStatus.ROLLED_BACK
    assert "deadline" in done.detail
    assert table_fingerprint(store.get_flow_rules()) == before
    assert store.get_flow_rules() == list(rec.snapshot.rules)


async def test_confirm_commits_when_healthy(mgr, sim, store) -> None:
    rec = await mgr.push(await pass_sim_id(sim, store), timeout_s=1)
    done = await mgr.confirm(rec.commit_id)
    assert done.status is CommitStatus.COMMITTED
    await asyncio.sleep(1.2)  # the cancelled timer must not roll back
    assert mgr.status(rec.commit_id).status is CommitStatus.COMMITTED
    assert store.get_flow_rule(rec.rule.rule_id) == rec.rule
    with pytest.raises(CommitRejected, match="already COMMITTED"):
        await mgr.confirm(rec.commit_id)


async def test_push_rejects_failing_simulation(mgr, sim, store) -> None:
    record, result = await sim.simulate(deny_attacker(store, 40))  # shadowed by rule #10
    assert result.verdict == "FAIL"
    before = store.flow_table_version()
    with pytest.raises(SimulationRejected, match="only PASS"):
        await mgr.push(record.simulation_id)
    with pytest.raises(SimulationRejected, match="Unknown"):
        await mgr.push("sim-doesnotexist")
    assert store.flow_table_version() == before
    assert store.list_commits() == []


async def test_push_rejects_stale_simulation(mgr, sim, store) -> None:
    sim_id = await pass_sim_id(sim, store)
    store.add_flow_rule(
        FlowRule(rule_id=99, priority=5, src_cidr="10.10.50.0/24", action=Action.DENY)
    )
    with pytest.raises(SimulationRejected, match="stale"):
        await mgr.push(sim_id)
    assert store.list_commits() == []


async def test_only_one_pending_commit(mgr, sim, store) -> None:
    await mgr.push(await pass_sim_id(sim, store))
    other = FlowRule(rule_id=77, priority=150, src_cidr="10.10.20.46/32", action=Action.DENY)
    record, _ = await sim.simulate(other)
    with pytest.raises(CommitRejected, match="PENDING"):
        await mgr.push(record.simulation_id)


async def test_confirm_refuses_and_rolls_back_when_unhealthy(mgr, sim, store, adapter) -> None:
    before = table_fingerprint(store.get_flow_rules())
    rec = await mgr.push(await pass_sim_id(sim, store))
    adapter.healthy = False
    done = await mgr.confirm(rec.commit_id)
    assert done.status is CommitStatus.ROLLED_BACK
    assert "health check failed" in done.detail and "neighbor down" in done.detail
    assert table_fingerprint(store.get_flow_rules()) == before


async def test_restore_failure_marks_failed(mgr, sim, store, adapter, monkeypatch) -> None:
    rec = await mgr.push(await pass_sim_id(sim, store))

    async def broken_restore(snapshot):
        raise RuntimeError("device unreachable")

    monkeypatch.setattr(adapter, "restore", broken_restore)
    done = await mgr.rollback(rec.commit_id)
    assert done.status is CommitStatus.FAILED
    assert "device unreachable" in done.detail


async def test_recover_rolls_back_expired_and_rearms_others(adapter, store, sim) -> None:
    now = [1_000.0]
    before = table_fingerprint(store.get_flow_rules())
    first = RollbackManager(adapter, store, sim, timeout_s=30, clock=lambda: now[0])
    rec = await first.push(await pass_sim_id(sim, store))
    await first.aclose()  # simulate a crash: the timer is gone, the commit stays PENDING
    assert store.get_commit(rec.commit_id).status is CommitStatus.PENDING

    # Restart before the deadline: the timer is re-armed, nothing is rolled back yet.
    now[0] += 10
    second = RollbackManager(adapter, store, sim, clock=lambda: now[0])
    handled = await second.recover()
    assert [h.status for h in handled] == [CommitStatus.PENDING]
    assert rec.commit_id in second._timers
    await second.aclose()

    # Restart after the deadline: rolled back immediately.
    now[0] += 30
    third = RollbackManager(adapter, store, sim, clock=lambda: now[0])
    handled = await third.recover()
    assert [h.status for h in handled] == [CommitStatus.ROLLED_BACK]
    assert "expired" in handled[0].detail
    assert table_fingerprint(store.get_flow_rules()) == before
    await third.aclose()


async def test_confirm_after_deadline_rolls_back(adapter, store, sim) -> None:
    now = [1_000.0]
    mgr = RollbackManager(adapter, store, sim, timeout_s=30, clock=lambda: now[0])
    rec = await mgr.push(await pass_sim_id(sim, store))
    now[0] += 31
    done = await mgr.confirm(rec.commit_id)
    assert done.status is CommitStatus.ROLLED_BACK
    await mgr.aclose()
