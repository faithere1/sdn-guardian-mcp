"""Act: push a simulated rule under a confirmed-commit window, then confirm or roll back.

Lifecycle of a commit:

    push(simulation_id) -> PENDING --confirm_commit (health OK)----> COMMITTED
                                   \\-confirm_commit (health FAIL)--> ROLLED_BACK
                                   \\-timer expires / recover()-----> ROLLED_BACK
                                   (restore itself raises)-----------> FAILED

Safety rules enforced here, not by the caller:
- Only a stored PASS simulation that is not stale may be pushed; the rule comes from it.
- At most one commit is PENDING at a time (like a NETCONF confirmed-commit).
- `confirm()` runs the health check itself and rolls back if it fails.
- Pending commits live in SQLite, so `recover()` can roll back expired ones after a restart.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable

from ..adapters.base_adapter import SDNAdapter
from ..models import CommitRecord, CommitStatus
from ..state import StateStore
from .conflict_simulator import ConflictSimulator, SimulationRejected

__all__ = ["CommitRejected", "RollbackManager", "SimulationRejected"]


class CommitRejected(Exception):
    """A push or confirm cannot proceed (another commit pending, unknown or resolved commit)."""


class RollbackManager:
    def __init__(
        self,
        adapter: SDNAdapter,
        store: StateStore,
        simulator: ConflictSimulator,
        timeout_s: float = 30,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.adapter = adapter
        self.store = store
        self.simulator = simulator
        self.timeout_s = timeout_s
        self.clock = clock
        self._lock = asyncio.Lock()
        self._timers: dict[str, asyncio.Task[None]] = {}

    # -- push --

    async def push(self, simulation_id: str, timeout_s: float | None = None) -> CommitRecord:
        """Install the rule of a PASS simulation provisionally and start the rollback timer."""
        timeout = self.timeout_s if timeout_s is None else timeout_s
        if timeout <= 0:
            raise ValueError("timeout_s must be > 0")
        async with self._lock:
            pending = self.store.list_commits(CommitStatus.PENDING)
            if pending:
                raise CommitRejected(
                    f"Commit `{pending[0].commit_id}` is still PENDING; confirm it or let it "
                    "roll back first."
                )
            sim = await self.simulator.load_pushable(simulation_id)
            snapshot = await self.adapter.snapshot()
            if snapshot.version != sim.flow_table_version:
                raise SimulationRejected(
                    f"Simulation `{simulation_id}` is stale (flow table changed). "
                    "Re-run the simulation."
                )
            try:
                await self.adapter.install_rule(sim.rule, confirm_timeout_s=int(max(1, timeout)))
            except Exception:
                await self.adapter.restore(snapshot)
                raise
            now = self.clock()
            record = CommitRecord(
                commit_id=f"commit-{uuid.uuid4().hex[:12]}",
                simulation_id=sim.simulation_id,
                rule=sim.rule,
                snapshot=snapshot,
                status=CommitStatus.PENDING,
                created_at=now,
                expires_at=now + timeout,
            )
            self.store.save_commit(record)
            self._schedule(record.commit_id, timeout)
            return record

    # -- confirm / rollback --

    async def confirm(self, commit_id: str) -> CommitRecord:
        """Health-check, then make the commit permanent; roll back if health fails or it expired."""
        async with self._lock:
            rec = self._require_pending(commit_id)
            if self.clock() >= rec.expires_at:
                return await self._rollback_locked(rec, "confirm arrived after the deadline")
            report = await self.adapter.health_check()
            if not report.ok:
                failed = "; ".join(f"{c.name}: {c.detail}" for c in report.failures())
                return await self._rollback_locked(rec, f"health check failed ({failed})")
            await self.adapter.confirm()
            self._cancel_timer(commit_id)
            self.store.resolve_commit(commit_id, CommitStatus.COMMITTED, "health check passed")
            return self._get(commit_id)

    async def rollback(self, commit_id: str, reason: str = "manual rollback") -> CommitRecord:
        async with self._lock:
            return await self._rollback_locked(self._require_pending(commit_id), reason)

    async def _rollback_locked(self, rec: CommitRecord, reason: str) -> CommitRecord:
        self._cancel_timer(rec.commit_id)
        try:
            await self.adapter.restore(rec.snapshot)
        except Exception as exc:  # the flow table may now be inconsistent: surface it loudly
            self.store.resolve_commit(
                rec.commit_id, CommitStatus.FAILED, f"{reason}; restore failed: {exc}"
            )
        else:
            self.store.resolve_commit(
                rec.commit_id,
                CommitStatus.ROLLED_BACK,
                f"{reason}; restored flow table v{rec.snapshot.version}",
            )
        return self._get(rec.commit_id)

    # -- timers --

    def _schedule(self, commit_id: str, delay_s: float) -> None:
        self._timers[commit_id] = asyncio.create_task(self._expire_after(commit_id, delay_s))

    def _cancel_timer(self, commit_id: str) -> None:
        task = self._timers.pop(commit_id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _expire_after(self, commit_id: str, delay_s: float) -> None:
        await asyncio.sleep(max(0.0, delay_s))
        async with self._lock:
            rec = self.store.get_commit(commit_id)
            if rec is not None and rec.status is CommitStatus.PENDING:
                await self._rollback_locked(rec, "not confirmed before the deadline")

    async def recover(self) -> list[CommitRecord]:
        """On startup: roll back expired PENDING commits and re-arm timers for the rest."""
        handled: list[CommitRecord] = []
        async with self._lock:
            now = self.clock()
            for rec in self.store.list_commits(CommitStatus.PENDING):
                if rec.expires_at <= now:
                    rolled = await self._rollback_locked(rec, "expired while server was down")
                    handled.append(rolled)
                elif rec.commit_id not in self._timers:
                    self._schedule(rec.commit_id, rec.expires_at - now)
                    handled.append(rec)
        return handled

    async def aclose(self) -> None:
        """Cancel in-process timers. PENDING commits stay in SQLite for `recover()`."""
        tasks = list(self._timers.values())
        self._timers.clear()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # -- queries --

    def status(self, commit_id: str) -> CommitRecord:
        return self._get(commit_id)

    def _get(self, commit_id: str) -> CommitRecord:
        rec = self.store.get_commit(commit_id)
        if rec is None:
            raise CommitRejected(f"Unknown commit `{commit_id}`.")
        return rec

    def _require_pending(self, commit_id: str) -> CommitRecord:
        rec = self._get(commit_id)
        if rec.status is not CommitStatus.PENDING:
            raise CommitRejected(f"Commit `{commit_id}` is already {rec.status.value}.")
        return rec
