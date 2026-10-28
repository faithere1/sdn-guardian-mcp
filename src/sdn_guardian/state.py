"""SQLite-backed state: Source of Truth, emulated device state, telemetry, simulations, commits."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import (
    Action,
    CommitRecord,
    CommitStatus,
    FlowRule,
    FlowTableSnapshot,
    InterfaceState,
    Protocol,
    SimulationRecord,
    TelemetrySample,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flow_rules (
    rule_id        INTEGER PRIMARY KEY,
    priority       INTEGER NOT NULL,
    src_cidr       TEXT NOT NULL,
    dst_cidr       TEXT NOT NULL,
    protocol       TEXT NOT NULL,
    dst_port_lo    INTEGER,
    dst_port_hi    INTEGER,
    action         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sot_interfaces (
    name        TEXT PRIMARY KEY,
    vlan        INTEGER NOT NULL,
    enabled     INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS live_interfaces (
    name        TEXT PRIMARY KEY,
    vlan        INTEGER NOT NULL,
    enabled     INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS telemetry (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    interface TEXT NOT NULL,
    src_ip    TEXT NOT NULL,
    dst_ip    TEXT NOT NULL,
    protocol  TEXT NOT NULL,
    dst_port  INTEGER,
    packets   INTEGER NOT NULL,
    bytes     INTEGER NOT NULL,
    syn       INTEGER NOT NULL DEFAULT 0,
    syn_ack   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry(ts);
CREATE TABLE IF NOT EXISTS simulations (
    simulation_id      TEXT PRIMARY KEY,
    rule_json          TEXT NOT NULL,
    rule_hash          TEXT NOT NULL,
    flow_table_version INTEGER NOT NULL,
    verdict            TEXT NOT NULL,
    report             TEXT NOT NULL,
    created_at         REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS commits (
    commit_id     TEXT PRIMARY KEY,
    simulation_id TEXT,
    rule_json     TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    status        TEXT NOT NULL,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    resolved_at   REAL,
    detail        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_commits_status ON commits(status);
"""

_FLOW_VERSION_KEY = "flow_table_version"
_SEEDED_KEY = "seeded"

# --- Demo scenario --------------------------------------------------------------------------

DEMO_FLOW_RULES: tuple[FlowRule, ...] = (
    FlowRule(
        rule_id=1, priority=1000, src_cidr="10.10.10.0/24", dst_cidr="any", action=Action.ALLOW
    ),
    # The shadowing trap: any deny for a host inside 10.10.20.0/24 must beat priority 100.
    FlowRule(
        rule_id=10, priority=100, src_cidr="10.10.20.0/24", dst_cidr="any", action=Action.ALLOW
    ),
    FlowRule(
        rule_id=20,
        priority=90,
        src_cidr="10.10.30.0/24",
        dst_cidr="10.10.40.0/24",
        protocol=Protocol.TCP,
        dst_port_range=(443, 443),
        action=Action.ALLOW,
    ),
)

DEMO_SOT_INTERFACES: tuple[InterfaceState, ...] = (
    InterfaceState(name="GigabitEthernet0/1", vlan=10, description="controller uplink"),
    InterfaceState(name="GigabitEthernet0/2", vlan=20, description="user access"),
    InterfaceState(name="GigabitEthernet0/3", vlan=30, description="web clients"),
)

# Live state drifts from SoT on Gi0/2 (VLAN 99 instead of 20).
DEMO_LIVE_INTERFACES: tuple[InterfaceState, ...] = (
    DEMO_SOT_INTERFACES[0],
    InterfaceState(name="GigabitEthernet0/2", vlan=99, description="user access"),
    DEMO_SOT_INTERFACES[2],
)

DEMO_ATTACKER_IP = "10.10.20.45"
DEMO_CONTROLLER_IP = "10.10.10.10"
DEMO_ATTACK_INTERFACE = "GigabitEthernet0/2"


def demo_telemetry(now: float, window_s: int = 60) -> list[TelemetrySample]:
    """Baseline traffic plus a SYN flood from the attacker, spread over `window_s` seconds."""
    samples: list[TelemetrySample] = []
    start = now - window_s
    for i in range(window_s // 10):
        ts = start + i * 10
        samples += [
            TelemetrySample(
                ts=ts, interface="GigabitEthernet0/3", src_ip="10.10.30.11",
                dst_ip="10.10.40.5", protocol=Protocol.TCP, dst_port=443,
                packets=120, bytes=96_000, syn=2, syn_ack=2,
            ),
            TelemetrySample(
                ts=ts, interface="GigabitEthernet0/2", src_ip="10.10.20.12",
                dst_ip="10.10.40.5", protocol=Protocol.TCP, dst_port=443,
                packets=80, bytes=52_000, syn=1, syn_ack=1,
            ),
            TelemetrySample(
                ts=ts, interface="GigabitEthernet0/1", src_ip="10.10.10.10",
                dst_ip="10.10.20.1", protocol=Protocol.TCP, dst_port=830,
                packets=15, bytes=9_000, syn=0, syn_ack=0,
            ),
            TelemetrySample(
                ts=ts, interface=DEMO_ATTACK_INTERFACE, src_ip=DEMO_ATTACKER_IP,
                dst_ip=DEMO_CONTROLLER_IP, protocol=Protocol.TCP, dst_port=443,
                packets=48_000, bytes=2_880_000, syn=47_500, syn_ack=310,
            ),
        ]  # fmt: skip
    return samples


# --- Store ------------------------------------------------------------------------------------


def _rule_from_row(row: sqlite3.Row) -> FlowRule:
    ports = None
    if row["dst_port_lo"] is not None:
        ports = (row["dst_port_lo"], row["dst_port_hi"])
    return FlowRule(
        rule_id=row["rule_id"],
        priority=row["priority"],
        src_cidr=row["src_cidr"],
        dst_cidr=row["dst_cidr"],
        protocol=Protocol(row["protocol"]),
        dst_port_range=ports,
        action=Action(row["action"]),
    )


def _iface_from_row(row: sqlite3.Row) -> InterfaceState:
    return InterfaceState(
        name=row["name"],
        vlan=row["vlan"],
        enabled=bool(row["enabled"]),
        description=row["description"],
    )


def _commit_from_row(row: sqlite3.Row) -> CommitRecord:
    return CommitRecord(
        commit_id=row["commit_id"],
        simulation_id=row["simulation_id"],
        rule=FlowRule.model_validate_json(row["rule_json"]),
        snapshot=FlowTableSnapshot.model_validate_json(row["snapshot_json"]),
        status=CommitStatus(row["status"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        resolved_at=row["resolved_at"],
        detail=row["detail"],
    )


class StateStore:
    """Thread-safe wrapper around one SQLite connection. Use ':memory:' for tests."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES (?, '0')", (_FLOW_VERSION_KEY,)
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _query(self, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    # -- meta / versioning --

    def _get_meta(self, key: str) -> str | None:
        rows = self._query("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0]["value"] if rows else None

    def get_meta(self, key: str) -> str | None:
        return self._get_meta(key)

    def set_meta(self, key: str, value: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def flow_table_version(self) -> int:
        return int(self._get_meta(_FLOW_VERSION_KEY) or 0)

    @staticmethod
    def _bump_version(conn: sqlite3.Connection) -> int:
        conn.execute(
            "UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = ?",
            (_FLOW_VERSION_KEY,),
        )
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (_FLOW_VERSION_KEY,)).fetchone()
        return int(row["value"])

    # -- flow table --

    def get_flow_rules(self) -> list[FlowRule]:
        rows = self._query("SELECT * FROM flow_rules ORDER BY priority DESC, rule_id ASC")
        return [_rule_from_row(r) for r in rows]

    def get_flow_rule(self, rule_id: int) -> FlowRule | None:
        rows = self._query("SELECT * FROM flow_rules WHERE rule_id = ?", (rule_id,))
        return _rule_from_row(rows[0]) if rows else None

    def snapshot(self) -> FlowTableSnapshot:
        with self._lock:
            return FlowTableSnapshot(
                version=self.flow_table_version(), rules=tuple(self.get_flow_rules())
            )

    @staticmethod
    def _insert_rule(conn: sqlite3.Connection, rule: FlowRule) -> None:
        lo, hi = rule.dst_port_range or (None, None)
        conn.execute(
            "INSERT INTO flow_rules(rule_id, priority, src_cidr, dst_cidr, protocol,"
            " dst_port_lo, dst_port_hi, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rule.rule_id, rule.priority, rule.src_cidr, rule.dst_cidr,
                rule.protocol.value, lo, hi, rule.action.value,
            ),
        )  # fmt: skip

    def add_flow_rule(self, rule: FlowRule) -> int:
        """Insert a rule; returns the new flow-table version. Fails if rule_id exists."""
        with self.transaction() as conn:
            exists = conn.execute(
                "SELECT 1 FROM flow_rules WHERE rule_id = ?", (rule.rule_id,)
            ).fetchone()
            if exists:
                raise ValueError(f"rule_id {rule.rule_id} already exists")
            self._insert_rule(conn, rule)
            return self._bump_version(conn)

    def remove_flow_rule(self, rule_id: int) -> int:
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM flow_rules WHERE rule_id = ?", (rule_id,))
            if cur.rowcount == 0:
                raise KeyError(f"rule_id {rule_id} not found")
            return self._bump_version(conn)

    def replace_flow_table(self, rules: Iterable[FlowRule]) -> int:
        with self.transaction() as conn:
            conn.execute("DELETE FROM flow_rules")
            for rule in rules:
                self._insert_rule(conn, rule)
            return self._bump_version(conn)

    def next_rule_id(self) -> int:
        row = self._query("SELECT COALESCE(MAX(rule_id), 0) + 1 AS n FROM flow_rules")[0]
        return int(row["n"])

    # -- interfaces --

    def _set_interfaces(self, table: str, ifaces: Iterable[InterfaceState]) -> None:
        with self.transaction() as conn:
            conn.execute(f"DELETE FROM {table}")
            conn.executemany(
                f"INSERT INTO {table}(name, vlan, enabled, description) VALUES (?, ?, ?, ?)",
                [(i.name, i.vlan, int(i.enabled), i.description) for i in ifaces],
            )

    def set_sot_interfaces(self, ifaces: Iterable[InterfaceState]) -> None:
        self._set_interfaces("sot_interfaces", ifaces)

    def set_live_interfaces(self, ifaces: Iterable[InterfaceState]) -> None:
        self._set_interfaces("live_interfaces", ifaces)

    def get_sot_interfaces(self) -> list[InterfaceState]:
        rows = self._query("SELECT * FROM sot_interfaces ORDER BY name")
        return [_iface_from_row(r) for r in rows]

    def get_live_interfaces(self) -> list[InterfaceState]:
        rows = self._query("SELECT * FROM live_interfaces ORDER BY name")
        return [_iface_from_row(r) for r in rows]

    # -- telemetry --

    def add_telemetry(self, samples: Iterable[TelemetrySample]) -> None:
        with self.transaction() as conn:
            conn.executemany(
                "INSERT INTO telemetry(ts, interface, src_ip, dst_ip, protocol, dst_port,"
                " packets, bytes, syn, syn_ack) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        s.ts, s.interface, str(s.src_ip), str(s.dst_ip), s.protocol.value,
                        s.dst_port, s.packets, s.bytes, s.syn, s.syn_ack,
                    )
                    for s in samples
                ],
            )  # fmt: skip

    def get_telemetry(self, since: float | None = None) -> list[TelemetrySample]:
        if since is None:
            rows = self._query("SELECT * FROM telemetry ORDER BY ts, id")
        else:
            rows = self._query("SELECT * FROM telemetry WHERE ts >= ? ORDER BY ts, id", (since,))
        return [
            TelemetrySample(
                ts=r["ts"], interface=r["interface"], src_ip=r["src_ip"], dst_ip=r["dst_ip"],
                protocol=Protocol(r["protocol"]), dst_port=r["dst_port"], packets=r["packets"],
                bytes=r["bytes"], syn=r["syn"], syn_ack=r["syn_ack"],
            )
            for r in rows
        ]  # fmt: skip

    # -- simulations --

    def save_simulation(self, sim: SimulationRecord) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO simulations(simulation_id, rule_json, rule_hash, flow_table_version,"
                " verdict, report, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    sim.simulation_id, sim.rule.model_dump_json(), sim.rule_hash,
                    sim.flow_table_version, sim.verdict, sim.report, sim.created_at,
                ),
            )  # fmt: skip

    def get_simulation(self, simulation_id: str) -> SimulationRecord | None:
        rows = self._query("SELECT * FROM simulations WHERE simulation_id = ?", (simulation_id,))
        if not rows:
            return None
        r = rows[0]
        return SimulationRecord(
            simulation_id=r["simulation_id"],
            rule=FlowRule.model_validate_json(r["rule_json"]),
            rule_hash=r["rule_hash"],
            flow_table_version=r["flow_table_version"],
            verdict=r["verdict"],
            report=r["report"],
            created_at=r["created_at"],
        )

    # -- commits --

    def save_commit(self, rec: CommitRecord) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO commits(commit_id, simulation_id, rule_json, snapshot_json, status,"
                " created_at, expires_at, resolved_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rec.commit_id, rec.simulation_id, rec.rule.model_dump_json(),
                    rec.snapshot.model_dump_json(), rec.status.value, rec.created_at,
                    rec.expires_at, rec.resolved_at, rec.detail,
                ),
            )  # fmt: skip

    def get_commit(self, commit_id: str) -> CommitRecord | None:
        rows = self._query("SELECT * FROM commits WHERE commit_id = ?", (commit_id,))
        return _commit_from_row(rows[0]) if rows else None

    def list_commits(self, status: CommitStatus | None = None) -> list[CommitRecord]:
        if status is None:
            rows = self._query("SELECT * FROM commits ORDER BY created_at")
        else:
            rows = self._query(
                "SELECT * FROM commits WHERE status = ? ORDER BY created_at", (status.value,)
            )
        return [_commit_from_row(r) for r in rows]

    def resolve_commit(
        self,
        commit_id: str,
        status: CommitStatus,
        detail: str = "",
        expected: CommitStatus = CommitStatus.PENDING,
    ) -> bool:
        """Move a commit out of `expected` state. Returns False if it was not in that state."""
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE commits SET status = ?, resolved_at = ?, detail = ?"
                " WHERE commit_id = ? AND status = ?",
                (status.value, time.time(), detail, commit_id, expected.value),
            )
            return cur.rowcount == 1

    # -- seeding --

    def is_seeded(self) -> bool:
        return self._get_meta(_SEEDED_KEY) == "1"

    def seed_demo_scenario(self, now: float | None = None, force: bool = False) -> bool:
        """Load the demo scenario; no-op if already seeded unless `force`. True if seeded."""
        if self.is_seeded() and not force:
            return False
        now = time.time() if now is None else now
        with self.transaction() as conn:
            for table in ("telemetry", "simulations", "commits"):
                conn.execute(f"DELETE FROM {table}")
        self.replace_flow_table(DEMO_FLOW_RULES)
        self.set_sot_interfaces(DEMO_SOT_INTERFACES)
        self.set_live_interfaces(DEMO_LIVE_INTERFACES)
        self.add_telemetry(demo_telemetry(now))
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, '1')"
                " ON CONFLICT(key) DO UPDATE SET value = '1'",
                (_SEEDED_KEY,),
            )
        return True
