"""Cisco IOS-XE adapter against a fake device: mocked httpx (RESTCONF) and ncclient (NETCONF)."""

from __future__ import annotations

import copy
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from ipaddress import IPv4Network
from typing import Any

import httpx
import pytest

from sdn_guardian.adapters.cisco_iosxe_adapter import (
    PERSIST_ID,
    CiscoIOSXEAdapter,
    IOSXEError,
    ace_to_rule,
    acl_config_xml,
    parse_interfaces,
)
from sdn_guardian.config import IOSXESettings, Settings
from sdn_guardian.engine.conflict_simulator import ConflictSimulator
from sdn_guardian.engine.rollback_manager import RollbackManager
from sdn_guardian.mcp_server import _make_adapter
from sdn_guardian.models import Action, CommitStatus, FlowRule, Protocol
from sdn_guardian.state import DEMO_ATTACKER_IP, StateStore

NC = "{urn:ietf:params:xml:ns:netconf:base:1.0}"
SETTINGS = IOSXESettings(host="sandbox.example", username="dev", password="pw")

RULE_10 = FlowRule(
    rule_id=10, priority=100, src_cidr="10.10.20.0/24", action=Action.ALLOW
)  # the shadowing trap of the demo
MGMT_ALLOW = FlowRule(rule_id=1, priority=1000, dst_cidr="10.10.10.10/32", action=Action.ALLOW)

INTERFACES_JSON = {
    "Cisco-IOS-XE-native:interface": {
        "GigabitEthernet": [
            {"name": "0/1", "description": "controller uplink"},
            {
                "name": "0/2",
                "description": "user access",
                "switchport": {"Cisco-IOS-XE-switch:access": {"vlan": {"vlan": 99}}},
            },
            {"name": "0/3", "shutdown": [None]},
        ],
        "Loopback": [{"name": 0}],
    }
}


class FakeDevice:
    """Running/candidate ACL entries (RESTCONF JSON shape) with confirmed-commit semantics."""

    def __init__(self) -> None:
        self.running: dict[int, dict[str, Any]] = {}
        self.candidate: dict[int, dict[str, Any]] = {}
        self.backup: dict[int, dict[str, Any]] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.restconf_up = True

    # -- RESTCONF --

    def handle(self, request: httpx.Request) -> httpx.Response:
        if not self.restconf_up:
            raise httpx.ConnectError("unreachable", request=request)
        assert request.headers["accept"] == "application/yang-data+json"
        path = request.url.path
        assert path.startswith("/restconf/data/Cisco-IOS-XE-native:native/")
        if path.endswith(":native/interface"):
            return httpx.Response(200, json=INTERFACES_JSON)
        if "Cisco-IOS-XE-acl:extended=SDN-GUARDIAN" in path:
            if not self.running:
                return httpx.Response(404)
            # RFC 7951: uint64 sequences are JSON strings.
            seq_rules = [
                {"sequence": str(seq), "ace-rule": ace} for seq, ace in sorted(self.running.items())
            ]
            body = {
                "Cisco-IOS-XE-acl:extended": [
                    {"name": "SDN-GUARDIAN", "access-list-seq-rule": seq_rules}
                ]
            }
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    # -- NETCONF --

    def edit_config(self, config: str) -> None:
        ext = ET.fromstring(config).find(".//{http://cisco.com/ns/yang/Cisco-IOS-XE-acl}extended")
        entries = {}
        for e in ext:
            if e.tag.endswith("access-list-seq-rule"):
                seq = int(e[0].text)
                ace = {child.tag.split("}")[-1]: (child.text or [None]) for child in e[1]}
                entries[seq] = {k: [None] if v == [None] else v for k, v in ace.items()}
        if ext.get(f"{NC}operation") == "replace":
            self.candidate = entries
        else:
            self.candidate.update(entries)

    def commit(self, confirmed=False, timeout=None, persist=None, persist_id=None) -> None:
        self.calls.append(
            (
                "commit",
                {
                    "confirmed": confirmed,
                    "timeout": timeout,
                    "persist": persist,
                    "persist_id": persist_id,
                },
            )
        )
        if persist_id is not None:
            if self.backup is None or persist_id != PERSIST_ID:
                raise RuntimeError("no confirmed commit pending")
            self.backup = None
            return
        if confirmed:
            self.backup = copy.deepcopy(self.running)
        self.running = copy.deepcopy(self.candidate)

    def cancel_commit(self, persist_id=None) -> None:
        self.calls.append(("cancel_commit", {"persist_id": persist_id}))
        if self.backup is None:
            raise RuntimeError("no confirmed commit pending")
        self.running, self.backup = self.backup, None
        self.candidate = copy.deepcopy(self.running)

    def expire(self) -> None:
        """The device-side confirmed-commit timer fires."""
        self.running, self.backup = self.backup, None
        self.candidate = copy.deepcopy(self.running)


class FakeManager:
    def __init__(self, device: FakeDevice) -> None:
        self.device = device

    def __enter__(self) -> FakeManager:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    @contextmanager
    def locked(self, target: str):
        assert target == "candidate"
        yield

    def edit_config(self, target: str, config: str) -> None:
        assert target == "candidate"
        self.device.calls.append(("edit_config", {"config": config}))
        self.device.edit_config(config)

    def commit(self, **kw: Any) -> None:
        self.device.commit(**kw)

    def cancel_commit(self, persist_id=None) -> None:
        self.device.cancel_commit(persist_id)

    def discard_changes(self) -> None:
        self.device.candidate = copy.deepcopy(self.device.running)


@pytest.fixture
def store() -> StateStore:
    s = StateStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def device() -> FakeDevice:
    return FakeDevice()


@pytest.fixture
async def adapter(store: StateStore, device: FakeDevice) -> CiscoIOSXEAdapter:
    a = CiscoIOSXEAdapter(
        SETTINGS,
        store,
        "10.10.10.10",
        (IPv4Network("10.10.10.0/24"),),
        transport=httpx.MockTransport(device.handle),
        netconf_connect=lambda _s: FakeManager(device),
    )
    yield a
    await a.aclose()


# --- parsing -----------------------------------------------------------------------------------


def test_ace_json_maps_to_flow_rule() -> None:
    entry = {
        "sequence": "9850",
        "ace-rule": {
            "action": "deny",
            "protocol": "tcp",
            "ipv4-address": "10.10.20.0",
            "mask": "0.0.0.255",
            "dst-host": "10.10.10.10",
            "dst-eq": "www",
        },
    }
    rule = ace_to_rule(entry, rule_id=7)
    assert rule == FlowRule(
        rule_id=7,
        priority=150,
        src_cidr="10.10.20.0/24",
        dst_cidr="10.10.10.10/32",
        protocol=Protocol.TCP,
        dst_port_range=(80, 80),
        action=Action.DENY,
    )
    rng = {
        "sequence": 9000,
        "ace-rule": {
            "action": "permit",
            "protocol": "udp",
            "any": [None],
            "dst-any": [None],
            "dst-range1": 1000,
            "dst-range2": 2000,
        },
    }
    r = ace_to_rule(rng, rule_id=1)
    assert (r.priority, r.src_cidr, r.dst_port_range, r.action) == (
        1000,
        "0.0.0.0/0",
        (1000, 2000),
        Action.ALLOW,
    )
    assert ace_to_rule({"sequence": "5", "remark": "managed by guardian"}, 1) is None


@pytest.mark.parametrize(
    "ace",
    [
        {"action": "permit", "protocol": "gre", "any": [None], "dst-any": [None]},
        {"action": "deny", "protocol": "tcp", "any": [None], "dst-any": [None], "src-eq": 22},
        {
            "action": "deny",
            "protocol": "ip",
            "ipv4-address": "10.0.0.0",
            "mask": "0.255.0.255",
            "dst-any": [None],
        },
    ],
)
def test_unmodelable_ace_is_rejected_not_widened(ace: dict[str, Any]) -> None:
    with pytest.raises(IOSXEError):
        ace_to_rule({"sequence": "100", "ace-rule": ace}, 1)


def test_interfaces_parse_vlan_shutdown_and_names() -> None:
    by_name = {i.name: i for i in parse_interfaces(INTERFACES_JSON)}
    assert set(by_name) == {"GigabitEthernet0/1", "GigabitEthernet0/2", "GigabitEthernet0/3"}
    assert by_name["GigabitEthernet0/2"].vlan == 99
    assert by_name["GigabitEthernet0/1"].vlan == 1
    assert by_name["GigabitEthernet0/3"].enabled is False
    assert by_name["GigabitEthernet0/1"].description == "controller uplink"


def test_config_xml_uses_seq_from_priority_and_replace() -> None:
    xml = acl_config_xml("SDN-GUARDIAN", [RULE_10], replace=True)
    assert "<sequence>9900</sequence>" in xml
    assert "<ipv4-address>10.10.20.0</ipv4-address><mask>0.0.0.255</mask>" in xml
    assert 'nc:operation="replace"' in xml
    ET.fromstring(xml)  # well-formed


# --- adapter reads/writes ----------------------------------------------------------------------


async def test_empty_acl_reads_as_empty_table(adapter: CiscoIOSXEAdapter) -> None:
    assert await adapter.get_flow_rules() == []
    assert await adapter.get_telemetry() == []
    v = await adapter.get_flow_table_version()
    assert v == await adapter.get_flow_table_version()  # stable while unchanged


async def test_install_round_trips_with_rule_id_and_confirmed_commit(
    adapter: CiscoIOSXEAdapter, device: FakeDevice
) -> None:
    v0 = await adapter.get_flow_table_version()
    deny = FlowRule(rule_id=11, priority=150, src_cidr=f"{DEMO_ATTACKER_IP}/32", action=Action.DENY)
    v1 = await adapter.install_rule(deny, confirm_timeout_s=30)
    assert v1 > v0
    assert await adapter.get_flow_rules() == [deny]
    assert (
        "commit",
        {"confirmed": True, "timeout": "30", "persist": PERSIST_ID, "persist_id": None},
    ) in device.calls

    await adapter.confirm()
    assert device.backup is None
    assert device.calls[-1] == (
        "commit",
        {"confirmed": False, "timeout": None, "persist": None, "persist_id": PERSIST_ID},
    )


async def test_install_rejects_priority_clash_and_out_of_range(
    adapter: CiscoIOSXEAdapter,
) -> None:
    await adapter.install_rule(RULE_10)
    with pytest.raises(IOSXEError, match="seq 9900 is taken"):
        await adapter.install_rule(RULE_10.model_copy(update={"rule_id": 12}))
    with pytest.raises(IOSXEError, match="does not fit"):
        await adapter.install_rule(RULE_10.model_copy(update={"rule_id": 13, "priority": 10000}))


async def test_restore_cancels_pending_confirmed_commit(
    adapter: CiscoIOSXEAdapter, device: FakeDevice
) -> None:
    await adapter.install_rule(RULE_10)
    snap = await adapter.snapshot()
    await adapter.install_rule(
        FlowRule(rule_id=11, priority=150, src_cidr="10.10.20.45/32", action=Action.DENY), 30
    )
    edits_before = sum(1 for name, _ in device.calls if name == "edit_config")
    await adapter.restore(snap)
    assert ("cancel_commit", {"persist_id": PERSIST_ID}) in device.calls
    assert (await adapter.snapshot()).fingerprint == snap.fingerprint
    # The device revert was enough: no replace edit was needed.
    assert sum(1 for name, _ in device.calls if name == "edit_config") == edits_before


async def test_restore_replaces_acl_when_nothing_is_pending(
    adapter: CiscoIOSXEAdapter, device: FakeDevice
) -> None:
    snap = await adapter.snapshot()  # empty table
    await adapter.install_rule(RULE_10)
    await adapter.install_rule(MGMT_ALLOW)
    await adapter.restore(snap)
    assert await adapter.get_flow_rules() == []
    assert 'nc:operation="replace"' in device.calls[-2][1]["config"]
    assert device.running == {}


async def test_health_check_reports_restconf_and_mgmt_reachability(
    adapter: CiscoIOSXEAdapter, device: FakeDevice
) -> None:
    report = await adapter.health_check()
    assert report.ok and report.checks[0].name == "restconf sandbox.example"

    await adapter.install_rule(
        FlowRule(rule_id=2, priority=500, dst_cidr="10.10.10.0/24", action=Action.DENY)
    )
    assert not (await adapter.health_check()).ok

    device.restconf_up = False
    report = await adapter.health_check()
    assert not report.ok and report.checks[0].detail == "unreachable"


async def test_interfaces_from_restconf(adapter: CiscoIOSXEAdapter) -> None:
    names = [i.name for i in await adapter.get_interfaces()]
    assert names == ["GigabitEthernet0/1", "GigabitEthernet0/2", "GigabitEthernet0/3"]


# --- engines over the live adapter -------------------------------------------------------------


async def test_canonical_push_confirm_and_timeout_rollback(
    adapter: CiscoIOSXEAdapter, store: StateStore, device: FakeDevice
) -> None:
    await adapter.install_rule(MGMT_ALLOW)
    await adapter.install_rule(RULE_10)
    sim = ConflictSimulator(adapter, store)
    mgr = RollbackManager(adapter, store, sim, timeout_s=30)

    shadowed, res = await sim.simulate(
        FlowRule(rule_id=11, priority=40, src_cidr=f"{DEMO_ATTACKER_IP}/32", action=Action.DENY)
    )
    assert res.verdict == "FAIL"
    good, res = await sim.simulate(
        FlowRule(rule_id=11, priority=150, src_cidr=f"{DEMO_ATTACKER_IP}/32", action=Action.DENY)
    )
    assert res.verdict == "PASS"

    rec = await mgr.push(good.simulation_id)
    assert device.backup is not None  # device-side confirmed commit is armed
    rec = await mgr.confirm(rec.commit_id)
    assert rec.status is CommitStatus.COMMITTED
    assert device.backup is None
    committed = await adapter.snapshot()

    # Bonus: an unconfirmed push rolls back to the exact snapshot.
    bonus, res = await sim.simulate(
        FlowRule(
            rule_id=12,
            priority=200,
            src_cidr="10.10.20.0/24",
            dst_cidr="10.10.40.0/24",
            action=Action.DENY,
        )
    )
    assert res.verdict == "PASS"
    rec = await mgr.push(bonus.simulation_id, timeout_s=0.05)
    rec = await mgr.rollback(rec.commit_id, "timer fired")
    assert rec.status is CommitStatus.ROLLED_BACK
    assert (await adapter.snapshot()).fingerprint == committed.fingerprint
    await mgr.aclose()


async def test_restore_after_device_timer_already_reverted(
    adapter: CiscoIOSXEAdapter, device: FakeDevice
) -> None:
    snap = await adapter.snapshot()
    await adapter.install_rule(RULE_10, confirm_timeout_s=5)
    device.expire()  # guardian was down; the device reverted on its own
    await adapter.restore(snap)
    assert (await adapter.snapshot()).fingerprint == snap.fingerprint


def test_make_adapter_live_mode(store: StateStore) -> None:
    with pytest.raises(ValueError, match="IOSXE_HOST"):
        _make_adapter(Settings(mode="live"), store)
    adapter = _make_adapter(Settings(mode="live", iosxe=SETTINGS), store)
    assert isinstance(adapter, CiscoIOSXEAdapter)
