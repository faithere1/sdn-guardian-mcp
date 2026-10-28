"""Cisco IOS-XE adapter: RESTCONF reads, NETCONF candidate + confirmed-commit writes.

The flow table is one guardian-owned extended ACL (default `SDN-GUARDIAN`) in the
Cisco-IOS-XE-native model. Priority maps to the ACE sequence (`seq = 10000 - priority`), so a
higher priority is evaluated first, as in OpenFlow. The device knows neither rule IDs nor table
versions, so the adapter keeps both in the StateStore meta table: a seq -> rule_id map, and a
version that bumps whenever the observed ACL content changes.

Writes use a persistent confirmed commit (`persist-id`), so the device reverts on its own if the
guardian dies before confirming, and any later NETCONF session can confirm or cancel it.

Device prerequisites: `restconf`, `netconf-yang`, `netconf-yang feature candidate-datastore`,
and the ACL bound to the interfaces it guards (binding is left to the operator).
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Network
from typing import Any
from urllib.parse import quote
from xml.sax.saxutils import escape

import httpx

from ..config import IOSXESettings
from ..models import (
    ANY_CIDR,
    Action,
    CheckResult,
    FlowRule,
    FlowTableSnapshot,
    HealthReport,
    InterfaceState,
    Protocol,
    TelemetrySample,
    table_fingerprint,
)
from ..state import StateStore
from .base_adapter import SDNAdapter

log = logging.getLogger("sdn_guardian.iosxe")

YANG_JSON = "application/yang-data+json"
NC_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
ACL_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-acl"

SEQ_BASE = 10000
PERSIST_ID = "sdn-guardian"
_RULE_IDS_KEY = "iosxe_rule_ids"
_VERSION_KEY = "iosxe_table_version"

# Port keywords IOS-XE may return instead of numbers.
PORT_NAMES: dict[str, int] = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "www": 80,
    "pop3": 110,
    "ntp": 123,
    "snmp": 161,
    "bgp": 179,
    "ldap": 389,
    "https": 443,
    "syslog": 514,
}

# ACE keys the rule model cannot express; an ACE carrying one is rejected, not silently widened.
_UNSUPPORTED_KEYS = ("src-eq", "src-gt", "src-lt", "src-range1", "src-neq", "dst-neq", "dscp")

NetconfConnect = Callable[[IOSXESettings], Any]


class IOSXEError(RuntimeError):
    """The device returned something the guardian cannot model or refuse to write."""


# --- priority <-> sequence ---------------------------------------------------------------------


def priority_to_seq(priority: int) -> int:
    seq = SEQ_BASE - priority
    if seq < 1:
        raise IOSXEError(f"priority {priority} does not fit an ACL sequence (max {SEQ_BASE - 1})")
    return seq


def seq_to_priority(seq: int) -> int:
    return max(0, SEQ_BASE - seq)


# --- RESTCONF JSON -> FlowRule -----------------------------------------------------------------


def _port(value: object) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text.isdigit():
        return int(text)
    if text in PORT_NAMES:
        return PORT_NAMES[text]
    raise IOSXEError(f"unknown port keyword {value!r}")


def _cidr(ace: dict[str, Any], any_key: str, host_key: str, addr_key: str, mask_key: str) -> str:
    if any_key in ace:
        return ANY_CIDR
    if host_key in ace:
        return f"{IPv4Address(ace[host_key])}/32"
    if addr_key in ace:
        # Wildcard masks are host masks; ipaddress accepts them directly.
        return str(IPv4Network(f"{ace[addr_key]}/{ace.get(mask_key, '0.0.0.0')}"))
    return ANY_CIDR


def ace_to_rule(entry: dict[str, Any], rule_id: int) -> FlowRule | None:
    """Parse one `access-list-seq-rule` entry. Remarks return None; unmodelable ACEs raise."""
    seq = int(entry["sequence"])
    ace = entry.get("ace-rule")
    if ace is None:
        return None
    bad = [k for k in _UNSUPPORTED_KEYS if k in ace]
    if bad:
        raise IOSXEError(f"ACE seq {seq} uses unsupported match {bad}")
    action = {"permit": Action.ALLOW, "deny": Action.DENY}.get(ace.get("action", ""))
    if action is None:
        raise IOSXEError(f"ACE seq {seq} has unknown action {ace.get('action')!r}")
    proto = str(ace.get("protocol", "ip")).lower()
    if proto not in ("ip", "tcp", "udp", "icmp"):
        raise IOSXEError(f"ACE seq {seq} uses unsupported protocol {proto!r}")
    ports: tuple[int, int] | None = None
    if "dst-eq" in ace:
        p = _port(ace["dst-eq"])
        ports = (p, p)
    elif "dst-range1" in ace:
        ports = (_port(ace["dst-range1"]), _port(ace["dst-range2"]))
    elif "dst-gt" in ace:
        ports = (_port(ace["dst-gt"]) + 1, 65535)
    elif "dst-lt" in ace:
        ports = (0, _port(ace["dst-lt"]) - 1)
    try:
        return FlowRule(
            rule_id=rule_id,
            priority=seq_to_priority(seq),
            src_cidr=_cidr(ace, "any", "host", "ipv4-address", "mask"),
            dst_cidr=_cidr(ace, "dst-any", "dst-host", "dest-ipv4-address", "dest-mask"),
            protocol=Protocol.ANY if proto == "ip" else Protocol(proto),
            dst_port_range=ports,
            action=action,
        )
    except ValueError as exc:
        raise IOSXEError(f"ACE seq {seq} cannot be modelled: {exc}") from exc


def parse_interfaces(data: dict[str, Any] | None) -> list[InterfaceState]:
    """Parse `Cisco-IOS-XE-native:interface` into switchport states (Ethernet ports only)."""
    if not data:
        return []
    out: list[InterfaceState] = []
    for kind, items in data.get("Cisco-IOS-XE-native:interface", {}).items():
        if not kind.endswith("Ethernet"):
            continue
        for item in items:
            vlan = 1  # IOS default access VLAN
            for key, val in item.get("switchport", {}).items():
                if key.split(":")[-1] == "access":
                    vlan = int(val.get("vlan", {}).get("vlan", 1))
            out.append(
                InterfaceState(
                    name=f"{kind}{item['name']}",
                    vlan=vlan,
                    enabled="shutdown" not in item,
                    description=item.get("description", ""),
                )
            )
    return out


# --- FlowRule -> NETCONF XML -------------------------------------------------------------------


def _addr_xml(net: IPv4Network, any_key: str, host_key: str, addr_key: str, mask_key: str) -> str:
    if net.prefixlen == 0:
        return f"<{any_key}/>"
    if net.prefixlen == 32:
        return f"<{host_key}>{net.network_address}</{host_key}>"
    return f"<{addr_key}>{net.network_address}</{addr_key}><{mask_key}>{net.hostmask}</{mask_key}>"


def rule_to_ace_xml(rule: FlowRule) -> str:
    parts = [
        f"<action>{'permit' if rule.action is Action.ALLOW else 'deny'}</action>",
        f"<protocol>{'ip' if rule.protocol is Protocol.ANY else rule.protocol.value}</protocol>",
        _addr_xml(rule.src_net, "any", "host", "ipv4-address", "mask"),
        _addr_xml(rule.dst_net, "dst-any", "dst-host", "dest-ipv4-address", "dest-mask"),
    ]
    if rule.dst_port_range:
        lo, hi = rule.dst_port_range
        parts.append(
            f"<dst-eq>{lo}</dst-eq>"
            if lo == hi
            else f"<dst-range1>{lo}</dst-range1><dst-range2>{hi}</dst-range2>"
        )
    return (
        f"<access-list-seq-rule><sequence>{priority_to_seq(rule.priority)}</sequence>"
        f"<ace-rule>{''.join(parts)}</ace-rule></access-list-seq-rule>"
    )


def acl_config_xml(acl_name: str, rules: list[FlowRule], replace: bool = False) -> str:
    op = ' nc:operation="replace"' if replace else ""
    entries = "".join(rule_to_ace_xml(r) for r in rules)
    return (
        f'<config xmlns="{NC_NS}" xmlns:nc="{NC_NS}"><native xmlns="{NATIVE_NS}"><ip>'
        f'<access-list><extended xmlns="{ACL_NS}"{op}><name>{escape(acl_name)}</name>{entries}'
        "</extended></access-list></ip></native></config>"
    )


def _ncclient_connect(s: IOSXESettings) -> Any:
    try:
        from ncclient import manager
    except ImportError as exc:  # pragma: no cover - depends on the optional extra
        raise RuntimeError('Live mode needs ncclient: pip install -e ".[live]"') from exc
    return manager.connect(
        host=s.host,
        port=s.netconf_port,
        username=s.username,
        password=s.password,
        hostkey_verify=False,  # sandbox devices have no pinned host key
        device_params={"name": "iosxe"},
        allow_agent=False,
        look_for_keys=False,
        timeout=30,
    )


# --- adapter -----------------------------------------------------------------------------------


class CiscoIOSXEAdapter(SDNAdapter):
    name = "cisco-iosxe"

    def __init__(
        self,
        settings: IOSXESettings,
        store: StateStore,
        controller_ip: IPv4Address | str = "10.10.10.10",
        protected_subnets: tuple[IPv4Network, ...] = (IPv4Network("10.10.10.0/24"),),
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        netconf_connect: NetconfConnect | None = None,
    ) -> None:
        if not settings.host:
            raise ValueError("Live mode needs IOSXE_HOST (and IOSXE_USERNAME/IOSXE_PASSWORD).")
        super().__init__(controller_ip, protected_subnets)
        self.settings = settings
        self.store = store
        self._connect = netconf_connect or _ncclient_connect
        self._http = httpx.AsyncClient(
            base_url=f"https://{settings.host}:{settings.restconf_port}/restconf/data",
            auth=(settings.username, settings.password),
            headers={"Accept": YANG_JSON, "Content-Type": YANG_JSON},
            verify=settings.verify_tls,
            timeout=15.0,
            transport=transport,
        )

    @property
    def acl_path(self) -> str:
        name = quote(self.settings.acl_name, safe="")
        return f"/Cisco-IOS-XE-native:native/ip/access-list/Cisco-IOS-XE-acl:extended={name}"

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- RESTCONF reads --

    async def _get(self, path: str) -> dict[str, Any] | None:
        resp = await self._http.get(path)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json() if resp.content else None

    async def get_flow_rules(self) -> list[FlowRule]:
        data = await self._get(self.acl_path)
        acls = (data or {}).get("Cisco-IOS-XE-acl:extended", [])
        entries = acls[0].get("access-list-seq-rule", []) if acls else []
        ids = self._rule_ids()
        rules: list[FlowRule] = []
        for entry in entries:
            seq = int(entry["sequence"])
            rule = ace_to_rule(entry, ids.get(seq, seq))
            if rule is not None:
                rules.append(rule)
        return rules

    async def get_flow_table_version(self) -> int:
        return self._observe_version(await self.get_flow_rules())

    async def snapshot(self) -> FlowTableSnapshot:
        rules = await self.get_flow_rules()
        return FlowTableSnapshot(version=self._observe_version(rules), rules=tuple(rules))

    async def get_interfaces(self) -> list[InterfaceState]:
        return parse_interfaces(await self._get("/Cisco-IOS-XE-native:native/interface"))

    async def get_telemetry(self, window_s: int = 60) -> list[TelemetrySample]:
        # IOS-XE exposes no per-flow source counters over RESTCONF; that needs a NetFlow
        # collector. Report no samples rather than invent them.
        return []

    # -- NETCONF writes --

    async def install_rule(self, rule: FlowRule, confirm_timeout_s: int | None = None) -> int:
        seq = priority_to_seq(rule.priority)
        clash = next(
            (
                r
                for r in await self.get_flow_rules()
                if r.priority == rule.priority and r.rule_id != rule.rule_id
            ),
            None,
        )
        if clash is not None:
            raise IOSXEError(f"ACL seq {seq} is taken by {clash.describe()}; use another priority")
        config = acl_config_xml(self.settings.acl_name, [rule])
        await asyncio.to_thread(self._commit_sync, config, confirm_timeout_s)
        self._set_rule_ids({**self._rule_ids(), seq: rule.rule_id})
        return await self.get_flow_table_version()

    async def confirm(self) -> None:
        await asyncio.to_thread(self._confirm_sync)

    async def restore(self, snapshot: FlowTableSnapshot) -> int:
        # Let the device revert a pending confirmed commit first, then make sure the ACL matches.
        await asyncio.to_thread(self._cancel_sync)
        self._set_rule_ids({priority_to_seq(r.priority): r.rule_id for r in snapshot.rules})
        if table_fingerprint(await self.get_flow_rules()) != snapshot.fingerprint:
            config = acl_config_xml(self.settings.acl_name, list(snapshot.rules), replace=True)
            await asyncio.to_thread(self._commit_sync, config, None)
        return await self.get_flow_table_version()

    def _commit_sync(self, config: str, confirm_timeout_s: int | None) -> None:
        with self._connect(self.settings) as m, m.locked("candidate"):
            try:
                m.edit_config(target="candidate", config=config)
                if confirm_timeout_s:
                    m.commit(confirmed=True, timeout=str(confirm_timeout_s), persist=PERSIST_ID)
                else:
                    m.commit()
            except Exception:
                m.discard_changes()
                raise

    def _confirm_sync(self) -> None:
        with self._connect(self.settings) as m:
            m.commit(persist_id=PERSIST_ID)

    def _cancel_sync(self) -> None:
        try:
            with self._connect(self.settings) as m:
                m.cancel_commit(persist_id=PERSIST_ID)
        except Exception as exc:  # usually "no confirmed commit pending"; restore verifies anyway
            log.info("cancel-commit skipped: %s", exc)

    # -- health --

    async def health_check(self) -> HealthReport:
        probe = f"restconf {self.settings.host}"
        try:
            rules = await self.get_flow_rules()
        except (httpx.HTTPError, IOSXEError) as exc:
            return HealthReport(checks=[CheckResult(name=probe, ok=False, detail=str(exc))])
        return HealthReport(
            checks=[
                CheckResult(name=probe, ok=True, detail="reachable"),
                *self._mgmt_reachability_checks(rules),
            ]
        )

    # -- local bookkeeping (rule IDs and versions the device does not keep) --

    def _rule_ids(self) -> dict[int, int]:
        raw = self.store.get_meta(_RULE_IDS_KEY)
        return {int(k): v for k, v in json.loads(raw).items()} if raw else {}

    def _set_rule_ids(self, ids: dict[int, int]) -> None:
        self.store.set_meta(_RULE_IDS_KEY, json.dumps({str(k): v for k, v in ids.items()}))

    def _observe_version(self, rules: list[FlowRule]) -> int:
        fp = table_fingerprint(rules)
        raw = self.store.get_meta(_VERSION_KEY)
        seen = json.loads(raw) if raw else {"fingerprint": None, "version": 0}
        if seen["fingerprint"] != fp:
            seen = {"fingerprint": fp, "version": int(seen["version"]) + 1}
            self.store.set_meta(_VERSION_KEY, json.dumps(seen))
        return int(seen["version"])
