"""Runtime settings loaded from environment variables (and an optional `.env` file)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from dotenv import load_dotenv

Mode = Literal["mock", "live"]
LLMBackend = Literal["auto", "bf16", "4bit", "vllm", "replay"]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw and raw.strip() else default


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    return raw.strip() if raw and raw.strip() else default


@dataclass(frozen=True)
class IOSXESettings:
    host: str = ""
    username: str = ""
    password: str = field(default="", repr=False)
    restconf_port: int = 443
    netconf_port: int = 830
    verify_tls: bool = False
    acl_name: str = "SDN-GUARDIAN"


@dataclass(frozen=True)
class Settings:
    mode: Mode = "mock"
    db_path: str = "./sdn_guardian.db"
    commit_timeout_s: int = 30
    protected_subnets: tuple[IPv4Network, ...] = (IPv4Network("10.10.10.0/24"),)
    controller_ip: IPv4Address = IPv4Address("10.10.10.10")
    iosxe: IOSXESettings = field(default_factory=IOSXESettings)
    hf_token: str = field(default="", repr=False)
    llm_backend: LLMBackend = "auto"

    @classmethod
    def from_env(cls, dotenv: bool = True) -> Settings:
        if dotenv:
            load_dotenv(override=False)
        mode = _env_str("SDN_GUARDIAN_MODE", "mock").lower()
        if mode not in ("mock", "live"):
            raise ValueError(f"SDN_GUARDIAN_MODE must be 'mock' or 'live', got {mode!r}")
        backend = _env_str("SDN_GUARDIAN_LLM_BACKEND", "auto").lower()
        if backend not in ("auto", "bf16", "4bit", "vllm", "replay"):
            raise ValueError(f"Unknown SDN_GUARDIAN_LLM_BACKEND {backend!r}")
        timeout = _env_int("SDN_GUARDIAN_COMMIT_TIMEOUT", 30)
        if timeout <= 0:
            raise ValueError("SDN_GUARDIAN_COMMIT_TIMEOUT must be > 0")
        subnets = tuple(
            IPv4Network(s.strip(), strict=False)
            for s in _env_str("SDN_GUARDIAN_PROTECTED_SUBNETS", "10.10.10.0/24").split(",")
            if s.strip()
        )
        return cls(
            mode=mode,  # type: ignore[arg-type]
            db_path=_env_str("SDN_GUARDIAN_DB", "./sdn_guardian.db"),
            commit_timeout_s=timeout,
            protected_subnets=subnets,
            controller_ip=IPv4Address(_env_str("SDN_GUARDIAN_CONTROLLER_IP", "10.10.10.10")),
            iosxe=IOSXESettings(
                host=_env_str("IOSXE_HOST", ""),
                username=_env_str("IOSXE_USERNAME", ""),
                password=os.getenv("IOSXE_PASSWORD", ""),
                restconf_port=_env_int("IOSXE_RESTCONF_PORT", 443),
                netconf_port=_env_int("IOSXE_NETCONF_PORT", 830),
                verify_tls=_env_bool("IOSXE_VERIFY_TLS", False),
                acl_name=_env_str("IOSXE_ACL_NAME", "SDN-GUARDIAN"),
            ),
            hf_token=os.getenv("HF_TOKEN", ""),
            llm_backend=backend,  # type: ignore[arg-type]
        )
