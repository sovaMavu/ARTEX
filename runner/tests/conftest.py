"""Shared fixtures for the runner test suite."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from runner.config import Config
from runner.scope import Scope, load_scope_payload, sign_scope

SCOPE_KEY = b"k" * 32
TASK_ID = 42


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scope_payload(**overrides: Any) -> dict[str, Any]:
    now = utc_now()
    payload: dict[str, Any] = {
        "schema": "artex.scope.v1",
        "task_id": TASK_ID,
        "company_id": 7,
        "engagement": "test-engagement",
        "domains": ["example.com", "*.example.com"],
        "ips": ["203.0.113.10"],
        "cidrs": ["10.10.0.0/16"],
        "excludes": ["10.10.5.0/24", "admin.example.com"],
        "exclude_ports": [22, 3389],
        "policy": {
            "max_rate": 500,
            "max_hosts": 4096,
            "allow_syn": False,
            "allow_os_detect": False,
            "allow_axfr": False,
        },
        "issued_at": iso(now),
        "expires_at": iso(now + timedelta(days=30)),
        "nonce": "0123456789abcdef",
    }
    payload.update(overrides)
    return payload


def signed_scope(**overrides: Any) -> dict[str, Any]:
    payload = scope_payload(**overrides)
    payload["signature"] = sign_scope(payload, SCOPE_KEY)
    return payload


def load_scope(**overrides: Any) -> Scope:
    return load_scope_payload(signed_scope(**overrides), SCOPE_KEY, TASK_ID)


def write_scope(
    directory: Path,
    *,
    task_id: int = TASK_ID,
    payload: dict[str, Any] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{task_id}.json"
    path.write_text(json.dumps(payload or signed_scope()), encoding="utf-8")
    return path


@pytest.fixture
def key() -> bytes:
    return SCOPE_KEY


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        token="t" * 32,
        scope_key=SCOPE_KEY,
        scope_dir=tmp_path / "scopes",
        artifact_root=tmp_path / "artifacts",
    )


@pytest.fixture
def scope() -> Scope:
    return load_scope()


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    return write_scope(tmp_path / "scopes")
