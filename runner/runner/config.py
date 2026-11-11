"""Environment configuration for the runner.

Configuration is validated once at startup.  Missing or malformed secrets are a
hard failure: the service must never come up with an empty bearer token or a
weak scope key.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class ConfigError(ValueError):
    pass


def _env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = (env.get(name) or "").strip()
    if raw == "":
        return default
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = (env.get(name) or "").strip().lower()
    if raw == "":
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean")


@dataclass(frozen=True)
class Config:
    token: str
    scope_key: bytes
    scope_dir: Path
    artifact_root: Path
    max_concurrent_jobs: int = 4
    max_jobs_per_task: int = 2
    default_timeout_s: int = 600
    max_timeout_s: int = 3600
    max_output_bytes: int = 1_048_576
    max_artifact_bytes: int = 64 * 1024 * 1024
    job_retention_s: int = 86_400
    dns_resolvers: tuple[str, ...] = ()
    log_level: str = "info"
    tool_packs: tuple[str, ...] = ("net",)
    home: str = "/tmp"
    host: str = "0.0.0.0"
    port: int = 8899
    max_request_bytes: int = 1_048_576

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env

        token = (env.get("RUNNER_TOKEN") or "").strip()
        if not token:
            raise ConfigError("RUNNER_TOKEN is required")
        # The spec requires 32+ random bytes.  A 32-character token is the
        # minimum acceptable encoded form (hex/base64 tokens are longer).
        if len(token) < 32:
            raise ConfigError("RUNNER_TOKEN must be at least 32 characters")

        key_raw = (env.get("RUNNER_SCOPE_KEY") or "").strip()
        if not key_raw:
            raise ConfigError("RUNNER_SCOPE_KEY is required")
        try:
            key = base64.b64decode(key_raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError("RUNNER_SCOPE_KEY must be valid base64") from exc
        if len(key) != 32:
            raise ConfigError("RUNNER_SCOPE_KEY must decode to exactly 32 bytes")

        log_level = (env.get("LOG_LEVEL") or "info").strip().lower()
        if log_level not in {"debug", "info", "warn", "warning", "error"}:
            raise ConfigError("LOG_LEVEL must be debug|info|warn|error")
        if log_level == "warning":
            log_level = "warn"

        packs = tuple(
            p.strip().lower()
            for p in (env.get("TOOL_PACKS") or "net").split(",")
            if p.strip()
        )
        if not packs:
            raise ConfigError("TOOL_PACKS must contain at least one pack")

        resolvers = tuple(
            r.strip()
            for r in (env.get("DNS_RESOLVERS") or "").split(",")
            if r.strip()
        )

        return cls(
            token=token,
            scope_key=key,
            scope_dir=Path(env.get("SCOPE_DIR") or "/scopes"),
            artifact_root=Path(env.get("ARTIFACT_ROOT") or "/artifacts"),
            max_concurrent_jobs=_env_int(env, "MAX_CONCURRENT_JOBS", 4, 1, 128),
            max_jobs_per_task=_env_int(env, "MAX_JOBS_PER_TASK", 2, 1, 64),
            default_timeout_s=_env_int(env, "DEFAULT_TIMEOUT_S", 600, 1, 86_400),
            max_timeout_s=_env_int(env, "MAX_TIMEOUT_S", 3600, 1, 86_400),
            max_output_bytes=_env_int(
                env, "MAX_OUTPUT_BYTES", 1_048_576, 1024, 64 * 1024 * 1024
            ),
            max_artifact_bytes=_env_int(
                env, "MAX_ARTIFACT_BYTES", 64 * 1024 * 1024, 1024, 1024 * 1024 * 1024
            ),
            job_retention_s=_env_int(
                env, "JOB_RETENTION_S", 86_400, 60, 30 * 86_400
            ),
            dns_resolvers=resolvers,
            log_level=log_level,
            tool_packs=packs,
            home=env.get("HOME") or "/tmp",
            host=(env.get("RUNNER_HOST") or "0.0.0.0").strip(),
            port=_env_int(env, "RUNNER_PORT", 8899, 1, 65_535),
            max_request_bytes=_env_int(
                env, "MAX_REQUEST_BYTES", 1_048_576, 1024, 16 * 1024 * 1024
            ),
        )

    def net_pack_enabled(self) -> bool:
        return "net" in self.tool_packs
