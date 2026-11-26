"""Signed scope files: load, verify, match, and always-blocked addresses.

The scope file is the hard authorization boundary.  The agent can never widen
it; only ARTEX writes it.  Every check here is default-deny.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .errors import (
    SCOPE_DENIED,
    SCOPE_EXPIRED,
    SCOPE_MISSING,
    RunnerError,
)

SCOPE_SCHEMA = "artex.scope.v1"
_SIGNATURE_PREFIX = "hmac-sha256:"
_MAX_SCOPE_BYTES = 2 * 1024 * 1024
_MAX_FUTURE_SKEW_S = 120
_CACHE_TTL_S = 5.0

_BLOCKED_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("255.255.255.255/32"),
)


def canonical_scope_payload(payload: dict[str, Any]) -> bytes:
    """Canonical JSON: signature removed, sorted keys, no whitespace, UTF-8."""

    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_scope(payload: dict[str, Any], key: bytes) -> str:
    digest = hmac.new(key, canonical_scope_payload(payload), hashlib.sha256).hexdigest()
    return _SIGNATURE_PREFIX + digest


def verify_scope_signature(payload: dict[str, Any], key: bytes) -> bool:
    signature = payload.get("signature")
    if not isinstance(signature, str) or not signature.startswith(_SIGNATURE_PREFIX):
        return False
    provided = signature[len(_SIGNATURE_PREFIX) :]
    if len(provided) != 64:
        return False
    expected = hmac.new(key, canonical_scope_payload(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


def _parse_dt(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(SCOPE_DENIED, f"scope field {field_name} is missing")
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise RunnerError(SCOPE_DENIED, f"scope field {field_name} is not a timestamp") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_domain(value: str) -> str:
    """Lowercase, strip a trailing dot, and validate a DNS name/wildcard."""

    if not isinstance(value, str):
        raise RunnerError(SCOPE_DENIED, "scope contains a non-string domain")
    v = value.strip().lower().rstrip(".")
    wildcard = v.startswith("*.")
    base = v[2:] if wildcard else v
    if not base or "*" in base or "/" in base or " " in base:
        raise RunnerError(SCOPE_DENIED, "scope contains an invalid domain")
    try:
        base = base.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise RunnerError(SCOPE_DENIED, "scope contains an invalid domain") from exc
    if len(base) > 253:
        raise RunnerError(SCOPE_DENIED, "scope contains an overlong domain")
    for label in base.split("."):
        if not label or len(label) > 63:
            raise RunnerError(SCOPE_DENIED, "scope contains an invalid domain")
        if label[0] == "-" or label[-1] == "-":
            raise RunnerError(SCOPE_DENIED, "scope contains an invalid domain")
        if not all(ch.isalnum() or ch in "-_" for ch in label):
            raise RunnerError(SCOPE_DENIED, "scope contains an invalid domain")
    return ("*." if wildcard else "") + base


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError as exc:
        raise RunnerError(SCOPE_DENIED, "scope contains an invalid IP address") from exc


def _parse_net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise RunnerError(SCOPE_DENIED, "scope contains an invalid network") from exc


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    return any(ip.version == net.version and ip in net for net in _BLOCKED_NETS)


def _domain_match(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host != suffix and host.endswith("." + suffix)
    return host == pattern


def _norm_target(target: str) -> str:
    if not isinstance(target, str):
        raise RunnerError(SCOPE_DENIED, "target must be a string")
    target = target.strip()
    if not target or len(target) > 255:
        raise RunnerError(SCOPE_DENIED, "target is empty or too long")
    if target.startswith("-"):
        raise RunnerError(SCOPE_DENIED, "target must not start with '-'")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in target):
        raise RunnerError(SCOPE_DENIED, "target contains whitespace or control characters")
    return target


def _split_target_port(target: str, default_port: int) -> tuple[str, int]:
    target = _norm_target(target)
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError as exc:
                raise RunnerError(SCOPE_DENIED, "invalid port") from exc
        return host, default_port
    if target.count(":") == 1:
        host, port_s = target.rsplit(":", 1)
        if port_s.isdigit():
            port = int(port_s)
            if 1 <= port <= 65535:
                return host, port
            raise RunnerError(SCOPE_DENIED, "invalid port")
    return target, default_port


def local_interface_ips() -> set[str]:
    """Best-effort local container addresses (blocked unless explicitly scoped)."""

    out: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = str(info[4][0]).split("%", 1)[0]
            if addr:
                out.add(addr)
    except OSError:
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1, no packet is sent
            out.add(sock.getsockname()[0])
        finally:
            sock.close()
    except OSError:
        pass
    return out


def default_gateways() -> set[str]:
    out: set[str] = set()
    try:
        with open("/proc/net/route", "r", encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    try:
                        raw = bytes.fromhex(parts[2])
                        out.add(str(ipaddress.IPv4Address(int.from_bytes(raw, "little"))))
                    except (ValueError, ipaddress.AddressValueError):
                        continue
    except OSError:
        pass
    try:
        with open("/proc/net/ipv6_route", "r", encoding="ascii") as fh:
            for line in fh:
                parts = line.split()
                # dest(32 hex) dest_prefix src src_prefix next_hop ...
                if len(parts) >= 5 and parts[0] == "0" * 32 and parts[1] == "00":
                    try:
                        out.add(str(ipaddress.IPv6Address(int(parts[4], 16))))
                    except (ValueError, ipaddress.AddressValueError):
                        continue
    except OSError:
        pass
    return out


@dataclass(frozen=True)
class ScopePolicy:
    max_rate: int = 500
    max_hosts: int = 4096
    allow_syn: bool = False
    allow_os_detect: bool = False
    allow_axfr: bool = False

    @classmethod
    def from_dict(cls, raw: Any) -> "ScopePolicy":
        if not isinstance(raw, dict):
            raise RunnerError(SCOPE_DENIED, "scope policy is missing")
        required = {"max_rate", "max_hosts", "allow_syn", "allow_os_detect", "allow_axfr"}
        if set(raw.keys()) != required:
            raise RunnerError(SCOPE_DENIED, "scope policy has unexpected fields")
        try:
            max_rate = int(raw["max_rate"])
            max_hosts = int(raw["max_hosts"])
        except (TypeError, ValueError) as exc:
            raise RunnerError(SCOPE_DENIED, "scope policy is invalid") from exc
        if not 1 <= max_rate <= 1000:
            raise RunnerError(SCOPE_DENIED, "scope policy max_rate is out of range")
        if not 1 <= max_hosts <= 65536:
            raise RunnerError(SCOPE_DENIED, "scope policy max_hosts is out of range")
        for key in ("allow_syn", "allow_os_detect", "allow_axfr"):
            if not isinstance(raw[key], bool):
                raise RunnerError(SCOPE_DENIED, f"scope policy {key} is not a boolean")
        return cls(
            max_rate=max_rate,
            max_hosts=max_hosts,
            allow_syn=bool(raw["allow_syn"]),
            allow_os_detect=bool(raw["allow_os_detect"]),
            allow_axfr=bool(raw["allow_axfr"]),
        )


@dataclass(frozen=True)
class Scope:
    task_id: int
    company_id: int | None
    engagement: str
    domains: tuple[str, ...]
    ips: tuple[str, ...]
    cidrs: tuple[str, ...]
    excludes: tuple[str, ...]
    exclude_ports: frozenset[int]
    policy: ScopePolicy
    issued_at: datetime
    expires_at: datetime
    nonce: str
    raw: dict[str, Any] = field(repr=False, compare=False)

    # Derived, normalized forms (excluded from equality/repr).
    domains_set: frozenset[str] = field(default=frozenset(), repr=False, compare=False)
    ips_set: frozenset[Any] = field(default=frozenset(), repr=False, compare=False)
    nets: tuple[Any, ...] = field(default=(), repr=False, compare=False)
    exclude_domains: tuple[str, ...] = field(default=(), repr=False, compare=False)
    exclude_ips: frozenset[Any] = field(default=frozenset(), repr=False, compare=False)
    exclude_nets: tuple[Any, ...] = field(default=(), repr=False, compare=False)


def parse_scope(
    payload: dict[str, Any],
    *,
    expected_task_id: int,
    now: datetime | None = None,
) -> Scope:
    """Validate a signature-verified payload and build a normalized Scope."""

    now = now or datetime.now(timezone.utc)
    if payload.get("schema") != SCOPE_SCHEMA:
        raise RunnerError(SCOPE_DENIED, "scope file has an unsupported schema")
    try:
        task_id = int(payload.get("task_id"))
    except (TypeError, ValueError) as exc:
        raise RunnerError(SCOPE_DENIED, "scope task_id is invalid") from exc
    if task_id != int(expected_task_id):
        raise RunnerError(SCOPE_DENIED, "scope file belongs to a different task")

    issued_at = _parse_dt(payload.get("issued_at"), "issued_at")
    expires_at = _parse_dt(payload.get("expires_at"), "expires_at")
    if expires_at <= now:
        raise RunnerError(
            SCOPE_EXPIRED,
            f"scope for task {task_id} expired at {expires_at.isoformat()}",
            details={"expires_at": expires_at.isoformat()},
        )
    if issued_at > now + timedelta(seconds=_MAX_FUTURE_SKEW_S):
        raise RunnerError(SCOPE_DENIED, "scope is issued in the future")

    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 16:
        raise RunnerError(SCOPE_DENIED, "scope nonce is missing or too short")

    domains_raw = payload.get("domains")
    ips_raw = payload.get("ips")
    cidrs_raw = payload.get("cidrs")
    excludes_raw = payload.get("excludes", [])
    ports_raw = payload.get("exclude_ports", [])
    for name, value in (
        ("domains", domains_raw),
        ("ips", ips_raw),
        ("cidrs", cidrs_raw),
        ("excludes", excludes_raw),
    ):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise RunnerError(SCOPE_DENIED, f"scope {name} must be a string array")
    if not isinstance(ports_raw, list):
        raise RunnerError(SCOPE_DENIED, "scope exclude_ports must be an integer array")

    domains: list[str] = []
    for raw in domains_raw:
        d = normalize_domain(raw)
        if d not in domains:
            domains.append(d)
    ips: list[str] = []
    ip_objs: list[Any] = []
    for raw in ips_raw:
        ip = _parse_ip(raw)
        if str(ip) not in ips:
            ips.append(str(ip))
            ip_objs.append(ip)
    cidrs: list[str] = []
    nets: list[Any] = []
    for raw in cidrs_raw:
        net = _parse_net(raw)
        text = str(net)
        if text not in cidrs:
            cidrs.append(text)
            nets.append(net)

    excludes: list[str] = []
    exclude_domains: list[str] = []
    exclude_ips: list[Any] = []
    exclude_nets: list[Any] = []
    for raw in excludes_raw:
        entry = raw.strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("*.") or (not _looks_like_ip_or_net(entry)):
            d = normalize_domain(entry)
            if d not in exclude_domains:
                exclude_domains.append(d)
                excludes.append(d)
            continue
        if "/" in entry:
            net = _parse_net(entry)
            if str(net) not in excludes:
                excludes.append(str(net))
            exclude_nets.append(net)
        else:
            ip = _parse_ip(entry)
            if str(ip) not in excludes:
                excludes.append(str(ip))
            exclude_ips.append(ip)

    exclude_ports: set[int] = set()
    for raw in ports_raw:
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise RunnerError(SCOPE_DENIED, "scope exclude_ports is invalid") from exc
        if not 1 <= port <= 65535:
            raise RunnerError(SCOPE_DENIED, "scope exclude_ports is out of range")
        exclude_ports.add(port)

    company_id: int | None = None
    if payload.get("company_id") is not None:
        try:
            company_id = int(payload["company_id"])
        except (TypeError, ValueError) as exc:
            raise RunnerError(SCOPE_DENIED, "scope company_id is invalid") from exc

    engagement = payload.get("engagement") or ""
    if not isinstance(engagement, str):
        raise RunnerError(SCOPE_DENIED, "scope engagement is invalid")

    return Scope(
        task_id=task_id,
        company_id=company_id,
        engagement=engagement[:200],
        domains=tuple(domains),
        ips=tuple(ips),
        cidrs=tuple(cidrs),
        excludes=tuple(excludes),
        exclude_ports=frozenset(exclude_ports),
        policy=ScopePolicy.from_dict(payload.get("policy")),
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        raw=payload,
        domains_set=frozenset(domains),
        ips_set=frozenset(ip_objs),
        nets=tuple(nets),
        exclude_domains=tuple(exclude_domains),
        exclude_ips=frozenset(exclude_ips),
        exclude_nets=tuple(exclude_nets),
    )


def _looks_like_ip_or_net(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_scope_payload(
    payload: dict[str, Any],
    key: bytes,
    expected_task_id: int,
    now: datetime | None = None,
) -> Scope:
    if not verify_scope_signature(payload, key):
        raise RunnerError(SCOPE_DENIED, "scope signature verification failed")
    return parse_scope(payload, expected_task_id=expected_task_id, now=now)


class ScopeStore:
    """Loads and verifies ``<scope_dir>/<task_id>.json`` with a short cache."""

    def __init__(
        self,
        scope_dir: Path,
        key: bytes,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.scope_dir = Path(scope_dir)
        self.key = key
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._cache: dict[int, tuple[int, int, float, Scope]] = {}
        self._lock = threading.Lock()

    def load(self, task_id: int) -> Scope:
        if not isinstance(task_id, int) or task_id <= 0:
            raise RunnerError(SCOPE_MISSING, "task_id is required to load a scope")
        path = self.scope_dir / f"{int(task_id)}.json"
        try:
            stat = path.stat()
        except FileNotFoundError as exc:
            raise RunnerError(
                SCOPE_MISSING,
                f"no scope file for task {task_id}; the runner denies all scans until ARTEX exports one",
                details={"task_id": task_id},
            ) from exc
        except OSError as exc:
            raise RunnerError(SCOPE_DENIED, "scope file is not readable") from exc
        if stat.st_size > _MAX_SCOPE_BYTES:
            raise RunnerError(SCOPE_DENIED, "scope file is unexpectedly large")

        now_mono = time.monotonic()
        with self._lock:
            cached = self._cache.get(int(task_id))
        if (
            cached
            and cached[0] == stat.st_mtime_ns
            and cached[1] == stat.st_size
            and now_mono - cached[2] <= _CACHE_TTL_S
        ):
            return cached[3]

        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise RunnerError(SCOPE_DENIED, "scope file is not readable") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError(SCOPE_DENIED, "scope file is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise RunnerError(SCOPE_DENIED, "scope file is not a JSON object")
        scope = load_scope_payload(
            payload, self.key, int(task_id), now=self._now()
        )
        with self._lock:
            self._cache[int(task_id)] = (
                stat.st_mtime_ns,
                stat.st_size,
                now_mono,
                scope,
            )
        return scope

    def invalidate(self, task_id: int | None = None) -> None:
        with self._lock:
            if task_id is None:
                self._cache.clear()
            else:
                self._cache.pop(int(task_id), None)


@dataclass(frozen=True)
class Authorization:
    target: str
    kind: str  # ip | cidr | domain
    resolved_ips: tuple[str, ...] = ()
    effective_rate: int = 0
    warnings: tuple[str, ...] = ()


class ScopeAuthorizer:
    """Authorizes one target for one tool call.

    Resolution is performed once per authorization.  Tools that accept an IP
    receive the resolved address; hostname-only tools (LDAP/Kerberos) have a
    documented TOCTOU window between this check and their own connection.
    """

    def __init__(
        self,
        scope: Scope,
        *,
        local_ips: Iterable[str] | None = None,
        gateways: Iterable[str] | None = None,
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self.scope = scope
        protected = set(local_ips if local_ips is not None else local_interface_ips())
        protected |= set(gateways if gateways is not None else default_gateways())
        self.protected_ips = {
            _parse_ip(ip) for ip in protected if _looks_like_ip_or_net(ip) and "/" not in ip
        }
        self._resolver = resolver or _system_resolve

    # -- individual checks -------------------------------------------------

    def _explicitly_allowed_ip(self, ip: Any) -> bool:
        if ip in self.scope.ips_set:
            return True
        return any(ip.version == net.version and ip in net for net in self.scope.nets)

    def _explicit_ip_entry(self, ip: Any) -> bool:
        """True only when the exact address is an ``ips`` entry.

        A protected address inside an allowed CIDR is not "explicitly present
        as a target"; operators must list the address itself.
        """

        return ip in self.scope.ips_set

    def _is_excluded_ip(self, ip: Any) -> bool:
        if ip in self.scope.exclude_ips:
            return True
        return any(
            ip.version == net.version and ip in net for net in self.scope.exclude_nets
        )

    def _blocked_or_protected(self, ip: Any, *, require_explicit: bool = True) -> str | None:
        if _is_blocked_ip(ip):
            return "target resolves to an always-blocked address"
        if self._is_excluded_ip(ip):
            return "target is excluded by the task scope"
        explicitly_allowed = self._explicitly_allowed_ip(ip)
        if ip in self.protected_ips and not self._explicit_ip_entry(ip):
            # The runner's own address and the default gateway are denied
            # unless the operator explicitly listed that exact address as a
            # scope target (normally never).
            return "target is the runner's own address or default gateway"
        if require_explicit and not explicitly_allowed:
            return "target is outside the task scope"
        return None

    def authorize_ip(self, value: str) -> Authorization:
        ip = _parse_ip(_norm_target(value))
        reason = self._blocked_or_protected(ip)
        if reason:
            raise RunnerError(
                SCOPE_DENIED,
                f"target {ip} is not authorized for task {self.scope.task_id}: {reason}",
                details={"target": str(ip), "task_id": self.scope.task_id},
            )
        return Authorization(
            target=str(ip),
            kind="ip",
            resolved_ips=(str(ip),),
            effective_rate=self.effective_rate(None),
        )

    def authorize_cidr(self, value: str) -> Authorization:
        target = _norm_target(value)
        net = _parse_net(target)
        if net.num_addresses > self.scope.policy.max_hosts:
            raise RunnerError(
                SCOPE_DENIED,
                f"target {net} exceeds max_hosts={self.scope.policy.max_hosts}; split it into smaller ranges",
                details={
                    "target": str(net),
                    "max_hosts": self.scope.policy.max_hosts,
                    "hint": "split the range into smaller CIDRs",
                },
            )
        contained = any(
            net.version == allowed.version and net.subnet_of(allowed)
            for allowed in self.scope.nets
        )
        if not contained:
            raise RunnerError(
                SCOPE_DENIED,
                f"target {net} is not fully contained in task {self.scope.task_id}'s scope",
                details={"target": str(net), "task_id": self.scope.task_id},
            )
        for blocked in _BLOCKED_NETS:
            if net.version == blocked.version and net.overlaps(blocked):
                raise RunnerError(
                    SCOPE_DENIED,
                    f"target {net} overlaps an always-blocked address range",
                    details={"target": str(net)},
                )
        for excluded in self.scope.exclude_nets:
            if net.version == excluded.version and net.overlaps(excluded):
                raise RunnerError(
                    SCOPE_DENIED,
                    f"target {net} overlaps an excluded range",
                    details={"target": str(net)},
                )
        for excluded_ip in self.scope.exclude_ips:
            if excluded_ip.version == net.version and excluded_ip in net:
                raise RunnerError(
                    SCOPE_DENIED,
                    f"target {net} contains an excluded address",
                    details={"target": str(net)},
                )
        for protected in self.protected_ips:
            if (
                protected.version == net.version
                and protected in net
                and not self._explicit_ip_entry(protected)
            ):
                raise RunnerError(
                    SCOPE_DENIED,
                    f"target {net} contains the runner's own address or default gateway",
                    details={"target": str(net)},
                )
        return Authorization(
            target=str(net),
            kind="cidr",
            effective_rate=self.effective_rate(None),
        )

    def authorize_domain(self, value: str) -> Authorization:
        host = normalize_domain(_norm_target(value))
        if host.startswith("*."):
            raise RunnerError(
                SCOPE_DENIED,
                "target must be a concrete host, not a wildcard",
                details={"target": host},
            )
        if not any(_domain_match(pattern, host) for pattern in self.scope.domains):
            raise RunnerError(
                SCOPE_DENIED,
                f"domain {host} is outside task {self.scope.task_id}'s scope",
                details={"target": host, "task_id": self.scope.task_id},
            )
        if any(_domain_match(pattern, host) for pattern in self.scope.exclude_domains):
            raise RunnerError(
                SCOPE_DENIED,
                f"domain {host} is excluded by the task scope",
                details={"target": host},
            )
        resolved = self._resolve(host)
        if not resolved:
            raise RunnerError(
                SCOPE_DENIED,
                f"domain {host} did not resolve to any address",
                details={"target": host},
            )
        resolved_ips: list[str] = []
        for raw in resolved:
            ip = _parse_ip(raw.split("%", 1)[0])
            reason = self._blocked_or_protected(ip, require_explicit=False)
            if reason:
                raise RunnerError(
                    SCOPE_DENIED,
                    f"domain {host} resolves to {ip}, which is not allowed: {reason}",
                    details={"target": host, "resolved_ip": str(ip)},
                )
            if str(ip) not in resolved_ips:
                resolved_ips.append(str(ip))
        return Authorization(
            target=host,
            kind="domain",
            resolved_ips=tuple(resolved_ips),
            effective_rate=self.effective_rate(None),
        )

    def authorize_target(self, value: str) -> Authorization:
        target = _norm_target(value)
        if "/" in target:
            return self.authorize_cidr(target)
        try:
            ipaddress.ip_address(target.strip("[]"))
        except ValueError:
            return self.authorize_domain(target)
        return self.authorize_ip(target)

    # -- helpers -----------------------------------------------------------

    def _resolve(self, host: str) -> list[str]:
        try:
            return self._resolver(host)
        except OSError as exc:
            raise RunnerError(
                SCOPE_DENIED,
                f"domain {host} could not be resolved",
                details={"target": host},
            ) from exc

    def effective_rate(self, requested: int | None) -> int:
        if requested is None or requested <= 0:
            return self.scope.policy.max_rate
        return min(int(requested), self.scope.policy.max_rate)

    def check_port(self, port: int) -> None:
        if port in self.scope.exclude_ports:
            raise RunnerError(
                SCOPE_DENIED,
                f"port {port} is excluded by the task scope",
                details={"port": port},
            )

    def check_ports(self, ports: Iterable[int]) -> None:
        blocked = sorted({p for p in ports if p in self.scope.exclude_ports})
        if blocked:
            raise RunnerError(
                SCOPE_DENIED,
                "one or more requested ports are excluded by the task scope",
                details={"ports": blocked},
            )

    def excluded_ports_arg(self) -> str | None:
        if not self.scope.exclude_ports:
            return None
        return ",".join(str(p) for p in sorted(self.scope.exclude_ports))

    def require_syn(self) -> None:
        if not self.scope.policy.allow_syn:
            raise RunnerError(
                SCOPE_DENIED,
                "SYN scanning is disabled by the task scope policy",
                details={"policy": "allow_syn"},
            )

    def require_os_detect(self) -> None:
        if not self.scope.policy.allow_os_detect:
            raise RunnerError(
                SCOPE_DENIED,
                "OS detection is disabled by the task scope policy",
                details={"policy": "allow_os_detect"},
            )

    def require_axfr(self) -> None:
        if not self.scope.policy.allow_axfr:
            raise RunnerError(
                SCOPE_DENIED,
                "zone transfer is disabled by the task scope policy",
                details={"policy": "allow_axfr"},
            )


def _system_resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if addr and addr not in out:
            out.append(addr)
    return out


def split_host_port(target: str, default_port: int) -> tuple[str, int]:
    """Public helper used by tools that accept ``host:port``."""

    return _split_target_port(target, default_port)


def format_host_port(host: str, port: int) -> str:
    """Format ``host:port``, bracketing IPv6 literals for tools that need it."""

    value = (host or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return f"{value}:{port}"
    if ip.version == 6:
        return f"[{value}]:{port}"
    return f"{value}:{port}"


def parse_port_list(spec: str) -> list[int]:
    """Parse an nmap-style port list (``22,80,8000-8100``) for validation."""

    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise RunnerError(SCOPE_DENIED, "invalid port range")
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    if any(p < 1 or p > 65535 for p in ports):
        raise RunnerError(SCOPE_DENIED, "port is out of range")
    return ports


def safe_filename_component(value: str) -> str:
    """Reject anything that could traverse out of the artifact directory."""

    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise RunnerError(SCOPE_DENIED, "invalid path component")
    return value


def file_under(root: Path, relative: str) -> Path:
    """Join a relative artifact path and prove it stays under ``root``."""

    if not relative or os.path.isabs(relative):
        raise RunnerError(SCOPE_DENIED, "artifact path must be relative")
    parts = Path(relative).parts
    if any(part in {"..", ""} for part in parts):
        raise RunnerError(SCOPE_DENIED, "artifact path contains traversal")
    full = (Path(root) / Path(*parts)).resolve()
    root_resolved = Path(root).resolve()
    try:
        full.relative_to(root_resolved)
    except ValueError as exc:
        raise RunnerError(SCOPE_DENIED, "artifact path escapes the data directory") from exc
    return full
