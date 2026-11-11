"""Typed Phase 1 network tools and their parsers.

There is deliberately no generic command bridge: every tool builds a fixed
argv vector from validated fields and the scope policy.  Shell interpolation
is never used.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from defusedxml import ElementTree as DefusedET
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .. import audit
from ..config import Config
from ..errors import (
    INVALID_ARGUMENT,
    INTERNAL,
    NOT_IMPLEMENTED,
    RATE_LIMITED,
    SCOPE_DENIED,
    TOOL_FAILED,
    TOOL_MISSING,
    TOOL_TIMEOUT,
    RunnerError,
    missing_binary,
)
from ..jobs import Job, JobCancelled, JobManager, JobOutcome
from ..sanitize import clean_text, redact_argv, truncate_text
from ..scope import (
    ScopeAuthorizer,
    ScopeStore,
    format_host_port,
    parse_port_list,
    split_host_port,
)

# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NmapInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    profile: Literal["discovery", "top100", "top1000", "full_tcp", "udp_top100", "custom"]
    ports: str | None = Field(default=None, pattern=r"^[0-9,-]{1,256}$")
    rate: int | None = Field(default=None, ge=1, le=1000)
    timeout_s: int | None = Field(default=None, ge=30, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    scripts: Literal["none", "safe", "discovery"] = "none"
    syn: bool = False
    os_detect: bool = False
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _custom_ports(self) -> "NmapInput":
        if self.profile == "custom" and not self.ports:
            raise ValueError("ports is required when profile=custom")
        if self.profile == "discovery" and (self.syn or self.os_detect):
            raise ValueError("syn/os_detect are not valid for profile=discovery")
        if self.ports:
            try:
                parse_port_list(self.ports)
            except (RunnerError, ValueError) as exc:
                raise ValueError(f"ports is not a valid port list: {exc}") from exc
        return self


class DNSInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    record_types: list[str] | None = None
    resolver: str | None = Field(default=None, max_length=255)
    axfr: bool = False
    timeout_s: int | None = Field(default=None, ge=1, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _types(self) -> "DNSInput":
        allowed = {"A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA"}
        types = [t.upper() for t in (self.record_types or ["A", "AAAA"])]
        if not types or any(t not in allowed for t in types):
            raise ValueError("record_types contains an unsupported type")
        deduped: list[str] = []
        for t in types:
            if t not in deduped:
                deduped.append(t)
        self.record_types = deduped
        return self


class TLSInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    profile: Literal["quick", "full"] = "quick"
    starttls: Literal["none", "smtp", "imap", "pop3", "xmpp", "ftp", "ldap"] = "none"
    timeout_s: int | None = Field(default=None, ge=1, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    reason: str | None = Field(default=None, max_length=500)


class SNMPInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    version: Literal["1", "2c", "3"] = "2c"
    community: str = Field(default="public", max_length=256)
    timeout_s: int | None = Field(default=None, ge=1, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _community(self) -> "SNMPInput":
        if not self.community or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in self.community):
            raise ValueError("community contains control characters")
        return self


class SMBInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    mode: Literal["shares", "users", "groups", "sessions", "policy", "all"] = "all"
    credential_id: int | None = Field(default=None, ge=1)
    timeout_s: int | None = Field(default=None, ge=1, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    reason: str | None = Field(default=None, max_length=500)


class LDAPInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    port: int = Field(default=389, ge=1, le=65535)
    base_dn: str = Field(default="", max_length=1024)
    filter: str = Field(default="(objectClass=*)", max_length=1024)
    attributes: list[str] | None = None
    scope: Literal["base", "one", "sub"] = "sub"
    use_tls: bool = False
    credential_id: int | None = Field(default=None, ge=1)
    max_entries: int = Field(default=200, ge=1, le=1000)
    timeout_s: int | None = Field(default=None, ge=1, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _ldap_fields(self) -> "LDAPInput":
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in self.filter):
            raise ValueError("filter contains control characters")
        if not self.filter.startswith("(") or not self.filter.endswith(")"):
            raise ValueError("filter must be a parenthesized LDAP filter")
        if self.filter.count("(") != self.filter.count(")"):
            raise ValueError("filter has unbalanced parentheses")
        attrs = self.attributes or ["*"]
        if len(attrs) > 50:
            raise ValueError("at most 50 attributes may be requested")
        for attr in attrs:
            if attr in {"*", "+"}:
                continue
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9;._-]{0,63}", attr or ""):
                raise ValueError("invalid attribute name")
        self.attributes = attrs
        if self.base_dn and (
            any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in self.base_dn)
            or self.base_dn.lstrip().startswith("-")
        ):
            raise ValueError("invalid base_dn")
        return self


class SSHInput(_Input):
    task_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    timeout_s: int | None = Field(default=None, ge=1, le=3600)
    wait_s: int = Field(default=30, ge=0, le=120)
    reason: str | None = Field(default=None, max_length=500)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


@dataclass
class Parsed:
    observations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: str = ""


_SERVICE_ALIASES = {
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "http": "http",
    "https": "http",
    "ssl/http": "http",
    "domain": "dns",
    "ldaps": "ldap",
    "ssh": "ssh",
    "snmp": "snmp",
    "microsoft-ds ": "smb",
}


def normalize_service_name(name: str) -> str:
    value = (name or "").strip().lower()
    return _SERVICE_ALIASES.get(value, value or "unknown")


def _text(node: Any) -> str:
    return clean_text(node.text or "") if node is not None else ""


def parse_nmap_xml(xml_bytes: bytes) -> Parsed:
    if not xml_bytes or not xml_bytes.strip():
        raise RunnerError(TOOL_FAILED, "nmap produced no XML output")
    try:
        root = DefusedET.fromstring(xml_bytes)
    except Exception as exc:  # defusedxml raises several parser errors
        raise RunnerError(TOOL_FAILED, "nmap XML could not be parsed") from exc
    if root.tag != "nmaprun":
        raise RunnerError(TOOL_FAILED, "nmap XML has an unexpected root element")

    observations: list[dict[str, Any]] = []
    warnings: list[str] = []
    hosts_up = 0
    open_tcp = 0
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        hosts_up += 1
        addresses = [
            a.get("addr", "")
            for a in host.findall("address")
            if a.get("addrtype") in {"ipv4", "ipv6"}
        ]
        addresses = [a for a in addresses if a]
        if not addresses:
            warnings.append("nmap reported an up host with no IP address")
            continue
        ip = addresses[0]
        hostnames = [
            h.get("name", "")
            for h in host.findall("hostnames/hostname")
            if h.get("name")
        ]
        ip_obs: dict[str, Any] = {"kind": "ip", "ip": ip, "hostnames": hostnames}
        extra: dict[str, Any] = {}
        scripts = []
        for script in host.findall("hostscript/script"):
            sid = script.get("id", "")
            output, _ = truncate_text(clean_text(script.get("output", "")), 2048)
            if sid:
                scripts.append({"id": sid, "output": output})
        if scripts:
            extra["scripts"] = scripts[:20]
        os_matches = []
        for osm in host.findall("os/osmatch"):
            name = osm.get("name", "")
            if not name:
                continue
            try:
                accuracy = int(osm.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            os_matches.append({"name": name, "accuracy": accuracy})
        if os_matches:
            extra["os_matches"] = os_matches[:5]
        if extra:
            ip_obs["extra"] = extra
        observations.append(ip_obs)

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            proto = port.get("protocol", "tcp")
            try:
                portid = int(port.get("portid", "0"))
            except ValueError:
                continue
            if state == "open":
                if proto == "tcp":
                    open_tcp += 1
                svc = port.find("service")
                svc_name = normalize_service_name(svc.get("name", "") if svc is not None else "")
                obs: dict[str, Any] = {
                    "kind": "service",
                    "ip": ip,
                    "port": portid,
                    "proto": proto,
                    "service": svc_name,
                }
                if svc is not None:
                    for attr, key in (
                        ("product", "product"),
                        ("version", "version"),
                        ("extrainfo", "extrainfo"),
                        ("tunnel", "tunnel"),
                        ("method", "method"),
                    ):
                        if svc.get(attr):
                            obs[key] = clean_text(svc.get(attr, ""))[:512]
                    cpes = [c.text for c in svc.findall("cpe") if c.text]
                    port_scripts = []
                    for script in port.findall("script"):
                        sid = script.get("id", "")
                        output, _ = truncate_text(clean_text(script.get("output", "")), 2048)
                        if sid:
                            port_scripts.append({"id": sid, "output": output})
                    if cpes or port_scripts:
                        obs["extra"] = {}
                        if cpes:
                            obs["extra"]["cpe"] = cpes[:10]
                        if port_scripts:
                            obs["extra"]["scripts"] = port_scripts[:20]
                observations.append(obs)
            elif state == "open|filtered":
                warnings.append(
                    f"{ip} {proto}/{portid} is open|filtered; not recorded as an open service"
                )
    if hosts_up == 0:
        warnings.append("nmap reported 0 hosts up")
    summary = f"{hosts_up} host{'s' if hosts_up != 1 else ''} up, {open_tcp} open TCP port{'s' if open_tcp != 1 else ''}"
    return Parsed(observations=observations, warnings=warnings, summary=summary)


def _strip_dot(value: str) -> str:
    return value[:-1] if value.endswith(".") else value


def parse_dig_answer(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        name, ttl_s, _cls, rtype = parts[0], parts[1], parts[2], parts[3].upper()
        values = parts[4:]
        try:
            ttl = int(ttl_s)
        except ValueError:
            ttl = 0
        rec: dict[str, Any] = {
            "name": _strip_dot(name).lower(),
            "type": rtype,
            "ttl": ttl,
            "value": " ".join(values),
        }
        if rtype == "MX" and len(values) >= 2:
            try:
                rec["priority"] = int(values[0])
            except ValueError:
                pass
            rec["value"] = _strip_dot(values[1])
        elif rtype == "SRV" and len(values) >= 4:
            try:
                rec["priority"] = int(values[0])
                rec["weight"] = int(values[1])
                rec["port"] = int(values[2])
            except ValueError:
                pass
            rec["value"] = _strip_dot(values[3])
        elif rtype in {"A", "AAAA", "NS", "CNAME", "PTR"}:
            rec["value"] = _strip_dot(values[0])
        elif rtype == "TXT":
            rec["value"] = " ".join(values).strip('"')
        records.append(rec)
    return records


def parse_testssl_json(data: Any) -> Parsed:
    if isinstance(data, dict):
        entries = data.get("scanResult") or data.get("scanResults") or []
        if isinstance(data.get("id"), str):
            entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        entries = []
    if not isinstance(entries, list):
        entries = []
    protocols: set[str] = set()
    cert: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        eid = str(entry.get("id") or "")
        severity = str(entry.get("severity") or "").upper()
        finding = clean_text(str(entry.get("finding") or ""))
        for match in re.findall(r"(?:TLS\s*v?1(?:\.[0-9])?|SSLv[23])", finding, re.I):
            protocols.add(re.sub(r"\s+", "", match).upper())
        if eid in {"cert", "certificate", "server_certificate"} or "certificate" in entry:
            candidate = entry.get("certificate") if isinstance(entry.get("certificate"), dict) else entry
            if isinstance(candidate, list) and candidate:
                candidate = candidate[0] if isinstance(candidate[0], dict) else {}
            if isinstance(candidate, dict):
                for src, dst in (
                    ("subject", "subject"),
                    ("issuer", "issuer"),
                    ("serial", "serial"),
                    ("notBefore", "not_before"),
                    ("not_before", "not_before"),
                    ("notAfter", "not_after"),
                    ("not_after", "not_after"),
                    ("expires", "not_after"),
                    ("san", "sans"),
                    ("SAN", "sans"),
                    ("subjectAltName", "sans"),
                ):
                    if candidate.get(src) and dst not in cert:
                        cert[dst] = candidate[src]
            for label, key in (
                ("subject:", "subject"),
                ("issuer:", "issuer"),
                ("serial:", "serial"),
                ("notBefore:", "not_before"),
                ("notAfter:", "not_after"),
                ("SAN:", "sans"),
            ):
                if key not in cert:
                    match = re.search(re.escape(label) + r"\s*(.+)", finding, re.I)
                    if match:
                        cert[key] = match.group(1).strip()
        if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"}:
            norm = "LOW" if severity == "WARN" else severity
            findings.append(
                {
                    "kind": "tls_finding",
                    "id": eid or "testssl",
                    "severity": norm,
                    "finding": truncate_text(finding, 2048)[0],
                }
            )
    if isinstance(cert.get("sans"), str):
        cert["sans"] = [s.strip() for s in re.split(r"[,\s]+", cert["sans"]) if s.strip()]
    if cert.get("sans") is None:
        cert.pop("sans", None)
    endpoint = {
        "kind": "tls_endpoint",
        "protocols": sorted(protocols),
        "cert": cert,
    }
    return Parsed(
        observations=[endpoint] + findings[:200],
        warnings=[] if entries else ["testssl produced no scanResult entries"],
        summary=f"{len(protocols)} protocol(s), {len(findings)} finding(s)",
    )


def _find_named_lists(value: Any, wanted: set[str], out: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lk = str(key).lower()
            if lk in wanted and isinstance(child, list):
                out.setdefault(lk, child)
            elif lk in wanted and isinstance(child, dict):
                out.setdefault(lk, child)
            _find_named_lists(child, wanted, out)
    elif isinstance(value, list):
        for child in value:
            _find_named_lists(child, wanted, out)


def parse_enum4linux_json(data: Any) -> Parsed:
    if not isinstance(data, (dict, list)):
        return Parsed(warnings=["enum4linux-ng produced no JSON object"])
    found: dict[str, Any] = {}
    _find_named_lists(
        data,
        {"shares", "users", "groups", "sessions", "passpol", "password_policy", "policy"},
        found,
    )
    observations: list[dict[str, Any]] = []
    warnings: list[str] = []

    def entries(key: str) -> list[dict[str, Any]]:
        value = found.get(key)
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        if isinstance(value, dict):
            for sub in ("shares", "users", "groups", "sessions", "items"):
                if isinstance(value.get(sub), list):
                    return [v for v in value[sub] if isinstance(v, dict)]
            return [value]
        return []

    for share in entries("shares")[:500]:
        name = share.get("name") or share.get("share") or share.get("share_name")
        if not name:
            continue
        obs = {"kind": "smb_share", "name": str(name)[:256]}
        comment = share.get("comment") or share.get("remark")
        if comment:
            obs["comment"] = clean_text(str(comment))[:1024]
        access = share.get("access") or share.get("permissions")
        if access:
            obs["access"] = clean_text(str(access))[:512]
        observations.append(obs)
    for user in entries("users")[:1000]:
        username = user.get("username") or user.get("name") or user.get("user")
        if not username:
            continue
        obs = {"kind": "smb_user", "username": str(username)[:256]}
        if user.get("domain"):
            obs["domain"] = clean_text(str(user["domain"]))[:256]
        if user.get("rid") is not None:
            obs["rid"] = user["rid"]
        if "enabled" in user:
            obs["enabled"] = bool(user["enabled"])
        observations.append(obs)
    for group in entries("groups")[:500]:
        name = group.get("groupname") or group.get("name") or group.get("group")
        if not name:
            continue
        obs = {"kind": "smb_group", "name": str(name)[:256]}
        if group.get("domain"):
            obs["domain"] = clean_text(str(group["domain"]))[:256]
        if group.get("rid") is not None:
            obs["rid"] = group["rid"]
        observations.append(obs)
    policy = found.get("passpol") or found.get("password_policy") or found.get("policy")
    if isinstance(policy, list) and policy:
        policy = policy[0]
    if isinstance(policy, dict):
        obs = {"kind": "smb_password_policy"}
        for src, dst in (
            ("min_password_length", "min_length"),
            ("min_length", "min_length"),
            ("lockout_threshold", "lockout_threshold"),
            ("lockout_duration", "lockout_duration"),
        ):
            if policy.get(src) is not None and dst not in obs:
                obs[dst] = policy[src]
        if len(obs) > 1:
            observations.append(obs)
    sessions = entries("sessions")
    if sessions:
        warnings.append(f"{len(sessions)} SMB session(s) observed; sessions are not persisted in Phase 1")
    return Parsed(
        observations=observations,
        warnings=warnings,
        summary=(
            f"{sum(1 for o in observations if o['kind'] == 'smb_share')} shares, "
            f"{sum(1 for o in observations if o['kind'] == 'smb_user')} users, "
            f"{sum(1 for o in observations if o['kind'] == 'smb_group')} groups"
        ),
    )


def _decode_ldif_value(kind: str, value: str) -> str:
    if kind == "::":
        try:
            return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return ""
    return value


def parse_ldif(text: str, *, max_entries: int = 200) -> tuple[list[dict[str, Any]], list[str]]:
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    logical: list[str] = []
    for raw in (text or "").splitlines():
        if raw.startswith(" "):
            if logical:
                logical[-1] += raw[1:]
            continue
        if raw.strip() == "":
            if logical:
                entries.append(logical)
                logical = []
            continue
        if raw.startswith("#"):
            continue
        logical.append(raw)
    if logical:
        entries.append(logical)

    parsed: list[dict[str, Any]] = []
    for lines in entries:
        if len(parsed) >= max_entries:
            warnings.append(f"LDAP output truncated at {max_entries} entries")
            break
        dn = ""
        attrs: dict[str, Any] = {}
        for line in lines:
            if line.lower().startswith("version:"):
                continue
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9;._-]{0,63})(<|::?)\s*(.*)$", line)
            if not match:
                continue
            name, kind, value = match.group(1).lower(), match.group(2), match.group(3)
            if kind == "<" or (kind == ":" and value.lstrip().startswith("<")):
                warnings.append(f"LDAP attribute {name} referenced an external URL; ignored")
                continue
            decoded = _decode_ldif_value(kind, value)
            if name == "dn":
                dn = decoded
                continue
            if name == "ntsecuritydescriptor":
                continue
            decoded = truncate_text(decoded, 4096)[0]
            if name in attrs:
                existing = attrs[name]
                if isinstance(existing, list):
                    if len(existing) < 50:
                        existing.append(decoded)
                else:
                    attrs[name] = [existing, decoded]
            else:
                attrs[name] = decoded
        if dn or attrs:
            parsed.append({"dn": dn, "attributes": attrs})
    return parsed, warnings


def parse_ssh_audit_json(data: Any) -> Parsed:
    if not isinstance(data, dict):
        raise RunnerError(TOOL_FAILED, "ssh-audit output is not a JSON object")
    banner_raw = data.get("banner")
    if isinstance(banner_raw, dict):
        banner = banner_raw.get("raw") or banner_raw.get("software") or ""
    else:
        banner = str(banner_raw or "")
    banner = clean_text(str(banner))[:1024]

    def algorithms(key: str) -> list[str]:
        value = data.get(key)
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for item in value:
            if isinstance(item, dict):
                alg = item.get("algorithm") or item.get("name")
            else:
                alg = item
            if alg:
                out.append(str(alg)[:256])
        return out[:100]

    kex = algorithms("kex")
    enc = algorithms("enc") or algorithms("encryption")
    mac = algorithms("mac")
    host_keys = algorithms("host_keys") or algorithms("key")

    findings: list[dict[str, Any]] = []
    weak_markers = ("warn", "fail", "weak", "insecure", "deprecated", "broken")
    for key in ("kex", "enc", "mac", "host_keys", "key"):
        value = data.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            alg = str(item.get("algorithm") or item.get("name") or "")
            notes = [str(n) for n in (item.get("notes") or [])]
            text = " ".join(notes).lower()
            if not alg:
                continue
            if any(marker in text for marker in weak_markers):
                severity = "MEDIUM" if "fail" in text or "broken" in text else "LOW"
                findings.append(
                    {
                        "kind": "ssh_finding",
                        "id": alg[:256],
                        "severity": severity,
                        "detail": clean_text("; ".join(notes))[:2048] or "weak algorithm",
                    }
                )
    server = {
        "kind": "ssh_server",
        "banner": banner,
        "kex": kex,
        "enc": enc,
        "mac": mac,
        "host_keys": host_keys,
    }
    return Parsed(
        observations=[server] + findings[:200],
        warnings=[] if banner else ["ssh-audit returned no banner"],
        summary=f"SSH banner {banner[:120]!r}, {len(kex)} KEX, {len(enc)} ciphers, {len(mac)} MACs",
    )


_SNMP_SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1": "sys_descr",
    "1.3.6.1.2.1.1.2": "sys_object_id",
    "1.3.6.1.2.1.1.3": "sys_uptime",
    "1.3.6.1.2.1.1.4": "sys_contact",
    "1.3.6.1.2.1.1.5": "sys_name",
    "1.3.6.1.2.1.1.6": "sys_location",
}
_SNMP_NAMES = {
    "sysdescr": "sys_descr",
    "sysobjectid": "sys_object_id",
    "sysuptime": "sys_uptime",
    "syscontact": "sys_contact",
    "sysname": "sys_name",
    "syslocation": "sys_location",
}


def parse_snmpwalk(text: str) -> Parsed:
    oids: list[dict[str, Any]] = []
    system: dict[str, Any] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        left, right = line.split("=", 1)
        oid = left.strip()
        if ":" in right:
            typ, value = right.split(":", 1)
        else:
            typ, value = "", right
        typ = clean_text(typ.strip())
        value = truncate_text(clean_text(value.strip()), 4096)[0]
        if len(oids) >= 500:
            break
        oids.append({"oid": oid[:256], "type": typ[:64], "value": value})
        numeric = oid.lstrip(".")
        if numeric.startswith("1.3.6.1.2.1.1."):
            base = numeric.rsplit(".", 1)[0]
            key = _SNMP_SYSTEM_OIDS.get(base)
        else:
            key = None
            name = oid.split("::")[-1].split(".")[0].lower()
            key = _SNMP_NAMES.get(name)
        if key and key not in system:
            system[key] = value
    obs: list[dict[str, Any]] = []
    if system:
        obs.append({"kind": "snmp_system", **system})
    return Parsed(
        observations=obs,
        warnings=[] if oids else ["snmpwalk returned no OIDs"],
        summary=f"{len(oids)} SNMP OIDs",
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Runner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.scopes = ScopeStore(config.scope_dir, config.scope_key)
        self.jobs = JobManager(config)
        self._versions: dict[str, str] = {}
        self._owner = hashlib.sha256(config.token.encode("utf-8")).hexdigest()

    # -- common helpers ----------------------------------------------------

    def _guard(self, tool: str, task_id: int, target: str, fn: Any) -> dict[str, Any]:
        try:
            return fn()
        except RunnerError as exc:
            audit.audit(
                "warn",
                task_id=task_id,
                tool=tool,
                target=target[:255],
                decision="deny",
                code=exc.code,
                message=exc.message[:500],
            )
            return exc.envelope()
        except Exception as exc:  # noqa: BLE001
            audit.audit(
                "error",
                task_id=task_id,
                tool=tool,
                target=target[:255],
                decision="error",
                code=INTERNAL,
                error=exc.__class__.__name__,
            )
            return RunnerError(INTERNAL, "unexpected runner error").envelope()

    def _timeout(self, default: int, requested: int | None) -> int:
        value = requested if requested is not None else default
        return max(1, min(int(value), self.config.max_timeout_s))

    def _authorizer(self, task_id: int) -> tuple[Any, ScopeAuthorizer]:
        scope = self.scopes.load(task_id)
        return scope, ScopeAuthorizer(scope)

    def _submit(
        self,
        *,
        task_id: int,
        tool: str,
        target: str,
        timeout_s: int,
        wait_s: int,
        reason: str,
        fn: Any,
    ) -> dict[str, Any]:
        job = self.jobs.submit(
            task_id=task_id,
            tool=tool,
            target=target,
            timeout_s=timeout_s,
            owner=self._owner,
            fn=fn,
            reason=reason,
        )
        if wait_s <= 0:
            return job.running()
        if job.wait(wait_s):
            return job.envelope or job.running()
        return job.running()

    def _which(self, binary: str) -> str:
        path = shutil.which(binary)
        if not path:
            raise missing_binary(binary)
        return path

    def _version(self, binary: str) -> str:
        if binary in self._versions:
            return self._versions[binary]
        path = shutil.which(binary)
        if not path:
            self._versions[binary] = ""
            return ""
        for flag in ("--version", "-V"):
            try:
                proc = subprocess.run(
                    [path, flag],
                    capture_output=True,
                    timeout=3,
                    text=True,
                    errors="replace",
                )
                line = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip().splitlines()
                if line:
                    self._versions[binary] = clean_text(line[0])[:200]
                    return self._versions[binary]
            except (OSError, subprocess.SubprocessError):
                continue
        self._versions[binary] = ""
        return ""

    def _run_process(
        self,
        job: Job,
        argv: list[str],
        timeout_s: int,
        *,
        env: dict[str, str] | None = None,
    ) -> tuple[int, bytes, bytes]:
        if not argv:
            raise RunnerError(TOOL_FAILED, "empty command")
        binary = argv[0]
        path = shutil.which(binary)
        if not path:
            raise missing_binary(os.path.basename(binary))
        argv = [path] + argv[1:]
        child_env = {
            k: v
            for k, v in os.environ.items()
            if k not in {"RUNNER_TOKEN", "RUNNER_SCOPE_KEY"}
        }
        child_env["HOME"] = self.config.home
        child_env["PYTHONUNBUFFERED"] = "1"
        if env:
            child_env.update(env)
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "env": child_env,
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        else:  # pragma: no cover - production image is Linux
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            proc = subprocess.Popen(argv, **kwargs)
        except OSError as exc:
            raise RunnerError(TOOL_FAILED, "the tool could not be started") from exc
        job.register_process(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            job.request_timeout()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
            raise RunnerError(
                TOOL_TIMEOUT,
                f"tool exceeded its {timeout_s}s timeout",
                retryable=True,
                details={"timeout_s": timeout_s},
            )
        finally:
            job.clear_process()
        if job.cancel_requested:
            raise JobCancelled()
        limit = self.config.max_artifact_bytes
        if len(stdout) > limit:
            stdout = stdout[:limit]
            job.writer.truncated = True
        if len(stderr) > limit:
            stderr = stderr[:limit]
            job.writer.truncated = True
        return proc.returncode if proc.returncode is not None else -1, stdout, stderr

    def _write_streams(
        self,
        job: Job,
        stdout: bytes,
        stderr: bytes,
        out_name: str,
        err_name: str,
    ) -> None:
        job.writer.write_text(out_name, stdout.decode("utf-8", errors="replace"))
        job.writer.write_text(err_name, stderr.decode("utf-8", errors="replace"))

    def _bounded_error(self, stderr: bytes) -> str:
        text = clean_text(stderr.decode("utf-8", errors="replace")).strip()
        return truncate_text(text, 1000)[0] or "no stderr output"

    # -- net_nmap ----------------------------------------------------------

    def net_nmap(self, req: NmapInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            _scope, authz = self._authorizer(req.task_id)
            auth = authz.authorize_target(req.target)
            if req.syn:
                authz.require_syn()
            if req.os_detect:
                authz.require_os_detect()
            timeout = self._timeout(1800 if req.profile == "full_tcp" else 600, req.timeout_s)
            scan_target = ",".join(auth.resolved_ips) if auth.kind == "domain" else auth.target
            effective_rate = authz.effective_rate(req.rate)
            argv = self._nmap_argv(req, authz, scan_target, timeout, effective_rate)
            warnings = list(auth.warnings)
            if req.rate is not None and req.rate > _scope.policy.max_rate:
                warnings.append(
                    f"requested rate {req.rate} was capped to scope max_rate {_scope.policy.max_rate}"
                )

            def run(job: Job) -> JobOutcome:
                code, out, err = self._run_process(job, argv, timeout)
                job.writer.write_bytes("nmap.xml", out)
                self._write_streams(job, out, err, "nmap.stdout", "nmap.stderr")
                if code != 0:
                    raise RunnerError(
                        TOOL_FAILED,
                        f"nmap exited with code {code}: {self._bounded_error(err)}",
                        details={"exit_code": code},
                    )
                parsed = parse_nmap_xml(out)
                return JobOutcome(
                    ok=True,
                    summary=parsed.summary,
                    observations=parsed.observations,
                    warnings=warnings + parsed.warnings,
                    tool_version=self._version("nmap"),
                    argv_redacted=redact_argv(argv, []),
                    exit_code=code,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_nmap",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_nmap", req.task_id, req.target, work)

    def _nmap_argv(
        self,
        req: NmapInput,
        authz: ScopeAuthorizer,
        scan_target: str,
        timeout: int,
        effective_rate: int,
    ) -> list[str]:
        argv = ["nmap", "-n"]
        profile = req.profile
        if profile == "discovery":
            argv += ["-sn"]
        else:
            argv += ["-Pn"]
            if profile == "udp_top100":
                argv += ["-sU"]
            elif req.syn:
                argv += ["-sS"]
            else:
                argv += ["-sT"]
            if profile == "top100":
                argv += ["--top-ports", "100"]
            elif profile == "top1000":
                argv += ["--top-ports", "1000"]
            elif profile == "full_tcp":
                argv += ["-p-"]
            elif profile == "custom" and req.ports:
                argv += ["-p", req.ports]
            if profile in {"top100", "top1000", "custom", "full_tcp"} and req.scripts != "discovery":
                argv += ["-sV", "--version-light"]
            if req.scripts in {"safe", "discovery"}:
                argv += ["--script", req.scripts]
            if req.os_detect:
                argv += ["-O", "--osscan-guess"]
        argv += ["--max-rate", str(effective_rate)]
        if profile != "discovery":
            argv += ["--host-timeout", f"{timeout}s"]
        excluded = authz.excluded_ports_arg()
        if excluded:
            argv += ["--exclude-ports", excluded]
        argv += ["-oX", "-", scan_target]
        return argv

    # -- net_dns -----------------------------------------------------------

    def net_dns(self, req: DNSInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            try:
                ipaddress.ip_address(req.target.strip("[]"))
                raise RunnerError(INVALID_ARGUMENT, "net_dns requires a domain target")
            except ValueError:
                pass
            _scope, authz = self._authorizer(req.task_id)
            auth = authz.authorize_domain(req.target)
            if req.axfr:
                authz.require_axfr()
            resolver = req.resolver
            if resolver:
                try:
                    ipaddress.ip_address(resolver)
                except ValueError as exc:
                    raise RunnerError(INVALID_ARGUMENT, "resolver must be an IP address") from exc
                if self.config.dns_resolvers:
                    if resolver not in self.config.dns_resolvers:
                        raise RunnerError(
                            SCOPE_DENIED,
                            "resolver is not in the runner's DNS_RESOLVERS allowlist",
                            details={"resolver": resolver},
                        )
                else:
                    authz.authorize_ip(resolver)
            timeout = self._timeout(300, req.timeout_s)
            types = req.record_types or ["A", "AAAA"]
            dig_timeout = max(1, min(timeout, 30))
            commands: list[tuple[str, list[str]]] = []
            for rtype in types:
                argv = [
                    "dig",
                    f"+time={dig_timeout}",
                    "+tries=1",
                    "+noall",
                    "+answer",
                    rtype,
                    auth.target,
                ]
                if resolver:
                    argv.append("@" + resolver)
                commands.append((rtype, argv))

            def run(job: Job) -> JobOutcome:
                records: list[dict[str, Any]] = []
                warnings: list[str] = list(auth.warnings)
                failures = 0
                for rtype, argv in commands:
                    try:
                        code, out, err = self._run_process(job, argv, dig_timeout + 5)
                    except RunnerError as exc:
                        failures += 1
                        warnings.append(f"dig {rtype} failed: {exc.message}")
                        continue
                    job.writer.write_text(f"dig-{rtype}.txt", out.decode("utf-8", errors="replace"))
                    if code != 0:
                        failures += 1
                        warnings.append(f"dig {rtype} exited {code}: {self._bounded_error(err)}")
                        continue
                    records.extend(parse_dig_answer(out.decode("utf-8", errors="replace")))
                if req.axfr:
                    axfr_records, axfr_warnings = self._axfr(job, auth.target, resolver, dig_timeout)
                    records.extend(axfr_records)
                    warnings.extend(axfr_warnings)
                if failures and not records:
                    raise RunnerError(TOOL_FAILED, "all DNS queries failed", details={"failures": failures})
                observations: list[dict[str, Any]] = []
                seen_ips: set[str] = set()
                for rec in records:
                    obs = {
                        "kind": "dns_record",
                        "name": rec["name"],
                        "type": rec["type"],
                        "ttl": rec.get("ttl", 0),
                        "value": rec["value"],
                    }
                    for key in ("priority", "weight", "port"):
                        if key in rec:
                            obs[key] = rec[key]
                    if rec.get("axfr"):
                        obs["axfr"] = True
                    observations.append(obs)
                    if rec["type"] in {"A", "AAAA"} and rec["value"] not in seen_ips:
                        try:
                            ipaddress.ip_address(rec["value"])
                        except ValueError:
                            continue
                        seen_ips.add(rec["value"])
                        observations.append(
                            {"kind": "ip", "ip": rec["value"], "hostnames": [auth.target]}
                        )
                job.writer.write_json(
                    "dns.json",
                    {"target": auth.target, "resolved_ips": list(auth.resolved_ips), "records": records},
                    indent=2,
                )
                if not records:
                    warnings.append("no DNS records were returned")
                summary = f"{len(records)} DNS record(s) for {auth.target}"
                return JobOutcome(
                    ok=True,
                    summary=summary,
                    observations=observations,
                    warnings=warnings,
                    tool_version=self._version("dig"),
                    argv_redacted=redact_argv(commands[0][1] if commands else ["dig"], []),
                    exit_code=0,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_dns",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_dns", req.task_id, req.target, work)

    def _axfr(
        self,
        job: Job,
        target: str,
        resolver: str | None,
        dig_timeout: int,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        warnings = ["AXFR is a high-impact action; output is bounded and evidence is on disk"]
        resolver_arg = ["@" + resolver] if resolver else []

        def short_query(rtype: str) -> tuple[int, bytes, bytes] | None:
            argv = [
                "dig",
                f"+time={dig_timeout}",
                "+tries=1",
                "+short",
                rtype,
                target,
                *resolver_arg,
            ]
            try:
                return self._run_process(job, argv, dig_timeout + 5)
            except RunnerError as exc:
                warnings.append(f"AXFR {rtype} query failed: {exc.message}")
                return None

        # The SOA answer identifies the zone's primary nameserver; the NS
        # answer lists every authoritative server.  Prefer NS, fall back to
        # the SOA MNAME when the zone does not return NS records.
        nameservers: list[str] = []
        soa = short_query("SOA")
        if soa is not None:
            code, out, _err = soa
            if code == 0:
                for line in out.decode("utf-8", errors="replace").splitlines():
                    parts = line.split()
                    if parts:
                        mname = _strip_dot(parts[0])
                        if mname and mname not in nameservers:
                            nameservers.append(mname)
                        break
        ns = short_query("NS")
        if ns is not None:
            code, out, _err = ns
            if code == 0:
                for line in out.decode("utf-8", errors="replace").splitlines():
                    ns_name = _strip_dot(line.strip())
                    if ns_name and ns_name not in nameservers:
                        nameservers.append(ns_name)
        nameservers = nameservers[:5]
        if not nameservers:
            return [], warnings + ["AXFR skipped: no NS or SOA nameserver found"]
        records: list[dict[str, Any]] = []
        for ns_name in nameservers:
            argv = ["dig", f"+time={dig_timeout}", "+tries=1", "AXFR", target, "@" + ns_name]
            try:
                code, out, err = self._run_process(job, argv, dig_timeout + 10)
            except RunnerError as exc:
                warnings.append(f"AXFR from {ns_name} failed: {exc.message}")
                continue
            job.writer.write_text(
                f"dig-AXFR-{re.sub(r'[^A-Za-z0-9._-]', '_', ns_name)[:80]}.txt",
                out.decode("utf-8", errors="replace"),
            )
            if code != 0:
                warnings.append(f"AXFR from {ns_name} exited {code}: {self._bounded_error(err)}")
                continue
            for rec in parse_dig_answer(out.decode("utf-8", errors="replace")):
                rec["axfr"] = True
                records.append(rec)
        return records, warnings

    # -- net_tls -----------------------------------------------------------

    def net_tls(self, req: TLSInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            host, port = split_host_port(req.target, 443)
            _scope, authz = self._authorizer(req.task_id)
            try:
                ipaddress.ip_address(host.strip("[]"))
                auth = authz.authorize_ip(host)
            except ValueError:
                auth = authz.authorize_domain(host)
            authz.check_port(port)
            host = auth.target
            timeout = self._timeout(300, req.timeout_s)
            testssl = shutil.which("testssl.sh") or shutil.which("testssl")
            if not testssl:
                raise missing_binary("testssl.sh")
            pin_ip = auth.resolved_ips[0] if auth.resolved_ips else host
            target_arg = format_host_port(host, port)

            def run(job: Job) -> JobOutcome:
                tmp = job.writer.dir / f".testssl-{uuid.uuid4().hex}.json"
                argv = [
                    testssl,
                    "--quiet",
                    "--color",
                    "0",
                    "--jsonfile",
                    str(tmp),
                    "--warnings",
                    "off",
                ]
                if req.profile == "full":
                    argv += [
                        "--protocols",
                        "--server-defaults",
                        "--server-preferred",
                        "--vulnerabilities",
                        "--headers",
                        "--certificate",
                    ]
                else:
                    argv += ["--protocols", "--server-defaults", "--certificate"]
                if req.starttls != "none":
                    argv += ["--starttls", req.starttls]
                if auth.kind == "domain":
                    argv += ["--ip", pin_ip, "--servername", host]
                argv.append(target_arg)
                try:
                    code, out, err = self._run_process(job, argv, timeout)
                finally:
                    pass
                raw_json = b""
                if tmp.exists():
                    try:
                        raw_json = tmp.read_bytes()
                    finally:
                        try:
                            tmp.unlink()
                        except OSError:
                            pass
                if not raw_json:
                    raw_json = out.strip()
                self._write_streams(job, out, err, "testssl.log", "testssl.stderr")
                if not raw_json:
                    raise RunnerError(
                        TOOL_FAILED,
                        f"testssl produced no JSON output (exit {code})",
                        details={"exit_code": code},
                    )
                try:
                    data = json.loads(raw_json.decode("utf-8", errors="replace"))
                except json.JSONDecodeError as exc:
                    raise RunnerError(TOOL_FAILED, "testssl JSON could not be parsed") from exc
                job.writer.write_bytes("testssl.json", raw_json)
                parsed = parse_testssl_json(data)
                warnings = list(auth.warnings)
                if code != 0:
                    warnings.append(f"testssl exited with code {code}; parsed output is still returned")
                for obs in parsed.observations:
                    if obs.get("kind") in {"tls_endpoint", "tls_finding"}:
                        obs["host"] = host
                        obs["port"] = port
                return JobOutcome(
                    ok=True,
                    summary=f"{parsed.summary} for {host}:{port}",
                    observations=parsed.observations,
                    warnings=warnings + parsed.warnings,
                    tool_version=self._version("testssl.sh") or self._version("testssl"),
                    argv_redacted=redact_argv(argv, []),
                    exit_code=code,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_tls",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_tls", req.task_id, req.target, work)

    # -- net_snmp ----------------------------------------------------------

    def net_snmp(self, req: SNMPInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            if req.version == "3":
                raise RunnerError(NOT_IMPLEMENTED, "SNMPv3 is not implemented in Phase 1")
            _scope, authz = self._authorizer(req.task_id)
            auth = authz.authorize_target(req.target)
            authz.check_port(161)
            scan_target = auth.resolved_ips[0] if auth.kind == "domain" else auth.target
            timeout = self._timeout(300, req.timeout_s)
            argv = [
                "snmpwalk",
                "-v",
                req.version,
                "-t",
                "5",
                "-r",
                "1",
                "-c",
                req.community,
                "-On",
                scan_target,
            ]

            def run(job: Job) -> JobOutcome:
                code, out, err = self._run_process(job, argv, timeout)
                self._write_streams(job, out, err, "snmpwalk.txt", "snmpwalk.stderr")
                if code != 0:
                    raise RunnerError(
                        TOOL_FAILED,
                        f"snmpwalk exited with code {code}: {self._bounded_error(err)}",
                        details={"exit_code": code},
                    )
                parsed = parse_snmpwalk(out.decode("utf-8", errors="replace"))
                for obs in parsed.observations:
                    if obs.get("kind") == "snmp_system":
                        obs["ip"] = scan_target
                parsed.observations.append(
                    {"kind": "service", "ip": scan_target, "port": 161, "proto": "udp", "service": "snmp"}
                )
                job.writer.write_json(
                    "snmp.json",
                    {"target": scan_target, "observations": parsed.observations},
                    indent=2,
                )
                return JobOutcome(
                    ok=True,
                    summary=parsed.summary,
                    observations=parsed.observations,
                    warnings=list(auth.warnings) + parsed.warnings,
                    tool_version=self._version("snmpwalk"),
                    argv_redacted=redact_argv(argv, [req.community]),
                    exit_code=code,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_snmp",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_snmp", req.task_id, req.target, work)

    # -- net_smb -----------------------------------------------------------

    def net_smb(self, req: SMBInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            if req.credential_id is not None:
                raise RunnerError(
                    NOT_IMPLEMENTED,
                    "authenticated SMB enumeration is not implemented in Phase 1",
                )
            _scope, authz = self._authorizer(req.task_id)
            auth = authz.authorize_target(req.target)
            authz.check_port(445)
            scan_target = auth.resolved_ips[0] if auth.kind == "domain" else auth.target
            timeout = self._timeout(300, req.timeout_s)
            flags: list[str]
            if req.mode == "shares":
                flags = ["-S"]
            elif req.mode == "users":
                flags = ["-U"]
            elif req.mode == "groups":
                flags = ["-G"]
            elif req.mode == "policy":
                flags = ["-P"]
            else:
                # sessions/all: enum4linux-ng has no dedicated session flag in
                # every packaged version; run the full enumeration and filter.
                flags = ["-A"]

            def run(job: Job) -> JobOutcome:
                tmp = job.writer.dir / f".enum4linux-{uuid.uuid4().hex}.json"
                argv = ["enum4linux-ng", *flags, "-oJ", str(tmp), scan_target]
                code, out, err = self._run_process(job, argv, timeout)
                self._write_streams(job, out, err, "enum4linux.stdout", "enum4linux.stderr")
                raw_json = b""
                if tmp.exists():
                    try:
                        raw_json = tmp.read_bytes()
                    finally:
                        try:
                            tmp.unlink()
                        except OSError:
                            pass
                if not raw_json:
                    raw_json = out.strip()
                if not raw_json:
                    raise RunnerError(
                        TOOL_FAILED,
                        f"enum4linux-ng produced no JSON output (exit {code})",
                        details={"exit_code": code},
                    )
                try:
                    data = json.loads(raw_json.decode("utf-8", errors="replace"))
                except json.JSONDecodeError as exc:
                    raise RunnerError(TOOL_FAILED, "enum4linux-ng JSON could not be parsed") from exc
                job.writer.write_bytes("enum4linux.json", raw_json)
                parsed = parse_enum4linux_json(data)
                for obs in parsed.observations:
                    if obs.get("kind") in {
                        "smb_share",
                        "smb_user",
                        "smb_group",
                        "smb_password_policy",
                    }:
                        obs["ip"] = scan_target
                parsed.observations.append(
                    {"kind": "service", "ip": scan_target, "port": 445, "proto": "tcp", "service": "smb"}
                )
                warnings = list(auth.warnings) + parsed.warnings
                if code != 0:
                    warnings.append(f"enum4linux-ng exited with code {code}")
                return JobOutcome(
                    ok=True,
                    summary=parsed.summary,
                    observations=parsed.observations,
                    warnings=warnings,
                    tool_version=self._version("enum4linux-ng"),
                    argv_redacted=redact_argv(argv, []),
                    exit_code=code,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_smb",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_smb", req.task_id, req.target, work)

    # -- net_ldap ----------------------------------------------------------

    def net_ldap(self, req: LDAPInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            if req.credential_id is not None:
                raise RunnerError(
                    NOT_IMPLEMENTED,
                    "authenticated LDAP binds are not implemented in Phase 1",
                )
            _scope, authz = self._authorizer(req.task_id)
            auth = authz.authorize_target(req.target)
            authz.check_port(req.port)
            timeout = self._timeout(300, req.timeout_s)
            tls = req.use_tls or req.port == 636
            scheme = "ldaps" if tls else "ldap"
            uri = f"{scheme}://{format_host_port(auth.target, req.port)}"
            time_limit = max(1, min(timeout, 60))
            argv = [
                "ldapsearch",
                "-LLL",
                "-x",
                "-H",
                uri,
                "-b",
                req.base_dn,
                "-s",
                req.scope,
                "-z",
                str(req.max_entries),
                "-l",
                str(time_limit),
                req.filter,
                *(req.attributes or ["*"]),
            ]

            def run(job: Job) -> JobOutcome:
                code, out, err = self._run_process(job, argv, timeout)
                self._write_streams(job, out, err, "ldap.ldif", "ldap.stderr")
                text = out.decode("utf-8", errors="replace")
                entries, warnings = parse_ldif(text, max_entries=req.max_entries)
                if code != 0 and not entries:
                    raise RunnerError(
                        TOOL_FAILED,
                        f"ldapsearch exited with code {code}: {self._bounded_error(err)}",
                        details={"exit_code": code},
                    )
                if code != 0:
                    warnings.append(f"ldapsearch exited with code {code}; parsed entries are returned")
                observations = [
                    {"kind": "ldap_entry", "dn": e["dn"], "attributes": e["attributes"]}
                    for e in entries
                ]
                job.writer.write_json(
                    "ldap.json",
                    {"target": req.target, "entries": entries, "count": len(entries)},
                    indent=2,
                )
                return JobOutcome(
                    ok=True,
                    summary=f"{len(entries)} LDAP entr{'y' if len(entries) == 1 else 'ies'}",
                    observations=observations,
                    warnings=list(auth.warnings) + warnings,
                    tool_version=self._version("ldapsearch"),
                    argv_redacted=redact_argv(argv, []),
                    exit_code=code,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_ldap",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_ldap", req.task_id, req.target, work)

    # -- net_ssh -----------------------------------------------------------

    def net_ssh(self, req: SSHInput) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            _scope, authz = self._authorizer(req.task_id)
            auth = authz.authorize_target(req.target)
            authz.check_port(req.port)
            scan_target = auth.resolved_ips[0] if auth.kind == "domain" else auth.target
            timeout = self._timeout(300, req.timeout_s)
            argv = ["ssh-audit", "-j", format_host_port(scan_target, req.port)]

            def run(job: Job) -> JobOutcome:
                code, out, err = self._run_process(job, argv, timeout)
                self._write_streams(job, out, err, "ssh-audit.txt", "ssh-audit.stderr")
                raw = out.strip() or err.strip()
                if not raw:
                    raise RunnerError(TOOL_FAILED, "ssh-audit produced no output")
                try:
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                except json.JSONDecodeError as exc:
                    raise RunnerError(TOOL_FAILED, "ssh-audit JSON could not be parsed") from exc
                job.writer.write_bytes("ssh-audit.json", raw)
                parsed = parse_ssh_audit_json(data)
                for obs in parsed.observations:
                    if obs.get("kind") in {"ssh_server", "ssh_finding"}:
                        obs["ip"] = scan_target
                        obs["port"] = req.port
                parsed.observations.append(
                    {"kind": "service", "ip": scan_target, "port": req.port, "proto": "tcp", "service": "ssh"}
                )
                warnings = list(auth.warnings) + parsed.warnings
                if code != 0:
                    warnings.append(f"ssh-audit exited with code {code}")
                return JobOutcome(
                    ok=True,
                    summary=parsed.summary,
                    observations=parsed.observations,
                    warnings=warnings,
                    tool_version=self._version("ssh-audit"),
                    argv_redacted=redact_argv(argv, []),
                    exit_code=code,
                )

            return self._submit(
                task_id=req.task_id,
                tool="net_ssh",
                target=req.target,
                timeout_s=timeout,
                wait_s=req.wait_s,
                reason=req.reason or "",
                fn=run,
            )

        return self._guard("net_ssh", req.task_id, req.target, work)

    # -- jobs --------------------------------------------------------------

    def job_wait(self, job_id: str, timeout_s: int = 30) -> dict[str, Any]:
        try:
            if not re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", job_id or ""):
                raise RunnerError(INVALID_ARGUMENT, "job_id is not a valid ULID")
            if not 1 <= timeout_s <= 60:
                raise RunnerError(INVALID_ARGUMENT, "timeout_s must be between 1 and 60")
            return self.jobs.wait(job_id, timeout_s, owner=self._owner)
        except RunnerError as exc:
            return exc.envelope()

    def job_cancel(self, job_id: str) -> dict[str, Any]:
        try:
            if not re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", job_id or ""):
                raise RunnerError(INVALID_ARGUMENT, "job_id is not a valid ULID")
            return self.jobs.cancel(job_id, owner=self._owner)
        except RunnerError as exc:
            return exc.envelope()


# ---------------------------------------------------------------------------
# FastMCP registration
# ---------------------------------------------------------------------------


def _validation_error(exc: ValidationError) -> dict[str, Any]:
    fields: set[str] = set()
    for error in exc.errors():
        location = error.get("loc") or ("argument",)
        fields.add(str(location[0]))
    return RunnerError(
        INVALID_ARGUMENT,
        "invalid tool arguments",
        details={"fields": sorted(fields)},
    ).envelope()


def register_tools(mcp: Any, runner: Runner) -> None:
    """Register the fixed Phase 1 tool surface.

    Function signatures are explicit so FastMCP emits a flat object schema;
    pydantic models are still used internally for strict validation.
    """

    @mcp.tool(name="net_nmap", description="TCP/UDP discovery and service identification with nmap.")
    def net_nmap(
        task_id: int,
        target: str,
        profile: Literal["discovery", "top100", "top1000", "full_tcp", "udp_top100", "custom"],
        ports: str | None = None,
        rate: int | None = None,
        timeout_s: int | None = None,
        wait_s: int = 30,
        scripts: Literal["none", "safe", "discovery"] = "none",
        syn: bool = False,
        os_detect: bool = False,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = NmapInput(
                task_id=task_id,
                target=target,
                profile=profile,
                ports=ports,
                rate=rate,
                timeout_s=timeout_s,
                wait_s=wait_s,
                scripts=scripts,
                syn=syn,
                os_detect=os_detect,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_nmap(req)

    @mcp.tool(name="net_dns", description="DNS records, resolution, and optional zone transfer.")
    def net_dns(
        task_id: int,
        target: str,
        record_types: list[str] | None = None,
        resolver: str | None = None,
        axfr: bool = False,
        timeout_s: int | None = None,
        wait_s: int = 30,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = DNSInput(
                task_id=task_id,
                target=target,
                record_types=record_types,
                resolver=resolver,
                axfr=axfr,
                timeout_s=timeout_s,
                wait_s=wait_s,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_dns(req)

    @mcp.tool(name="net_tls", description="TLS configuration and certificate review with testssl.sh.")
    def net_tls(
        task_id: int,
        target: str,
        profile: Literal["quick", "full"] = "quick",
        starttls: Literal["none", "smtp", "imap", "pop3", "xmpp", "ftp", "ldap"] = "none",
        timeout_s: int | None = None,
        wait_s: int = 30,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = TLSInput(
                task_id=task_id,
                target=target,
                profile=profile,
                starttls=starttls,
                timeout_s=timeout_s,
                wait_s=wait_s,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_tls(req)

    @mcp.tool(name="net_snmp", description="SNMP system enumeration (v1/v2c, single community).")
    def net_snmp(
        task_id: int,
        target: str,
        version: Literal["1", "2c", "3"] = "2c",
        community: str = "public",
        timeout_s: int | None = None,
        wait_s: int = 30,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = SNMPInput(
                task_id=task_id,
                target=target,
                version=version,
                community=community,
                timeout_s=timeout_s,
                wait_s=wait_s,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_snmp(req)

    @mcp.tool(name="net_smb", description="Anonymous SMB share, user, group, and policy enumeration.")
    def net_smb(
        task_id: int,
        target: str,
        mode: Literal["shares", "users", "groups", "sessions", "policy", "all"] = "all",
        credential_id: int | None = None,
        timeout_s: int | None = None,
        wait_s: int = 30,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = SMBInput(
                task_id=task_id,
                target=target,
                mode=mode,
                credential_id=credential_id,
                timeout_s=timeout_s,
                wait_s=wait_s,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_smb(req)

    @mcp.tool(name="net_ldap", description="Read-only anonymous LDAP/AD queries with bounded output.")
    def net_ldap(
        task_id: int,
        target: str,
        port: int = 389,
        base_dn: str = "",
        filter: str = "(objectClass=*)",
        attributes: list[str] | None = None,
        scope: Literal["base", "one", "sub"] = "sub",
        use_tls: bool = False,
        credential_id: int | None = None,
        max_entries: int = 200,
        timeout_s: int | None = None,
        wait_s: int = 30,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = LDAPInput(
                task_id=task_id,
                target=target,
                port=port,
                base_dn=base_dn,
                filter=filter,
                attributes=attributes,
                scope=scope,
                use_tls=use_tls,
                credential_id=credential_id,
                max_entries=max_entries,
                timeout_s=timeout_s,
                wait_s=wait_s,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_ldap(req)

    @mcp.tool(name="net_ssh", description="SSH banner and algorithm audit with ssh-audit.")
    def net_ssh(
        task_id: int,
        target: str,
        port: int = 22,
        timeout_s: int | None = None,
        wait_s: int = 30,
        reason: str | None = None,
    ) -> dict[str, Any]:
        try:
            req = SSHInput(
                task_id=task_id,
                target=target,
                port=port,
                timeout_s=timeout_s,
                wait_s=wait_s,
                reason=reason,
            )
        except ValidationError as exc:
            return _validation_error(exc)
        return runner.net_ssh(req)

    @mcp.tool(name="job_wait", description="Wait for a runner job and return its final envelope or current state.")
    def job_wait(job_id: str, timeout_s: int = 30) -> dict[str, Any]:
        return runner.job_wait(job_id, timeout_s)

    @mcp.tool(name="job_cancel", description="Cancel a runner job (process-group SIGTERM, then SIGKILL).")
    def job_cancel(job_id: str) -> dict[str, Any]:
        return runner.job_cancel(job_id)
