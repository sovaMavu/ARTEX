"""Parser golden-file tests.

Every parser must return structured observations for valid output and a
structured ``RunnerError`` (or an empty list) for malformed input, never a
traceback.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.errors import TOOL_FAILED, RunnerError
from runner.tools.net import (
    parse_dig_answer,
    parse_enum4linux_json,
    parse_ldif,
    parse_nmap_xml,
    parse_snmpwalk,
    parse_ssh_audit_json,
    parse_testssl_json,
)

DATA = Path(__file__).parent / "testdata"


def read(name: str) -> bytes:
    return (DATA / name).read_bytes()


def read_text(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def read_json(name: str):
    return json.loads(read_text(name))


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


def test_nmap_host_up():
    parsed = parse_nmap_xml(read("nmap/host-up.xml"))
    kinds = [obs["kind"] for obs in parsed.observations]
    assert kinds.count("ip") == 1
    assert kinds.count("service") == 4
    ip_obs = parsed.observations[0]
    assert ip_obs["ip"] == "10.10.0.5"
    assert ip_obs["hostnames"] == ["dc01.corp.local", "dc01"]
    assert ip_obs["extra"]["os_matches"][0]["name"] == "Linux 5.0 - 5.14"
    assert any(s["id"] == "smb2-security-mode" for s in ip_obs["extra"]["scripts"])

    services = {obs["port"]: obs for obs in parsed.observations if obs["kind"] == "service"}
    assert services[22]["service"] == "ssh"
    assert services[22]["product"] == "OpenSSH"
    assert services[22]["version"] == "9.6p1"
    assert services[445]["service"] == "smb"
    assert services[3389]["service"] == "rdp"
    assert services[80]["service"] == "http"
    assert services[80]["proto"] == "tcp"
    assert "8080" not in {str(p) for p in services}
    assert "4 open TCP port" in parsed.summary


def test_nmap_no_hosts_is_success_with_warning():
    parsed = parse_nmap_xml(read("nmap/no-hosts.xml"))
    assert parsed.observations == []
    assert any("0 hosts up" in warning for warning in parsed.warnings)
    assert "0 host" in parsed.summary


def test_nmap_ipv6():
    parsed = parse_nmap_xml(read("nmap/ipv6.xml"))
    assert parsed.observations[0] == {
        "kind": "ip",
        "ip": "2001:db8::10",
        "hostnames": ["ipv6.example.com"],
    }
    service = parsed.observations[1]
    assert service["ip"] == "2001:db8::10"
    assert service["port"] == 443
    assert service["service"] == "http"
    assert service["tunnel"] == "ssl"


def test_nmap_scripts():
    parsed = parse_nmap_xml(read("nmap/scripts.xml"))
    ip_obs = parsed.observations[0]
    script_ids = {s["id"] for s in ip_obs["extra"]["scripts"]}
    assert {"smb2-security-mode", "clock-skew"} <= script_ids
    service = parsed.observations[1]
    assert service["extra"]["scripts"][0]["id"] == "ssl-cert"


def test_nmap_udp_open_filtered_is_warning_not_service():
    parsed = parse_nmap_xml(read("nmap/udp.xml"))
    services = [obs for obs in parsed.observations if obs["kind"] == "service"]
    assert [(s["port"], s["service"]) for s in services] == [(161, "snmp")]
    assert any("500" in warning and "open|filtered" in warning for warning in parsed.warnings)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"   ",
        b"<notnmap/>",
        b"<nmaprun><host>",
        b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun>&xxe;</nmaprun>',
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><nmaprun>&lol2;</nmaprun>',
    ],
)
def test_nmap_malformed_is_structured_error(payload):
    with pytest.raises(RunnerError) as exc:
        parse_nmap_xml(payload)
    assert exc.value.code == TOOL_FAILED


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def test_dig_answer_parsing():
    records = parse_dig_answer(read_text("dns/answers.txt"))
    by_type = {}
    for record in records:
        by_type.setdefault(record["type"], []).append(record)

    assert by_type["A"][0]["value"] == "203.0.113.10"
    assert by_type["A"][0]["ttl"] == 300
    assert by_type["AAAA"][0]["value"] == "2001:db8::10"
    assert by_type["MX"][0]["priority"] == 10
    assert by_type["MX"][0]["value"] == "mail.example.com"
    assert by_type["SRV"][0]["priority"] == 10
    assert by_type["SRV"][0]["weight"] == 60
    assert by_type["SRV"][0]["port"] == 5060
    assert by_type["SRV"][0]["value"] == "sip.example.com"
    assert by_type["TXT"][0]["value"] == "v=spf1 -all"
    assert by_type["CNAME"][0]["value"] == "example.com"
    assert by_type["NS"][0]["value"] == "ns1.example.com"
    assert by_type["CAA"][0]["value"] == '0 issue "letsencrypt.org"'


def test_dig_answer_ignores_comments_and_garbage():
    assert parse_dig_answer("; comment\nnot enough fields\n") == []


# ---------------------------------------------------------------------------
# testssl.sh
# ---------------------------------------------------------------------------


def test_testssl_parsing():
    parsed = parse_testssl_json(read_json("testssl/scan.json"))
    endpoint = parsed.observations[0]
    assert endpoint["kind"] == "tls_endpoint"
    assert endpoint["cert"]["subject"] == "CN=example.com"
    assert endpoint["cert"]["issuer"].startswith("CN=Test CA")
    assert endpoint["cert"]["serial"] == "01AB23CD"
    assert endpoint["cert"]["not_after"] == "2026-12-31T23:59:59Z"
    assert endpoint["cert"]["sans"] == ["example.com", "www.example.com"]
    assert any(p.startswith("TLS1") for p in endpoint["protocols"])

    findings = [obs for obs in parsed.observations if obs["kind"] == "tls_finding"]
    assert {f["severity"] for f in findings} == {"LOW", "HIGH"}
    assert all(f["id"] for f in findings)


def test_testssl_empty_input():
    parsed = parse_testssl_json({})
    assert parsed.observations[0]["kind"] == "tls_endpoint"
    assert parsed.warnings


# ---------------------------------------------------------------------------
# enum4linux-ng
# ---------------------------------------------------------------------------


def test_enum4linux_parsing():
    parsed = parse_enum4linux_json(read_json("enum4linux/scan.json"))
    shares = [o for o in parsed.observations if o["kind"] == "smb_share"]
    users = [o for o in parsed.observations if o["kind"] == "smb_user"]
    groups = [o for o in parsed.observations if o["kind"] == "smb_group"]
    policies = [o for o in parsed.observations if o["kind"] == "smb_password_policy"]

    assert {s["name"] for s in shares} == {"ADMIN$", "Public"}
    assert shares[0]["comment"] == "Remote Admin"
    assert shares[0]["access"] == "READ"
    assert {u["username"] for u in users} == {"Administrator", "guest"}
    assert users[0]["rid"] == 500
    assert users[0]["enabled"] is True
    assert groups[0]["name"] == "Domain Admins"
    assert groups[0]["domain"] == "CORP"
    assert policies[0]["min_length"] == 8
    assert policies[0]["lockout_threshold"] == 5
    assert any("session" in warning for warning in parsed.warnings)


def test_enum4linux_non_object():
    parsed = parse_enum4linux_json("not json")
    assert parsed.observations == []
    assert parsed.warnings


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------


def test_ldif_parsing():
    entries, warnings = parse_ldif(read_text("ldap/entries.ldif"))
    assert warnings == []
    assert len(entries) == 3
    admin = entries[0]
    assert admin["dn"] == "CN=Administrator,CN=Users,DC=corp,DC=local"
    assert admin["attributes"]["cn"] == "Administrator"
    assert admin["attributes"]["objectclass"] == ["top", "person"]
    assert admin["attributes"]["memberof"].startswith("CN=Domain Admins")

    guest = entries[1]
    assert guest["attributes"]["cn"] == "Guest"
    assert guest["attributes"]["description"] == "This is a longfolded description"

    service = entries[2]
    assert service["attributes"]["serviceprincipalname"] == "MSSQLSvc/sql01.corp.local:1433"


def test_ldif_caps_entries():
    entries, warnings = parse_ldif(read_text("ldap/entries.ldif"), max_entries=1)
    assert len(entries) == 1
    assert any("truncated" in warning for warning in warnings)


def test_ldif_ignores_external_references():
    text = "dn: cn=test\ndescription:< file:///etc/passwd\ncn: test\n"
    entries, warnings = parse_ldif(text)
    assert entries[0]["attributes"]["cn"] == "test"
    assert any("external URL" in warning for warning in warnings)


# ---------------------------------------------------------------------------
# ssh-audit
# ---------------------------------------------------------------------------


def test_ssh_audit_parsing():
    parsed = parse_ssh_audit_json(read_json("ssh-audit/scan.json"))
    server = parsed.observations[0]
    assert server["kind"] == "ssh_server"
    assert server["banner"].startswith("SSH-2.0-OpenSSH_8.2p1")
    assert "curve25519-sha256" in server["kex"]
    assert "aes128-cbc" in server["enc"]
    assert "hmac-md5" in server["mac"]
    assert "ssh-rsa" in server["host_keys"]

    findings = [o for o in parsed.observations if o["kind"] == "ssh_finding"]
    assert len(findings) == 4
    assert any(f["severity"] == "MEDIUM" for f in findings)


def test_ssh_audit_rejects_non_object():
    with pytest.raises(RunnerError) as exc:
        parse_ssh_audit_json([])
    assert exc.value.code == TOOL_FAILED


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------


def test_snmpwalk_parsing():
    parsed = parse_snmpwalk(read_text("snmp/walk.txt"))
    system = parsed.observations[0]
    assert system["kind"] == "snmp_system"
    assert system["sys_descr"] == "Linux target 5.15.0"
    assert system["sys_object_id"] == ".1.3.6.1.4.1.8072.3.2.10"
    assert system["sys_uptime"] == "(12345) 0:02:03.45"
    assert system["sys_contact"] == "admin@example.com"
    assert system["sys_name"] == "target"
    assert system["sys_location"] == "rack 1"


def test_snmpwalk_empty():
    parsed = parse_snmpwalk("")
    assert parsed.observations == []
    assert parsed.warnings
