"""Scope signing, matching, and always-blocked address tests."""

from __future__ import annotations

import ipaddress
import json
from datetime import timedelta

import pytest

from runner.errors import SCOPE_DENIED, SCOPE_EXPIRED, SCOPE_MISSING, RunnerError
from runner.scope import (
    ScopeAuthorizer,
    ScopeStore,
    canonical_scope_payload,
    format_host_port,
    parse_port_list,
    sign_scope,
    verify_scope_signature,
)

from .conftest import (
    SCOPE_KEY,
    TASK_ID,
    iso,
    load_scope,
    scope_payload,
    signed_scope,
    utc_now,
    write_scope,
)


def authorizer(scope, *, local_ips=(), gateways=(), resolver=None):
    return ScopeAuthorizer(
        scope,
        local_ips=list(local_ips),
        gateways=list(gateways),
        resolver=resolver or (lambda _host: ["203.0.113.10"]),
    )


# ---------------------------------------------------------------------------
# Canonicalization and signatures
# ---------------------------------------------------------------------------


def test_canonical_payload_is_order_independent():
    first = {"b": 2, "a": 1, "signature": "ignored"}
    second = {"a": 1, "b": 2, "signature": "different"}
    assert canonical_scope_payload(first) == canonical_scope_payload(second)
    assert sign_scope(first, SCOPE_KEY) == sign_scope(second, SCOPE_KEY)


def test_signature_round_trip_and_tamper():
    payload = scope_payload()
    signature = sign_scope(payload, SCOPE_KEY)
    payload["signature"] = signature
    assert verify_scope_signature(payload, SCOPE_KEY)
    payload["cidrs"] = ["0.0.0.0/0"]
    assert not verify_scope_signature(payload, SCOPE_KEY)


def test_signature_requires_prefix_and_hex_length():
    payload = scope_payload()
    payload["signature"] = "hmac-sha256:abc"
    assert not verify_scope_signature(payload, SCOPE_KEY)
    payload["signature"] = "sha256:" + "0" * 64
    assert not verify_scope_signature(payload, SCOPE_KEY)


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def test_load_scope_normalizes_and_dedupes():
    scope = load_scope(
        domains=["Example.COM.", "example.com", "*.Example.com"],
        ips=["203.0.113.10", "203.0.113.10"],
        cidrs=["10.10.1.9/16"],
        excludes=["10.10.5.0/24", "Admin.Example.Com."],
    )
    assert scope.domains == ("example.com", "*.example.com")
    assert scope.ips == ("203.0.113.10",)
    assert scope.cidrs == ("10.10.0.0/16",)
    assert "admin.example.com" in scope.excludes
    assert 22 in scope.exclude_ports


def test_expired_scope_is_denied():
    now = utc_now()
    payload = signed_scope(
        issued_at=iso(now - timedelta(days=40)),
        expires_at=iso(now - timedelta(days=1)),
    )
    with pytest.raises(RunnerError) as exc:
        from runner.scope import load_scope_payload

        load_scope_payload(payload, SCOPE_KEY, TASK_ID)
    assert exc.value.code == SCOPE_EXPIRED


def test_future_issued_scope_is_denied():
    now = utc_now()
    payload = signed_scope(issued_at=iso(now + timedelta(hours=1)))
    with pytest.raises(RunnerError) as exc:
        from runner.scope import load_scope_payload

        load_scope_payload(payload, SCOPE_KEY, TASK_ID)
    assert exc.value.code == SCOPE_DENIED


def test_missing_scope_file(tmp_path):
    store = ScopeStore(tmp_path / "scopes", SCOPE_KEY)
    with pytest.raises(RunnerError) as exc:
        store.load(TASK_ID)
    assert exc.value.code == SCOPE_MISSING


def test_invalid_signature_file(tmp_path):
    directory = tmp_path / "scopes"
    directory.mkdir()
    payload = signed_scope()
    payload["signature"] = "hmac-sha256:" + "0" * 64
    (directory / f"{TASK_ID}.json").write_text(json.dumps(payload), encoding="utf-8")
    store = ScopeStore(directory, SCOPE_KEY)
    with pytest.raises(RunnerError) as exc:
        store.load(TASK_ID)
    assert exc.value.code == SCOPE_DENIED


def test_scope_store_reloads_changed_file(tmp_path):
    directory = tmp_path / "scopes"
    path = write_scope(directory)
    store = ScopeStore(directory, SCOPE_KEY)
    first = store.load(TASK_ID)
    assert "example.com" in first.domains

    payload = signed_scope(domains=["changed.example"])
    path.write_text(json.dumps(payload), encoding="utf-8")
    second = store.load(TASK_ID)
    assert second.domains == ("changed.example",)


# ---------------------------------------------------------------------------
# IP / CIDR / domain matching
# ---------------------------------------------------------------------------


def test_ip_inside_and_outside_scope(scope):
    authz = authorizer(scope)
    assert authz.authorize_ip("10.10.0.5").kind == "ip"
    assert authz.authorize_ip("203.0.113.10").resolved_ips == ("203.0.113.10",)
    with pytest.raises(RunnerError) as exc:
        authz.authorize_ip("8.8.8.8")
    assert exc.value.code == SCOPE_DENIED


def test_cidr_must_be_fully_contained(scope):
    authz = authorizer(scope)
    assert authz.authorize_cidr("10.10.1.0/24").kind == "cidr"
    with pytest.raises(RunnerError):
        authz.authorize_cidr("10.10.0.0/15")
    with pytest.raises(RunnerError):
        authz.authorize_cidr("10.11.0.0/16")


def test_cidr_max_hosts(scope):
    authz = authorizer(load_scope(policy={**scope_payload()["policy"], "max_hosts": 256}))
    with pytest.raises(RunnerError) as exc:
        authz.authorize_cidr("10.10.0.0/16")
    assert "max_hosts" in exc.value.message


def test_domain_exact_wildcard_and_apex(scope):
    authz = authorizer(scope)
    assert authz.authorize_domain("example.com").kind == "domain"
    assert authz.authorize_domain("www.example.com").kind == "domain"
    with pytest.raises(RunnerError):
        authz.authorize_domain("example.net")


def test_wildcard_does_not_match_apex_when_only_wildcard_is_allowed():
    scope = load_scope(domains=["*.example.com"])
    authz = authorizer(scope)
    with pytest.raises(RunnerError):
        authz.authorize_domain("example.com")
    assert authz.authorize_domain("a.example.com").kind == "domain"


def test_wildcard_target_is_rejected(scope):
    authz = authorizer(scope)
    with pytest.raises(RunnerError):
        authz.authorize_domain("*.example.com")


def test_excludes_win_for_domains_and_networks(scope):
    authz = authorizer(scope)
    with pytest.raises(RunnerError):
        authz.authorize_domain("admin.example.com")
    with pytest.raises(RunnerError):
        authz.authorize_ip("10.10.5.5")
    with pytest.raises(RunnerError):
        authz.authorize_cidr("10.10.5.0/24")


def test_domain_resolution_blocks_any_bad_address(scope):
    authz = authorizer(scope, resolver=lambda _host: ["203.0.113.10", "127.0.0.1"])
    with pytest.raises(RunnerError) as exc:
        authz.authorize_domain("example.com")
    assert "127.0.0.1" in exc.value.message


def test_domain_resolution_requires_at_least_one_address(scope):
    authz = authorizer(scope, resolver=lambda _host: [])
    with pytest.raises(RunnerError):
        authz.authorize_domain("example.com")


# ---------------------------------------------------------------------------
# Always blocked and protected addresses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "0.0.0.0",
        "::",
        "255.255.255.255",
    ],
)
def test_always_blocked_addresses_cannot_be_authorized(address):
    payload = signed_scope(
        ips=[address],
        cidrs=[],
        excludes=[],
        domains=[],
    )
    from runner.scope import load_scope_payload

    scope = load_scope_payload(payload, SCOPE_KEY, TASK_ID)
    with pytest.raises(RunnerError):
        authorizer(scope).authorize_ip(address)


def test_rfc1918_is_allowed_only_when_covered():
    scope = load_scope(cidrs=["10.10.0.0/16"], ips=[])
    authz = authorizer(scope)
    assert authz.authorize_ip("10.10.1.1").kind == "ip"
    with pytest.raises(RunnerError):
        authz.authorize_ip("192.168.1.1")


def test_protected_address_allowed_when_explicitly_scoped():
    scope = load_scope(ips=["10.10.0.5"], cidrs=[])
    authz = authorizer(scope, local_ips=["10.10.0.5"], gateways=["10.10.0.1"])
    assert authz.authorize_ip("10.10.0.5").kind == "ip"
    with pytest.raises(RunnerError):
        authz.authorize_ip("10.10.0.1")


def test_protected_address_inside_cidr_is_not_explicit():
    scope = load_scope(ips=[], cidrs=["10.10.0.0/24"])
    authz = authorizer(scope, local_ips=["10.10.0.5"])
    with pytest.raises(RunnerError):
        authz.authorize_cidr("10.10.0.0/24")


def test_protected_address_can_be_explicit_and_inside_cidr():
    scope = load_scope(ips=["10.10.0.5"], cidrs=["10.10.0.0/24"])
    authz = authorizer(scope, local_ips=["10.10.0.5"])
    assert authz.authorize_cidr("10.10.0.0/24").kind == "cidr"


# ---------------------------------------------------------------------------
# Ports and policy
# ---------------------------------------------------------------------------


def test_excluded_ports(scope):
    authz = authorizer(scope)
    authz.check_port(443)
    with pytest.raises(RunnerError):
        authz.check_port(22)
    with pytest.raises(RunnerError):
        authz.check_ports([80, 3389])
    assert authz.excluded_ports_arg() == "22,3389"


def test_policy_flags(scope):
    authz = authorizer(scope)
    with pytest.raises(RunnerError):
        authz.require_syn()
    with pytest.raises(RunnerError):
        authz.require_os_detect()
    with pytest.raises(RunnerError):
        authz.require_axfr()


def test_effective_rate_is_capped(scope):
    authz = authorizer(scope)
    assert authz.effective_rate(None) == 500
    assert authz.effective_rate(100) == 100
    assert authz.effective_rate(1000) == 500


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def test_parse_port_list():
    assert parse_port_list("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(RunnerError):
        parse_port_list("8002-8000")
    with pytest.raises((RunnerError, ValueError)):
        parse_port_list("not-a-port")
    with pytest.raises(RunnerError):
        parse_port_list("70000")


def test_format_host_port_brackets_ipv6():
    assert format_host_port("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert format_host_port("203.0.113.10", 443) == "203.0.113.10:443"
    assert format_host_port("example.com", 443) == "example.com:443"


def test_ip_network_normalization():
    assert str(ipaddress.ip_network("10.10.1.9/16", strict=False)) == "10.10.0.0/16"
