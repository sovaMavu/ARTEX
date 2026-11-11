"""Configuration and input-model validation tests."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from runner.config import Config, ConfigError
from runner.tools.net import DNSInput, LDAPInput, NmapInput, SNMPInput, SSHInput, TLSInput

KEY = base64.b64encode(b"k" * 32).decode()


def env(**overrides):
    values = {
        "RUNNER_TOKEN": "t" * 32,
        "RUNNER_SCOPE_KEY": KEY,
        "SCOPE_DIR": "/scopes",
        "ARTIFACT_ROOT": "/artifacts",
    }
    values.update(overrides)
    return values


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_defaults():
    config = Config.from_env(env())
    assert config.scope_dir.as_posix() == "/scopes"
    assert config.artifact_root.as_posix() == "/artifacts"
    assert config.max_concurrent_jobs == 4
    assert config.max_jobs_per_task == 2
    assert config.max_output_bytes == 1_048_576
    assert config.net_pack_enabled()


def test_config_requires_token_and_key():
    with pytest.raises(ConfigError):
        Config.from_env({})
    with pytest.raises(ConfigError):
        Config.from_env(env(RUNNER_TOKEN="short"))
    with pytest.raises(ConfigError):
        Config.from_env(env(RUNNER_SCOPE_KEY=""))


def test_config_key_must_be_32_bytes_base64():
    with pytest.raises(ConfigError):
        Config.from_env(env(RUNNER_SCOPE_KEY="not-base64!"))
    with pytest.raises(ConfigError):
        Config.from_env(env(RUNNER_SCOPE_KEY=base64.b64encode(b"short").decode()))


def test_config_rejects_invalid_integers_and_booleans():
    with pytest.raises(ConfigError):
        Config.from_env(env(MAX_CONCURRENT_JOBS="0"))
    with pytest.raises(ConfigError):
        Config.from_env(env(MAX_CONCURRENT_JOBS="many"))
    with pytest.raises(ConfigError):
        Config.from_env(env(LOG_LEVEL="verbose"))


def test_config_normalizes_warning_and_packs():
    config = Config.from_env(env(LOG_LEVEL="warning", TOOL_PACKS="net, ad"))
    assert config.log_level == "warn"
    assert config.tool_packs == ("net", "ad")
    with pytest.raises(ConfigError):
        Config.from_env(env(TOOL_PACKS=" , "))


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


def test_nmap_custom_requires_ports():
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="custom")


def test_nmap_invalid_ports_are_validation_errors():
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="custom", ports="not-ports")
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="custom", ports="8002-8000")
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="custom", ports="70000")


def test_nmap_rejects_syn_and_os_for_discovery():
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="discovery", syn=True)
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="discovery", os_detect=True)


def test_nmap_bounds():
    with pytest.raises(ValidationError):
        NmapInput(task_id=0, target="10.0.0.1", profile="top100")
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="top100", wait_s=121)
    with pytest.raises(ValidationError):
        NmapInput(task_id=1, target="10.0.0.1", profile="top100", rate=1001)


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------


def test_dns_normalizes_and_dedupes_record_types():
    request = DNSInput(task_id=1, target="example.com", record_types=["a", "A", "mx"])
    assert request.record_types == ["A", "MX"]
    default = DNSInput(task_id=1, target="example.com")
    assert default.record_types == ["A", "AAAA"]


def test_dns_rejects_unsupported_record_types():
    with pytest.raises(ValidationError):
        DNSInput(task_id=1, target="example.com", record_types=["HINFO"])


# ---------------------------------------------------------------------------
# tls / ssh
# ---------------------------------------------------------------------------


def test_tls_profile_and_starttls_are_restricted():
    assert TLSInput(task_id=1, target="example.com").profile == "quick"
    with pytest.raises(ValidationError):
        TLSInput(task_id=1, target="example.com", profile="everything")
    with pytest.raises(ValidationError):
        TLSInput(task_id=1, target="example.com", starttls="postgres")


def test_ssh_port_bounds():
    assert SSHInput(task_id=1, target="10.0.0.1").port == 22
    with pytest.raises(ValidationError):
        SSHInput(task_id=1, target="10.0.0.1", port=0)


# ---------------------------------------------------------------------------
# ldap
# ---------------------------------------------------------------------------


def test_ldap_defaults_and_attributes():
    request = LDAPInput(task_id=1, target="dc01.corp.local")
    assert request.filter == "(objectClass=*)"
    assert request.attributes == ["*"]
    assert request.scope == "sub"


@pytest.mark.parametrize(
    "ldap_filter",
    [
        "(cn=test)\x00",
        "(cn=test)\n",
        "(cn=test)\t",
        "(cn=test)\x1f",
    ],
)
def test_ldap_filter_rejects_control_characters(ldap_filter):
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", filter=ldap_filter)


def test_ldap_filter_must_be_parenthesized_and_balanced():
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", filter="cn=test")
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", filter="(cn=test")


def test_ldap_attribute_names_are_restricted():
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", attributes=["cn: evil"])
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", attributes=["-o"])


def test_ldap_base_dn_rejects_control_and_leading_dash():
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", base_dn="-b evil")
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", base_dn="dc=corp\x00")


def test_ldap_max_entries_bounds():
    with pytest.raises(ValidationError):
        LDAPInput(task_id=1, target="dc01.corp.local", max_entries=1001)


# ---------------------------------------------------------------------------
# snmp
# ---------------------------------------------------------------------------


def test_snmp_community_rejects_control_characters():
    assert SNMPInput(task_id=1, target="10.0.0.1").community == "public"
    with pytest.raises(ValidationError):
        SNMPInput(task_id=1, target="10.0.0.1", community="public\x00")
    with pytest.raises(ValidationError):
        SNMPInput(task_id=1, target="10.0.0.1", community="public\n")
