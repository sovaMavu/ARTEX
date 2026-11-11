"""End-to-end tool tests with a fake process layer.

These exercise validation, scope checks, command construction, parsing, job
finalization, and artifact writing without requiring the Kali toolchain.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.config import Config
from runner.errors import SCOPE_DENIED, RunnerError
from runner.tools.net import (
    DNSInput,
    LDAPInput,
    NmapInput,
    SNMPInput,
    SSHInput,
    SMBInput,
    TLSInput,
    Runner,
)

from .conftest import SCOPE_KEY, TASK_ID, signed_scope, write_scope

DATA = Path(__file__).parent / "testdata"


def make_runner(config: Config, monkeypatch) -> Runner:
    write_scope(config.scope_dir)
    runner = Runner(config)
    runner._version = lambda _binary: ""  # type: ignore[method-assign]
    monkeypatch.setattr("runner.scope._system_resolve", lambda _host: ["203.0.113.10"])
    return runner


def fake_process(runner: Runner, monkeypatch, result):
    calls = []

    def fake(job, argv, timeout_s, env=None):
        calls.append(list(argv))
        return result(job, argv) if callable(result) else result

    monkeypatch.setattr(runner, "_run_process", fake)
    return calls


def test_nmap_command_and_observations(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    xml = (DATA / "nmap/host-up.xml").read_bytes()
    calls = fake_process(runner, monkeypatch, lambda _job, _argv: (0, xml, b""))

    result = runner.net_nmap(
        NmapInput(
            task_id=TASK_ID,
            target="10.10.0.5",
            profile="top100",
            rate=100,
            wait_s=10,
        )
    )
    assert result["ok"] is True
    assert result["observations_total"] == 5
    assert result["tool"] == "net_nmap"
    assert result["result_artifact"]["name"] == "result.json"

    argv = calls[0]
    assert "-sT" in argv
    assert "--top-ports" in argv and "100" in argv
    assert "--max-rate" in argv and argv[argv.index("--max-rate") + 1] == "100"
    assert "--exclude-ports" in argv and argv[argv.index("--exclude-ports") + 1] == "22,3389"
    assert argv[-1] == "10.10.0.5"

    job_dir = config.artifact_root / str(TASK_ID) / "runner" / result["job_id"]
    assert (job_dir / "nmap.xml").is_file()
    assert (job_dir / "result.json").is_file()
    manifest = json.loads((job_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["argv_redacted"][0] == "nmap"


def test_nmap_rate_is_capped_to_scope(config, monkeypatch):
    write_scope(
        config.scope_dir,
        payload=signed_scope(
            policy={
                "max_rate": 50,
                "max_hosts": 4096,
                "allow_syn": False,
                "allow_os_detect": False,
                "allow_axfr": False,
            }
        ),
    )
    runner = Runner(config)
    runner._version = lambda _binary: ""  # type: ignore[method-assign]
    calls = fake_process(
        runner, monkeypatch, lambda _job, _argv: (0, (DATA / "nmap/no-hosts.xml").read_bytes(), b"")
    )

    result = runner.net_nmap(
        NmapInput(task_id=TASK_ID, target="10.10.0.5", profile="top100", rate=500, wait_s=10)
    )
    assert result["ok"] is True
    assert calls[0][calls[0].index("--max-rate") + 1] == "50"
    assert any("capped" in warning for warning in result["warnings"])


def test_nmap_out_of_scope_is_denied_before_spawn(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    calls = fake_process(runner, monkeypatch, (0, b"", b""))

    result = runner.net_nmap(
        NmapInput(task_id=TASK_ID, target="8.8.8.8", profile="top100", wait_s=0)
    )
    assert result["ok"] is False
    assert result["error"]["code"] == SCOPE_DENIED
    assert calls == []


def test_nmap_syn_requires_policy(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    fake_process(runner, monkeypatch, (0, b"", b""))
    result = runner.net_nmap(
        NmapInput(task_id=TASK_ID, target="10.10.0.5", profile="top100", syn=True, wait_s=0)
    )
    assert result["error"]["code"] == SCOPE_DENIED


def test_nmap_job_wait_and_cancel_round_trip(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    import threading

    release = threading.Event()

    def slow(job, argv):
        release.wait(5)
        return 0, (DATA / "nmap/no-hosts.xml").read_bytes(), b""

    fake_process(runner, monkeypatch, slow)
    started = runner.net_nmap(
        NmapInput(task_id=TASK_ID, target="10.10.0.5", profile="top100", wait_s=0)
    )
    assert started["state"] in {"queued", "running"}
    job_id = started["job_id"]
    waiting = runner.job_wait(job_id, timeout_s=1)
    assert waiting["state"] in {"queued", "running"}
    release.set()
    final = runner.job_wait(job_id, timeout_s=10)
    assert final["state"] == "succeeded"
    assert final["ok"] is True


def test_dns_tool_and_artifacts(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    answers = (DATA / "dns/answers.txt").read_bytes()
    calls = fake_process(runner, monkeypatch, lambda _job, _argv: (0, answers, b""))

    result = runner.net_dns(
        DNSInput(task_id=TASK_ID, target="example.com", record_types=["A", "MX"], wait_s=10)
    )
    assert result["ok"] is True
    assert result["observations_total"] >= 3
    kinds = [o["kind"] for o in result["observations"]]
    assert "dns_record" in kinds
    assert "ip" in kinds
    assert calls[0][-1] == "example.com"
    job_dir = config.artifact_root / str(TASK_ID) / "runner" / result["job_id"]
    assert (job_dir / "dns.json").is_file()
    assert (job_dir / "dig-A.txt").is_file()
    assert (job_dir / "dig-MX.txt").is_file()


def test_tls_tool_pins_hostname_and_enriches_findings(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    scan = (DATA / "testssl/scan.json").read_bytes()
    monkeypatch.setattr("runner.tools.net.shutil.which", lambda name: f"/usr/bin/{name}")

    def fake(job, argv, timeout_s, env=None):
        path = Path(argv[argv.index("--jsonfile") + 1])
        path.write_bytes(scan)
        return 0, b"", b""

    monkeypatch.setattr(runner, "_run_process", fake)
    result = runner.net_tls(
        TLSInput(task_id=TASK_ID, target="example.com:443", wait_s=10)
    )
    assert result["ok"] is True
    endpoint = next(o for o in result["observations"] if o["kind"] == "tls_endpoint")
    assert endpoint["host"] == "example.com"
    assert endpoint["port"] == 443
    findings = [o for o in result["observations"] if o["kind"] == "tls_finding"]
    assert findings and all(f["host"] == "example.com" and f["port"] == 443 for f in findings)
    job_dir = config.artifact_root / str(TASK_ID) / "runner" / result["job_id"]
    assert (job_dir / "testssl.json").is_file()


def test_snmp_redacts_community(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    walk = (DATA / "snmp/walk.txt").read_bytes()
    calls = fake_process(runner, monkeypatch, lambda _job, _argv: (0, walk, b""))

    result = runner.net_snmp(
        SNMPInput(task_id=TASK_ID, target="10.10.0.5", community="s3cret", wait_s=10)
    )
    assert result["ok"] is True
    assert calls[0][calls[0].index("-c") + 1] == "s3cret"
    job_dir = config.artifact_root / str(TASK_ID) / "runner" / result["job_id"]
    manifest = (job_dir / "manifest.json").read_text(encoding="utf-8")
    result_json = (job_dir / "result.json").read_text(encoding="utf-8")
    assert "s3cret" not in manifest
    assert "s3cret" not in result_json
    assert "***" in manifest
    system = next(o for o in result["observations"] if o["kind"] == "snmp_system")
    assert system["ip"] == "10.10.0.5"
    service = next(o for o in result["observations"] if o["kind"] == "service")
    assert (service["port"], service["proto"]) == (161, "udp")


def test_smb_tool_enriches_ip(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    scan = (DATA / "enum4linux/scan.json").read_bytes()

    def fake(job, argv, timeout_s, env=None):
        path = Path(argv[argv.index("-oJ") + 1])
        path.write_bytes(scan)
        return 0, b"", b""

    monkeypatch.setattr(runner, "_run_process", fake)
    result = runner.net_smb(
        SMBInput(task_id=TASK_ID, target="10.10.0.5", mode="all", wait_s=10)
    )
    assert result["ok"] is True
    for obs in result["observations"]:
        if obs["kind"].startswith("smb_"):
            assert obs["ip"] == "10.10.0.5"
    assert any(o["kind"] == "service" and o["port"] == 445 for o in result["observations"])


def test_ldap_tool_parses_ldif(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    ldif = (DATA / "ldap/entries.ldif").read_bytes()
    calls = fake_process(runner, monkeypatch, lambda _job, _argv: (0, ldif, b""))

    result = runner.net_ldap(
        LDAPInput(
            task_id=TASK_ID,
            target="10.10.0.5",
            base_dn="dc=corp,dc=local",
            filter="(objectClass=person)",
            attributes=["cn", "memberOf"],
            wait_s=10,
        )
    )
    assert result["ok"] is True
    assert result["observations_total"] == 3
    assert result["observations"][0]["kind"] == "ldap_entry"
    argv = calls[0]
    assert argv[0] == "ldapsearch"
    assert "-x" in argv
    assert argv[-1] == "memberOf"


def test_ssh_tool_enriches_findings(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    scan = (DATA / "ssh-audit/scan.json").read_bytes()
    fake_process(runner, monkeypatch, lambda _job, _argv: (0, scan, b""))

    result = runner.net_ssh(
        SSHInput(task_id=TASK_ID, target="10.10.0.5", port=2222, wait_s=10)
    )
    assert result["ok"] is True
    server = next(o for o in result["observations"] if o["kind"] == "ssh_server")
    assert server["ip"] == "10.10.0.5"
    assert server["port"] == 2222
    findings = [o for o in result["observations"] if o["kind"] == "ssh_finding"]
    assert findings and all(f["ip"] == "10.10.0.5" and f["port"] == 2222 for f in findings)


def test_excluded_port_is_denied(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    calls = fake_process(runner, monkeypatch, (0, b"", b""))
    result = runner.net_ssh(
        SSHInput(task_id=TASK_ID, target="10.10.0.5", port=22, wait_s=0)
    )
    assert result["error"]["code"] == SCOPE_DENIED
    assert calls == []


def test_missing_binary_is_structured(config, monkeypatch):
    runner = make_runner(config, monkeypatch)
    monkeypatch.setattr("runner.tools.net.shutil.which", lambda _name: None)
    result = runner.net_tls(TLSInput(task_id=TASK_ID, target="10.10.0.5", wait_s=0))
    assert result["error"]["code"] == "TOOL_MISSING"
