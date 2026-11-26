"""Artifact writer, atomic file, and manifest tests."""

from __future__ import annotations

import hashlib
import json

import pytest

from runner.artifacts import ArtifactWriter
from runner.errors import ARTIFACT_WRITE_FAILED, RunnerError


def test_atomic_write_and_manifest(tmp_path):
    writer = ArtifactWriter(tmp_path, 42, "01JOB", "net_nmap")
    ref = writer.write_bytes("nmap.xml", b"<nmaprun/>")
    assert ref is not None
    assert (writer.dir / "nmap.xml").read_bytes() == b"<nmaprun/>"
    assert ref.path == "42/runner/01JOB/nmap.xml"
    assert ref.sha256 == hashlib.sha256(b"<nmaprun/>").hexdigest()

    result = writer.write_json("result.json", {"schema": "artex.runner.result.v1"})
    manifest_ref = writer.finalize_manifest(
        job_id="01JOB",
        task_id=42,
        tool="net_nmap",
        tool_version="7.95",
        argv_redacted=["nmap", "-Pn", "10.0.0.1"],
        started_at="2026-11-09T10:00:00Z",
        finished_at="2026-11-09T10:01:00Z",
        exit_code=0,
    )
    assert result is not None and manifest_ref is not None
    manifest = json.loads((writer.dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "artex.runner.manifest.v1"
    assert manifest["job_id"] == "01JOB"
    names = {entry["name"] for entry in manifest["files"]}
    assert {"nmap.xml", "result.json"} <= names
    assert "manifest.json" not in names
    for entry in manifest["files"]:
        data = (writer.dir / entry["name"]).read_bytes()
        assert entry["bytes"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()


def test_text_is_sanitized_by_default(tmp_path):
    writer = ArtifactWriter(tmp_path, 1, "J", "net_ssh")
    writer.write_text("stdout.txt", "\x1b[31mred\x1b[0m\x00\n")
    assert (writer.dir / "stdout.txt").read_text(encoding="utf-8") == "red\n"


def test_raw_bytes_are_not_sanitized(tmp_path):
    writer = ArtifactWriter(tmp_path, 1, "J", "net_ldap")
    payload = b"\x00\x01binary"
    writer.write_bytes("ldap.ldif", payload)
    assert (writer.dir / "ldap.ldif").read_bytes() == payload


def test_size_cap_sets_truncated(tmp_path):
    writer = ArtifactWriter(tmp_path, 1, "J", "net_nmap", max_bytes=10)
    ref = writer.write_bytes("big.txt", b"x" * 20)
    assert ref is not None
    assert ref.bytes == 10
    assert writer.truncated
    assert (writer.dir / "big.txt").read_bytes() == b"x" * 10
    assert writer.write_bytes("more.txt", b"y") is None


def test_result_and_manifest_bypass_raw_output_cap(tmp_path):
    writer = ArtifactWriter(tmp_path, 1, "J", "net_nmap", max_bytes=10)
    assert writer.write_bytes("big.txt", b"x" * 20) is not None
    assert writer.truncated

    payload = {"schema": "artex.runner.result.v1", "observations": [{"ip": "192.0.2.1"}] * 5}
    result_ref = writer.write_json("result.json", payload, enforce_cap=False)
    assert result_ref is not None
    on_disk = json.loads((writer.dir / "result.json").read_text(encoding="utf-8"))
    assert on_disk == payload

    manifest_ref = writer.finalize_manifest(
        job_id="J",
        task_id=1,
        tool="net_nmap",
        tool_version="",
        argv_redacted=[],
        started_at=None,
        finished_at=None,
        exit_code=0,
    )
    assert manifest_ref is not None
    manifest = json.loads((writer.dir / "manifest.json").read_text(encoding="utf-8"))
    names = {entry["name"] for entry in manifest["files"]}
    assert {"big.txt", "result.json"} <= names
    assert "manifest.json" not in names


def test_invalid_artifact_names_are_rejected(tmp_path):
    writer = ArtifactWriter(tmp_path, 1, "J", "net_nmap")
    for name in ("../escape", "a/b", "", ".hidden", "a" * 200):
        with pytest.raises(RunnerError) as exc:
            writer.write_bytes(name, b"x")
        assert exc.value.code == ARTIFACT_WRITE_FAILED


def test_artifact_directory_is_created(tmp_path):
    writer = ArtifactWriter(tmp_path / "nested", 7, "J", "net_nmap")
    assert writer.dir.is_dir()
    assert writer.dir == tmp_path / "nested" / "7" / "runner" / "J"
