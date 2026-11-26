"""Job manager tests: success, timeout, cancel, concurrency, retention."""

from __future__ import annotations

import os
import subprocess
import time
from datetime import timedelta

import pytest

from runner.config import Config
from runner.errors import ARTIFACT_WRITE_FAILED, RATE_LIMITED, TOOL_TIMEOUT, RunnerError
from runner.jobs import Job, JobCancelled, JobManager, JobOutcome, utcnow


def make_config(tmp_path, **overrides) -> Config:
    values = {
        "token": "t" * 32,
        "scope_key": b"k" * 32,
        "scope_dir": tmp_path / "scopes",
        "artifact_root": tmp_path / "artifacts",
        "max_concurrent_jobs": 4,
        "max_jobs_per_task": 2,
        "max_timeout_s": 60,
    }
    values.update(overrides)
    return Config(**values)


def submit(manager: JobManager, fn, *, task_id=1, timeout_s=5):
    return manager.submit(
        task_id=task_id,
        tool="net_nmap",
        target="10.0.0.1",
        timeout_s=timeout_s,
        owner="owner",
        fn=fn,
    )


def test_job_success_writes_result_and_manifest(tmp_path):
    manager = JobManager(make_config(tmp_path))

    def fn(job: Job) -> JobOutcome:
        job.writer.write_text("stdout.txt", "hello")
        return JobOutcome(
            ok=True,
            summary="one host up",
            observations=[{"kind": "ip", "ip": "10.0.0.1", "hostnames": []}],
            tool_version="7.95",
            argv_redacted=["nmap", "10.0.0.1"],
        )

    job = submit(manager, fn)
    assert job.wait(5)
    envelope = job.envelope
    assert envelope is not None
    assert envelope["ok"] is True
    assert envelope["state"] == "succeeded"
    assert envelope["observations_total"] == 1
    assert envelope["result_artifact"]["name"] == "result.json"
    assert (job.writer.dir / "result.json").is_file()
    assert (job.writer.dir / "manifest.json").is_file()
    result = (job.writer.dir / "result.json").read_text(encoding="utf-8")
    assert "artex.runner.result.v1" in result


def test_job_timeout(tmp_path):
    manager = JobManager(make_config(tmp_path))

    def fn(job: Job) -> JobOutcome:
        deadline = time.time() + 5
        while time.time() < deadline:
            if job.timeout_requested:
                raise RunnerError(TOOL_TIMEOUT, "timed out", retryable=True)
            time.sleep(0.01)
        return JobOutcome(ok=True)

    job = submit(manager, fn, timeout_s=1)
    assert job.wait(5)
    assert job.envelope["state"] == "timed_out"
    assert job.envelope["error"]["code"] == TOOL_TIMEOUT


def test_job_cancel(tmp_path):
    manager = JobManager(make_config(tmp_path))

    def fn(job: Job) -> JobOutcome:
        deadline = time.time() + 5
        while time.time() < deadline:
            if job.cancel_requested:
                raise JobCancelled()
            time.sleep(0.01)
        return JobOutcome(ok=True)

    job = submit(manager, fn)
    assert job.wait(1) is False
    envelope = manager.cancel(job.id, owner="owner")
    assert envelope["state"] == "cancelled"
    assert job._done.is_set()


def test_job_wait_returns_running_on_timeout(tmp_path):
    manager = JobManager(make_config(tmp_path))
    release = __import__("threading").Event()

    def fn(job: Job) -> JobOutcome:
        release.wait(5)
        return JobOutcome(ok=True, summary="done")

    job = submit(manager, fn)
    envelope = manager.wait(job.id, 0, owner="owner")
    assert envelope["state"] in {"queued", "running"}
    release.set()
    assert job.wait(5)


def test_global_concurrency_limit(tmp_path):
    manager = JobManager(make_config(tmp_path, max_concurrent_jobs=1, max_jobs_per_task=1))
    release = __import__("threading").Event()

    def fn(job: Job) -> JobOutcome:
        release.wait(5)
        return JobOutcome(ok=True)

    first = submit(manager, fn, task_id=1)
    with pytest.raises(RunnerError) as exc:
        submit(manager, fn, task_id=2)
    assert exc.value.code == RATE_LIMITED
    release.set()
    assert first.wait(5)


def test_per_task_concurrency_limit(tmp_path):
    manager = JobManager(make_config(tmp_path, max_concurrent_jobs=4, max_jobs_per_task=1))
    release = __import__("threading").Event()

    def fn(job: Job) -> JobOutcome:
        release.wait(5)
        return JobOutcome(ok=True)

    first = submit(manager, fn, task_id=1)
    other = submit(manager, fn, task_id=2)
    with pytest.raises(RunnerError) as exc:
        submit(manager, fn, task_id=1)
    assert exc.value.code == RATE_LIMITED
    release.set()
    assert first.wait(5) and other.wait(5)


def test_job_retention_gc(tmp_path):
    manager = JobManager(make_config(tmp_path, job_retention_s=60))

    def fn(job: Job) -> JobOutcome:
        return JobOutcome(ok=True)

    job = submit(manager, fn)
    assert job.wait(5)
    job.finished_at = utcnow() - timedelta(seconds=120)
    manager._gc_locked()
    assert manager.get(job.id) is None


def test_finalize_failure_produces_structured_envelope(tmp_path, monkeypatch):
    manager = JobManager(make_config(tmp_path))

    def fn(job: Job) -> JobOutcome:
        return JobOutcome(ok=True, summary="done")

    job = submit(manager, fn)
    assert job.wait(5)

    # Force finalization to run again with a broken writer.
    job._finalized = False
    job.envelope = None
    monkeypatch.setattr(
        job.writer,
        "write_json",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RunnerError(ARTIFACT_WRITE_FAILED, "disk full")
        ),
    )
    job.finalize()
    assert job.envelope["ok"] is False
    assert job.envelope["error"]["code"] == ARTIFACT_WRITE_FAILED


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-specific")
def test_cancel_kills_process_group(tmp_path):
    manager = JobManager(make_config(tmp_path))
    proc_holder = {}

    def fn(job: Job) -> JobOutcome:
        proc = subprocess.Popen(
            ["sh", "-c", "sleep 30"],
            start_new_session=True,
        )
        proc_holder["proc"] = proc
        job.register_process(proc)
        proc.wait(30)
        return JobOutcome(ok=True)

    job = submit(manager, fn)
    deadline = time.time() + 5
    while "proc" not in proc_holder and time.time() < deadline:
        time.sleep(0.01)
    assert "proc" in proc_holder
    job.request_cancel()
    proc_holder["proc"].wait(5)
    assert proc_holder["proc"].returncode is not None
