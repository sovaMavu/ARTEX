"""In-memory async job manager with process-group cancellation.

Artifacts and ``result.json`` are the durable record; jobs themselves are
deliberately in memory.  A runner restart loses in-flight work.
"""

from __future__ import annotations

import hmac
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .artifacts import ArtifactWriter
from .config import Config
from .envelope import MODEL_SCHEMA, build_full_result, build_model_envelope, running_envelope
from .errors import (
    ARTIFACT_WRITE_FAILED,
    INTERNAL,
    JOB_NOT_FOUND,
    RATE_LIMITED,
    TOOL_FAILED,
    TOOL_TIMEOUT,
    RunnerError,
)

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    value = (int(time.time() * 1000) & ((1 << 48) - 1)) << 80
    value |= int.from_bytes(os.urandom(10), "big")
    chars: list[str] = []
    for _ in range(26):
        chars.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class JobCancelled(Exception):
    """Raised by a tool runner when cancellation was requested."""


@dataclass
class JobOutcome:
    ok: bool
    summary: str = ""
    observations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tool_version: str = ""
    argv_redacted: list[str] = field(default_factory=list)
    exit_code: int | None = None
    truncated: bool = False
    error: RunnerError | None = None


class Job:
    def __init__(
        self,
        *,
        job_id: str,
        task_id: int,
        tool: str,
        target: str,
        timeout_s: int,
        owner: str,
        fn: Callable[["Job"], JobOutcome],
        writer: ArtifactWriter,
        max_output_bytes: int,
        reason: str = "",
    ) -> None:
        self.id = job_id
        self.task_id = task_id
        self.tool = tool
        self.target = target
        self.timeout_s = timeout_s
        self.owner = owner
        self.reason = reason
        self.fn = fn
        self.writer = writer
        self.max_output_bytes = max_output_bytes

        self.state = "queued"
        self.created_at = utcnow()
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.cancel_requested = False
        self.timeout_requested = False
        self.outcome: JobOutcome | None = None
        self.error: RunnerError | None = None
        self.envelope: dict[str, Any] | None = None

        self._lock = threading.Lock()
        self._finalize_lock = threading.Lock()
        self._done = threading.Event()
        self._finalized = False
        self._proc: subprocess.Popen[bytes] | None = None
        self._thread: threading.Thread | None = None

    # -- process group -----------------------------------------------------

    def register_process(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._proc = proc
            requested = self.cancel_requested or self.timeout_requested
        if requested:
            self._kill_group(proc)

    def clear_process(self) -> None:
        with self._lock:
            self._proc = None

    def _kill_group(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is not None:
            return
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.terminate()
                except OSError:
                    return
        else:  # pragma: no cover - the production image is Linux
            try:
                proc.terminate()
            except OSError:
                return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
        else:  # pragma: no cover
            try:
                proc.kill()
            except OSError:
                pass

    def request_cancel(self) -> None:
        with self._lock:
            self.cancel_requested = True
            proc = self._proc
        if proc is not None:
            self._kill_group(proc)

    def request_timeout(self) -> None:
        with self._lock:
            self.timeout_requested = True
            proc = self._proc
        if proc is not None:
            self._kill_group(proc)

    # -- waiting / finalizing ---------------------------------------------

    def wait(self, timeout_s: float) -> bool:
        return self._done.wait(timeout=max(0.0, timeout_s))

    def finalize(self) -> None:
        with self._finalize_lock:
            if self._finalized:
                return
            self._finalized = True

        state = self._final_state()
        outcome = self.outcome or JobOutcome(ok=False)
        error = self.error or outcome.error
        if state == "timed_out":
            error = RunnerError(
                TOOL_TIMEOUT,
                f"job exceeded its {self.timeout_s}s timeout",
                retryable=True,
                details={"timeout_s": self.timeout_s},
            )
        elif state == "cancelled":
            error = RunnerError(TOOL_FAILED, "job was cancelled", retryable=True)
        if error is not None and not outcome.summary:
            outcome.summary = error.message
        if state == "succeeded" and error is not None:
            state = "failed"

        try:
            artifact_refs = [
                ref.to_dict()
                for name, ref in self.writer.files.items()
                if name not in {"result.json", "manifest.json"}
            ]
            full = build_full_result(
                job_id=self.id,
                task_id=self.task_id,
                tool=self.tool,
                state=state,
                started_at=_iso(self.started_at),
                finished_at=_iso(self.finished_at or utcnow()),
                summary=outcome.summary,
                observations=outcome.observations,
                warnings=outcome.warnings,
                truncated=outcome.truncated or self.writer.truncated,
                error=error.to_dict() if error is not None else None,
                tool_version=outcome.tool_version,
                argv_redacted=outcome.argv_redacted,
                artifacts=artifact_refs,
                exit_code=outcome.exit_code,
            )
            # result.json is the durable source of truth for ingestion and must
            # never be truncated by the raw-output byte cap. It is still written
            # atomically and included in the manifest.
            result_ref = self.writer.write_json(
                "result.json", full, enforce_cap=False
            )
            manifest_ref = self.writer.finalize_manifest(
                job_id=self.id,
                task_id=self.task_id,
                tool=self.tool,
                tool_version=outcome.tool_version,
                argv_redacted=outcome.argv_redacted,
                started_at=full["started_at"],
                finished_at=full["finished_at"],
                exit_code=outcome.exit_code,
            )
            envelope_artifacts = list(artifact_refs)
            if manifest_ref is not None:
                envelope_artifacts.append(manifest_ref.to_dict())
            self.envelope = build_model_envelope(
                full,
                result_ref=result_ref.to_dict() if result_ref is not None else None,
                artifact_refs=envelope_artifacts,
                max_bytes=self.max_output_bytes,
            )
        except Exception as exc:  # noqa: BLE001 - never kill the worker thread
            # A disk failure must still produce a structured result; the job
            # thread has to reach ``_done.set()`` so waiters are released.
            code = getattr(exc, "code", None) or (
                ARTIFACT_WRITE_FAILED
                if isinstance(exc, RunnerError)
                else INTERNAL
            )
            self.envelope = {
                "schema": MODEL_SCHEMA,
                "ok": False,
                "job_id": self.id,
                "task_id": self.task_id,
                "tool": self.tool,
                "state": state,
                "error": {
                    "code": code,
                    "message": "the job result could not be persisted",
                    "retryable": False,
                },
                "truncated": True,
            }

    def _final_state(self) -> str:
        if self.timeout_requested:
            return "timed_out"
        if self.cancel_requested:
            return "cancelled"
        if self.error is not None:
            return "failed"
        if self.outcome is not None and self.outcome.ok:
            return "succeeded"
        return "failed"

    def running(self) -> dict[str, Any]:
        return running_envelope(
            job_id=self.id,
            task_id=self.task_id,
            tool=self.tool,
            state=self.state if self.state in {"queued", "running"} else self.state,
        )


class JobManager:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._active = 0
        self._per_task: dict[int, int] = {}

    def submit(
        self,
        *,
        task_id: int,
        tool: str,
        target: str,
        timeout_s: int,
        owner: str,
        fn: Callable[[Job], JobOutcome],
        reason: str = "",
    ) -> Job:
        job_id = new_ulid()
        with self._lock:
            self._gc_locked()
            if self._active >= self.config.max_concurrent_jobs:
                raise RunnerError(
                    RATE_LIMITED,
                    "the runner is at its global job concurrency limit",
                    retryable=True,
                    details={"retry_after_s": 5},
                )
            if self._per_task.get(task_id, 0) >= self.config.max_jobs_per_task:
                raise RunnerError(
                    RATE_LIMITED,
                    f"task {task_id} is at its job concurrency limit",
                    retryable=True,
                    details={"retry_after_s": 5, "task_id": task_id},
                )
            writer = ArtifactWriter(
                self.config.artifact_root,
                task_id,
                job_id,
                tool,
                max_bytes=self.config.max_artifact_bytes,
            )
            job = Job(
                job_id=job_id,
                task_id=task_id,
                tool=tool,
                target=target,
                timeout_s=timeout_s,
                owner=owner,
                fn=fn,
                writer=writer,
                max_output_bytes=self.config.max_output_bytes,
                reason=reason,
            )
            self._jobs[job_id] = job
            self._active += 1
            self._per_task[task_id] = self._per_task.get(task_id, 0) + 1
            thread = threading.Thread(
                target=self._run,
                args=(job,),
                name=f"job-{job_id}",
                daemon=True,
            )
            job._thread = thread
            thread.start()
        return job

    def _run(self, job: Job) -> None:
        with job._lock:
            job.state = "running"
            job.started_at = utcnow()
            skip = job.cancel_requested or job.timeout_requested
        timer = threading.Timer(job.timeout_s, job.request_timeout)
        timer.daemon = True
        timer.start()
        try:
            if not skip:
                outcome = job.fn(job)
                if isinstance(outcome, JobOutcome):
                    job.outcome = outcome
        except JobCancelled:
            job.cancel_requested = True
        except RunnerError as exc:
            job.error = exc
        except Exception as exc:  # noqa: BLE001 - mapped to a safe envelope
            job.error = RunnerError(INTERNAL, "unexpected runner error")
            job.outcome = job.outcome or JobOutcome(ok=False)
            job.outcome.warnings.append(f"internal error: {exc.__class__.__name__}")
        finally:
            timer.cancel()
            job.finished_at = utcnow()
            if job.timeout_requested:
                job.state = "timed_out"
            elif job.cancel_requested:
                job.state = "cancelled"
            elif job.error is not None:
                job.state = "failed"
            elif job.outcome is not None and job.outcome.ok:
                job.state = "succeeded"
            else:
                job.state = "failed"
            try:
                job.finalize()
            finally:
                with self._lock:
                    self._active = max(0, self._active - 1)
                    n = self._per_task.get(job.task_id, 0) - 1
                    if n <= 0:
                        self._per_task.pop(job.task_id, None)
                    else:
                        self._per_task[job.task_id] = n
                job._done.set()

    def _lookup(self, job_id: str, owner: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise RunnerError(JOB_NOT_FOUND, "job not found or expired")
        if job.owner and owner and not hmac.compare_digest(job.owner, owner):
            # Do not reveal another caller's job.
            raise RunnerError(JOB_NOT_FOUND, "job not found or expired")
        return job

    def wait(self, job_id: str, timeout_s: int, owner: str = "") -> dict[str, Any]:
        job = self._lookup(job_id, owner)
        if job.wait(timeout_s):
            return job.envelope or job.running()
        return job.running()

    def cancel(self, job_id: str, owner: str = "") -> dict[str, Any]:
        job = self._lookup(job_id, owner)
        if job._done.is_set():
            return job.envelope or job.running()
        job.request_cancel()
        if not job.wait(5):
            # The process group was signalled; give the worker a moment to
            # finalize, then write the durable cancelled record ourselves.
            job.finished_at = job.finished_at or utcnow()
            job.state = "cancelled"
            job.finalize()
            job._done.set()
        return job.envelope or job.running()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _gc_locked(self) -> None:
        cutoff = time.time() - self.config.job_retention_s
        expired = [
            jid
            for jid, job in self._jobs.items()
            if job.finished_at is not None and job.finished_at.timestamp() < cutoff
        ]
        for jid in expired:
            self._jobs.pop(jid, None)

    def shutdown(self) -> None:
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            if not job._done.is_set():
                job.request_cancel()
