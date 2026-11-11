"""Durable artifact store with atomic writes and SHA-256 manifests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ARTIFACT_WRITE_FAILED, RunnerError
from .sanitize import clean_text

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class ArtifactRef:
    name: str
    path: str
    bytes: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


class ArtifactWriter:
    """Writes files under ``<root>/<task>/runner/<job>/`` only.

    No caller-supplied path ever reaches this class: names are fixed by the
    tool implementation and validated against a conservative basename regex.
    """

    def __init__(
        self,
        root: Path,
        task_id: int,
        job_id: str,
        tool: str,
        max_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.root = Path(root)
        self.task_id = int(task_id)
        self.job_id = job_id
        self.tool = tool
        self.max_bytes = int(max_bytes)
        self.dir = self.root / str(self.task_id) / "runner" / job_id
        self.files: dict[str, ArtifactRef] = {}
        self.bytes_written = 0
        self.truncated = False
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RunnerError(
                ARTIFACT_WRITE_FAILED,
                "could not create the artifact directory",
                details={"error": exc.__class__.__name__},
            ) from exc

    def _safe_name(self, name: str) -> str:
        if not _NAME_RE.match(name or ""):
            raise RunnerError(
                ARTIFACT_WRITE_FAILED,
                "invalid artifact name",
                details={"name": name[:80]},
            )
        return name

    def _atomic_write(
        self, name: str, data: bytes, *, enforce_cap: bool = True
    ) -> ArtifactRef | None:
        name = self._safe_name(name)
        if enforce_cap:
            remaining = self.max_bytes - self.bytes_written
            if remaining <= 0:
                self.truncated = True
                return None
            if len(data) > remaining:
                data = data[:remaining]
                self.truncated = True

        tmp = self.dir / f".{name}.{uuid.uuid4().hex}.tmp"
        dest = self.dir / name
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dest)
            try:
                dfd = os.open(self.dir, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                # Directory fsync is not available on every platform (Windows).
                pass
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise RunnerError(
                ARTIFACT_WRITE_FAILED,
                "could not write an artifact",
                details={"name": name, "error": exc.__class__.__name__},
            ) from exc

        digest = hashlib.sha256(data).hexdigest()
        ref = ArtifactRef(
            name=name,
            path=f"{self.task_id}/runner/{self.job_id}/{name}",
            bytes=len(data),
            sha256=digest,
        )
        self.files[name] = ref
        self.bytes_written += len(data)
        return ref

    def write_bytes(
        self, name: str, data: bytes, *, enforce_cap: bool = True
    ) -> ArtifactRef | None:
        return self._atomic_write(name, bytes(data), enforce_cap=enforce_cap)

    def write_text(
        self,
        name: str,
        text: str,
        sanitize: bool = True,
        *,
        enforce_cap: bool = True,
    ) -> ArtifactRef | None:
        if sanitize:
            text = clean_text(text)
        return self._atomic_write(
            name,
            text.encode("utf-8", errors="replace"),
            enforce_cap=enforce_cap,
        )

    def write_json(
        self,
        name: str,
        value: Any,
        *,
        indent: int | None = None,
        enforce_cap: bool = True,
    ) -> ArtifactRef | None:
        text = json.dumps(
            value,
            ensure_ascii=False,
            indent=indent,
            separators=(",", ":") if indent is None else None,
        )
        return self.write_text(
            name, text, sanitize=False, enforce_cap=enforce_cap
        )

    def finalize_manifest(
        self,
        *,
        job_id: str,
        task_id: int,
        tool: str,
        tool_version: str,
        argv_redacted: list[str],
        started_at: str | None,
        finished_at: str | None,
        exit_code: int | None,
    ) -> ArtifactRef | None:
        files = [
            {
                "name": ref.name,
                "bytes": ref.bytes,
                "sha256": ref.sha256,
            }
            for ref in sorted(self.files.values(), key=lambda r: r.name)
            if ref.name != "manifest.json"
        ]
        manifest = {
            "schema": "artex.runner.manifest.v1",
            "job_id": job_id,
            "task_id": task_id,
            "tool": tool,
            "tool_version": tool_version,
            "argv_redacted": argv_redacted,
            "started_at": started_at,
            "finished_at": finished_at,
            "exit_code": exit_code,
            "truncated": self.truncated,
            "files": files,
        }
        return self.write_json(
            "manifest.json", manifest, indent=2, enforce_cap=False
        )
