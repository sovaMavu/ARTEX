"""Build the full result document and the bounded model-facing envelope."""

from __future__ import annotations

import json
from typing import Any

from .sanitize import cap_json, truncate_text

MODEL_SCHEMA = "artex.runner.v1"
RESULT_SCHEMA = "artex.runner.result.v1"
MAX_PREVIEW_ITEMS = 200


def build_full_result(
    *,
    job_id: str,
    task_id: int,
    tool: str,
    state: str,
    started_at: str | None,
    finished_at: str | None,
    summary: str,
    observations: list[dict[str, Any]],
    warnings: list[str],
    truncated: bool,
    error: dict[str, Any] | None,
    tool_version: str = "",
    argv_redacted: list[str] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    exit_code: int | None = None,
    observations_truncated: bool = False,
) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "ok": error is None and state == "succeeded",
        "job_id": job_id,
        "task_id": task_id,
        "tool": tool,
        "state": state,
        "started_at": started_at,
        "finished_at": finished_at,
        "summary": truncate_text(summary or "", 2000)[0],
        "observations_total": len(observations),
        "observations_truncated": bool(observations_truncated),
        "observations": observations,
        "artifacts": artifacts or [],
        "truncated": bool(truncated),
        "warnings": [truncate_text(w, 1000)[0] for w in (warnings or [])[:200]],
        "error": error,
        "tool_version": tool_version,
        "argv_redacted": argv_redacted or [],
        "exit_code": exit_code,
    }


def build_model_envelope(
    full: dict[str, Any],
    *,
    result_ref: dict[str, Any] | None,
    artifact_refs: list[dict[str, Any]],
    max_bytes: int,
) -> dict[str, Any]:
    observations = full.get("observations") or []
    total = len(observations)
    preview = [cap_json(o, text_limit=4096, list_limit=100) for o in observations[:MAX_PREVIEW_ITEMS]]
    obs_truncated = total > len(preview)

    def make() -> dict[str, Any]:
        return {
            "schema": MODEL_SCHEMA,
            "ok": bool(full.get("ok")),
            "job_id": full.get("job_id"),
            "task_id": full.get("task_id"),
            "tool": full.get("tool"),
            "state": full.get("state"),
            "started_at": full.get("started_at"),
            "finished_at": full.get("finished_at"),
            "summary": truncate_text(str(full.get("summary") or ""), 2000)[0],
            # Kept early so a truncated ARTEX tool result still carries the
            # reference the ingestion hook needs.
            "result_artifact": result_ref,
            "artifacts": artifact_refs,
            "observations_total": total,
            "observations_truncated": obs_truncated,
            "observations": preview,
            "truncated": bool(full.get("truncated")) or obs_truncated,
            "warnings": [truncate_text(str(w), 1000)[0] for w in (full.get("warnings") or [])[:50]],
            "error": full.get("error"),
        }

    envelope = make()
    encoded = _encode(envelope)
    while len(encoded.encode("utf-8")) > max_bytes and preview:
        # Drop the tail in chunks; the full list is in result.json.
        drop = max(1, len(preview) // 4)
        del preview[-drop:]
        obs_truncated = True
        envelope = make()
        encoded = _encode(envelope)
    if len(encoded.encode("utf-8")) > max_bytes:
        # Even the empty preview is too large (pathological summary/warnings).
        envelope["warnings"] = []
        envelope["summary"] = truncate_text(envelope["summary"], 500)[0]
        envelope["truncated"] = True
        encoded = _encode(envelope)
    return json.loads(encoded)


def running_envelope(
    *,
    job_id: str,
    task_id: int,
    tool: str,
    state: str = "running",
) -> dict[str, Any]:
    return {
        "schema": MODEL_SCHEMA,
        "ok": True,
        "job_id": job_id,
        "task_id": task_id,
        "tool": tool,
        "state": state,
        "poll_with": "job_wait",
    }


def _encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
