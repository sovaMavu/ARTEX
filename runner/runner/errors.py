"""Structured runner errors.

Every failure path in the runner must end in one of these codes.  The MCP
layer receives a normal tool result containing the error envelope, never a
Python traceback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


AUTH_FAILED = "AUTH_FAILED"
INVALID_ARGUMENT = "INVALID_ARGUMENT"
SCOPE_DENIED = "SCOPE_DENIED"
SCOPE_EXPIRED = "SCOPE_EXPIRED"
SCOPE_MISSING = "SCOPE_MISSING"
RATE_LIMITED = "RATE_LIMITED"
TOOL_MISSING = "TOOL_MISSING"
TOOL_TIMEOUT = "TOOL_TIMEOUT"
TOOL_FAILED = "TOOL_FAILED"
JOB_NOT_FOUND = "JOB_NOT_FOUND"
ARTIFACT_WRITE_FAILED = "ARTIFACT_WRITE_FAILED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
INTERNAL = "INTERNAL"


@dataclass
class RunnerError(Exception):
    """A typed, model-safe error."""

    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.details:
            out["details"] = self.details
        return out

    def envelope(self) -> dict[str, Any]:
        return {
            "schema": "artex.runner.v1",
            "ok": False,
            "error": self.to_dict(),
        }


def error_envelope(exc: BaseException) -> dict[str, Any]:
    """Convert any exception to an ``artex.runner.v1`` error envelope.

    Unexpected exceptions are logged by the caller with their real detail; the
    model only sees a generic INTERNAL message so stack traces and secrets do
    not leak into the transcript.
    """

    if isinstance(exc, RunnerError):
        return exc.envelope()
    return RunnerError(INTERNAL, "unexpected runner error").envelope()


def invalid(message: str, **details: Any) -> RunnerError:
    return RunnerError(INVALID_ARGUMENT, message, details=details)


def denied(message: str, **details: Any) -> RunnerError:
    return RunnerError(SCOPE_DENIED, message, details=details)


def missing_binary(binary: str) -> RunnerError:
    return RunnerError(
        TOOL_MISSING,
        f"required tool '{binary}' is not installed in the runner image",
        details={"tool": binary},
    )
