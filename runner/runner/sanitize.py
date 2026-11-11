"""Output sanitisation and bounding.

Target output is untrusted input.  Everything that can reach the model or a
human-readable artifact passes through these helpers.
"""

from __future__ import annotations

import re
from typing import Any

# CSI sequences: ESC [ ... final byte
_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# OSC sequences: ESC ] ... BEL or ST
_ANSI_OSC = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
# Remaining two-byte ESC sequences (charset selection, etc.)
_ANSI_OTHER = re.compile(r"\x1b[@-_]")
# C0 controls except TAB (0x09), LF (0x0a); DEL is also dropped.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: str) -> str:
    """Strip ANSI/OSC escapes, NUL bytes and control characters.

    Newlines and tabs are preserved because they carry structure in tool output.
    """

    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = _ANSI_OSC.sub("", value)
    value = _ANSI_CSI.sub("", value)
    value = _ANSI_OTHER.sub("", value)
    value = value.replace("\x00", "")
    value = _CONTROL.sub("", value)
    return value


def truncate_text(value: str, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0:
        return "", bool(value)
    if len(value) <= max_chars:
        return value, False
    return value[:max_chars], True


def truncate_bytes(value: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate a string to at most ``max_bytes`` UTF-8 bytes.

    The cut is moved back to a codepoint boundary so the result is always
    valid UTF-8.
    """

    if max_bytes <= 0:
        return "", bool(value)
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    cut = encoded[:max_bytes]
    while cut:
        try:
            return cut.decode("utf-8"), True
        except UnicodeDecodeError:
            cut = cut[:-1]
    return "", True


def cap_json(value: Any, text_limit: int = 4096, list_limit: int = 500) -> Any:
    """Recursively bound strings/lists in a JSON-compatible value.

    The full data lives in ``result.json``; this only bounds the model-facing
    preview envelope.
    """

    if isinstance(value, str):
        return truncate_text(clean_text(value), text_limit)[0]
    if isinstance(value, list):
        return [cap_json(v, text_limit, list_limit) for v in value[:list_limit]]
    if isinstance(value, tuple):
        return [cap_json(v, text_limit, list_limit) for v in value[:list_limit]]
    if isinstance(value, dict):
        return {str(k): cap_json(v, text_limit, list_limit) for k, v in value.items()}
    return value


def redact_argv(argv: list[str], secret_values: list[str]) -> list[str]:
    """Replace every exact secret occurrence in an argv vector."""

    secrets = [s for s in secret_values if s]
    out: list[str] = []
    for arg in argv:
        redacted = arg
        for secret in secrets:
            redacted = redacted.replace(secret, "***")
        out.append(redacted)
    return out
