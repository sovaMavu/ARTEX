"""Sanitizer and bounded-output tests."""

from __future__ import annotations

from runner.sanitize import cap_json, clean_text, redact_argv, truncate_bytes, truncate_text


def test_clean_text_strips_ansi_csi_osc_and_controls():
    raw = (
        "\x1b[31mred\x1b[0m "
        "\x1b]0;title\x07 "
        "a\x00b\x01c\x7fd "
        "line1\r\nline2\rline3\tend"
    )
    cleaned = clean_text(raw)
    assert "red" in cleaned
    assert "\x1b" not in cleaned
    assert "\x00" not in cleaned
    assert "\x01" not in cleaned
    assert "\x7f" not in cleaned
    assert "line1\nline2\nline3\tend" in cleaned


def test_truncate_text_reports_whether_it_cut():
    assert truncate_text("abc", 10) == ("abc", False)
    assert truncate_text("abcdef", 3) == ("abc", True)
    assert truncate_text("abc", 0) == ("", True)


def test_truncate_bytes_is_utf8_safe():
    text = "a" * 10 + "é" + "b" * 10
    cut, truncated = truncate_bytes(text, 11)
    assert truncated
    assert cut == "a" * 10
    assert cut.encode("utf-8")


def test_cap_json_bounds_strings_and_lists():
    value = {"text": "x" * 100, "items": list(range(20)), "nested": [{"a": "y" * 100}]}
    capped = cap_json(value, text_limit=10, list_limit=5)
    assert capped["text"] == "x" * 10
    assert capped["items"] == [0, 1, 2, 3, 4]
    assert capped["nested"][0]["a"] == "y" * 10


def test_redact_argv_replaces_exact_secret_occurrences():
    argv = ["snmpwalk", "-c", "public", "public-host"]
    assert redact_argv(argv, ["public"]) == ["snmpwalk", "-c", "***", "***-host"]
    assert redact_argv(argv, []) == argv
