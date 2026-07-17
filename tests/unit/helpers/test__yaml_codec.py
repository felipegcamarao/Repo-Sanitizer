"""test__yaml_codec.py — copia local Sentinel (DEF-08)."""
from __future__ import annotations

from repo_sanitizer.helpers._yaml_codec import (
    parse_frontmatter,
    serialize_frontmatter,
)


def test_serialize_simple_scalars() -> None:
    out = serialize_frontmatter({"a": 1, "b": "hello", "c": True})
    assert "a: 1" in out
    assert "b: hello" in out
    assert "c: true" in out


def test_serialize_quotes_special_chars() -> None:
    out = serialize_frontmatter({"k": "with: colon"})
    assert '"with: colon"' in out


def test_serialize_null() -> None:
    out = serialize_frontmatter({"x": None})
    assert "x: null" in out


def test_serialize_list_as_json() -> None:
    out = serialize_frontmatter({"items": [1, 2, 3]})
    assert "[1, 2, 3]" in out


def test_serialize_nested_dict_1_level() -> None:
    out = serialize_frontmatter({"origem": {"agent": "test", "version": "1.0"}})
    assert "origem:" in out
    assert "agent: test" in out
    assert "version" in out


def test_parse_roundtrip_scalars() -> None:
    d = {"a": 1, "b": "hello", "c": True, "d": False, "e": None}
    parsed = parse_frontmatter(serialize_frontmatter(d))
    assert parsed == d


def test_parse_quoted_string() -> None:
    parsed = parse_frontmatter('k: "with: colon"')
    assert parsed["k"] == "with: colon"


def test_parse_nested() -> None:
    text = "origem:\n  agent: test\n  version: 1.0"
    parsed = parse_frontmatter(text)
    assert parsed["origem"]["agent"] == "test"


def test_parse_empty_or_comment_lines_ignored() -> None:
    text = "\n# comment line\nk: v\n"
    parsed = parse_frontmatter(text)
    assert parsed == {"k": "v"}


def test_parse_line_without_colon_ignored() -> None:
    text = "valid: yes\nrandom-text-no-colon\nb: 2"
    parsed = parse_frontmatter(text)
    assert parsed == {"valid": "yes", "b": 2}


def test_parse_float() -> None:
    parsed = parse_frontmatter("pi: 3.14")
    assert parsed["pi"] == 3.14


def test_parse_single_quoted() -> None:
    parsed = parse_frontmatter("k: 'a''b'")
    assert parsed["k"] == "a'b"
