"""test__binary_detector.py — magic-bytes + null-byte (ADR-009)."""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.helpers._binary_detector import (
    MAGIC_BYTES,
    classify,
    detect_magic,
    has_null_byte,
    is_binary,
)


def test_detect_magic_png() -> None:
    assert detect_magic(b"\x89PNG\r\n\x1a\nrest") == "PNG"


def test_detect_magic_pdf() -> None:
    assert detect_magic(b"%PDF-1.4 rest") == "PDF"


def test_detect_magic_zip() -> None:
    assert detect_magic(b"PK\x03\x04rest") == "ZIP/Office"


def test_detect_magic_jpeg() -> None:
    assert detect_magic(b"\xff\xd8\xff\xe0rest") == "JPEG"


def test_detect_magic_none_for_text() -> None:
    assert detect_magic(b"hello world\nbye") is None


def test_has_null_byte() -> None:
    assert has_null_byte(b"hello\x00world") is True
    assert has_null_byte(b"hello world") is False


def test_is_binary_png(tmp_path: Path) -> None:
    p = tmp_path / "fake.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\nrest_of_data")
    assert is_binary(p) is True


def test_is_binary_text(tmp_path: Path) -> None:
    p = tmp_path / "readme.md"
    p.write_text("# olar\nhello\n", encoding="utf-8")
    assert is_binary(p) is False


def test_classify_png_returns_dict(tmp_path: Path) -> None:
    p = tmp_path / "fake.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    info = classify(p)
    assert info["is_binary"] is True
    assert info["magic_label"] == "PNG"


def test_magic_bytes_has_10_known_formats() -> None:
    assert len(MAGIC_BYTES) >= 10
