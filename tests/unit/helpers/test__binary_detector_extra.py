"""test__binary_detector_extra.py — Bloco 02 02.4 smoke 10 magic-bytes (ADR-009).

Cobertura adicional sobre full impl: 10 formatos canonicos + null-byte heuristic
+ corner cases (file vazio, file menor que magic, sample limit).
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.helpers._binary_detector import (
    DEFAULT_SAMPLE_BYTES,
    MAGIC_BYTES,
    classify,
    detect_magic,
    is_binary,
    sample_file,
)


def test_magic_bytes_canonicos_inclui_14_formatos() -> None:
    """Bloco 02 02.4: full impl deve cobrir >=14 formatos."""
    assert len(MAGIC_BYTES) >= 14
    labels = set(MAGIC_BYTES.values())
    # Spot check formatos canonicos exigidos pelo plano
    assert "PNG" in labels
    assert "PDF" in labels
    assert "ZIP/Office" in labels
    assert "JPEG" in labels
    assert "ELF" in labels
    assert "PE/DOS" in labels
    assert "GZIP" in labels
    assert "SQLite3" in labels


def test_detect_magic_gif87() -> None:
    assert detect_magic(b"GIF87a\x00\x00") == "GIF87"


def test_detect_magic_gif89() -> None:
    assert detect_magic(b"GIF89a\x00\x00") == "GIF89"


def test_detect_magic_bmp() -> None:
    assert detect_magic(b"BM\x36\x00\x00\x00") == "BMP"


def test_detect_magic_ico() -> None:
    assert detect_magic(b"\x00\x00\x01\x00\x01\x00") == "ICO"


def test_detect_magic_riff() -> None:
    assert detect_magic(b"RIFF\x10\x00\x00\x00WEBP") == "WebP/RIFF"


def test_detect_magic_7z() -> None:
    assert detect_magic(b"7z\xbc\xaf\x27\x1c\x00\x00") == "7Z"


def test_detect_magic_gzip() -> None:
    assert detect_magic(b"\x1f\x8b\x08\x00") == "GZIP"


def test_detect_magic_xz() -> None:
    assert detect_magic(b"\xfd7zXZ\x00\x00") == "XZ"


def test_detect_magic_elf() -> None:
    assert detect_magic(b"\x7fELF\x02\x01\x01\x00") == "ELF"


def test_detect_magic_pe() -> None:
    assert detect_magic(b"MZ\x90\x00\x03\x00") == "PE/DOS"


def test_detect_magic_sqlite() -> None:
    assert detect_magic(b"SQLite format 3\x00\x00") == "SQLite3"


def test_detect_magic_wasm() -> None:
    assert detect_magic(b"\x00asm\x01\x00\x00\x00") == "WASM"


def test_classify_pdf_with_size_field(tmp_path: Path) -> None:
    p = tmp_path / "doc.pdf"
    p.write_bytes(b"%PDF-1.7\n%random binary stuff\x00\x00")
    info = classify(p)
    assert info["is_binary"] is True
    assert info["magic_label"] == "PDF"
    assert info["has_null_byte"] is True
    assert info["sample_size"] > 0


def test_classify_empty_file_returns_safe(tmp_path: Path) -> None:
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    info = classify(p)
    assert info["is_binary"] is False
    assert info["magic_label"] == ""
    assert info["sample_size"] == 0


def test_classify_pure_text_no_null(tmp_path: Path) -> None:
    p = tmp_path / "code.py"
    p.write_text("import os\nprint('ok')\n", encoding="utf-8")
    info = classify(p)
    assert info["is_binary"] is False
    assert info["magic_label"] == ""
    assert info["has_null_byte"] is False


def test_is_binary_text_with_embedded_null(tmp_path: Path) -> None:
    """Null-byte heuristica: aceita FP em texto com null intencional (INV-5)."""
    p = tmp_path / "weird.txt"
    p.write_bytes(b"oi mundo\x00bytes")
    assert is_binary(p) is True


def test_sample_file_respects_limit(tmp_path: Path) -> None:
    p = tmp_path / "big.bin"
    p.write_bytes(b"X" * 20_000)
    sample = sample_file(p, n=1024)
    assert len(sample) == 1024


def test_sample_file_missing_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "nope.bin"
    sample = sample_file(p)
    assert sample == b""


def test_default_sample_bytes_is_8kb() -> None:
    assert DEFAULT_SAMPLE_BYTES == 8 * 1024


def test_classify_jpeg_real_prefix(tmp_path: Path) -> None:
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01")
    info = classify(p)
    assert info["is_binary"] is True
    assert info["magic_label"] == "JPEG"


def test_zip_office_match(tmp_path: Path) -> None:
    """docx/xlsx/jar -> ZIP/Office (PK header)."""
    p = tmp_path / "spreadsheet.xlsx"
    p.write_bytes(b"PK\x03\x04\x14\x00\x06\x00")
    info = classify(p)
    assert info["magic_label"] == "ZIP/Office"
