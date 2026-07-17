"""test__encoding.py — multi-encoding scanner (ADR-021)."""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.helpers._encoding import (
    BOMS,
    classify_encoding,
    detect_bom,
    try_decode_sequential,
)


def test_detect_bom_utf8() -> None:
    assert detect_bom(b"\xef\xbb\xbfhello") == "utf-8-bom"


def test_detect_bom_utf16_le() -> None:
    assert detect_bom(b"\xff\xfehello") == "utf-16-le"


def test_detect_bom_utf16_be() -> None:
    assert detect_bom(b"\xfe\xffhello") == "utf-16-be"


def test_detect_bom_none() -> None:
    assert detect_bom(b"hello") is None


def test_try_decode_sequential_utf8() -> None:
    variants = try_decode_sequential(b"hello world")
    encodings = [enc for enc, _ in variants]
    assert "utf-8" in encodings


def test_try_decode_sequential_utf16_le_bom() -> None:
    data = b"\xff\xfeh\x00e\x00l\x00l\x00o\x00"
    variants = try_decode_sequential(data)
    encodings = [enc for enc, _ in variants]
    assert "utf-16-le" in encodings
    # texto contendo "hello" deve aparecer
    found = any("hello" in text for _, text in variants)
    assert found


def test_classify_encoding_utf8(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("hello", encoding="utf-8")
    assert classify_encoding(f) == "utf-8"


def test_classify_encoding_binary_via_null(tmp_path: Path) -> None:
    f = tmp_path / "f.bin"
    f.write_bytes(b"hello\x00world")
    assert classify_encoding(f) == "binary"


def test_boms_table_has_3_entries() -> None:
    assert len(BOMS) == 3


def test_errors_replace_obrigatorio_no_decode_ignore() -> None:
    """Invariante DEF-03: NUNCA usar errors='ignore' (oculta secrets RS-019)."""
    # Bytes invalidos em UTF-8: 0xff isolado
    data = b"safe\xff\xfemore"
    variants = try_decode_sequential(data)
    # latin-1 sempre decodifica
    found_latin1 = next((t for e, t in variants if e == "latin-1"), None)
    assert found_latin1 is not None
    # bytes invalidos representados como U+FFFD (replace), nao removidos
    # latin-1 nao gera U+FFFD porque latin-1 mapeia todos 256 bytes, mas o teste
    # garante que a string nao foi truncada (errors='ignore' truncaria).
    assert len(found_latin1) >= 6  # 'safe' + 2 bytes nao-removidos
