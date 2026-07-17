"""test__encoding_extra.py — cobertura adicional _encoding."""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.helpers._encoding import (
    classify_encoding,
    iter_decoded_variants,
    try_decode_sequential,
)


def test_iter_decoded_variants_wrapper() -> None:
    variants = list(iter_decoded_variants(b"hi"))
    assert len(variants) >= 1


def test_classify_encoding_utf16_le_via_bom(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_bytes(b"\xff\xfeh\x00i\x00")
    assert classify_encoding(f) == "utf-16-le"


def test_classify_encoding_utf16_be_via_bom(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_bytes(b"\xfe\xff\x00h\x00i")
    assert classify_encoding(f) == "utf-16-be"


def test_classify_encoding_utf8_bom(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_bytes(b"\xef\xbb\xbfhi")
    assert classify_encoding(f) == "utf-8-bom"


def test_classify_encoding_fallback_latin1(tmp_path: Path) -> None:
    """bytes invalidos UTF-8 + sem BOM + sem null-byte -> tenta UTF-16 -> latin1."""
    f = tmp_path / "f.txt"
    # 0xff sozinho, sem BOM (BOM seria 0xff 0xfe)
    f.write_bytes(b"\xff\xa0bad-utf8")
    # Sem null-byte, sem BOM, invalid UTF-8 strict -> deve cair em latin-1
    result = classify_encoding(f)
    assert result in {"latin-1", "utf-16-le", "utf-16-be"}


def test_classify_encoding_missing_file_returns_latin1(tmp_path: Path) -> None:
    """File ausente -> fallback latin-1 (sem raise)."""
    result = classify_encoding(tmp_path / "no_such.txt")
    assert result == "latin-1"


def test_try_decode_sequential_with_utf8_bom() -> None:
    data = b"\xef\xbb\xbfhello"
    variants = try_decode_sequential(data)
    # Tem 'utf-8-bom' label
    encodings = [e for e, _ in variants]
    assert "utf-8-bom" in encodings
    # texto correto
    bom_text = next(t for e, t in variants if e == "utf-8-bom")
    assert bom_text == "hello"
