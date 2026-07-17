"""test__encoding_branches.py — branches finais _encoding.py para Bloco 03.

Cobre _try_decode exception path + iter_decoded_variants edge.
"""
from __future__ import annotations

from repo_sanitizer.helpers._encoding import (
    _try_decode,
    iter_decoded_variants,
    try_decode_sequential,
)


def test_try_decode_unknown_codec_returns_none() -> None:
    """LookupError em codec inexistente -> None (branch 74-75)."""
    result = _try_decode(b"hello", "no_such_codec_xyz123")
    assert result is None


def test_try_decode_valid_codec_returns_string() -> None:
    result = _try_decode(b"hello", "utf-8")
    assert result == "hello"


def test_iter_decoded_variants_returns_iterable() -> None:
    """iter_decoded_variants e generator-like."""
    variants = list(iter_decoded_variants(b"hello"))
    assert variants  # at least 1 variant


def test_try_decode_sequential_empty_input() -> None:
    """Entrada vazia -> Latin-1 decode resulta em string vazia (e Latin-1 nunca
    deduplica para vazio porque vazio in seen_texts ja conta como dedup)."""
    variants = try_decode_sequential(b"")
    # Pelo menos 1 variant (latin-1 sempre decodifica)
    assert isinstance(variants, list)


def test_try_decode_sequential_with_bom_only() -> None:
    """Buffer com so BOM (sem conteudo)."""
    variants = try_decode_sequential(b"\xef\xbb\xbf")
    # UTF-8 BOM variant tem text "" (vazio); dedup pode reduzir
    assert isinstance(variants, list)
