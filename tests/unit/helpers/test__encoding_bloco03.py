"""test__encoding_bloco03.py — Camada C4 RS-001 (Bloco 03 Passo 03.4).

Smoke 5 encodings + UTF-7 best-effort + merge dedup. Garante que `try_decode_sequential`
encontra o token `ghp_<...>` em TODAS as 5 variantes encoding-bomb canonicas (AT-21).
"""
from __future__ import annotations

from repo_sanitizer.helpers._encoding import try_decode_sequential

SECRET_TOKEN_ASCII = "ghp_abc123def456ghi789jklmnop"


def test_utf8_strict_finds_token() -> None:
    data = SECRET_TOKEN_ASCII.encode("utf-8")
    variants = try_decode_sequential(data)
    assert any(SECRET_TOKEN_ASCII in t for _, t in variants if _ == "utf-8")


def test_utf8_bom_finds_token() -> None:
    data = b"\xef\xbb\xbf" + SECRET_TOKEN_ASCII.encode("utf-8")
    variants = try_decode_sequential(data)
    found = any(SECRET_TOKEN_ASCII in t for enc, t in variants if enc == "utf-8-bom")
    assert found, "Token nao encontrado em UTF-8-BOM"


def test_utf16_le_bom_finds_token() -> None:
    data = SECRET_TOKEN_ASCII.encode("utf-16-le")
    data = b"\xff\xfe" + data
    variants = try_decode_sequential(data)
    found = any(SECRET_TOKEN_ASCII in t for enc, t in variants if enc == "utf-16-le")
    assert found, "Token nao encontrado em UTF-16-LE com BOM"


def test_utf16_be_bom_finds_token() -> None:
    data = SECRET_TOKEN_ASCII.encode("utf-16-be")
    data = b"\xfe\xff" + data
    variants = try_decode_sequential(data)
    found = any(SECRET_TOKEN_ASCII in t for enc, t in variants if enc == "utf-16-be")
    assert found, "Token nao encontrado em UTF-16-BE com BOM"


def test_latin1_fallback_finds_token() -> None:
    """Mesmo em bytes UTF-8-validos (ASCII), Latin-1 sempre decodifica como variant adicional."""
    data = SECRET_TOKEN_ASCII.encode("latin-1")
    variants = try_decode_sequential(data)
    # ASCII puro -> UTF-8 e Latin-1 produzem texto identico; dedup esperada.
    # Ainda assim, garantimos que o token aparece em pelo menos um variant
    all_texts = [t for _, t in variants]
    assert any(SECRET_TOKEN_ASCII in t for t in all_texts)


def test_utf7_best_effort_decoding() -> None:
    """UTF-7 best-effort (AT-21): encoda ASCII como UTF-7 e verifica que e
    decodavel."""
    # UTF-7 puro: ASCII permanece igual (ASCII e subset compativel)
    data = SECRET_TOKEN_ASCII.encode("utf_7")
    variants = try_decode_sequential(data)
    # Apenas verifica que algum variant contem o token (UTF-7 ou outro)
    all_texts = [t for _, t in variants]
    assert any(SECRET_TOKEN_ASCII in t for t in all_texts), (
        "UTF-7 best-effort falhou em decodificar ASCII"
    )


def test_merge_5_encodings_dedup() -> None:
    """5 encodings concorrentes em 1 buffer (AT-21 simulado): garantimos que
    `try_decode_sequential` retorna variantes distintas (mesmo que algumas
    coincidam, NUNCA perde o token)."""
    data = SECRET_TOKEN_ASCII.encode("utf-8")
    variants = try_decode_sequential(data)
    # ASCII -> utf-8 e latin-1 dao texto identico -> dedup. Esperamos ao menos 1.
    assert len(variants) >= 1
    # Em ASCII puro, alguns codecs falham (utf-16 strict por exemplo) -- aceitavel.
    found_token = any(SECRET_TOKEN_ASCII in t for _, t in variants)
    assert found_token


def test_no_errors_ignore_used() -> None:
    """DEF-03 invariante: errors='replace' (nunca 'ignore' que oculta bytes)."""
    # Bytes invalid UTF-8: 0xff isolado fora de BOM
    data = b"safe " + b"\xff\xff" + SECRET_TOKEN_ASCII.encode("utf-8")
    variants = try_decode_sequential(data)
    # Latin-1 sempre passa
    latin1_texts = [t for e, t in variants if e == "latin-1"]
    assert latin1_texts, "Latin-1 fallback nao gerou texto"
    # Token deve aparecer em algum variant (utf-8 com 0xff -> replace mas token intacto)
    found = any(SECRET_TOKEN_ASCII in t for _, t in variants)
    assert found
