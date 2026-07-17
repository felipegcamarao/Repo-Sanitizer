"""test__entropy_detector.py — C2 / MV-04 / RS-NEW-035/036/037/047 / ADR-034 (unit).

Testa `_entropy_detector` isolado:
- (a) token custom alta-entropia sem prefixo -> redatado (RS-NEW-037);
- (b) git-SHA40 / SHA256 / UUID / SRI -> 0 redacao (RS-NEW-036);
- (c) prosa normal -> nao disparada;
- (d) lockfile / linha integrity -> no-op;
- (e) flag off -> no-op;
- zero-literal no EntropyMatch (RS-NEW-047);
- shannon_entropy correta; cobertura >=90%.
"""
from __future__ import annotations

import math

import pytest

from repo_sanitizer.helpers._entropy_detector import (
    ENTROPY_PLACEHOLDER,
    EntropyMatch,
    is_lockfile,
    redact_high_entropy,
    shannon_entropy,
)

# Token base64-like custom: 32 chars, alfabeto rico, alta entropia, SEM prefixo.
CUSTOM_TOKEN = "aB3xQ9zK7mP2wV5nL8rT4yU6sD1fG0hJ"
# git SHA-1 (40 hex).
GIT_SHA40 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
# git SHA-256 (64 hex).
GIT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# UUID v4.
UUID_V4 = "550e8400-e29b-41d4-a716-446655440000"
# SRI hash sha512.
SRI_HASH = "sha512-v2sBQ7vQVABCDEF0123456789abcdefXYZ+v5pX6vQ7vQVghijklmnop=="


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------

def test_shannon_empty_string_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_uniform_string_zero() -> None:
    """String de 1 simbolo repetido -> entropia 0 (sem incerteza)."""
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_shannon_two_symbols_one_bit() -> None:
    """50/50 de dois simbolos -> exatamente 1 bit/char."""
    assert math.isclose(shannon_entropy("abab"), 1.0)


def test_shannon_high_for_random_token() -> None:
    assert shannon_entropy(CUSTOM_TOKEN) > 4.5


# ---------------------------------------------------------------------------
# (a) Positivo — token custom redatado (RS-NEW-037)
# ---------------------------------------------------------------------------

def test_custom_token_redacted() -> None:
    text = f"API_SECRET={CUSTOM_TOKEN}"
    out, matches = redact_high_entropy(text, "config.py", "config.py", enabled=True)
    assert ENTROPY_PLACEHOLDER in out
    assert CUSTOM_TOKEN not in out
    assert len(matches) == 1


def test_custom_token_in_assignment_keeps_surrounding() -> None:
    text = f'token = "{CUSTOM_TOKEN}"'
    out, _ = redact_high_entropy(text, "x.py", "x.py", enabled=True)
    assert out == f'token = "{ENTROPY_PLACEHOLDER}"'


def test_multiple_custom_tokens_all_redacted() -> None:
    t2 = "Zx9Kp2Lm7Qw3Er8Ty5Ui1Op4As6Df0Gh"
    text = f"a={CUSTOM_TOKEN}\nb={t2}\n"
    out, matches = redact_high_entropy(text, "x.env", "x.env", enabled=True)
    assert CUSTOM_TOKEN not in out and t2 not in out
    assert len(matches) == 2
    # Numeros de linha corretos.
    assert {m.line for m in matches} == {1, 2}


# ---------------------------------------------------------------------------
# (b) ANTI-FP — allowlist dura (RS-NEW-036 / T-01)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [GIT_SHA40, GIT_SHA256, UUID_V4, SRI_HASH])
def test_allowlist_values_never_redacted(value: str) -> None:
    text = f"ref: {value}"
    out, matches = redact_high_entropy(text, "x.txt", "x.txt", enabled=True)
    assert value in out
    assert ENTROPY_PLACEHOLDER not in out
    assert matches == []


def test_git_sha40_uppercase_preserved() -> None:
    text = f"COMMIT={GIT_SHA40.upper()}"
    out, matches = redact_high_entropy(text, "x.txt", "x.txt", enabled=True)
    assert GIT_SHA40.upper() in out
    assert matches == []


def test_already_redacted_not_reprocessed() -> None:
    """Trecho ja `<REDACTED-*>` por camada anterior nao re-dispara (MV04-F)."""
    text = "value=<REDACTED-API_KEY_aws_access>"
    out, matches = redact_high_entropy(text, "x.py", "x.py", enabled=True)
    assert out == text
    assert matches == []


# ---------------------------------------------------------------------------
# (c) Prosa normal nao disparada
# ---------------------------------------------------------------------------

def test_normal_prose_untouched() -> None:
    prose = "The quick brown fox jumps over the lazy dog near the riverbank."
    out, matches = redact_high_entropy(prose, "README.md", "README.md", enabled=True)
    assert out == prose
    assert matches == []


def test_short_token_below_min_len_untouched() -> None:
    """Token < 24 chars nunca dispara (mesmo alta entropia)."""
    short = "aB3xQ9zK7mP2"  # 12 chars
    text = f"x={short}"
    out, matches = redact_high_entropy(text, "x.py", "x.py", enabled=True)
    assert short in out
    assert matches == []


def test_low_entropy_long_token_untouched() -> None:
    """Token longo mas de baixa entropia (repetitivo) nao dispara."""
    low = "abababababababababababababababab"  # 32 chars, 2 simbolos -> 1 bit
    text = f"x={low}"
    out, matches = redact_high_entropy(text, "x.py", "x.py", enabled=True)
    assert low in out
    assert matches == []


def test_hex_token_above_hex_threshold_redacted() -> None:
    """Hex de 48 chars com alta variedade -> dispara (HEX_THRESHOLD 3.0)."""
    hex_token = "0123456789abcdef0123456789abcdef0123456789abcdef"
    # NOTA: usar separador que NAO seja `hash=`/`integrity:` (esses pulam a linha).
    text = f"digest {hex_token}"
    out, matches = redact_high_entropy(text, "x.txt", "x.txt", enabled=True)
    # 48 hex nao casa allowlist (nao e 40 nem 64) e tem entropia 4.0 > 3.0.
    assert hex_token not in out
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# (d) Lockfiles / linhas integrity (RS-NEW-036)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("basename", [
    "package-lock.json", "yarn.lock", "uv.lock", "poetry.lock",
    "Cargo.lock", "go.sum", "pnpm-lock.yaml", "deps.lock", "checksums.sum",
])
def test_lockfile_basenames_no_op(basename: str) -> None:
    text = f"resolved {CUSTOM_TOKEN}"
    out, matches = redact_high_entropy(text, basename, basename, enabled=True)
    assert CUSTOM_TOKEN in out
    assert matches == []


def test_is_lockfile_helper() -> None:
    assert is_lockfile("package-lock.json") is True
    assert is_lockfile("foo.lock") is True
    assert is_lockfile("checksums.SUM") is True
    assert is_lockfile("main.py") is False


def test_integrity_line_skipped_in_non_lockfile() -> None:
    """Linha com `integrity:` num arquivo nao-lockfile (ex.: yaml) e pulada."""
    text = f"deps:\n  integrity: {CUSTOM_TOKEN}\n  name: foo\n"
    out, matches = redact_high_entropy(text, "manifest.yaml", "manifest.yaml", enabled=True)
    assert CUSTOM_TOKEN in out
    assert matches == []


def test_resolved_line_skipped() -> None:
    text = f'  resolved: "{CUSTOM_TOKEN}"\n'
    out, matches = redact_high_entropy(text, "x.yaml", "x.yaml", enabled=True)
    assert CUSTOM_TOKEN in out
    assert matches == []


# ---------------------------------------------------------------------------
# (e) Flag off -> no-op
# ---------------------------------------------------------------------------

def test_disabled_is_no_op() -> None:
    text = f"secret={CUSTOM_TOKEN}"
    out, matches = redact_high_entropy(text, "x.py", "x.py", enabled=False)
    assert out == text
    assert matches == []


# ---------------------------------------------------------------------------
# Zero-literal (RS-NEW-047) + metadados
# ---------------------------------------------------------------------------

def test_entropy_match_is_zero_literal() -> None:
    """EntropyMatch NUNCA carrega os bytes do token (so metadados)."""
    # Separador ` "` (space+quote) NAO esta no charset do token -> boundary limpa.
    text = f'k = "{CUSTOM_TOKEN}"'
    _, matches = redact_high_entropy(text, "rel/x.py", "x.py", enabled=True)
    m = matches[0]
    assert isinstance(m, EntropyMatch)
    assert m.rel_path == "rel/x.py"
    assert m.length == len(CUSTOM_TOKEN)
    assert m.entropy > 4.5
    # Nenhum campo contem o token literal.
    for field_val in (m.rel_path, str(m.entropy), str(m.length), str(m.line)):
        assert CUSTOM_TOKEN not in field_val


def test_no_match_returns_original_text_object() -> None:
    """Sem matches -> retorna o texto original (sem reconstruir)."""
    text = "nothing to see here, just words"
    out, matches = redact_high_entropy(text, "x.md", "x.md", enabled=True)
    assert out == text
    assert matches == []


# ---------------------------------------------------------------------------
# DoS / cap (MV04-D)
# ---------------------------------------------------------------------------

def test_large_base64_line_does_not_hang() -> None:
    """Linha base64 gigante (5 MB) nao trava — tokenizador tem cap {24,512}."""
    big = "A" * (5 * 1024 * 1024)
    text = f"data:image/png;base64,{big}"
    # Nao deve travar; 'A'*N tem entropia 0 -> nao redatado de qualquer forma.
    out, matches = redact_high_entropy(text, "x.html", "x.html", enabled=True)
    assert isinstance(out, str)
    assert matches == []
