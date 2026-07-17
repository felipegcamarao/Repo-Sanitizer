"""test_entropy_allowlist.py — C2 / MV-04 / RS-NEW-035/036/037/047 (security).

Testes de seguranca da Camada de entropia:
- allowlist dura: git-SHA40/UUID/SRI/hash-de-lockfile -> 0 redacao (T-01);
- bypass: `.sanitizer-allow` no source NAO desliga o detector (T-02 / RS-NEW-035);
- leak via report: EntropyMatch forjado nao expoe bytes (RS-NEW-047);
- DoS: linha base64 de 5 MB nao trava (MV04-D).
"""
from __future__ import annotations

import inspect
from pathlib import Path

from repo_sanitizer.helpers import _entropy_detector as ed
from repo_sanitizer.helpers._entropy_detector import (
    ENTROPY_PLACEHOLDER,
    redact_high_entropy,
)

CUSTOM_TOKEN = "aB3xQ9zK7mP2wV5nL8rT4yU6sD1fG0hJ"


# ---------------------------------------------------------------------------
# RS-NEW-036 — allowlist dura (anti-FP que quebra build)
# ---------------------------------------------------------------------------

def test_package_lock_sri_hash_never_redacted() -> None:
    """SRI `sha512-...` num `package-lock.json` NAO redatado (quebraria build)."""
    sri = "sha512-abcDEF0123456789+/abcDEF0123456789ghijklMNOPqrstuvwx=="
    content = f'"integrity": "{sri}"'
    out, matches = redact_high_entropy(
        content, "package-lock.json", "package-lock.json", enabled=True,
    )
    assert sri in out
    assert matches == []


def test_uv_lock_content_never_redacted() -> None:
    """Conteudo de `uv.lock` (hashes) intacto (RS-NEW-036)."""
    content = (
        "[[package]]\n"
        f'name = "requests"\n'
        f'wheels = [{{ hash = "{CUSTOM_TOKEN}aaaa" }}]\n'
    )
    out, matches = redact_high_entropy(content, "uv.lock", "uv.lock", enabled=True)
    assert ENTROPY_PLACEHOLDER not in out
    assert matches == []


# ---------------------------------------------------------------------------
# RS-NEW-035 — anti-bypass por config-do-source (T-02)
# ---------------------------------------------------------------------------

def test_allowlist_is_hardcoded_not_read_from_source(tmp_path: Path) -> None:
    """`.sanitizer-allow` no source NAO altera o que a entropia redata.

    A allowlist e CONSTANTE do modulo; nenhum arquivo de source pode estende-la.
    """
    # Simula um atacante colocando um arquivo de "allow" no source com o token.
    (tmp_path / ".sanitizer-allow").write_text(
        f"allow: {CUSTOM_TOKEN}\n", encoding="utf-8",
    )
    # O detector nao tem API para ler config de source; redata mesmo assim.
    content = f"leaked={CUSTOM_TOKEN}"
    out, matches = redact_high_entropy(content, "app.py", "app.py", enabled=True)
    assert CUSTOM_TOKEN not in out
    assert len(matches) == 1


def test_module_does_not_read_filesystem_for_config() -> None:
    """Grep de codigo: o modulo de entropia nao le allowlist de arquivo.

    Nenhuma chamada a open/read_text/Path para carregar config dinamica — a
    allowlist e literal no codigo (RS-NEW-035).
    """
    source = inspect.getsource(ed)
    # Nao deve haver IO de leitura de config no modulo.
    for forbidden in ("open(", ".read_text(", ".read_bytes(", "json.load", "tomllib.load"):
        assert forbidden not in source, f"entropia nao deve ler config: {forbidden!r}"


# ---------------------------------------------------------------------------
# RS-NEW-047 — zero-literal no report
# ---------------------------------------------------------------------------

def test_entropy_match_repr_has_no_token() -> None:
    """repr/str do EntropyMatch nao expoe o token (so metadados)."""
    _, matches = redact_high_entropy(f"k={CUSTOM_TOKEN}", "x.py", "x.py", enabled=True)
    m = matches[0]
    assert CUSTOM_TOKEN not in repr(m)
    assert CUSTOM_TOKEN not in str(m)


# ---------------------------------------------------------------------------
# MV04-D — DoS / cap
# ---------------------------------------------------------------------------

def test_huge_high_variety_base64_does_not_hang() -> None:
    """Linha base64 grande com variedade nao trava (cap {24,512} por token)."""
    import random
    rng = random.Random(42)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    big = "".join(rng.choice(alphabet) for _ in range(2 * 1024 * 1024))
    text = f"blob = {big}"
    out, matches = redact_high_entropy(text, "x.txt", "x.txt", enabled=True)
    # Token unico de 2 MB excede MAX_LEN do tokenizador -> nao casa um unico match
    # gigante; o cap impede ReDoS/OOM. So garantimos que retorna sem travar.
    assert isinstance(out, str)
    assert isinstance(matches, list)
