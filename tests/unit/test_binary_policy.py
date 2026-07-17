"""test_binary_policy.py — B4 / MV-06 / RS-NEW-042 / ADR-036 (unit).

Tabela de tiers por extensao + magic: credenciais e dados -> excluir; neutros
-> safe; imagens/midia -> safe + flag EXIF. Tiers HARDCODED (anti-bypass
RS-NEW-035). Cobertura ≥90%.
"""
from __future__ import annotations

import pytest

from repo_sanitizer.helpers._binary_policy import (
    classify_binary_tier,
    is_image_media,
    tier_excludes,
)

# (basename, magic_label, tier_esperado)
TIER_TABLE: list[tuple[str, str, str]] = [
    # Credenciais -> credential (excluir)
    ("server.pem", "", "credential"),
    ("id_rsa.key", "", "credential"),
    ("cert.pfx", "", "credential"),
    ("store.p12", "", "credential"),
    ("keystore.jks", "", "credential"),
    ("app.keystore", "", "credential"),
    ("vault.kdbx", "", "credential"),
    ("secrets.env.enc", "", "credential"),
    # Dados -> data (excluir)
    ("clientes.sqlite", "SQLite3", "data"),
    ("data.sqlite3", "", "data"),
    ("legacy.db", "", "data"),
    ("export.csv", "", "data"),
    ("table.tsv", "", "data"),
    ("model.parquet", "", "data"),
    ("sheet.xlsx", "", "data"),
    ("old.xls", "", "data"),
    ("model.pkl", "", "data"),
    ("obj.pickle", "", "data"),
    ("weights.h5", "", "data"),
    ("dump.sql", "", "data"),
    ("backup.dump", "", "data"),
    ("report.docx", "", "data"),
    # Magic forca data mesmo sem extensao reconhecida (anti-rename-spoof)
    ("renamed.bin", "SQLite3", "data"),
    # Imagens/midia -> safe
    ("logo.png", "PNG", "safe"),
    ("photo.jpg", "JPEG", "safe"),
    ("anim.gif", "GIF89", "safe"),
    ("manual.pdf", "PDF", "safe"),
    ("clip.mp4", "", "safe"),
    # Neutros -> safe
    ("mod.wasm", "WASM", "safe"),
    ("favicon.ico", "ICO", "safe"),
    ("font.woff2", "", "safe"),
    ("lib.so", "ELF", "safe"),
    ("plugin.dll", "PE/DOS", "safe"),
    # Codigo / desconhecido -> safe (default conservador)
    ("main.py", "", "safe"),
    ("noext", "", "safe"),
]


@pytest.mark.parametrize(("basename", "magic", "expected"), TIER_TABLE)
def test_classify_binary_tier_table(basename: str, magic: str, expected: str) -> None:
    assert classify_binary_tier(basename, magic) == expected


def test_credential_and_data_are_excluded() -> None:
    assert tier_excludes("credential") is True
    assert tier_excludes("data") is True
    assert tier_excludes("safe") is False


def test_image_media_flag_by_extension() -> None:
    """Imagens/PDF/midia -> flag EXIF (metadados nao inspecionados)."""
    for name in ("logo.png", "p.jpeg", "doc.pdf", "v.mp4", "a.gif"):
        assert is_image_media(name, "") is True


def test_image_media_flag_by_magic_when_ext_masked() -> None:
    """Imagem renomeada (sem ext) ainda recebe flag via magic-label."""
    assert is_image_media("logo.bin", "PNG") is True
    assert is_image_media("x.bin", "JPEG") is True


def test_neutral_binary_no_exif_flag() -> None:
    """Binario neutro (wasm/ico/font/so) NAO recebe flag EXIF."""
    for name, magic in (("m.wasm", "WASM"), ("i.ico", "ICO"),
                        ("f.woff2", ""), ("l.so", "ELF")):
        assert is_image_media(name, magic) is False


def test_case_insensitive_extension() -> None:
    """Extensao maiuscula tambem classifica (anti-case-spoof)."""
    assert classify_binary_tier("DATA.SQLITE", "") == "data"
    assert classify_binary_tier("CERT.PEM", "") == "credential"
    assert classify_binary_tier("LOGO.PNG", "") == "safe"


def test_dotfile_without_extension_is_safe() -> None:
    """`.gitignore` (dotfile sem extensao real) -> safe (nao engole)."""
    assert classify_binary_tier(".gitignore", "") == "safe"
    assert classify_binary_tier(".env", "") == "safe"
