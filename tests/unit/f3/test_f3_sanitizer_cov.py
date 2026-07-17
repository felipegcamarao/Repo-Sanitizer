"""test_f3_sanitizer_cov.py — branches de cobertura final Bloco 03.

Targets specific branches uncovered after extra tests, focando em
LeakDetectedInDestination raise + subdir .env + safe_sub timeout + fs_write
exception path + secondary variant skip_file.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from repo_sanitizer.f3_sanitizer import (
    F3Timeout,
    LeakDetectedInDestination,
    rescan_destination,
    run_f3,
    safe_sub,
    sanitize_text_content,
)
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _setup(tmp_path: Path, slug: str = "cov"):
    src = tmp_path / "src"
    src.mkdir()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    dest = allowed / f"GIT_{slug}-v1"
    dest.mkdir()
    fw = FsWriter(source_path=src, allowed_roots=[allowed], override_forbidden=[])
    audit = AuditLogger(
        audit_file=relatorios / "audit-log.jsonl", fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="0.3.0a1", sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64, slug=slug,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    return src, dest, fw, audit


# ===========================================================================
# safe_sub timeout
# ===========================================================================

def test_safe_sub_timeout_raises_f3timeout() -> None:
    """ReDoS via safe_sub: pattern catastrofica + entrada longa = timeout."""
    pat = re.compile(r"(a+)+!")
    with pytest.raises(F3Timeout):
        safe_sub(pat, "X", "a" * 5000, timeout_seconds=1)


# ===========================================================================
# LeakDetectedInDestination raise
# ===========================================================================

def test_run_f3_raises_leak_detected_when_dest_poisoned(tmp_path: Path) -> None:
    """Pre-polui dest com .env -> Camada C6 detecta apos F3 -> raise."""
    src, dest, fw, audit = _setup(tmp_path)
    (src / "README.md").write_text("# clean\n", encoding="utf-8")
    # Polui dest ANTES de F3 com um .env file (NAO um .example)
    (dest / ".env").write_text("KEY=val\n", encoding="utf-8")

    with pytest.raises(LeakDetectedInDestination):
        run_f3(
            source_path=src, dest_path=dest,
            fs_writer=fw, audit=audit,
            project_root=PROJECT_ROOT,
            raise_on_leak=True,
        )


# ===========================================================================
# .env em subdir -> dest_env_example com path corrigido
# ===========================================================================

def test_run_f3_env_in_subdir_emits_correct_example_path(tmp_path: Path) -> None:
    """Source com `config/.env` -> dest com `config/.env.example`."""
    src, dest, fw, audit = _setup(tmp_path, slug="subdir")
    (src / "config").mkdir()
    (src / "config" / ".env").write_text("KEY=val\n", encoding="utf-8")
    (src / "README.md").write_text("# demo\n", encoding="utf-8")

    run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    assert not (dest / "config" / ".env").exists()
    assert (dest / "config" / ".env.example").exists()


# ===========================================================================
# rescan_destination com .env real (nao .example) detecta
# ===========================================================================

def test_rescan_detects_real_env_not_example(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / ".env").write_text("KEY=v\n", encoding="utf-8")
    (dest / "ok.env.example").write_text("KEY=\n", encoding="utf-8")  # safe
    n, matches = rescan_destination(dest)
    # Pelo menos .env deve disparar; .env.example NAO deve disparar
    assert n >= 1
    assert all(not m.rel_path.endswith(".env.example") for m in matches)


# ===========================================================================
# sanitize_text_content cobre branch acao=remove_file inline (C7 PEM block)
# ===========================================================================

def test_sanitize_text_content_skip_pem_block_signal_via_remove_file() -> None:
    """C7 PEM block dispara skip_file via _CONTENT_FILE_LEVEL_TIPOS branch."""
    text = (
        "header\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAA...\n"
        "-----END RSA PRIVATE KEY-----\n"
        "footer\n"
    )
    r = sanitize_text_content(text, "utf-8")
    assert r.skip_file is True
    assert r.matches  # ao menos 1 match


# ===========================================================================
# rescan_destination com binary clean + texto clean = 0
# ===========================================================================

def test_rescan_destination_mix_binary_text_clean(tmp_path: Path) -> None:
    """Mix de binario limpo + texto limpo -> 0 leaks."""
    dest = tmp_path / "dest"
    dest.mkdir()
    # Texto clean
    (dest / "main.py").write_text("print('hello')\n", encoding="utf-8")
    # Binario clean (PNG magic)
    (dest / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    n, _ = rescan_destination(dest)
    assert n == 0


def test_rescan_destination_with_subdirectory(tmp_path: Path) -> None:
    """Walk recursivo deve descer subdirs."""
    dest = tmp_path / "dest"
    dest.mkdir()
    sub = dest / "sub"
    sub.mkdir()
    (sub / "secret.txt").write_text("token=ghp_abcdef123456789012345\n", encoding="utf-8")
    n, _ = rescan_destination(dest)
    assert n >= 1


# ===========================================================================
# Encoding utf-7 path branch via sanitize_text_content
# ===========================================================================

def test_sanitize_text_content_with_utf7_encoding_label() -> None:
    """Variant utf-7 deve ser tratada e nao quebrar."""
    text = "API_KEY = sk-1234567890abcdef1234567890abcdef\n"
    r = sanitize_text_content(text, "utf-7")
    # sanitiza no encoding utf-7 tambem
    assert "<REDACTED" in r.sanitized_text
