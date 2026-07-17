"""test_phase5_cross_platform_win11.py — Fase 5 cross-platform Windows 11.

DoD 5 da Fase 5: 5 cenarios Windows-specific (INV-13 Windows first):

1. Symlink/junction handling sem developer mode (skip esperado; nao bloqueia)
2. Windows reserved names (NUL/CON/COM1..9/LPT1..9/PRN) -> FsWriter bloqueia
3. NTFS Unicode (acentos PT-BR; caminho com `ç`, `ã`, `á`)
4. cp1252 stdout encoding fix (UTF-8 reconfigure)
5. PowerShell vs cmd.exe shell=False compatibility

Todos os testes preservam INV-1: source nunca tocada; tmp_path apenas.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

# ---------------------------------------------------------------------------
# 1. Reserved Windows names blocked
# ---------------------------------------------------------------------------


WINDOWS_RESERVED = ["NUL", "CON", "AUX", "PRN", "COM1", "COM9", "LPT1", "LPT9"]


@pytest.mark.parametrize("reserved_name", WINDOWS_RESERVED)
def test_cross_platform_reserved_names_blocked(reserved_name: str, tmp_path: Path) -> None:
    """Windows reserved names rejected by FsWriter."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / reserved_name
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(target, "should not write")


# ---------------------------------------------------------------------------
# 2. NTFS Unicode PT-BR (acentos)
# ---------------------------------------------------------------------------


def test_cross_platform_unicode_pt_br_path_round_trip(tmp_path: Path) -> None:
    """NTFS aceita paths com acentos PT-BR (ç, ã, á)."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "GIT_canção" / "configuração-pt-br.md"
    written = fw.safe_write_text(target, "# Configuração PT-BR\nConteúdo com acentos: ç, ã, á.\n")
    assert written.exists()
    content = written.read_text(encoding="utf-8")
    assert "Configuração" in content
    assert "ç, ã, á" in content


# ---------------------------------------------------------------------------
# 3. cp1252 stdout encoding (Windows default; release_gate fix)
# ---------------------------------------------------------------------------


def test_cross_platform_release_gate_utf8_stdout_reconfig() -> None:
    """release_gate_v1_0.py reconfigura stdout para UTF-8 (D-EX-29)."""
    gate_src = Path("scripts/release_gate_v1_0.py").read_text(encoding="utf-8")
    # Esperar referenciada reconfiguracao UTF-8 OR encoding-safe fallback
    assert (
        "reconfigure" in gate_src
        or "encoding=\"utf-8\"" in gate_src.lower()
        or "encoding='utf-8'" in gate_src.lower()
    ), "release_gate deve reconfigurar stdout UTF-8 (Windows cp1252 fix)"


# ---------------------------------------------------------------------------
# 4. PowerShell-compatible subprocess shell=False (RS-015)
# ---------------------------------------------------------------------------


def test_cross_platform_subprocess_shell_false_pattern() -> None:
    """F4 markdownlint/link-check usa shell=False (defesa contra injection)."""
    f4_src = Path("src/repo_sanitizer/f4_readme.py").read_text(encoding="utf-8")
    # Conta uso de shell=False em subprocess.run
    assert "shell=False" in f4_src, (
        "F4 subprocess.run DEVE usar shell=False (RS-015 + RS-007)"
    )


# ---------------------------------------------------------------------------
# 5. Symlink handling without developer mode (skip esperado)
# ---------------------------------------------------------------------------


def test_cross_platform_symlink_dev_mode_skip(tmp_path: Path) -> None:
    """Symlink em Windows sem developer mode: tentar criar; skip esperado.

    Defesa F3/F4 NAO depende de developer mode (opera sobre destino sanitizado).
    """
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target = tmp_path / "target.txt"
    target.write_text("real", encoding="utf-8")
    link = allowed / "link.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlink em Windows requer developer mode (esperado)")
    # Se chegou aqui (developer mode habilitado): _symlink_guard exclui
    from repo_sanitizer.helpers._symlink_guard import is_unsafe_link

    assert is_unsafe_link(link), "Symlink criado deve ser sinalizado como unsafe"


# ---------------------------------------------------------------------------
# 6. Path canonicalizer rejeita `..` traversal mesmo no Windows
# ---------------------------------------------------------------------------


def test_cross_platform_dotdot_traversal_blocked_win(tmp_path: Path) -> None:
    """Path traversal `..\\` blocked on Windows."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "..\\..\\escape.txt"
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(target, "x")
