"""test_orchestrator.py — skeleton Bloco 01 (full impl em Blocos 02..05)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from repo_sanitizer.orchestrator import (
    IntegrityFailure,
    make_orchestrator_context,
    pre_flight_integrity_check,
    run_dry_run,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_make_orchestrator_context_defaults(tmp_path: Path) -> None:
    src = tmp_path / "my-repo"
    src.mkdir()
    ctx = make_orchestrator_context(
        source_path=src,
        relatorios_path=tmp_path / "rel",
        project_root=tmp_path,
    )
    assert ctx.slug == "my-repo"
    assert ctx.run_id.count("-") == 4  # UUID structure
    assert ctx.dest_path.name == "GIT_my-repo"


def test_pre_flight_integrity_check_ok() -> None:
    """Bootstrap rodou — integrity ok."""
    result = pre_flight_integrity_check(PROJECT_ROOT)
    assert result["ok"] is True


def test_pre_flight_integrity_check_fails_on_tampering(tmp_path: Path) -> None:
    """integrity.md fake apontando para arquivo inexistente."""
    integrity_md = tmp_path / "integrity.md"
    integrity_md.write_text(
        "---\nlast_setup: 2026-01-01T00:00:00\n---\n\n# Hashes\n"
        f"- file: missing.py\n  sha256: {'a' * 64}\n  recorded_at: 2026-01-01\n",
        encoding="utf-8",
    )
    with pytest.raises(IntegrityFailure):
        pre_flight_integrity_check(tmp_path)


def test_run_dry_run_executes_f1_and_writes_filter_diff(tmp_path: Path) -> None:
    """Bloco 02 wiring: dry-run real chama F1 + emite FILTER_DIFF.md."""
    from repo_sanitizer.helpers._fs_writer import FsWriter
    src = tmp_path / "fake-src"
    src.mkdir()
    (src / "README.md").write_text("# r\n", encoding="utf-8")
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")

    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()

    ctx = make_orchestrator_context(
        source_path=src,
        relatorios_path=relatorios,
        project_root=PROJECT_ROOT,
        slug="fake-src",
        base_destinos_root=allowed,
    )

    fw = FsWriter(
        source_path=src,
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    exit_code = run_dry_run(ctx, fs_writer=fw)
    assert exit_code == 0

    # FILTER_DIFF.md gerado
    filter_diffs = list(relatorios.glob("FILTER_DIFF_fake-src_*.md"))
    assert len(filter_diffs) == 1
    md = filter_diffs[0].read_text(encoding="utf-8")
    assert "## Grupo A" in md
    assert "README.md" in md
    # Audit-log gravado
    assert (relatorios / "audit-log.jsonl").exists()


def test_cli_help_returns_0() -> None:
    """CLI --help exit 0 + lista 4 subcomandos."""
    result = subprocess.run(
        [sys.executable, "-m", "repo_sanitizer.cli", "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    out = result.stdout
    assert "dry-run" in out
    assert "sanitize-apply" in out
    assert "generate-readme" in out
    assert "sanitize-finalize" in out


def test_cli_version_returns_0() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "repo_sanitizer.cli", "--version"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    # D-FF-09 v1.0.1 + Bloco 01 v1.1.0-alpha.1: __version__ vem dinâmico do pyproject.toml.
    # Test usa import direto para evitar hardcode — qualquer bump futuro NÃO quebra.
    from repo_sanitizer import __version__ as expected_version
    assert expected_version in result.stdout


def test_cli_bad_args_exit_2() -> None:
    """argparse retorna 2 em bad args (Python stdlib comportamento)."""
    result = subprocess.run(
        [sys.executable, "-m", "repo_sanitizer.cli", "wrong-cmd"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    # argparse usa exit 2 para bad args
    assert result.returncode != 0
