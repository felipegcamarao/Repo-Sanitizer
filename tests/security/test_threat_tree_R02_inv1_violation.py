"""test_threat_tree_R02_inv1_violation.py — Threat Tree R-RS-02 (INV-1 Violation).

Bloco 02. Endereca AT-31 (INV-1 violation TOP-01) e AT-02 (race condition fonte
mid-run). [NOME] reforcou INV-1 2 vezes; este teste e o gate canonico.

DREAD-5 = 45/50 (TOP-01 empatado com RS-001). Defesa em camadas:
- C1: snapshot SHA-256 pre-walk em dry-run
- C2: snapshot SHA-256 pos-walk em dry-run + assert_unchanged
- C3: race detection gate em apply (re-snapshot vs FILTER_DIFF embedded)
- C4: FsWriter FORBIDDEN_PATHS adiciona source_path automaticamente
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f1_filter import run_filter
from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter
from repo_sanitizer.helpers._hash_tree import assert_unchanged, snapshot
from repo_sanitizer.orchestrator import (
    Inv1Violation,
    make_orchestrator_context,
    run_apply,
    run_dry_run,
)
from tests.fixtures.repos import build_python_simple

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _setup(tmp_path: Path):
    sources_root = tmp_path / "sources"
    sources_root.mkdir()
    src = build_python_simple(sources_root)
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    ctx = make_orchestrator_context(
        source_path=src,
        relatorios_path=relatorios,
        project_root=PROJECT_ROOT,
        slug="python_simple",
        base_destinos_root=allowed,
    )
    fw = FsWriter(source_path=src, allowed_roots=[allowed], override_forbidden=[])
    return ctx, fw, src, allowed, relatorios


# ============================================================================
# AT-31 — INV-1 violation defense: source_path no FORBIDDEN_PATHS automatico
# ============================================================================

def test_at31_fs_writer_blocks_write_to_source(tmp_path: Path) -> None:
    """ADR-020 + RS-002: FsWriter recusa qualquer escrita dentro do source_path."""
    src = tmp_path / "fonte"
    src.mkdir()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(source_path=src, allowed_roots=[allowed, src], override_forbidden=[])
    # Mesmo se source_path estiver dentro de allowed, FORBIDDEN ainda barra
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(src / "test.txt", "ok")


def test_at31_fs_writer_blocks_subdir_of_source(tmp_path: Path) -> None:
    """Defesa: subdir do source tambem proibido."""
    src = tmp_path / "fonte"
    sub = src / "sub" / "deep"
    sub.mkdir(parents=True)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(source_path=src, allowed_roots=[allowed, src], override_forbidden=[])
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(sub / "x.md", "ok")


# ============================================================================
# AT-02 — Race condition (fonte alterada entre dry-run e apply)
# ============================================================================

def test_at02_race_condition_added_file_blocks_apply(tmp_path: Path) -> None:
    """RS-016: arquivo novo aparece na fonte mid-run -> Inv1Violation exit 2."""
    ctx, fw, src, _allowed, _rel = _setup(tmp_path)
    run_dry_run(ctx, fs_writer=fw)
    (src / "novo-mid-run.py").write_text("apareci\n", encoding="utf-8")
    with pytest.raises(Inv1Violation):
        run_apply(ctx, fs_writer=fw)


def test_at02_race_condition_modified_file_blocks_apply(tmp_path: Path) -> None:
    """RS-016: arquivo existente modificado -> Inv1Violation."""
    ctx, fw, src, _allowed, _rel = _setup(tmp_path)
    run_dry_run(ctx, fs_writer=fw)
    (src / "README.md").write_text("# DIFFERENT-CONTENT\n", encoding="utf-8")
    with pytest.raises(Inv1Violation):
        run_apply(ctx, fs_writer=fw)


def test_at02_race_condition_deleted_file_blocks_apply(tmp_path: Path) -> None:
    """RS-016: arquivo removido mid-run -> Inv1Violation."""
    ctx, fw, src, _allowed, _rel = _setup(tmp_path)
    run_dry_run(ctx, fs_writer=fw)
    (src / "README.md").unlink()
    with pytest.raises(Inv1Violation):
        run_apply(ctx, fs_writer=fw)


# ============================================================================
# Defesa em camadas: F1 walk read-only nao toca fonte
# ============================================================================

def test_f1_walk_does_not_modify_source(tmp_path: Path) -> None:
    """run_filter -> snapshot pre/pos identical."""
    sources_root = tmp_path / "sources"
    sources_root.mkdir()
    src = build_python_simple(sources_root)
    snap_pre = snapshot(src)
    _ = run_filter(src)
    snap_pos = snapshot(src)
    assert_unchanged(snap_pre, snap_pos)


def test_orchestrator_dry_run_does_not_modify_source(tmp_path: Path) -> None:
    """orchestrator dry-run integra F1 + writer + audit; snapshot identical."""
    ctx, fw, src, _allowed, _rel = _setup(tmp_path)
    snap_pre = snapshot(src)
    run_dry_run(ctx, fs_writer=fw)
    snap_pos = snapshot(src)
    assert_unchanged(snap_pre, snap_pos)


def test_orchestrator_apply_does_not_modify_source(tmp_path: Path) -> None:
    """apply cria destino versionado; fonte INTOCADA."""
    ctx, fw, src, _allowed, _rel = _setup(tmp_path)
    snap_pre = snapshot(src)
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    snap_pos = snapshot(src)
    assert_unchanged(snap_pre, snap_pos)


# ============================================================================
# Audit-log: inv1_violation entry gravado em race
# ============================================================================

def test_audit_log_records_inv1_violation_on_race(tmp_path: Path) -> None:
    """RS-011 + ADR-016: race detection grava entry inv1_violation no audit-log."""
    ctx, fw, src, _allowed, relatorios = _setup(tmp_path)
    run_dry_run(ctx, fs_writer=fw)
    (src / "novo.py").write_text("apareci\n", encoding="utf-8")
    with pytest.raises(Inv1Violation):
        run_apply(ctx, fs_writer=fw)
    # Audit-log deve conter "inv1_violation"
    audit_lines = (relatorios / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()
    inv1_entries = [line for line in audit_lines if '"inv1_violation"' in line]
    assert len(inv1_entries) >= 1
