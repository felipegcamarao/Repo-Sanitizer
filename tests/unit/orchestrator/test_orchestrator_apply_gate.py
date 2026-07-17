"""test_orchestrator_apply_gate.py — Bloco 02 02.9 + 02.10:
race detection gate + auto-versionamento mkdir destino.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.orchestrator import (
    Inv1Violation,
    find_latest_filter_diff,
    list_versions,
    make_orchestrator_context,
    race_detection_gate,
    run_apply,
    run_dry_run,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _build_simple_repo(tmp: Path) -> Path:
    src = tmp / "demo-src"
    src.mkdir()
    (src / "README.md").write_text("# r\n", encoding="utf-8")
    (src / "main.py").write_text("print('ok')\n", encoding="utf-8")
    return src


def _make_ctx_and_fw(tmp_path: Path, slug: str = "demo-src"):
    src = _build_simple_repo(tmp_path)
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    ctx = make_orchestrator_context(
        source_path=src,
        relatorios_path=relatorios,
        project_root=PROJECT_ROOT,
        slug=slug,
        base_destinos_root=allowed,
    )
    fw = FsWriter(
        source_path=src,
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    return ctx, fw, src, allowed, relatorios


class TestRaceDetectionGate:
    def test_gate_passes_when_source_unchanged(self, tmp_path: Path) -> None:
        from repo_sanitizer.orchestrator import make_audit_logger
        ctx, fw, _src, _allowed, _rel = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx, fs_writer=fw)
        audit = make_audit_logger(ctx, fw)
        # Sem mutar a fonte:
        snap = race_detection_gate(ctx, fs_writer=fw, audit=audit)
        assert "aggregate" in snap

    def test_gate_raises_when_source_mutated(self, tmp_path: Path) -> None:
        from repo_sanitizer.orchestrator import make_audit_logger
        ctx, fw, src, _allowed, _rel = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx, fs_writer=fw)
        # Race: arquivo novo aparece na fonte entre dry-run e apply
        (src / "novo.py").write_text("apareci depois\n", encoding="utf-8")
        audit = make_audit_logger(ctx, fw)
        with pytest.raises(Inv1Violation, match="race detection"):
            race_detection_gate(ctx, fs_writer=fw, audit=audit)

    def test_gate_raises_when_no_filter_diff(self, tmp_path: Path) -> None:
        from repo_sanitizer.orchestrator import make_audit_logger
        ctx, fw, _src, _allowed, _rel = _make_ctx_and_fw(tmp_path, slug="never-ran")
        audit = make_audit_logger(ctx, fw)
        with pytest.raises(Inv1Violation, match="nenhum FILTER_DIFF"):
            race_detection_gate(ctx, fs_writer=fw, audit=audit)


class TestAutoVersionamento:
    def test_apply_creates_v1_when_no_prior(self, tmp_path: Path) -> None:
        ctx, fw, _src, allowed, _rel = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx, fs_writer=fw)
        exit_code = run_apply(ctx, fs_writer=fw)
        assert exit_code == 0
        assert (allowed / "GIT_demo-src").exists()
        assert ctx.dest_path.name == "GIT_demo-src"

    def test_apply_creates_v2_when_v1_exists(self, tmp_path: Path) -> None:
        # Run 1: cria v1
        ctx1, fw1, _, allowed, _rel = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx1, fs_writer=fw1)
        run_apply(ctx1, fs_writer=fw1)

        # Run 2: nova ctx (mesmo slug); deve criar v2.
        # Aguarda 1s para FILTER_DIFF ter timestamp diferente (e ser detectado como mais recente)
        time.sleep(1.1)
        ctx2 = make_orchestrator_context(
            source_path=ctx1.source_path,
            relatorios_path=ctx1.relatorios_path,
            project_root=PROJECT_ROOT,
            slug="demo-src",
            base_destinos_root=allowed,
        )
        # FsWriter novo (cada apply tem seu state)
        fw2 = FsWriter(
            source_path=ctx2.source_path,
            allowed_roots=[allowed],
            override_forbidden=[],
        )
        run_dry_run(ctx2, fs_writer=fw2)
        run_apply(ctx2, fs_writer=fw2)
        assert (allowed / "GIT_demo-src-v2").exists()

    def test_apply_creates_v3_when_v1_v2_exist(self, tmp_path: Path) -> None:
        ctx1, fw1, _, allowed, _rel = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx1, fs_writer=fw1)
        run_apply(ctx1, fs_writer=fw1)
        time.sleep(1.1)

        ctx2 = make_orchestrator_context(
            source_path=ctx1.source_path,
            relatorios_path=ctx1.relatorios_path,
            project_root=PROJECT_ROOT,
            slug="demo-src",
            base_destinos_root=allowed,
        )
        fw2 = FsWriter(source_path=ctx2.source_path, allowed_roots=[allowed], override_forbidden=[])
        run_dry_run(ctx2, fs_writer=fw2)
        run_apply(ctx2, fs_writer=fw2)
        time.sleep(1.1)

        ctx3 = make_orchestrator_context(
            source_path=ctx1.source_path,
            relatorios_path=ctx1.relatorios_path,
            project_root=PROJECT_ROOT,
            slug="demo-src",
            base_destinos_root=allowed,
        )
        fw3 = FsWriter(source_path=ctx3.source_path, allowed_roots=[allowed], override_forbidden=[])
        run_dry_run(ctx3, fs_writer=fw3)
        run_apply(ctx3, fs_writer=fw3)

        assert (allowed / "GIT_demo-src").exists()
        assert (allowed / "GIT_demo-src-v2").exists()
        assert (allowed / "GIT_demo-src-v3").exists()

    def test_list_versions_helper(self, tmp_path: Path) -> None:
        ctx, fw, _src, _allowed, _rel = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx, fs_writer=fw)
        run_apply(ctx, fs_writer=fw)
        versions = list_versions(ctx)
        assert len(versions) == 1


class TestFindLatestFilterDiff:
    def test_returns_none_when_no_files(self, tmp_path: Path) -> None:
        assert find_latest_filter_diff(tmp_path, "x") is None

    def test_returns_most_recent(self, tmp_path: Path) -> None:
        ctx, fw, _src, _allowed, relatorios = _make_ctx_and_fw(tmp_path)
        run_dry_run(ctx, fs_writer=fw)
        time.sleep(1.1)
        run_dry_run(ctx, fs_writer=fw)  # 2a invocation cria FILTER_DIFF mais novo
        latest = find_latest_filter_diff(relatorios, "demo-src")
        assert latest is not None
        # 2 arquivos esperados (timestamps distintos)
        all_files = list(relatorios.glob("FILTER_DIFF_demo-src_*.md"))
        assert len(all_files) >= 1
