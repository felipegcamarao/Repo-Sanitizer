"""test_f1_filter.py — F1 Filter Grupos A/B/C + walk + run_filter (Bloco 02 02.1..02.3).

Cobertura:
- Grupo A: 10+ categorias canonicas (.git, __pycache__, node_modules, .vscode,
  .idea, *.log, *.tmp, dist/, build/, *.pyc + bonus)
- Grupo C: whitelist por nome (LICENSE, README, .gitignore, package.json, etc.)
  + .vscode whitelist (extensions.json)
- Grupo B: heuristica ambiguo (draft/rascunho/teste-local/...) + threshold review
- Walk: read-only INV-1; exclui symlink/junction/hardlink
- run_filter: snapshot pre + counts + symlink_excluded list
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from repo_sanitizer.f1_filter import (
    GROUP_A_PATTERNS,
    GROUP_B_HEURISTICS,
    GROUP_B_REVIEW_THRESHOLD,
    GROUP_C_FILES,
    GROUP_C_VSCODE_WHITELIST,
    classify_group_a,
    classify_group_b,
    classify_group_c,
    classify_path,
    run_filter,
    walk_source,
)

# ============================================================================
# Grupo A — 10 categorias canonicas
# ============================================================================

class TestGroupA:
    def test_dot_git_dir(self) -> None:
        matched, motivo = classify_group_a(".git/HEAD")
        assert matched is True
        assert ".git" in motivo

    def test_pycache_dir(self) -> None:
        matched, _ = classify_group_a("src/__pycache__/foo.cpython-311.pyc")
        assert matched is True

    def test_node_modules_dir(self) -> None:
        matched, _ = classify_group_a("frontend/node_modules/lodash/index.js")
        assert matched is True

    def test_vscode_dir(self) -> None:
        matched, _ = classify_group_a(".vscode/launch.json")
        assert matched is True

    def test_vscode_whitelist_extensions_json_not_grupo_a(self) -> None:
        """ADR-007: .vscode/extensions.json e whitelist (Grupo C)."""
        matched, _ = classify_group_a(".vscode/extensions.json")
        assert matched is False

    def test_idea_dir(self) -> None:
        matched, _ = classify_group_a(".idea/workspace.xml")
        assert matched is True

    def test_log_extension(self) -> None:
        matched, _ = classify_group_a("debug.log")
        assert matched is True
        matched, _ = classify_group_a("logs/server.log")
        assert matched is True

    def test_tmp_extension(self) -> None:
        matched, _ = classify_group_a("buffer.tmp")
        assert matched is True
        matched, _ = classify_group_a("foo.temp")
        assert matched is True

    def test_dist_dir(self) -> None:
        matched, _ = classify_group_a("dist/bundle.js")
        assert matched is True

    def test_build_dir(self) -> None:
        matched, _ = classify_group_a("build/main.exe")
        assert matched is True

    def test_pyc_extension(self) -> None:
        matched, _ = classify_group_a("foo.pyc")
        assert matched is True

    def test_pytest_cache(self) -> None:
        matched, _ = classify_group_a(".pytest_cache/v/cache/lastfailed")
        assert matched is True

    def test_safe_path_not_grupo_a(self) -> None:
        matched, _ = classify_group_a("src/main.py")
        assert matched is False

    def test_grupo_a_canonical_count_min_10(self) -> None:
        """DoD plano: 10 categorias canonicas (testamos 10+ aqui)."""
        assert len(GROUP_A_PATTERNS) >= 10


# ============================================================================
# Grupo C — Whitelist canonica por nome
# ============================================================================

class TestGroupC:
    def test_license(self) -> None:
        matched, motivo = classify_group_c("LICENSE")
        assert matched is True
        assert "LICENSE" in motivo or "whitelist" in motivo.lower()

    def test_license_md(self) -> None:
        matched, _ = classify_group_c("LICENSE.md")
        assert matched is True

    def test_readme_md(self) -> None:
        matched, _ = classify_group_c("README.md")
        assert matched is True

    def test_gitignore(self) -> None:
        matched, _ = classify_group_c(".gitignore")
        assert matched is True

    def test_package_json(self) -> None:
        matched, _ = classify_group_c("package.json")
        assert matched is True

    def test_pyproject_toml(self) -> None:
        matched, _ = classify_group_c("pyproject.toml")
        assert matched is True

    def test_contributing(self) -> None:
        matched, _ = classify_group_c("CONTRIBUTING.md")
        assert matched is True

    def test_security_md(self) -> None:
        matched, _ = classify_group_c("SECURITY.md")
        assert matched is True

    def test_dockerfile(self) -> None:
        matched, _ = classify_group_c("Dockerfile")
        assert matched is True

    def test_makefile_lower(self) -> None:
        matched, _ = classify_group_c("Makefile")
        assert matched is True

    def test_vscode_extensions_json_via_whitelist(self) -> None:
        matched, motivo = classify_group_c(".vscode/extensions.json")
        assert matched is True
        assert ".vscode" in motivo

    def test_random_file_not_in_whitelist(self) -> None:
        matched, _ = classify_group_c("src/main.py")
        assert matched is False

    def test_vscode_whitelist_subset(self) -> None:
        assert "extensions.json" in GROUP_C_VSCODE_WHITELIST

    def test_grupo_c_files_lowercase_only(self) -> None:
        """Whitelist deve ser case-insensitive via lowercase entries."""
        for f in GROUP_C_FILES:
            assert f == f.lower(), f"Entry nao lowercase: {f}"


# ============================================================================
# Grupo B — Heuristica ambiguo
# ============================================================================

class TestGroupB:
    def test_draft(self) -> None:
        matched, _ = classify_group_b("notas/draft-feature.md")
        assert matched is True

    def test_rascunho(self) -> None:
        matched, _ = classify_group_b("rascunho-arquitetura.md")
        assert matched is True

    def test_teste_local(self) -> None:
        matched, _ = classify_group_b("teste-local/foo.py")
        assert matched is True

    def test_notas_noma(self) -> None:
        matched, _ = classify_group_b("notas-noma/ideias.md")
        assert matched is True

    def test_todo_pessoal(self) -> None:
        matched, _ = classify_group_b("todo-pessoal.md")
        assert matched is True

    def test_scratch(self) -> None:
        matched, _ = classify_group_b("scratch/notes.txt")
        assert matched is True

    def test_sandbox(self) -> None:
        matched, _ = classify_group_b("sandbox-poc/main.py")
        assert matched is True

    def test_old_suffix(self) -> None:
        matched, _ = classify_group_b("config_old.json")
        assert matched is True

    def test_copy_marker(self) -> None:
        matched, _ = classify_group_b("backup-copy.md")
        assert matched is True

    def test_safe_path_not_grupo_b(self) -> None:
        matched, _ = classify_group_b("src/main.py")
        assert matched is False

    def test_threshold_default_10(self) -> None:
        assert GROUP_B_REVIEW_THRESHOLD == 10

    def test_grupo_b_count(self) -> None:
        """Plano canoniza 11 heuristicas Grupo B; sanity check."""
        assert len(GROUP_B_HEURISTICS) >= 8


# ============================================================================
# classify_path — orquestracao A -> C -> B -> default
# ============================================================================

class TestClassifyPath:
    def test_grupo_a_wins_over_c(self) -> None:
        # `dist/license.txt` matcha Grupo A `dist/` antes do Grupo C `license.txt`
        grupo, _, acao = classify_path("dist/license.txt")
        assert grupo == "A"
        assert acao == "excluir"

    def test_grupo_c_canonical(self) -> None:
        grupo, _, acao = classify_path("LICENSE")
        assert grupo == "C"
        assert acao == "incluir"

    def test_grupo_b_marker(self) -> None:
        grupo, _, acao = classify_path("docs/draft-feature.md")
        assert grupo == "B"
        assert acao == "excluir"

    def test_default_include(self) -> None:
        grupo, _, acao = classify_path("src/main.py")
        assert grupo == "default-include"
        assert acao == "incluir"

    def test_grupo_b_wins_over_default(self) -> None:
        grupo, _, _ = classify_path("docs/rascunho.md")
        assert grupo == "B"


# ============================================================================
# walk_source — INV-1 read-only + symlink_excluded
# ============================================================================

class TestWalkSource:
    def test_walk_simple_repo(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (tmp_path / "README.md").write_text("# repo\n", encoding="utf-8")
        cands = list(walk_source(tmp_path))
        rels = sorted(c.rel_path_posix for c in cands)
        assert "README.md" in rels
        assert "src/main.py" in rels

    def test_walk_excludes_inside_node_modules(self, tmp_path: Path) -> None:
        """Walk DEVE descer em node_modules — F1 emite cada arquivo como Grupo A
        para FILTER_DIFF deixar Noma ver o que estava la."""
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        (tmp_path / "node_modules" / "pkg" / "index.js").write_text("x", encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.js").write_text("y", encoding="utf-8")
        cands = list(walk_source(tmp_path))
        # node_modules entries APARECEM (pra log no FILTER_DIFF) classificados como Grupo A
        nm_cands = [c for c in cands if "node_modules" in c.rel_path_posix]
        assert len(nm_cands) >= 1

    def test_walk_excludes_hardlink_dir(self, tmp_path: Path) -> None:
        """Hardlink isolado em arquivo: sinalizado como symlink_excluded."""
        real = tmp_path / "real.txt"
        real.write_text("ok", encoding="utf-8")
        link = tmp_path / "linked.txt"
        try:
            os.link(real, link)
        except (OSError, NotImplementedError):
            pytest.skip("hardlink nao suportado")
        cands = list(walk_source(tmp_path))
        link_excluded = [c for c in cands if c.acao == "symlink_excluded"]
        assert len(link_excluded) >= 1

    def test_walk_classifies_default_include_for_unknown(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "weird.txt").write_text("ok", encoding="utf-8")
        cands = list(walk_source(tmp_path))
        weird = [c for c in cands if c.rel_path_posix == "src/weird.txt"]
        assert len(weird) == 1
        assert weird[0].grupo == "default-include"
        assert weird[0].acao == "incluir"


# ============================================================================
# run_filter — pipeline completo F1 dry-run
# ============================================================================

class TestRunFilter:
    def test_run_filter_basic_repo(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# repo\n", encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("ok\n", encoding="utf-8")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")

        result = run_filter(tmp_path)
        assert len(result.entries) >= 3
        assert result.snapshot_pre["aggregate"]
        assert result.snapshot_pre["file_count"] >= 3

    def test_run_filter_counts_by_group(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (tmp_path / "README.md").write_text("# r\n", encoding="utf-8")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
        (tmp_path / "rascunho.md").write_text("draft\n", encoding="utf-8")

        result = run_filter(tmp_path)
        assert result.counts_by_group["A"] >= 1  # .git
        assert result.counts_by_group["B"] >= 1  # rascunho
        assert result.counts_by_group["C"] >= 2  # LICENSE + README

    def test_run_filter_threshold_excedido(self, tmp_path: Path) -> None:
        for i in range(GROUP_B_REVIEW_THRESHOLD + 1):
            (tmp_path / f"draft-{i}.md").write_text("x", encoding="utf-8")
        result = run_filter(tmp_path)
        assert result.grupo_b_excedeu_threshold is True

    def test_run_filter_threshold_nao_excedido(self, tmp_path: Path) -> None:
        for i in range(2):
            (tmp_path / f"draft-{i}.md").write_text("x", encoding="utf-8")
        result = run_filter(tmp_path)
        assert result.grupo_b_excedeu_threshold is False

    def test_run_filter_inv1_snapshot_present(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("ok", encoding="utf-8")
        result = run_filter(tmp_path)
        assert "aggregate" in result.snapshot_pre
        assert "entries" in result.snapshot_pre

    def test_run_filter_pii_redacted_in_path(self, tmp_path: Path) -> None:
        """RS-018: path com PII vai redacted no FilterDiffEntry."""
        d = tmp_path / "Noma-Rabia"
        d.mkdir()
        (d / "code.py").write_text("ok", encoding="utf-8")
        result = run_filter(tmp_path)
        # Pelo menos 1 entry contem REDACTED-PII
        has_redacted = any("[REDACTED-PII]" in e.path_redacted for e in result.entries)
        assert has_redacted is True

    def test_run_filter_missing_source_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            run_filter(tmp_path / "no-such-dir")

    def test_run_filter_binary_classification(self, tmp_path: Path) -> None:
        """FilterDiffEntry.is_binary True para PNG."""
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nrest_of_data")
        result = run_filter(tmp_path)
        png = [e for e in result.entries if e.path_redacted.endswith("logo.png")]
        assert len(png) == 1
        assert png[0].is_binary is True

    def test_run_filter_inv1_no_writes_to_source(self, tmp_path: Path) -> None:
        """INV-1 reforcado 2x: hash-tree fonte pre/pos identical."""
        from repo_sanitizer.helpers._hash_tree import (
            assert_unchanged,
            snapshot,
        )
        (tmp_path / "f.txt").write_text("ok", encoding="utf-8")
        snap_pre = snapshot(tmp_path)
        _ = run_filter(tmp_path)
        snap_pos = snapshot(tmp_path)
        assert_unchanged(snap_pre, snap_pos)
