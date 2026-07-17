"""test_filter_diff_writer.py — emit FILTER_DIFF.md (Bloco 02 02.8)."""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f1_filter import run_filter
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.reports.filter_diff_writer import (
    build_filter_diff_md,
    extract_hash_tree_snapshot,
    filter_diff_filename,
    write_filter_diff,
)

RUN_ID = "11111111-2222-3333-4444-555555555555"


def _build_simple_repo(tmp: Path) -> Path:
    src = tmp / "src-fixture"
    src.mkdir()
    (src / "README.md").write_text("# r\n", encoding="utf-8")
    (src / "src").mkdir()
    (src / "src" / "main.py").write_text("ok\n", encoding="utf-8")
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
    (src / "rascunho.md").write_text("draft\n", encoding="utf-8")
    return src


def test_build_filter_diff_md_contains_yaml_header(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="C:/redacted/source",
        dest_path_redacted="C:/redacted/dest",
    )
    assert md.startswith("---\n")
    assert 'agent: "repo-sanitizer-agent"' in md
    assert "counts:" in md
    assert "inv1_snapshot_aggregate_prefix" in md


def test_build_contains_4_sections(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    assert "## Grupo A" in md
    assert "## Grupo B" in md
    assert "## Grupo C" in md
    assert "## Symlinks" in md


def test_build_lists_grupo_a_files(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    # `.git/HEAD` deve aparecer em Grupo A
    assert ".git/HEAD" in md or ".git" in md


def test_build_lists_grupo_b_rascunho(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    assert "rascunho.md" in md


def test_build_lists_grupo_c_readme_license(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    (src / "LICENSE").write_text("MIT\n", encoding="utf-8")
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    assert "README.md" in md
    assert "LICENSE" in md


def test_build_threshold_warning_when_excedido(tmp_path: Path) -> None:
    src = tmp_path / "many-drafts"
    src.mkdir()
    for i in range(15):  # > 10 threshold
        (src / f"draft-{i}.md").write_text("d", encoding="utf-8")
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    assert "excedeu threshold" in md or "REVIEW" in md


def test_filter_diff_filename_format() -> None:
    fname = filter_diff_filename("meurepo")
    assert fname.startswith("FILTER_DIFF_meurepo_")
    assert fname.endswith(".md")
    fname2 = filter_diff_filename("meurepo", run_id_prefix="abcd1234")
    assert "abcd1234" in fname2


def test_extract_hash_tree_snapshot_roundtrip(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    snap = extract_hash_tree_snapshot(md)
    assert snap is not None
    assert snap["aggregate"] == result.snapshot_pre["aggregate"]
    assert snap["file_count"] == result.snapshot_pre["file_count"]


def test_write_filter_diff_via_fs_writer(tmp_path: Path) -> None:
    """Smoke E2E: run_filter -> write_filter_diff -> arquivo no /Relatorios/."""
    src = _build_simple_repo(tmp_path)
    relatorios = tmp_path / "Relatorios"
    relatorios.mkdir()

    # FsWriter precisa override_forbidden para AppData/tmp
    fw = FsWriter(
        source_path=src,
        allowed_roots=[tmp_path],
        override_forbidden=[],  # so source_path adicionado runtime
    )
    result = run_filter(src)
    written = write_filter_diff(
        result, slug="testrepo", run_id=RUN_ID,
        fs_writer=fw, relatorios_dir=relatorios,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    assert written.exists()
    content = written.read_text(encoding="utf-8")
    assert "## Grupo A" in content


def test_write_filter_diff_blocks_outside_allowed(tmp_path: Path) -> None:
    """Defesa ADR-020: tentar escrever fora de ALLOWED_ROOTS -> raise."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError

    src = _build_simple_repo(tmp_path)
    fw = FsWriter(
        source_path=src,
        allowed_roots=[tmp_path / "allowed"],  # nao existe ainda
        override_forbidden=[],
    )
    result = run_filter(src)
    bad_dir = tmp_path / "outside"
    bad_dir.mkdir()
    with pytest.raises(FsWriteOutOfBoundsError):
        write_filter_diff(
            result, slug="x", run_id=RUN_ID,
            fs_writer=fw, relatorios_dir=bad_dir,
            source_path_redacted="src", dest_path_redacted="dst",
        )


def test_md_table_escapes_pipe_in_path(tmp_path: Path) -> None:
    """path com | nao quebra tabela Markdown."""
    src = tmp_path / "src"
    src.mkdir()
    weird = src / "weird|name.txt"
    try:
        weird.write_text("ok", encoding="utf-8")
    except OSError:
        pytest.skip("filesystem nao suporta '|' em filename")
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="x", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    # `|` deve estar escaped em conteudo de celula
    assert "weird\\|name.txt" in md or "weird|name.txt" not in md.split("\n## Grupo")[1]


def test_inv1_snapshot_in_yaml_header(tmp_path: Path) -> None:
    src = _build_simple_repo(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="x", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    expected_prefix = result.snapshot_pre["aggregate"][:16]
    assert f'inv1_snapshot_aggregate_prefix: "{expected_prefix}"' in md


# ---------------------------------------------------------------------------
# Bloco 03 — secao "Camada F1.5 — Cross-Project Detection" (ADR-031)
# ---------------------------------------------------------------------------


def _build_repo_with_cross_project(tmp: Path) -> Path:
    """Fixture canonica: source-tree com 1 cross-plan + 1 cache + intra."""
    src = tmp / "TestRepo"
    src.mkdir()
    # context.md canonico (slug = "testrepo")
    (src / "context-testrepo.md").write_text(
        '---\nslug: "testrepo"\n---\n\n## Identificacao\n\n**Nome:** TestRepo\n',
        encoding="utf-8",
    )
    (src / "README.md").write_text("# r\n", encoding="utf-8")
    # cross-project plan
    (src / "plano-implementacao-outro-projeto.md").write_text(
        "x", encoding="utf-8",
    )
    # cache (portfolio)
    (src / "memory").mkdir()
    (src / "memory" / "projetos.md").write_text("portfolio", encoding="utf-8")
    return src


def test_filter_diff_contains_f1_5_section_and_counts_yaml(tmp_path: Path) -> None:
    """Bloco 03 / 3.3 — secao F1.5 + frontmatter `f1_5_counts:` presentes."""
    src = _build_repo_with_cross_project(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )

    # YAML frontmatter — counts F1.5 + project_slug_resolved
    assert "f1_5_counts:" in md
    assert "  cross_project_to_B: 1" in md
    assert "  cache_to_A: 1" in md
    assert 'project_slug_resolved: "testrepo"' in md

    # Body — secao canonica + 3 sub-secoes
    assert "## Camada F1.5 — Cross-Project Detection" in md
    assert "### Cross-project (Grupo B — review)" in md
    assert "### Cache (Grupo A — exclude)" in md
    assert "### Ambiguos (Grupo B — review defensivo)" in md
    # Linha-resumo com counts em bold
    assert "Cross-project promovidos para Grupo B: **1**" in md
    assert "Caches promovidos para Grupo A: **1**" in md


def test_filter_diff_f1_5_section_lists_classified_paths(tmp_path: Path) -> None:
    """Bloco 03 / 3.3 — paths classificados aparecem na tabela com evidence."""
    src = _build_repo_with_cross_project(tmp_path)
    result = run_filter(src)
    md = build_filter_diff_md(
        result, slug="testrepo", run_id=RUN_ID,
        source_path_redacted="src", dest_path_redacted="dst",
    )

    # Cross-project: path aparece na sub-tabela com category + promoted_to
    assert "plano-implementacao-outro-projeto.md" in md
    assert "cross_project" in md
    # Cache: portfolio path aparece
    assert "projetos.md" in md
    assert "cache" in md
    # Tabelas markdown corretamente formatadas
    assert "| path | category | evidence | promoted_to |" in md
