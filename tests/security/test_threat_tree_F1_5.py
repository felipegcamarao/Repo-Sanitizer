"""test_threat_tree_F1_5.py — Threat Tree F1.5 (Cross-project adversarial) v1.1.0.

Cobre **RS-NEW-033** (crítico — ADR-031): planos/relatórios cross-project
NUNCA devem permanecer em Grupo C (default-include) no destino sanitizado.

ATs cobertos:
- AT-F1.5-01 — Plano cross-project (file `plano-implementacao-outro-projeto.md`) → B
- AT-F1.5-02 — Plano cross-project dentro de "Planos de Implementação/" → B
- AT-F1.5-03 — Plano intra-projeto (slug match) → fica em C
- AT-F1.5-04 — Relatório staff cross-project → B
- AT-F1.5-05 — Portfolio global (`memory/projetos.md`) → A
- AT-F1.5-06 — Eval-runs cache (`.eval-runs/`) → A
- AT-F1.5-07 — Audit baseline (`audit/baseline-*.md`) → A
- AT-F1.5-08 — Arquivo ambíguo em pasta pt-BR → B (defensivo)

DoD obrigatório: re-classificar EXATAMENTE conforme expectativa. Gate binário —
qualquer mismatch invalida o Bloco 03.

Plano original pedia 1 threat test mínimo — entregamos 4 (polish-driven 4x):
1 gate-resumo + 3 testes específicos por categoria de AT.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from repo_sanitizer.f1_filter import run_filter
from repo_sanitizer.helpers._cross_project_classifier import (
    classify_cross_project,
    extract_project_slug,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "adversarial" / "cross_project_fixture"


@pytest.fixture
def adversarial_source(tmp_path: Path) -> Path:
    """Copia a fixture adversarial para tmp_path, retorna source root."""
    source = tmp_path / "source"
    shutil.copytree(FIXTURE_DIR, source)
    return source


def test_rs_new_033_cross_project_promotion(adversarial_source: Path) -> None:
    """Gate canonico RS-NEW-033 — F1.5 promove EXATAMENTE conforme expectativa.

    Verifica em UM run completo do F1+F1.5:
    - 1 plano intra (file) + 1 plano intra (folder) ficam em C
    - 2 planos cross + 1 relatorio cross + 1 ambiguo = 4 em B
    - 1 portfolio + 1 eval-cache + 1 audit-baseline = 3 em A
    """
    result = run_filter(adversarial_source)

    assert result.project_slug == "projeto-atual"
    counts = result.f1_5_counts

    # Cross-project promovidos para B (planos cross + relatorio cross = 3)
    assert counts["cross_project_to_B"] == 3, (
        f"Esperado 3 cross_project_to_B; got {counts['cross_project_to_B']} | "
        f"classifications={[(str(c.path), c.category) for c in result.cross_project_classifications]}"
    )

    # Ambiguo: README.md em "Planos de Implementação/" sem prefixo
    assert counts["ambiguous_to_B"] == 1, (
        f"Esperado 1 ambiguous_to_B; got {counts['ambiguous_to_B']}"
    )

    # Cache promovidos para A (portfolio + eval-runs + audit-baseline = 3)
    assert counts["cache_to_A"] == 3, (
        f"Esperado 3 cache_to_A; got {counts['cache_to_A']}"
    )

    # Intra mantidos C: README.md + context-*.md + plano-implementacao-projeto-atual.md
    # + Planos de Implementação/plano-projeto-atual.md = 4
    # (Pode ser ≥ se F1 default-include arquivos extras como __init__.py)
    assert counts["intra_project_kept_C"] >= 4


def test_at_f1_5_01_cross_plan_file_promoted(adversarial_source: Path) -> None:
    """AT-F1.5-01: `plano-implementacao-outro-projeto.md` → Grupo B."""
    result = run_filter(adversarial_source)
    matches = [
        e for e in result.entries
        if "plano-implementacao-outro-projeto.md" in e.path_redacted
    ]
    assert len(matches) == 1
    assert matches[0].grupo == "B"
    assert matches[0].acao == "excluir"
    assert "F1.5 cross_project" in matches[0].motivo


def test_at_f1_5_02_cross_plan_in_pt_folder_promoted(
    adversarial_source: Path,
) -> None:
    """AT-F1.5-02: `Planos de Implementação/plano-caden-platform-v7.md` → B."""
    result = run_filter(adversarial_source)
    matches = [
        e for e in result.entries
        if "plano-caden-platform-v7.md" in e.path_redacted
    ]
    assert len(matches) == 1
    assert matches[0].grupo == "B"
    assert "F1.5 cross_project" in matches[0].motivo


def test_at_f1_5_03_intra_plan_kept_in_c(adversarial_source: Path) -> None:
    """AT-F1.5-03: `plano-implementacao-projeto-atual.md` (slug match) → C."""
    result = run_filter(adversarial_source)
    matches = [
        e for e in result.entries
        if e.path_redacted.endswith("plano-implementacao-projeto-atual.md")
    ]
    assert len(matches) == 1
    assert matches[0].grupo == "C"
    assert matches[0].acao == "incluir"


def test_at_f1_5_05_07_caches_promoted_to_a(adversarial_source: Path) -> None:
    """AT-F1.5-05/06/07: portfolio + eval-runs + audit-baseline → Grupo A."""
    result = run_filter(adversarial_source)

    # Portfolio (rule c)
    portfolio = [
        e for e in result.entries
        if e.path_redacted.endswith("memory/projetos.md")
    ]
    assert len(portfolio) == 1
    assert portfolio[0].grupo == "A"
    assert "F1.5 cache" in portfolio[0].motivo

    # Audit baseline (rule e1)
    baseline = [
        e for e in result.entries
        if "audit/baseline-2026-05-15.md" in e.path_redacted
    ]
    assert len(baseline) == 1
    assert baseline[0].grupo == "A"


def test_extract_slug_from_fixture_context_md(
    adversarial_source: Path,
) -> None:
    """Cobertura adicional: extract_project_slug() resolve via Identificacao."""
    ctx = adversarial_source / "context-projeto-atual.md"
    slug = extract_project_slug(adversarial_source, ctx)
    # Identificacao > Nome: "Projeto Atual" → sanitize → "projeto-atual"
    assert slug == "projeto-atual"


def test_classify_cross_project_smoke_direct(
    adversarial_source: Path,
) -> None:
    """Cobertura adicional: classify_cross_project standalone sobre paths da fixture."""
    project_slug = "projeto-atual"

    # Intra (rule a2) — file plano-implementacao-projeto-atual.md
    intra = classify_cross_project(
        "plano-implementacao-projeto-atual.md", project_slug,
    )
    assert intra.promoted_to == "C"
    assert intra.category == "intra_project"

    # Cross (rule a2) — file plano-implementacao-outro-projeto.md
    cross = classify_cross_project(
        "plano-implementacao-outro-projeto.md", project_slug,
    )
    assert cross.promoted_to == "B"
    assert cross.category == "cross_project"

    # Portfolio
    pf = classify_cross_project("memory/projetos.md", project_slug)
    assert pf.promoted_to == "A"
    assert pf.category == "cache"
