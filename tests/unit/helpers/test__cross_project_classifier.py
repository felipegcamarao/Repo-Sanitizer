"""test__cross_project_classifier.py — F1.5 helper (ADR-031 + RS-NEW-033 + Bloco 03 / 3.1).

Cobre as 5 regras canônicas (a..e) + slug-extraction (3 modos + sentinel) +
edge cases (unicode/version-suffix/folder-ancestor/defensive). Meta de cobertura
sobre ``_cross_project_classifier.py`` ≥90%.

Plano original pedia 8+ testes — entregamos 38 (polish-driven 4.75x) para
cobertura defensiva sobre cada regra + edge cases + modo defensivo + slug
versionado + extensão polish-driven (folder ancestor).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.helpers._cross_project_classifier import (
    UNKNOWN_PROJECT_SENTINEL,
    CrossProjectClassification,
    classify_cross_project,
    extract_project_slug,
    sanitize_slug,
)

# ---------------------------------------------------------------------------
# sanitize_slug
# ---------------------------------------------------------------------------


class TestSanitizeSlug:
    """Normalização canônica de slug (NFKD + lowercase + kebab + dot-preserve)."""

    def test_basic_lowercase_and_hyphen(self) -> None:
        assert sanitize_slug("GitHub Repo Sanitizer Agent") == "github-repo-sanitizer-agent"

    def test_unicode_combining_marks_stripped(self) -> None:
        # "Nomão" → "Nomao" → "nomao"
        assert sanitize_slug("Noma Nomão") == "noma-nomao"

    def test_punctuation_becomes_hyphen(self) -> None:
        # & e outros símbolos viram hífens; colapso evita "---"
        assert sanitize_slug("GitHub Repo Sanitizer & Publisher Agent") == \
            "github-repo-sanitizer-publisher-agent"

    def test_dots_preserved_for_versions(self) -> None:
        # Dots preservados para "v1.1.0"
        assert sanitize_slug("repo-sanitizer-agent v1.1.0") == "repo-sanitizer-agent-v1.1.0"

    def test_empty_input(self) -> None:
        assert sanitize_slug("") == ""

    def test_collapse_multiple_hyphens_and_strip(self) -> None:
        assert sanitize_slug("  --foo  --  bar--  ") == "foo-bar"


# ---------------------------------------------------------------------------
# extract_project_slug
# ---------------------------------------------------------------------------


class TestExtractProjectSlug:
    """3 modos de resolução + polish-driven YAML slug + sentinel defensivo."""

    def test_context_md_identificacao_nome(self, tmp_path: Path) -> None:
        ctx = tmp_path / "context-foo.md"
        ctx.write_text(
            "# Title\n\n"
            "## Identificação\n\n"
            "**Nome:** GitHub Repo Sanitizer & Publisher Agent\n\n"
            "## Outra Seção\n\n"
            "**Nome:** valor-ignorado-em-outra-seção\n",
            encoding="utf-8",
        )
        src = tmp_path / "project-folder"
        src.mkdir()
        result = extract_project_slug(src, ctx)
        assert result == "github-repo-sanitizer-publisher-agent"

    def test_context_md_yaml_slug_polish_driven(self, tmp_path: Path) -> None:
        # Quando NÃO há `## Identificação`, polish-driven cai no YAML slug:
        ctx = tmp_path / "context-bar.md"
        ctx.write_text(
            "---\n"
            'nome_projeto: "Foo Bar Baz"\n'
            'slug: "foo-bar-baz"\n'
            "---\n\n# Title\n",
            encoding="utf-8",
        )
        src = tmp_path / "outro"
        src.mkdir()
        result = extract_project_slug(src, ctx)
        assert result == "foo-bar-baz"

    def test_context_md_priority_identificacao_over_yaml(self, tmp_path: Path) -> None:
        # Identificação > **Nome:** tem prioridade sobre YAML slug:
        ctx = tmp_path / "context-c.md"
        ctx.write_text(
            "---\n"
            'slug: "yaml-slug-value"\n'
            "---\n\n"
            "## Identificação\n\n"
            "**Nome:** Identificacao Nome Value\n",
            encoding="utf-8",
        )
        src = tmp_path / "x"
        src.mkdir()
        result = extract_project_slug(src, ctx)
        assert result == "identificacao-nome-value"

    def test_basename_fallback_when_no_context(self, tmp_path: Path) -> None:
        src = tmp_path / "Repo Sanitizer Agent"
        src.mkdir()
        result = extract_project_slug(src, None)
        assert result == "repo-sanitizer-agent"

    def test_basename_fallback_when_context_missing_file(self, tmp_path: Path) -> None:
        ctx = tmp_path / "context-nope.md"  # não existe
        src = tmp_path / "Meu Projeto"
        src.mkdir()
        result = extract_project_slug(src, ctx)
        assert result == "meu-projeto"

    def test_defensive_sentinel_when_basename_empty(self, tmp_path: Path) -> None:
        # source_path com basename que sanitiza para vazio (e.g., "---")
        src = tmp_path / "---"
        src.mkdir()
        result = extract_project_slug(src, None)
        assert result == UNKNOWN_PROJECT_SENTINEL


# ---------------------------------------------------------------------------
# classify_cross_project — Regra (a) Planos
# ---------------------------------------------------------------------------


class TestRulePlanos:
    """Rule (a): planos cross-project promovem para Grupo B."""

    def test_a1_planos_folder_slug_match_keeps_group_c(self) -> None:
        result = classify_cross_project(
            "Planos de Implementação/plano-repo-sanitizer-agent.md",
            project_slug="repo-sanitizer-agent",
        )
        assert isinstance(result, CrossProjectClassification)
        assert result.category == "intra_project"
        assert result.promoted_to == "C"
        assert any("slug-match" in e for e in result.evidence)

    def test_a1_planos_folder_slug_mismatch_promotes_group_b(self) -> None:
        result = classify_cross_project(
            "Planos de Implementação/plano-caden-platform-v7.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"
        assert any("slug-mismatch" in e for e in result.evidence)
        assert "rule:planos_folder" in result.evidence

    def test_a2_plano_implementacao_file_mismatch(self) -> None:
        result = classify_cross_project(
            "plano-implementacao-outro-projeto.md",
            project_slug="projeto-atual",
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"
        assert "rule:plano_implementacao_file" in result.evidence

    def test_a2_plano_implementacao_file_match_versioned(self) -> None:
        # Polish-driven: version-suffix matches base project slug
        result = classify_cross_project(
            "plano-implementacao-repo-sanitizer-agent-v1.1.0.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "intra_project"
        assert result.promoted_to == "C"

    def test_a3_folder_ancestor_slug_match_keeps_group_c(self) -> None:
        # Polish-driven: pasta-ancestral é o padrão real deste projeto
        result = classify_cross_project(
            "plano-implementacao-repo-sanitizer-agent-v1.1.0/00-INDEX.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "intra_project"
        assert result.promoted_to == "C"
        assert "rule:plano_implementacao_ancestor" in result.evidence

    def test_a3_folder_ancestor_slug_mismatch_promotes_group_b(self) -> None:
        result = classify_cross_project(
            "plano-implementacao-caden-platform-v7/01-foundation.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"


# ---------------------------------------------------------------------------
# classify_cross_project — Regra (b) Relatórios
# ---------------------------------------------------------------------------


class TestRuleRelatorios:
    """Rule (b): relatórios staff cross-project promovem para Grupo B."""

    def test_b1_relatorios_folder_mismatch(self) -> None:
        result = classify_cross_project(
            "Relatórios Staff/relatorio-staff-commission-dashboard.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"
        assert "rule:relatorios_folder" in result.evidence

    def test_b1_relatorios_folder_match_keeps_group_c(self) -> None:
        result = classify_cross_project(
            "Relatórios Staff/relatorio-staff-repo-sanitizer-agent.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "intra_project"
        assert result.promoted_to == "C"

    def test_b2_relatorio_staff_file_anywhere(self) -> None:
        # Sem pasta pt-BR, ainda assim deve casar pelo prefixo do arquivo
        result = classify_cross_project(
            "docs/relatorio-staff-nex.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"
        assert "rule:relatorio_staff_file" in result.evidence


# ---------------------------------------------------------------------------
# classify_cross_project — Regras (c) (d) (e)
# ---------------------------------------------------------------------------


class TestRulePortfolioCachesBaselines:
    """Rules (c) portfolio + (d) eval caches + (e) audit baselines → Grupo A."""

    def test_c_portfolio_pt_br(self) -> None:
        result = classify_cross_project(
            "memory/projetos.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"
        assert "rule:portfolio" in result.evidence

    def test_c_portfolio_en(self) -> None:
        result = classify_cross_project(
            "Agents Memory/memory/projects.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"

    def test_d_eval_runs_dotted_dir(self) -> None:
        result = classify_cross_project(
            ".eval-runs/run-2026-05-26.jsonl",
            project_slug="x",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"
        assert "rule:eval_caches" in result.evidence

    def test_d_underscore_eval_runs_in_subdir(self) -> None:
        result = classify_cross_project(
            "evals/_eval_runs/2026-05/result.json",
            project_slug="x",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"

    def test_d_fixtures_derivation_cache(self) -> None:
        result = classify_cross_project(
            "tests/.fixtures-derivation/foo.json",
            project_slug="x",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"

    def test_e1_audit_baseline_md(self) -> None:
        result = classify_cross_project(
            "audit/baseline-2026-05-15.md",
            project_slug="x",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"
        assert "rule:audit_baseline" in result.evidence

    def test_e2_baseline_directory(self) -> None:
        result = classify_cross_project(
            "_baseline-pre-v4.2.0/notes.md",
            project_slug="x",
        )
        assert result.category == "cache"
        assert result.promoted_to == "A"
        assert "rule:baseline_dir" in result.evidence


# ---------------------------------------------------------------------------
# Modo defensivo (project_slug == UNKNOWN_PROJECT_SENTINEL)
# ---------------------------------------------------------------------------


class TestDefensiveMode:
    """Sem context.md (sentinel) — todos planos/relatórios vão para Grupo B."""

    def test_defensive_promotes_even_apparently_matching_slug(self) -> None:
        # Mesmo um plano que parece pertencer ao projeto vai para B
        result = classify_cross_project(
            "plano-implementacao-unknown-project.md",
            project_slug=UNKNOWN_PROJECT_SENTINEL,
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"
        assert "no_context_md_defensive" in result.evidence

    def test_defensive_relatorio_also_promotes(self) -> None:
        result = classify_cross_project(
            "Relatórios Staff/relatorio-staff-foo.md",
            project_slug=UNKNOWN_PROJECT_SENTINEL,
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"
        assert "no_context_md_defensive" in result.evidence

    def test_defensive_does_not_affect_portfolio_or_caches(self) -> None:
        # Caches sempre vão para A, slug irrelevante
        result = classify_cross_project(
            "memory/projetos.md",
            project_slug=UNKNOWN_PROJECT_SENTINEL,
        )
        assert result.promoted_to == "A"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Files dentro de pasta pt-BR sem prefixo + paths Windows + default."""

    def test_ambiguous_in_planos_without_prefix(self) -> None:
        # README.md dentro de "Planos de Implementação/" sem prefixo "plano-"
        result = classify_cross_project(
            "Planos de Implementação/README.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "ambiguous"
        assert result.promoted_to == "B"
        assert "in_planos_folder_no_prefix" in result.evidence

    def test_ambiguous_in_relatorios_without_prefix(self) -> None:
        result = classify_cross_project(
            "Relatórios Staff/NOTAS.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "ambiguous"
        assert result.promoted_to == "B"

    def test_windows_backslash_path_normalized(self) -> None:
        # Path Windows com backslash deve ser normalizado
        result = classify_cross_project(
            r"Planos de Implementação\plano-other.md",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "cross_project"
        assert result.promoted_to == "B"

    def test_default_intra_project_for_unmatched(self) -> None:
        # Arquivo qualquer fora das regras → intra default
        result = classify_cross_project(
            "src/repo_sanitizer/cli.py",
            project_slug="repo-sanitizer-agent",
        )
        assert result.category == "intra_project"
        assert result.promoted_to == "C"
        assert "no_cross_project_pattern_matched" in result.evidence

    def test_pathobject_input_accepted(self) -> None:
        # Tipo Path também deve funcionar
        result = classify_cross_project(
            Path("memory") / "projetos.md",
            project_slug="x",
        )
        assert result.promoted_to == "A"


# ---------------------------------------------------------------------------
# Smoke: integração extract_project_slug ↔ classify_cross_project
# ---------------------------------------------------------------------------


class TestExtractAndClassifySmoke:
    """Pipeline mínimo: extrai slug do context.md + classifica arquivos."""

    @pytest.fixture
    def project_tree(self, tmp_path: Path) -> tuple[Path, Path]:
        src = tmp_path / "Repo Sanitizer Agent"
        src.mkdir()
        ctx = src / "context-repo-sanitizer-agent.md"
        ctx.write_text(
            "---\n"
            'slug: "repo-sanitizer-agent"\n'
            "---\n\n"
            "## Identificação\n\n"
            "**Nome:** GitHub Repo Sanitizer & Publisher Agent\n",
            encoding="utf-8",
        )
        return src, ctx

    def test_smoke_intra_and_cross(self, project_tree: tuple[Path, Path]) -> None:
        src, ctx = project_tree
        slug = extract_project_slug(src, ctx)
        assert slug == "github-repo-sanitizer-publisher-agent"  # via Identificação

        # Esse plano não matcha (slug "Caden Platform v7")
        cross = classify_cross_project(
            "plano-implementacao-caden-platform-v7.md", slug,
        )
        assert cross.promoted_to == "B"
        assert cross.category == "cross_project"

        # Esse plano matcha versionado
        intra = classify_cross_project(
            "plano-implementacao-github-repo-sanitizer-publisher-agent-v1.1.0.md", slug,
        )
        assert intra.promoted_to == "C"
        assert intra.category == "intra_project"

    def test_smoke_defensive_when_context_missing(self, tmp_path: Path) -> None:
        src = tmp_path / "x"  # basename "x" produz slug "x"
        src.mkdir()
        slug = extract_project_slug(src, None)
        # Slug não é defensive — basename funcionou:
        assert slug == "x"
        # E qualquer plano não-matching vira B normalmente:
        result = classify_cross_project("plano-implementacao-foo.md", slug)
        assert result.promoted_to == "B"
