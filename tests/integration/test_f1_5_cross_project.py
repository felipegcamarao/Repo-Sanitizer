"""test_f1_5_cross_project.py — F1.5 integration (ADR-031 + RS-NEW-033 + Bloco 03 / 3.2).

Cobre 4 cenarios canonicos de integracao F1 + F1.5 sobre fixtures-temporarias
(`tmp_path`): (1) planos cross + relatorios cross, (2) portfolio + caches +
audit baselines, (3) plano intra-projeto (slug match), (4) modo defensivo
(sem context.md).

Plano original pedia 4 testes minimos — entregamos 6 (polish-driven 1.5x):
4 cenarios + 2 testes de robustez (`f1_5_counts` consistency + `cross_project_classifications` list).
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f1_filter import run_filter
from repo_sanitizer.helpers._cross_project_classifier import (
    UNKNOWN_PROJECT_SENTINEL,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context_md(source: Path, slug: str) -> Path:
    """Escreve context-<slug>.md com YAML frontmatter canonico."""
    ctx = source / f"context-{slug}.md"
    ctx.write_text(
        f"---\n"
        f"nome_projeto: \"{slug.replace('-', ' ').title()}\"\n"
        f"slug: \"{slug}\"\n"
        f"---\n\n"
        f"## Identificacao\n\n"
        f"**Nome:** {slug.replace('-', ' ').title()}\n",
        encoding="utf-8",
    )
    return ctx


def _touch(p: Path, content: str = "stub") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Cenario 1 — Planos + Relatorios cross-project
# ---------------------------------------------------------------------------


class TestF15CrossProjectPromotions:
    """Cenario canonico: planos/relatorios de outros projetos vao para Grupo B."""

    def test_cross_project_plans_and_reports_promote_to_group_b(self, tmp_path: Path) -> None:
        source = tmp_path / "Repo Sanitizer Agent"
        source.mkdir()
        _make_context_md(source, "repo-sanitizer-agent")

        # Intra: plano deste projeto (versionado)
        _touch(source / "plano-implementacao-repo-sanitizer-agent-v1.1.0.md")
        # Intra: arquivo qualquer (default)
        _touch(source / "README.md", "# Repo Sanitizer Agent\n")
        _touch(source / "src" / "main.py", "x = 1\n")
        # Cross: plano de OUTRO projeto
        _touch(source / "plano-implementacao-caden-platform-v7.md")
        _touch(source / "plano-implementacao-commission-dashboard.md")
        # Cross: relatorio staff de outro projeto
        _touch(source / "relatorio-staff-nexus.md")

        result = run_filter(source)

        assert result.project_slug == "repo-sanitizer-agent"
        # 2 planos cross + 1 relatorio cross = 3 promocoes para B
        assert result.f1_5_counts["cross_project_to_B"] == 3
        # Intra: 1 plano intra (versionado) + README + main.py + context.md = 4 mantidos C
        assert result.f1_5_counts["intra_project_kept_C"] >= 4
        # Group counts pos-F1.5
        assert result.counts_by_group.get("B", 0) >= 3

        # Sanidade: arquivos cross estao em Grupo B com motivo F1.5
        cross_paths = [e.path_redacted for e in result.entries if e.grupo == "B"]
        assert any("caden-platform" in p for p in cross_paths)
        assert any("nexus" in p for p in cross_paths)


# ---------------------------------------------------------------------------
# Cenario 2 — Portfolio + Caches + Audit baselines (Grupo A)
# ---------------------------------------------------------------------------


class TestF15CachePromotions:
    """Cenario canonico: portfolio, .eval-runs/, audit/baseline-* vao para Grupo A."""

    def test_portfolio_caches_baselines_promote_to_group_a(self, tmp_path: Path) -> None:
        source = tmp_path / "Project"
        source.mkdir()
        _make_context_md(source, "project")

        # Portfolio pt-BR + en
        _touch(source / "memory" / "projetos.md", "portfolio")
        _touch(source / "Agents Memory" / "memory" / "projects.md", "portfolio en")
        # Eval caches
        _touch(source / ".eval-runs" / "run1.jsonl", "{}")
        _touch(source / "evals" / "_eval_runs" / "result.json", "{}")
        _touch(source / "tests" / ".fixtures-derivation" / "x.json", "{}")
        # Audit baselines
        _touch(source / "audit" / "baseline-2026-05-15.md", "baseline")
        _touch(source / "_baseline-pre-v4.2.0" / "notes.md", "old")
        # Intra files (default C)
        _touch(source / "README.md", "# project")

        result = run_filter(source)

        # 2 portfolio + 3 eval caches + 2 baselines = 7 promocoes para A
        assert result.f1_5_counts["cache_to_A"] == 7
        # Group counts pos-F1.5 — Group A inclui esses 7 + caches deterministicos (se houver)
        assert result.counts_by_group.get("A", 0) >= 7


# ---------------------------------------------------------------------------
# Cenario 3 — Plano intra-projeto (slug match) NAO promove
# ---------------------------------------------------------------------------


class TestF15IntraProjectKept:
    """Cenario canonico: arquivos do proprio projeto ficam em Grupo C."""

    def test_intra_project_plans_stay_in_group_c(self, tmp_path: Path) -> None:
        source = tmp_path / "Repo Sanitizer Agent"
        source.mkdir()
        _make_context_md(source, "repo-sanitizer-agent")

        # Planos do PROPRIO projeto (devem ficar em C)
        _touch(source / "plano-implementacao-repo-sanitizer-agent.md", "plan v1")
        _touch(
            source / "plano-implementacao-repo-sanitizer-agent-v1.1.0"
            / "00-INDEX.md",
            "manifesto",
        )
        _touch(
            source / "plano-implementacao-repo-sanitizer-agent-v1.1.0"
            / "01-pii-detector-layer.md",
            "sub-plano",
        )
        # Relatorio do proprio projeto
        _touch(source / "relatorio-staff-repo-sanitizer-agent.md", "staff")

        result = run_filter(source)

        assert result.project_slug == "repo-sanitizer-agent"
        # Esperado: ZERO promocoes (todos slug-match)
        assert result.f1_5_counts["cross_project_to_B"] == 0
        # Grupo B nao deve crescer pelo F1.5 (apenas Grupo B deterministico do F1, que neste fixture eh 0)
        b_paths = [e.path_redacted for e in result.entries if e.grupo == "B"]
        assert not any(
            "plano-implementacao-repo-sanitizer-agent" in p for p in b_paths
        ), f"Plano intra-projeto promovido erroneamente: {b_paths}"


# ---------------------------------------------------------------------------
# Cenario 4 — Modo defensivo (sem context.md)
# ---------------------------------------------------------------------------


class TestF15DefensiveMode:
    """Sem context.md mas com basename que vira slug → ainda detecta cross.

    Caso defensivo PURO (sentinel) requer basename vazio/sanitizavel-zero —
    cenario raro mas testado em unit. Aqui validamos que basename funciona
    como fallback canonico.
    """

    def test_defensive_when_no_context_md_basename_fallback(
        self, tmp_path: Path,
    ) -> None:
        # Source sem context-*.md; basename vira slug "outro-projeto"
        source = tmp_path / "Outro Projeto"
        source.mkdir()

        _touch(source / "README.md", "x")
        # Plano que NAO matcha basename → cross
        _touch(source / "plano-implementacao-foo-bar.md")

        result = run_filter(source)
        assert result.project_slug == "outro-projeto"
        assert result.f1_5_counts["cross_project_to_B"] == 1

    def test_full_defensive_when_basename_sanitizes_to_empty(
        self, tmp_path: Path,
    ) -> None:
        # Basename "---" sanitiza para vazio → sentinel
        source = tmp_path / "---"
        source.mkdir()
        _touch(source / "plano-implementacao-anything.md")

        result = run_filter(source)
        assert result.project_slug == UNKNOWN_PROJECT_SENTINEL
        # Defensivo: plano vai para B com evidence no_context_md_defensive
        assert result.f1_5_counts["cross_project_to_B"] == 1
        cross_entries = [e for e in result.entries if e.grupo == "B"]
        assert any(
            "no_context_md_defensive" in (e.grupo_reason_detail or "")
            for e in cross_entries
        )


# ---------------------------------------------------------------------------
# Robustez — listas e contagens consistentes
# ---------------------------------------------------------------------------


class TestF15CountsConsistency:
    """f1_5_counts soma == cross_project_classifications len (sanity check)."""

    def test_f1_5_counts_sum_matches_classifications_len(
        self, tmp_path: Path,
    ) -> None:
        source = tmp_path / "X"
        source.mkdir()
        _make_context_md(source, "x")

        _touch(source / "memory" / "projetos.md")
        _touch(source / "README.md")
        _touch(source / "plano-implementacao-other.md")
        _touch(source / "src" / "main.py", "y = 2")

        result = run_filter(source)
        total_classified = sum(result.f1_5_counts.values())
        assert total_classified == len(result.cross_project_classifications)
        # Sanidade adicional: pelo menos 1 cross + 1 cache + 2 intra
        assert result.f1_5_counts["cross_project_to_B"] == 1
        assert result.f1_5_counts["cache_to_A"] == 1
        assert result.f1_5_counts["intra_project_kept_C"] >= 2


# ---------------------------------------------------------------------------
# Backward-compat — chamada antiga (sem kwargs) continua funcionando
# ---------------------------------------------------------------------------


class TestF15BackwardCompat:
    """`run_filter(source)` posicional (sem context_md_path) mantem assinatura v1.0."""

    def test_positional_call_still_works(self, tmp_path: Path) -> None:
        source = tmp_path / "MyProject"
        source.mkdir()
        _touch(source / "README.md")

        # Chamada estilo v1.0.x — apenas posicional
        result = run_filter(source)
        assert result.project_slug == "myproject"
        assert isinstance(result.f1_5_counts, dict)
        assert isinstance(result.cross_project_classifications, list)
