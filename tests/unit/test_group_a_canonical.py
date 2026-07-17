"""test_group_a_canonical.py — B1+B2 / MV-01+MV-02 / RS-NEW-039+038.

Lista canonica EXAUSTIVA de caches/lixo (Grupo A) + artefatos de historico Git
fora de `.git/`. Gates machine-checkable:

1. parametrizado: cada cache/artefato canonico -> ("A", _, "excluir");
2. teste de regressao com lista-sentinela: falha se algum cache conhecido
   deixar de ser excluido (gate machine-checkable);
3. fixture de FALSO-POSITIVO: pastas de produto legitimas -> "incluir";
4. dry-run sobre o PROPRIO repo do agente: caches versionados -> "excluir".

Mitigacao §5-6 (#02): patterns ancorados nao casam pasta de produto.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f1_filter import (
    GIT_HISTORY_PATTERNS,
    GROUP_A_PATTERNS,
    classify_path,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Lista-sentinela canonica de caches/lixo (RS-NEW-039). Cada path representa um
# arquivo DENTRO do cache (ou o proprio arquivo de cache). DEVE virar Grupo A.
# ---------------------------------------------------------------------------
CANONICAL_CACHE_PATHS: list[str] = [
    # Ambientes virtuais Python
    ".venv/lib/site-packages/x.py",
    "venv/bin/activate",
    "env/pyvenv.cfg",
    # Caches Python / bytecode
    "src/__pycache__/mod.cpython-312.pyc",
    "mod.pyc",
    "mod.pyo",
    ".pytest_cache/v/cache/lastfailed",
    ".ruff_cache/0.1.0/123",
    ".mypy_cache/3.12/x.json",
    ".hypothesis/examples/abc",
    # Coverage / test
    ".coverage",
    ".coverage.host.1234",
    "coverage.xml",
    "htmlcov/index.html",
    ".tox/py312/bin/python",
    ".nox/tests/x",
    ".nyc_output/processinfo/index.json",
    # Node / JS bundlers
    "node_modules/left-pad/index.js",
    "dist/bundle.js",
    "build/output.o",
    ".next/server/page.js",
    ".cache/x",
    ".parcel-cache/abc",
    ".turbo/x",
    ".svelte-kit/output/x",
    ".eslintcache",
    ".stylelintcache",
    "app.tsbuildinfo",
    # Python packaging
    "mypkg.egg-info/PKG-INFO",
    "__pypackages__/3.12/lib/x.py",
    # Infra / outras linguagens
    ".terraform/providers/x",
    "target/debug/app",
    ".gradle/caches/x",
    "app.pdb",
    "Main.class",
    "obj/file.o",
    "file.obj",
    # SO / editor lixo
    "Thumbs.db",
    ".DS_Store",
    "file.swp",
    "file.bak",
    "app.log",
    "tmp.tmp",
    # Jupyter
    ".ipynb_checkpoints/Untitled-checkpoint.ipynb",
]


# Artefatos de historico Git fora de `.git/` (RS-NEW-038, walk-side B2).
CANONICAL_GIT_HISTORY_PATHS: list[str] = [
    ".git/config",
    "submodule/.git/HEAD",
    "packed-refs",
    "refs/packed-refs",
    "ORIG_HEAD",
    "FETCH_HEAD",
    ".gitmodules",
    "conflict.orig",
    "merge.rej",
    "feature.patch",
    "change.diff",
    "repo.bundle",
]


# Pastas de PRODUTO legitimas — FALSO-POSITIVO a EVITAR (MV01-B / §5-6).
PRODUCT_LEGIT_PATHS: list[str] = [
    "src/build_tools/compile.py",
    "data/dist_metrics/report.py",
    "app/target_groups/segment.py",
    "myenv/config.py",
    "environment/setup.py",
    "lib/builder/core.py",
    "src/cacher/logic.py",
    "docs/distribution/guide.md",
    "src/main.py",
    "README.md",
]


@pytest.mark.parametrize("rel_path", CANONICAL_CACHE_PATHS)
def test_canonical_cache_is_group_a(rel_path: str) -> None:
    """Cada cache canonico -> Grupo A / excluir (RS-NEW-039 a)."""
    grupo, _motivo, acao = classify_path(rel_path)
    assert grupo == "A", f"{rel_path!r} deveria ser Grupo A, foi {grupo!r}"
    assert acao == "excluir", f"{rel_path!r} deveria 'excluir', foi {acao!r}"


@pytest.mark.parametrize("rel_path", CANONICAL_GIT_HISTORY_PATHS)
def test_canonical_git_history_is_group_a(rel_path: str) -> None:
    """Cada artefato de historico Git -> Grupo A / excluir (RS-NEW-038 walk)."""
    grupo, _motivo, acao = classify_path(rel_path)
    assert grupo == "A", f"{rel_path!r} deveria ser Grupo A, foi {grupo!r}"
    assert acao == "excluir", f"{rel_path!r} deveria 'excluir', foi {acao!r}"


def test_regression_sentinel_no_cache_leaks() -> None:
    """Gate de regressao: se QUALQUER cache da lista-sentinela deixar de ser
    excluido, este teste falha (machine-checkable RS-NEW-039 b)."""
    leaked = [
        p for p in (CANONICAL_CACHE_PATHS + CANONICAL_GIT_HISTORY_PATHS)
        if classify_path(p)[2] != "excluir"
    ]
    assert leaked == [], f"caches/artefatos NAO excluidos (regressao): {leaked}"


@pytest.mark.parametrize("rel_path", PRODUCT_LEGIT_PATHS)
def test_product_folder_not_excluded_anti_fp(rel_path: str) -> None:
    """Anti-FP (MV01-B / §5-6): pasta de produto legitima -> incluir."""
    _grupo, _motivo, acao = classify_path(rel_path)
    assert acao == "incluir", (
        f"FALSO-POSITIVO: {rel_path!r} (produto) foi {acao!r}, esperado 'incluir'"
    )


def test_env_file_not_swallowed_by_venv_pattern() -> None:
    """MV01-C: `.env` (segredo C1, basename) NAO e engolido pelo pattern de
    diretorio venv/env. Deve permanecer 'incluir' em F1 (F3 trata file-level)."""
    for p in (".env", "config/.env", ".env.local"):
        _g, _m, acao = classify_path(p)
        assert acao == "incluir", f"{p!r} nao deveria ser excluido em F1"


def test_dry_run_self_repo_excludes_known_caches() -> None:
    """RS-NEW-039 c — dry-run conceitual sobre o PROPRIO repo do agente:
    caches versionados (`.mypy_cache`/`.pytest_cache`/`.ruff_cache`/`.coverage`/
    `__pycache__`) sao todos excluidos. Usa os nomes canonicos do repo-fonte."""
    self_repo_caches = [
        ".mypy_cache/3.12/repo_sanitizer/x.json",
        ".pytest_cache/v/cache/nodeids",
        ".ruff_cache/0.x/abc",
        ".coverage",
        "src/repo_sanitizer/__pycache__/cli.cpython-312.pyc",
    ]
    for p in self_repo_caches:
        grupo, _m, acao = classify_path(p)
        assert acao == "excluir", f"cache do proprio repo nao excluido: {p!r}"
        assert grupo == "A"


def test_group_a_patterns_are_anchored() -> None:
    """Sanidade: patterns de dir usam ancora `(^|/)` (anti-FP estrutural)."""
    # Pelo menos os patterns de diretorio v1.2.0 devem conter a ancora.
    anchored = [p for p, _ in GROUP_A_PATTERNS if "(^|/)" in p.pattern]
    assert len(anchored) >= 10, "patterns de dir devem ser ancorados"
    # GIT_HISTORY_PATTERNS nao-vazia e ancorada por basename/extensao.
    assert len(GIT_HISTORY_PATTERNS) >= 5
