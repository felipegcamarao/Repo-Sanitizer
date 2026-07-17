"""test_inv1_snapshot_f3.py — Bloco 03 Passo 03.16 INV-1 SNAPSHOT FINAL F3.

RS-002 reforcado 2x pelo [NOME]. Hash-tree fonte SHA-256 pre/pos identical em
10 fixtures (5 Bloco 02 + 5 adversariais Bloco 03):

Herdadas Bloco 02:
1. python_simple
2. node_monorepo
3. docs_only
4. symlink_adversarial
5. pii_in_paths

Adversariais Bloco 03 (selecao das 7 que afetam scan F3):
6. encoding_bomb
7. binary_with_keys
8. injection_in_readme
9. cat_not_covered
10. cleanup_falho

DoD: 10/10 hash idêntico bit-a-bit pre/pos run_apply (que dispara F3).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._hash_tree import assert_unchanged, snapshot
from repo_sanitizer.orchestrator import (
    make_orchestrator_context,
    run_apply,
    run_dry_run,
)
from tests.fixtures.repos import REPO_FACTORIES, REPO_NAMES
from tests.fixtures.repos.adversarial import ADVERSARIAL_FACTORIES

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _setup_with_factory(tmp_path: Path, slug: str, factory) -> tuple:
    """Constroi fixture + ctx + fw isolado em tmp_path."""
    src_root = tmp_path / "sources"
    src_root.mkdir()
    src = factory(src_root)

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
    return ctx, fw, src


# ===========================================================================
# 5 fixtures Bloco 02 — INV-1 pre/pos identical apos F3
# ===========================================================================

@pytest.mark.parametrize("slug", REPO_NAMES)
def test_inv1_snapshot_identical_after_f3_bloco_02_fixtures(
    slug: str, tmp_path: Path,
) -> None:
    """5 fixtures Bloco 02: hash-tree fonte INTOCADO apos dry-run + apply (F3)."""
    factory = REPO_FACTORIES[slug]
    ctx, fw, src = _setup_with_factory(tmp_path, slug, factory)

    snap_pre = snapshot(src)
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    snap_pos = snapshot(src)

    assert exit_code == 0
    assert_unchanged(snap_pre, snap_pos)
    assert snap_pre["aggregate"] == snap_pos["aggregate"]


# ===========================================================================
# 5 fixtures adversariais Bloco 03 — INV-1 pre/pos identical apos F3
# ===========================================================================

# Subset que faz sentido para INV-1 (alguns mockam tampering em project_root, nao fonte).
# Bloco 04 adiciona 2 fixtures realistas (realistic_python_repo + realistic_node_repo)
# para validacao INV-1 + score >= 8 simultaneamente.
_ADVERSARIAL_INV1_FIXTURES = [
    "encoding_bomb",
    "binary_with_keys",
    "injection_in_readme",
    "cat_not_covered",
    "cleanup_falho",
    "realistic_python_repo",
    "realistic_node_repo",
]


@pytest.mark.parametrize("slug", _ADVERSARIAL_INV1_FIXTURES)
def test_inv1_snapshot_identical_after_f3_bloco_03_fixtures(
    slug: str, tmp_path: Path,
) -> None:
    """5 fixtures adversariais Bloco 03: hash-tree fonte INTOCADO apos F3."""
    factory = ADVERSARIAL_FACTORIES[slug]
    ctx, fw, src = _setup_with_factory(tmp_path, slug, factory)

    snap_pre = snapshot(src)
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    snap_pos = snapshot(src)

    assert exit_code == 0
    assert_unchanged(snap_pre, snap_pos)
    assert snap_pre["aggregate"] == snap_pos["aggregate"], f"{slug}: aggregate mismatch"


# ===========================================================================
# Agregate DoD: 10/10 fixtures verdes
# ===========================================================================

def test_inv1_dod_10_fixtures_all_unchanged(tmp_path: Path) -> None:
    """DoD Passo 03.16: 10+ fixtures hash-tree fonte identical pre/pos F3.

    Bloco 03 entregou 10 fixtures (5 Bloco 02 + 5 adversariais); Bloco 04
    expandiu para 12 (+2 realistas). Threshold inviolavel: 100% das fixtures."""
    all_factories = list(REPO_FACTORIES.items()) + [
        (slug, ADVERSARIAL_FACTORIES[slug]) for slug in _ADVERSARIAL_INV1_FIXTURES
    ]
    assert len(all_factories) >= 10, "DoD Passo 03.16 exige >= 10 fixtures"

    results: dict[str, bool] = {}
    for slug, factory in all_factories:
        sub_path = tmp_path / slug
        sub_path.mkdir()
        ctx, fw, src = _setup_with_factory(sub_path, slug, factory)

        snap_pre = snapshot(src)
        try:
            run_dry_run(ctx, fs_writer=fw)
            run_apply(ctx, fs_writer=fw)
        except Exception as exc:
            results[slug] = False
            pytest.fail(f"{slug} falhou apply: {exc!r}")
        snap_pos = snapshot(src)
        results[slug] = (snap_pre["aggregate"] == snap_pos["aggregate"])

    assert all(results.values()), f"INV-1 falhou em: {[k for k, v in results.items() if not v]}"
