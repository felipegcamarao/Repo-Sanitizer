"""test__versioning.py — auto-versionamento GIT_[NOME]-vN (Bloco 02 02.10)."""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._versioning import (
    GIT_PREFIX,
    atomic_create_versioned_dest,
    iter_existing_versions,
    next_versioned_dest,
)


def _fw(tmp_path: Path, allow: Path) -> FsWriter:
    src = tmp_path / "fake-source"
    src.mkdir()
    return FsWriter(source_path=src, allowed_roots=[allow], override_forbidden=[])


def test_next_dest_when_no_prior_returns_base(tmp_path: Path) -> None:
    base_root = tmp_path / "Git Hub - [NOME]"
    base_root.mkdir()
    dest = next_versioned_dest(base_root, "meu-repo")
    assert dest.name == "GIT_meu-repo"


def test_next_dest_when_base_exists_returns_v2(tmp_path: Path) -> None:
    base_root = tmp_path / "Git Hub - [NOME]"
    base_root.mkdir()
    (base_root / "GIT_meu-repo").mkdir()
    dest = next_versioned_dest(base_root, "meu-repo")
    assert dest.name == "GIT_meu-repo-v2"


def test_next_dest_when_v2_exists_returns_v3(tmp_path: Path) -> None:
    base_root = tmp_path / "Git Hub - [NOME]"
    base_root.mkdir()
    (base_root / "GIT_meu-repo").mkdir()
    (base_root / "GIT_meu-repo-v2").mkdir()
    dest = next_versioned_dest(base_root, "meu-repo")
    assert dest.name == "GIT_meu-repo-v3"


def test_next_dest_skips_to_next_unused_n(tmp_path: Path) -> None:
    """Defesa: gaps na sequencia (v2 ausente, v3 presente) retornam v2 (menor disponivel)."""
    base_root = tmp_path / "Git Hub - [NOME]"
    base_root.mkdir()
    (base_root / "GIT_meu-repo").mkdir()
    (base_root / "GIT_meu-repo-v3").mkdir()
    dest = next_versioned_dest(base_root, "meu-repo")
    # Algoritmo procura o menor N nao usado >= 2; v2 esta livre
    assert dest.name == "GIT_meu-repo-v2"


def test_iter_existing_versions_counts_correctly(tmp_path: Path) -> None:
    base_root = tmp_path / "Git Hub - [NOME]"
    base_root.mkdir()
    (base_root / "GIT_meu-repo").mkdir()
    (base_root / "GIT_meu-repo-v2").mkdir()
    (base_root / "GIT_outro-repo").mkdir()
    versions = iter_existing_versions(base_root, "meu-repo")
    assert len(versions) == 2
    names = [v.name for v in versions]
    assert "GIT_meu-repo" in names
    assert "GIT_meu-repo-v2" in names


def test_iter_existing_versions_empty_when_root_missing(tmp_path: Path) -> None:
    versions = iter_existing_versions(tmp_path / "no-such", "x")
    assert versions == []


def test_iter_existing_versions_ignores_other_slugs(tmp_path: Path) -> None:
    base_root = tmp_path / "root"
    base_root.mkdir()
    (base_root / "GIT_meu-repo").mkdir()
    (base_root / "GIT_meu-repo-extra").mkdir()  # nao matcha pattern -vN
    versions = iter_existing_versions(base_root, "meu-repo")
    names = [v.name for v in versions]
    assert "GIT_meu-repo" in names
    # GIT_meu-repo-extra tambem matcha _NON_VERSIONED_RE? NAO porque comeca com -extra (o slug seria 'meu-repo-extra')
    # Vamos validar que slug puro 'meu-repo' nao puxa 'meu-repo-extra'
    assert "GIT_meu-repo-extra" not in names


def test_atomic_create_versioned_dest_creates_v1(tmp_path: Path) -> None:
    base_root = tmp_path / "root"
    base_root.mkdir()
    fw = _fw(tmp_path, allow=tmp_path)
    dest = atomic_create_versioned_dest(base_root, "rep1", fw)
    assert dest.exists()
    assert dest.name == "GIT_rep1"


def test_atomic_create_versioned_dest_creates_v2_then_v3(tmp_path: Path) -> None:
    base_root = tmp_path / "root"
    base_root.mkdir()
    fw = _fw(tmp_path, allow=tmp_path)
    d1 = atomic_create_versioned_dest(base_root, "x", fw)
    d2 = atomic_create_versioned_dest(base_root, "x", fw)
    d3 = atomic_create_versioned_dest(base_root, "x", fw)
    assert d1.name == "GIT_x"
    assert d2.name == "GIT_x-v2"
    assert d3.name == "GIT_x-v3"
    assert d1.exists() and d2.exists() and d3.exists()


def test_git_prefix_constant() -> None:
    assert GIT_PREFIX == "GIT_"


def test_atomic_create_blocks_outside_allowed(tmp_path: Path) -> None:
    """ADR-020: tentar criar pasta fora ALLOWED_ROOTS -> raise."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError

    fw = _fw(tmp_path, allow=tmp_path / "allowed-only")
    bad_root = tmp_path / "outside"
    bad_root.mkdir()
    with pytest.raises(FsWriteOutOfBoundsError):
        atomic_create_versioned_dest(bad_root, "x", fw)
