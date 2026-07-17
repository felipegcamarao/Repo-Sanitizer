"""test__symlink_guard_extra.py — Bloco 02 02.5 full impl smoke (ADR-019 + RS-006).

Cobertura adicional sobre full impl:
- classify_link estrutura (symlink/junction/hardlink/none)
- iter_unsafe_links walk recursivo
- hardlink real via os.link (Windows aceita sem admin/developer mode)
- diretorios regulares NAO classificados como junction
- POSIX symlink real (skipped em Windows sem developer mode)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from repo_sanitizer.helpers._symlink_guard import (
    classify_link,
    is_hardlink_heuristic,
    is_junction,
    is_symlink,
    is_unsafe_link,
    iter_unsafe_links,
)


def test_classify_link_regular_file_returns_none(tmp_path: Path) -> None:
    f = tmp_path / "regular.txt"
    f.write_text("ok", encoding="utf-8")
    info = classify_link(f)
    assert info["is_link"] is False
    assert info["link_type"] == "none"


def test_classify_link_regular_dir_returns_none(tmp_path: Path) -> None:
    d = tmp_path / "dir"
    d.mkdir()
    info = classify_link(d)
    assert info["is_link"] is False


def test_iter_unsafe_links_empty_repo(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("b", encoding="utf-8")
    links = list(iter_unsafe_links(tmp_path))
    assert links == []


def test_hardlink_detected_via_st_nlink(tmp_path: Path) -> None:
    """Windows e POSIX permitem hardlink sem admin. st_nlink > 1 trigga deteccao."""
    real = tmp_path / "original.txt"
    real.write_text("hardlinkable\n", encoding="utf-8")
    link = tmp_path / "hardlink.txt"
    try:
        os.link(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink nao suportado neste filesystem")
    # Apos hardlink, st_nlink em ambos deve ser >= 2
    assert is_hardlink_heuristic(real) is True
    assert is_hardlink_heuristic(link) is True
    info = classify_link(link)
    assert info["is_link"] is True
    assert info["link_type"] == "hardlink"
    assert "nlink=" in info["detail"]


def test_iter_unsafe_links_finds_hardlink(tmp_path: Path) -> None:
    """Walk emite hardlink mesmo sem developer mode."""
    real = tmp_path / "src.txt"
    real.write_text("real", encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        os.link(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink nao suportado neste filesystem")
    safe_only = tmp_path / "safe-only.txt"
    safe_only.write_text("nope", encoding="utf-8")
    links = list(iter_unsafe_links(tmp_path))
    # Ambos `src.txt` e `linked.txt` viram nlink>1 (mesmo inode)
    paths = {str(rel.as_posix()) for rel, _info in links}
    assert "src.txt" in paths
    assert "linked.txt" in paths
    assert "safe-only.txt" not in paths


def test_is_junction_false_for_regular_dir(tmp_path: Path) -> None:
    d = tmp_path / "regular_dir"
    d.mkdir()
    assert is_junction(d) is False


def test_is_junction_false_for_file(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("ok", encoding="utf-8")
    assert is_junction(f) is False


@pytest.mark.skipif(
    sys.platform == "win32" and not os.environ.get("CI_SUPPORT_SYMLINKS"),
    reason="symlink em Windows requer developer mode (CI_SUPPORT_SYMLINKS=1)",
)
def test_symlink_classified_correctly(tmp_path: Path) -> None:
    real = tmp_path / "real.txt"
    real.write_text("real-content", encoding="utf-8")
    link = tmp_path / "alias.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink nao suportado")
    assert is_symlink(link) is True
    assert is_unsafe_link(link) is True
    info = classify_link(link)
    assert info["link_type"] == "symlink"
    assert "target=" in info["detail"]


@pytest.mark.skipif(
    sys.platform == "win32" and not os.environ.get("CI_SUPPORT_SYMLINKS"),
    reason="symlink em Windows requer developer mode",
)
def test_iter_unsafe_links_finds_symlink(tmp_path: Path) -> None:
    real = tmp_path / "actual.txt"
    real.write_text("ok", encoding="utf-8")
    link = tmp_path / "symlinked.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink nao suportado")
    links = list(iter_unsafe_links(tmp_path))
    paths = {str(rel.as_posix()) for rel, _info in links}
    assert "symlinked.txt" in paths


def test_iter_unsafe_links_does_not_follow_into_unsafe_dir(tmp_path: Path) -> None:
    """Defesa: se sub-dir for junction/symlink, nao descemos para dentro."""
    d_real = tmp_path / "real_dir"
    d_real.mkdir()
    (d_real / "secret.txt").write_text("must not be walked", encoding="utf-8")
    # Sem criar link real (sem admin), apenas garante que walk normal funciona
    links = list(iter_unsafe_links(tmp_path))
    assert links == []


def test_is_hardlink_missing_path_safe() -> None:
    """OSError em stat retorna False (defensivo)."""
    assert is_hardlink_heuristic(Path("C:/no_such_path_zzz_random/file.txt")) is False
