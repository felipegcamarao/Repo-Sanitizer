"""test__symlink_guard.py — stub Bloco 01 (full impl em Bloco 02)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from repo_sanitizer.helpers._symlink_guard import (
    is_hardlink_heuristic,
    is_junction,
    is_symlink,
    is_unsafe_link,
)


def test_regular_file_not_symlink(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("ok", encoding="utf-8")
    assert is_symlink(f) is False
    assert is_unsafe_link(f) is False


def test_regular_dir_not_junction(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir()
    assert is_junction(d) is False


@pytest.mark.skipif(sys.platform == "win32" and not os.environ.get("CI_SUPPORT_SYMLINKS"),
                    reason="symlink em Windows requer developer mode")
def test_symlink_detected(tmp_path: Path) -> None:
    f = tmp_path / "real.txt"
    f.write_text("ok", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        os.symlink(f, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink nao suportado.")
    assert is_symlink(link) is True
    assert is_unsafe_link(link) is True


def test_hardlink_heuristic_false_on_unique_file(tmp_path: Path) -> None:
    f = tmp_path / "unique.txt"
    f.write_text("x", encoding="utf-8")
    assert is_hardlink_heuristic(f) is False
