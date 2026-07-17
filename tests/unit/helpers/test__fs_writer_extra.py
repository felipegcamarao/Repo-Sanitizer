"""test__fs_writer_extra.py — cobertura edge cases _fs_writer (assert_allowed paths).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import (
    DEFAULT_ALLOWED_ROOTS,
    DEFAULT_FORBIDDEN_PATHS,
    FsWriter,
    _has_windows_reserved_segment,
    _is_ancestor,
)


def test_default_constants_exist() -> None:
    assert len(DEFAULT_ALLOWED_ROOTS) >= 1
    assert len(DEFAULT_FORBIDDEN_PATHS) >= 3


def test_is_ancestor_helper() -> None:
    p = Path("/a/b").resolve()
    c = Path("/a/b/c").resolve()
    assert _is_ancestor(p, c) is True
    assert _is_ancestor(c, p) is False


def test_windows_reserved_segment_drives_ok() -> None:
    """Drive segments (C:\\) nao devem disparar reserved-name false positive."""
    from pathlib import PureWindowsPath
    assert _has_windows_reserved_segment(PureWindowsPath("C:/Users/safe/file.txt")) is False
    assert _has_windows_reserved_segment(PureWindowsPath("/COM1/x")) is True
    assert _has_windows_reserved_segment(PureWindowsPath("/CON.txt")) is True
    # com sufixo .txt — heuristica match COM1.txt
    assert _has_windows_reserved_segment(PureWindowsPath("/safe/COM1.txt")) is True


def test_safe_write_text_creates_parent_dirs(tmp_path: Path) -> None:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    deep = allowed / "level1" / "level2" / "level3" / "f.txt"
    fw.safe_write_text(deep, "hi")
    assert deep.exists()


def test_safe_copy_succeeds(tmp_path: Path) -> None:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    src = tmp_path / "src.txt"
    src.write_text("content", encoding="utf-8")
    dest = allowed / "copy.txt"
    fw.safe_copy(src, dest)
    assert dest.read_text(encoding="utf-8") == "content"


def test_safe_copy_missing_src_raises(tmp_path: Path) -> None:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    with pytest.raises(FileNotFoundError):
        fw.safe_copy(tmp_path / "no_such.txt", allowed / "x.txt")


def test_safe_move_succeeds(tmp_path: Path) -> None:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    src = tmp_path / "src.txt"
    src.write_text("c", encoding="utf-8")
    dest = allowed / "moved.txt"
    fw.safe_move(src, dest)
    assert dest.exists()
    assert not src.exists()


def test_safe_move_missing_src_raises(tmp_path: Path) -> None:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    with pytest.raises(FileNotFoundError):
        fw.safe_move(tmp_path / "no_such.txt", allowed / "x.txt")


def test_safe_write_bytes_replace_existing(tmp_path: Path) -> None:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    dest = allowed / "f.txt"
    fw.safe_write_bytes(dest, b"v1")
    fw.safe_write_bytes(dest, b"v2")
    assert dest.read_bytes() == b"v2"
