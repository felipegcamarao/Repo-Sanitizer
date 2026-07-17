"""test__hash_tree.py — SHA-256 hash-tree (ADR-025 + RS-002)."""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.helpers._hash_tree import (
    aggregate_hash,
    assert_unchanged,
    compute_file_sha256,
    compute_tree_hashes,
    snapshot,
)


def test_compute_file_sha256(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_bytes(b"hello\n")
    h = compute_file_sha256(f)
    assert len(h) == 64
    assert h == "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


def test_compute_tree_hashes_returns_sorted(tmp_path: Path) -> None:
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.txt").write_text("sx", encoding="utf-8")
    entries = compute_tree_hashes(tmp_path)
    paths = [e["path"] for e in entries]
    assert paths == sorted(paths)
    assert set(paths) == {"a.txt", "sub/x.txt", "z.txt"}


def test_aggregate_hash_deterministico(tmp_path: Path) -> None:
    (tmp_path / "a").write_text("a", encoding="utf-8")
    (tmp_path / "b").write_text("b", encoding="utf-8")
    entries = compute_tree_hashes(tmp_path)
    h1 = aggregate_hash(entries)
    h2 = aggregate_hash(entries)
    assert h1 == h2
    assert len(h1) == 64


def test_snapshot_full(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("ok", encoding="utf-8")
    snap = snapshot(tmp_path)
    assert snap["file_count"] == 1
    assert snap["aggregate"]
    assert snap["root"] == str(tmp_path.resolve())


def test_assert_unchanged_passes_when_identical(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("x", encoding="utf-8")
    pre = snapshot(tmp_path)
    pos = snapshot(tmp_path)
    assert_unchanged(pre, pos)


def test_assert_unchanged_fails_on_mutation(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("x", encoding="utf-8")
    pre = snapshot(tmp_path)
    (tmp_path / "f.txt").write_text("MUTATED", encoding="utf-8")
    pos = snapshot(tmp_path)
    with pytest.raises(AssertionError, match="INV-1 violation"):
        assert_unchanged(pre, pos)
