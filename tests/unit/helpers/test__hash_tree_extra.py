"""test__hash_tree_extra.py — Bloco 02 02.6 full impl smoke (ADR-025 + RS-002/RS-016).

Cobertura adicional:
- diff_snapshots estrutura para audit-log
- aggregate determinismo cross-run
- exclude_links integra com _symlink_guard
- performance smoke (5 MB < 5s; full plan exige 100 MB < 30s; aqui menor por CI)
- chunk_size diferente nao muda hash
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from repo_sanitizer.helpers._hash_tree import (
    DEFAULT_CHUNK_SIZE,
    aggregate_hash,
    compute_file_sha256,
    compute_tree_hashes,
    diff_snapshots,
    snapshot,
)


def test_default_chunk_size_is_64kb() -> None:
    assert DEFAULT_CHUNK_SIZE == 65536


def test_chunk_size_does_not_affect_hash(tmp_path: Path) -> None:
    p = tmp_path / "data.bin"
    p.write_bytes(os.urandom(200_000))
    h1 = compute_file_sha256(p, chunk_size=4096)
    h2 = compute_file_sha256(p, chunk_size=65536)
    h3 = compute_file_sha256(p, chunk_size=128)
    assert h1 == h2 == h3


def test_aggregate_changes_when_file_added(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    snap1 = snapshot(tmp_path)
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    snap2 = snapshot(tmp_path)
    assert snap1["aggregate"] != snap2["aggregate"]
    assert snap2["file_count"] == snap1["file_count"] + 1


def test_diff_snapshots_added(tmp_path: Path) -> None:
    (tmp_path / "old.txt").write_text("ok", encoding="utf-8")
    pre = snapshot(tmp_path)
    (tmp_path / "new.txt").write_text("brand new", encoding="utf-8")
    pos = snapshot(tmp_path)
    diff = diff_snapshots(pre, pos)
    assert diff["added_count"] == 1
    assert "new.txt" in diff["added_paths"]
    assert diff["removed_count"] == 0
    assert diff["modified_count"] == 0


def test_diff_snapshots_modified(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("v1", encoding="utf-8")
    pre = snapshot(tmp_path)
    (tmp_path / "x.txt").write_text("v2-bigger-content", encoding="utf-8")
    pos = snapshot(tmp_path)
    diff = diff_snapshots(pre, pos)
    assert diff["modified_count"] == 1
    assert "x.txt" in diff["modified_paths"]


def test_diff_snapshots_removed(tmp_path: Path) -> None:
    p = tmp_path / "deleted.txt"
    p.write_text("temp", encoding="utf-8")
    pre = snapshot(tmp_path)
    p.unlink()
    pos = snapshot(tmp_path)
    diff = diff_snapshots(pre, pos)
    assert diff["removed_count"] == 1
    assert "deleted.txt" in diff["removed_paths"]


def test_diff_snapshots_caps_at_10(tmp_path: Path) -> None:
    """Cap defensivo: audit-log nao explode com >10 paths."""
    pre = snapshot(tmp_path)  # vazio
    for i in range(15):
        (tmp_path / f"f{i:02d}.txt").write_text(str(i), encoding="utf-8")
    pos = snapshot(tmp_path)
    diff = diff_snapshots(pre, pos)
    assert diff["added_count"] == 15
    assert len(diff["added_paths"]) == 10  # cap


def test_diff_snapshots_aggregate_prefix_present(tmp_path: Path) -> None:
    pre = snapshot(tmp_path)
    (tmp_path / "f.txt").write_text("ok", encoding="utf-8")
    pos = snapshot(tmp_path)
    diff = diff_snapshots(pre, pos)
    assert len(diff["pre_aggregate_prefix"]) == 16
    assert len(diff["pos_aggregate_prefix"]) == 16


def test_compute_tree_hashes_excludes_hardlink(tmp_path: Path) -> None:
    real = tmp_path / "real.txt"
    real.write_text("ok", encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        os.link(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink nao suportado")
    entries = compute_tree_hashes(tmp_path, exclude_links=True)
    paths = [e["path"] for e in entries]
    # Tanto real quanto link tem nlink>1, logo ambos sao excluidos
    assert "real.txt" not in paths
    assert "linked.txt" not in paths


def test_compute_tree_hashes_includes_hardlink_when_exclude_false(tmp_path: Path) -> None:
    real = tmp_path / "real.txt"
    real.write_text("ok", encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        os.link(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink nao suportado")
    entries = compute_tree_hashes(tmp_path, exclude_links=False)
    paths = [e["path"] for e in entries]
    assert "real.txt" in paths
    assert "linked.txt" in paths


def test_aggregate_hash_empty_entries() -> None:
    assert aggregate_hash([]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # SHA-256 do vazio


def test_compute_tree_hashes_deterministic_across_runs(tmp_path: Path) -> None:
    """Defesa: mesmo conteudo, mesmo aggregate (independe de mtime/atime)."""
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    h1 = aggregate_hash(compute_tree_hashes(tmp_path))
    h2 = aggregate_hash(compute_tree_hashes(tmp_path))
    assert h1 == h2


def test_perf_5mb_under_5s(tmp_path: Path) -> None:
    """Smoke perf reduzido (5 MB / 50 files); plano canonico exige 100 MB <30s."""
    for i in range(50):
        (tmp_path / f"chunk_{i:03d}.bin").write_bytes(os.urandom(100_000))  # 100 KB cada
    start = time.perf_counter()
    snap = snapshot(tmp_path)
    elapsed = time.perf_counter() - start
    assert snap["file_count"] == 50
    assert elapsed < 5.0, f"5 MB hash demorou {elapsed:.2f}s (limite 5s)"
