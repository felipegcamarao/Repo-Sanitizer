"""_hash_tree.py — SHA-256 hash-tree da arvore fonte (ADR-025 + RS-002/RS-016).

Bloco 02 FULL impl. Usado para:
1. Snapshot pre/pos do fonte (INV-1 gate — RS-002 reforcado 2x pelo [NOME]).
2. Registro em FILTER_DIFF secao oculta; verify pre-apply (race condition AT-02
   detection — RS-016).

Output canonico:
    {
      "root": "<absolute path>",
      "entries": [{"path": "rel/posix.ext", "sha256": "..."}, ...],  # ordenado lexico
      "aggregate": "...",  # SHA-256 da concatenacao das entries
      "file_count": int,
    }

INVARIANTE (defesa INV-1):
- Walk usa `os.walk(followlinks=False)` SEMPRE.
- Symlinks/junctions/hardlinks classificados via `_symlink_guard.is_unsafe_link`
  sao EXCLUIDOS do hash-tree (mesmo que F1 sinalize-os, eles nao alteram o
  estado do fonte; INV-1 cobre apenas conteudo legitimamente acessivel).
- Per-file SHA-256 chunked (65536 bytes) — performance smoke 100 MB < 30s.

API publica:
    compute_file_sha256(path, chunk_size=65536) -> str
    compute_tree_hashes(root, exclude_links=True) -> list[dict]
    aggregate_hash(entries) -> str
    snapshot(root) -> dict          # canonico para gate INV-1
    assert_unchanged(pre, pos)      # raise AssertionError em INV-1 violation
    diff_snapshots(pre, pos) -> dict # estrutura para audit_log inv1_violation detail
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from repo_sanitizer.helpers._symlink_guard import is_unsafe_link

DEFAULT_CHUNK_SIZE = 65536  # 64 KB (perf SHA-256 sweetspot Windows NTFS)


def compute_file_sha256(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """SHA-256 hex de arquivo (chunked para suportar arquivos grandes)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_tree_hashes(
    root: Path,
    exclude_links: bool = True,
) -> list[dict[str, str]]:
    """Walk recursivo (followlinks=False); retorna lista ordenada {path, sha256}.

    Args:
        root: pasta-raiz.
        exclude_links: se True (default), EXCLUI qualquer arquivo classificado
            como link suspeito (ADR-019 + RS-006).

    Returns:
        Lista ordenada lexico por path POSIX (cross-platform deterministica).
    """
    root = Path(root).resolve()
    entries: list[dict[str, str]] = []
    for dirpath, dirnames, files in os.walk(root, followlinks=False):
        # Defesa: nao descer em junction/symlink dirs (consistente com _symlink_guard.iter_unsafe_links).
        if exclude_links:
            for d in list(dirnames):
                full_d = Path(dirpath) / d
                if is_unsafe_link(full_d):
                    dirnames.remove(d)
        for fname in sorted(files):
            full = Path(dirpath) / fname
            if exclude_links and is_unsafe_link(full):
                continue
            try:
                rel = full.relative_to(root).as_posix()
                entries.append({"path": rel, "sha256": compute_file_sha256(full)})
            except (OSError, ValueError):
                # Arquivo inacessivel (permissao); pula sem falhar
                continue
    entries.sort(key=lambda e: e["path"])
    return entries


def aggregate_hash(entries: list[dict[str, str]]) -> str:
    """SHA-256 do `path\\tsha256\\n` concatenado (ordenado lexico)."""
    h = hashlib.sha256()
    for e in entries:
        h.update(e["path"].encode("utf-8"))
        h.update(b"\t")
        h.update(e["sha256"].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def snapshot(root: Path) -> dict[str, Any]:
    """Snapshot canonico: {root, entries, aggregate, file_count}.

    Usado em pares (pre, pos) para gate INV-1.
    """
    entries = compute_tree_hashes(root, exclude_links=True)
    return {
        "root": str(Path(root).resolve()),
        "entries": entries,
        "aggregate": aggregate_hash(entries),
        "file_count": len(entries),
    }


def assert_unchanged(pre: dict[str, Any], pos: dict[str, Any]) -> None:
    """RS-002 enforce: pre/pos do fonte devem ter aggregate identico.

    Raises:
        AssertionError: se hash-tree pre != pos (INV-1 violation).
    """
    if pre["aggregate"] != pos["aggregate"]:
        raise AssertionError(
            f"INV-1 violation: hash-tree mudou pre={pre['aggregate'][:16]}... "
            f"pos={pos['aggregate'][:16]}... ({pre['file_count']} files pre vs "
            f"{pos['file_count']} files pos)"
        )


def diff_snapshots(pre: dict[str, Any], pos: dict[str, Any]) -> dict[str, Any]:
    """Estrutura compacta de diff para audit_log inv1_violation detail.

    Retorna apenas paths (sem hashes literais > 16 chars; defesa em camadas
    contra leak via audit-log; ADR-024).
    """
    pre_map = {e["path"]: e["sha256"] for e in pre["entries"]}
    pos_map = {e["path"]: e["sha256"] for e in pos["entries"]}
    pre_keys = set(pre_map.keys())
    pos_keys = set(pos_map.keys())

    added = sorted(pos_keys - pre_keys)
    removed = sorted(pre_keys - pos_keys)
    modified = sorted(p for p in (pre_keys & pos_keys) if pre_map[p] != pos_map[p])

    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "modified_count": len(modified),
        "added_paths": added[:10],  # cap 10 para audit-log nao explodir
        "removed_paths": removed[:10],
        "modified_paths": modified[:10],
        "pre_aggregate_prefix": pre["aggregate"][:16],
        "pos_aggregate_prefix": pos["aggregate"][:16],
    }


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "aggregate_hash",
    "assert_unchanged",
    "compute_file_sha256",
    "compute_tree_hashes",
    "diff_snapshots",
    "snapshot",
]
