"""_symlink_guard.py — deteccao symlink/junction/hardlink (ADR-019 + RS-006).

Bloco 02 FULL impl. Cobre 5 tipos de link em Windows + POSIX:
1. POSIX symlink (`os.symlink` em Linux/macOS).
2. WSL symlink (POSIX symlink em montagem WSL — Path.is_symlink True).
3. Cygwin symlink (Win32 symlink ou system file marker).
4. Windows junction (`mklink /J` — Path.is_junction Python 3.12+).
5. Windows hardlink (`mklink /H` — st_nlink > 1; heuristica conservadora).

INVARIANTE: nenhum codigo de copia do agente segue symlinks
(`os.walk(followlinks=False)` + `shutil.copy*(follow_symlinks=False)` +
`shutil.copytree(symlinks=False)`). Funcao 1 EXCLUI + sinaliza.

API publica:
    is_symlink(p) -> bool                 # POSIX/WSL/Cygwin
    is_junction(p) -> bool                # Windows junction (3.12+ + fallback)
    is_hardlink_heuristic(p) -> bool      # st_nlink > 1
    is_unsafe_link(p) -> bool             # qualquer dos 3 acima
    classify_link(p) -> dict[str, bool|str]   # estrutura para FILTER_DIFF
    iter_unsafe_links(root) -> Iterator   # walk recursivo (followlinks=False)

Aceita FP raros (arquivos com hardlink intencional) per ADR-019/RS-006: melhor
EXCLUIR-e-sinalizar do que arriscar exfiltracao.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def is_symlink(p: Path) -> bool:
    """Symlink classico (POSIX + WSL + Cygwin). Path.is_symlink retorna True
    para Win32 symlinks tambem (em Python 3.8+).
    """
    try:
        return Path(p).is_symlink()
    except OSError:
        return False


def is_junction(p: Path) -> bool:
    """Windows junction (`mklink /J`). Python 3.12+: `Path.is_junction()`.

    Fallback pre-3.12: heuristica via `lstat().st_reparse_tag` (atributo
    presente apenas em Windows >= 3.12; em outras versoes/SO retorna False).
    """
    p = Path(p)
    # Python 3.12+: API canonica
    if sys.version_info >= (3, 12):
        try:
            return p.is_junction()  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            return False
    # Fallback pre-3.12 (improvavel — pyproject pin 3.11+, mas defensivo):
    try:
        st = p.lstat()
        if hasattr(st, "st_reparse_tag"):
            return bool(getattr(st, "st_reparse_tag", 0)) and p.is_dir()
    except OSError:
        return False
    return False


def is_hardlink_heuristic(p: Path) -> bool:
    """Heuristica conservadora: hardlink em Windows tem st_nlink > 1.

    Aceita FP (arquivos com multiplos hardlinks intencionais raros em projetos);
    INV-5 Modo Paranoico — preferimos sinalizar+excluir do que arriscar.
    Nunca acessa o link target.
    """
    try:
        st = Path(p).stat()
        return st.st_nlink > 1
    except OSError:
        return False


def is_unsafe_link(p: Path) -> bool:
    """True sse p e qualquer tipo de link suspeito (symlink/junction/hardlink)."""
    p = Path(p)
    return is_symlink(p) or is_junction(p) or is_hardlink_heuristic(p)


def classify_link(p: Path) -> dict[str, Any]:
    """Retorna dict estruturado para FILTER_DIFF (secao Symlinks excluidos).

    {is_link: bool, link_type: 'symlink'|'junction'|'hardlink'|'none', detail: str}
    """
    p = Path(p)
    if is_symlink(p):
        link_type = "symlink"
        try:
            target = os.readlink(p)
            detail = f"target={target}"
        except OSError:
            detail = "target=unreadable"
        return {"is_link": True, "link_type": link_type, "detail": detail}
    if is_junction(p):
        return {"is_link": True, "link_type": "junction", "detail": "windows-junction"}
    if is_hardlink_heuristic(p):
        try:
            nlink = p.stat().st_nlink
        except OSError:
            nlink = 0
        return {"is_link": True, "link_type": "hardlink", "detail": f"nlink={nlink}"}
    return {"is_link": False, "link_type": "none", "detail": ""}


def iter_unsafe_links(root: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Walk recursivo (followlinks=False) emitindo apenas paths classificados como unsafe.

    Yields:
        (path_relativo_a_root, classify_link_dict)
    """
    root = Path(root).resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Tambem checar diretorios (junctions sao dirs)
        for dname in list(dirnames):
            full = Path(dirpath) / dname
            info = classify_link(full)
            if info["is_link"]:
                yield full.relative_to(root), info
                # NAO descer dentro do link (defesa: dirnames.remove evitara walk)
                dirnames.remove(dname)
        for fname in filenames:
            full = Path(dirpath) / fname
            info = classify_link(full)
            if info["is_link"]:
                yield full.relative_to(root), info


__all__ = [
    "classify_link",
    "is_hardlink_heuristic",
    "is_junction",
    "is_symlink",
    "is_unsafe_link",
    "iter_unsafe_links",
]
