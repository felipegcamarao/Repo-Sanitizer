"""_versioning.py — auto-versionamento GIT_[NOME]-vN (ADR-008 + RS-021).

Bloco 02 02.10. Garante que destino nunca seja sobrescrito; em colisao,
incrementa sufixo `-v2`, `-v3`, etc.

API publica:
    next_versioned_dest(base_root: Path, slug: str) -> Path
    iter_existing_versions(base_root: Path, slug: str) -> list[Path]
    atomic_create_versioned_dest(base_root, slug, fs_writer) -> Path
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_sanitizer.helpers._fs_writer import FsWriter

GIT_PREFIX = "GIT_"
_VERSIONED_RE = re.compile(rf"^{re.escape(GIT_PREFIX)}(?P<slug>.+)-v(?P<n>\d+)$")
_NON_VERSIONED_RE = re.compile(rf"^{re.escape(GIT_PREFIX)}(?P<slug>.+)$")


def iter_existing_versions(base_root: Path, slug: str) -> list[Path]:
    """Lista pastas existentes que matcham `GIT_<slug>` ou `GIT_<slug>-vN`.

    Inclui base sem sufixo se existir. Ordenada por N crescente (base = N=1).
    """
    base_root = Path(base_root)
    if not base_root.exists():
        return []
    out: list[tuple[int, Path]] = []
    base_name = f"{GIT_PREFIX}{slug}"
    for child in base_root.iterdir():
        if not child.is_dir():
            continue
        name = child.name
        if name == base_name:
            out.append((1, child))
            continue
        m = _VERSIONED_RE.match(name)
        if m and m.group("slug") == slug:
            out.append((int(m.group("n")), child))
    out.sort(key=lambda t: t[0])
    return [p for _n, p in out]


def next_versioned_dest(base_root: Path, slug: str) -> Path:
    """Retorna proximo path disponivel: GIT_<slug> | GIT_<slug>-v2 | -v3 | ...

    Nao cria a pasta — apenas calcula o nome. Use `atomic_create_versioned_dest`
    para criar atomicamente.
    """
    base_root = Path(base_root)
    base_name = f"{GIT_PREFIX}{slug}"
    base_path = base_root / base_name
    if not base_path.exists():
        return base_path
    # Encontra proximo N
    existing = iter_existing_versions(base_root, slug)
    used_ns: set[int] = set()
    for p in existing:
        if p.name == base_name:
            used_ns.add(1)
        else:
            m = _VERSIONED_RE.match(p.name)
            if m:
                used_ns.add(int(m.group("n")))
    n = 2
    while n in used_ns:
        n += 1
    return base_root / f"{base_name}-v{n}"


def atomic_create_versioned_dest(
    base_root: Path,
    slug: str,
    fs_writer: FsWriter,
    max_retries: int = 5,
) -> Path:
    """Cria pasta destino atomicamente via mkdir(exist_ok=False).

    Retry-loop defensivo contra race condition (2 invocacoes concorrentes
    chegando no mesmo N): em FileExistsError, recalcula proximo N.

    Returns: path absoluto da pasta criada.
    """
    last_exc: Exception | None = None
    for _attempt in range(max_retries):
        candidate = next_versioned_dest(base_root, slug)
        try:
            return fs_writer.safe_mkdir(candidate, exist_ok=False, parents=True)
        except FileExistsError as exc:
            last_exc = exc
            continue
    raise RuntimeError(
        f"atomic_create_versioned_dest: nao conseguiu alocar pasta apos "
        f"{max_retries} tentativas para slug={slug!r}. Ultima: {last_exc}"
    )


__all__ = [
    "GIT_PREFIX",
    "atomic_create_versioned_dest",
    "iter_existing_versions",
    "next_versioned_dest",
]
