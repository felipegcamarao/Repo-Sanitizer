"""_git_history_scan.py — Gate BLOQUEANTE de historico Git no destino.

v1.2.0 / MV-02 / RS-NEW-038 / ADR-035 / mitigacao §5-5 (#02 threat model).

Re-escaneia a arvore do DESTINO sanitizado e detecta QUALQUER artefato de
historico Git, por **NOME E CONTEUDO**:

- por NOME: diretorio `.git/` (e aninhado/submodule), arquivo `.git` (gitdir
  pointer), `packed-refs`, `ORIG_HEAD`, `FETCH_HEAD`, `*.bundle`, `*.orig`,
  `*.rej`, `*.patch`, `*.diff`, `.gitmodules`;
- por CONTEUDO: arquivo `.git` cujo 1o conteudo comeca com `gitdir:`
  (worktree/submodule pointer); `.gitattributes` com filtros `filter=` /
  `clean` / `smudge` (vetor de exfiltracao via filtros git).

A allowlist (`.gitignore`, `.gitkeep`, `.gitattributes` SEM filtros,
`.editorconfig`) e HARDCODED neste modulo — NUNCA lida do repo-fonte
(RS-NEW-035 anti-bypass).

`scan_git_history_artifacts(dest_path)` retorna `list[GitArtifact]`. Caller
(`f3_sanitizer.run_f3`) levanta `GitHistoryInDestination` se a lista for
nao-vazia e `raise_on_leak=True`, mapeado para **exit code 8** na CLI.

INV-1: este modulo so LE o destino (read-only); nenhuma escrita.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Constantes HARDCODED (RS-NEW-035 — nunca lidas do source)
# ---------------------------------------------------------------------------

# Basenames de artefatos de historico Git (deteccao por NOME).
_GIT_HISTORY_BASENAMES: frozenset[str] = frozenset({
    "packed-refs",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "MERGE_HEAD",
    "HEAD",  # ref file (so dentro de arvore git; checado com contexto abaixo)
    ".gitmodules",
})

# Extensoes de artefatos de historico/patch (deteccao por NOME).
_GIT_HISTORY_SUFFIXES: tuple[str, ...] = (
    ".bundle", ".orig", ".rej", ".patch", ".diff",
)

# Allowlist HARDCODED — arquivos `.git*` LEGITIMOS que NAO sao historico.
# `.gitattributes` so e legitimo quando NAO contem filtros (checado por conteudo).
_GIT_ALLOWLIST_BASENAMES: frozenset[str] = frozenset({
    ".gitignore",
    ".gitkeep",
    ".editorconfig",
})

# `.gitattributes` com filtros = vetor de exfiltracao (clean/smudge/filter).
_GITATTR_FILTER_RE = re.compile(r"(^|\s)(filter=|filter\s|clean\s*=|smudge\s*=)", re.IGNORECASE)

# Conteudo: arquivo `.git` (nao-dir) que e um gitdir pointer.
_GITDIR_POINTER_PREFIX = "gitdir:"

# Quantos bytes ler para checagem de conteudo (defensivo anti-OOM).
_CONTENT_SNIFF_BYTES = 4096


@dataclass(frozen=True)
class GitArtifact:
    """Um artefato de historico Git encontrado no destino.

    `rel_path` e POSIX relativo ao dest_path (NUNCA absoluto — zero-leak).
    `kind` e o motivo canonico (nome curto, sem conteudo literal).
    """

    rel_path: str
    kind: str


def _is_git_dir_name(name: str) -> bool:
    """True sse `name` e exatamente `.git` (diretorio de historico)."""
    return name == ".git"


def _read_sniff(path: Path) -> str:
    """Le ate `_CONTENT_SNIFF_BYTES` do arquivo como texto best-effort.

    Retorna "" em qualquer erro de IO (degrade gracioso, nunca raise).
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_CONTENT_SNIFF_BYTES)
    except OSError:
        return ""
    return raw.decode("utf-8", errors="replace")


def _classify_basename(
    basename: str, full_path: Path,
) -> str | None:
    """Classifica um basename de ARQUIVO. Retorna `kind` ou None se benigno.

    Deteccao por nome (+ conteudo para `.git` pointer e `.gitattributes`).
    """
    lower = basename.lower()

    # 1) `.git` como ARQUIVO (gitdir pointer de submodule/worktree) — conteudo.
    if basename == ".git":
        head = _read_sniff(full_path).lstrip()
        if head.startswith(_GITDIR_POINTER_PREFIX):
            return "git_dir_pointer"  # `.git` file -> gitdir: ...
        return "git_file"  # `.git` arquivo (anomalo) — bloqueia por seguranca

    # 2) Allowlist HARDCODED (.gitignore/.gitkeep/.editorconfig) — benigno.
    if lower in _GIT_ALLOWLIST_BASENAMES:
        return None

    # 3) `.gitattributes` — legitimo SO sem filtros (clean/smudge/filter).
    if lower == ".gitattributes":
        content = _read_sniff(full_path)
        if _GITATTR_FILTER_RE.search(content):
            return "gitattributes_filter"
        return None  # `.gitattributes` benigno

    # 4) Basenames de historico (packed-refs/ORIG_HEAD/.gitmodules/...).
    if basename in _GIT_HISTORY_BASENAMES:
        return f"git_history:{basename}"

    # 5) Sufixos de patch/bundle.
    for suf in _GIT_HISTORY_SUFFIXES:
        if lower.endswith(suf):
            return f"git_artifact:{suf}"

    return None


def scan_git_history_artifacts(dest_path: Path) -> list[GitArtifact]:
    """Re-escaneia `dest_path` por artefatos de historico Git (nome+conteudo).

    Read-only. Retorna lista (possivelmente vazia) de `GitArtifact` com
    `rel_path` POSIX relativo ao destino. Caller decide raise/log.

    Detecta:
        - diretorio `.git/` (incl. aninhado/submodule);
        - arquivo `.git` (gitdir pointer ou anomalo);
        - `packed-refs`/`ORIG_HEAD`/`FETCH_HEAD`/`MERGE_HEAD`/`HEAD`/`.gitmodules`;
        - `*.bundle`/`*.orig`/`*.rej`/`*.patch`/`*.diff`;
        - `.gitattributes` com filtros `clean/smudge/filter=`.
    """
    out: list[GitArtifact] = []
    if not dest_path.exists():
        return out

    for dirpath, dirnames, filenames in os.walk(dest_path, followlinks=False):
        # Diretorios `.git` (incl. aninhados) — bloqueia e NAO desce dentro.
        for d in list(dirnames):
            if _is_git_dir_name(d):
                full_d = Path(dirpath) / d
                try:
                    rel = full_d.relative_to(dest_path).as_posix()
                except ValueError:
                    rel = d
                out.append(GitArtifact(rel_path=rel + "/", kind="git_dir"))
                dirnames.remove(d)  # nao desce na arvore de historico

        for fname in filenames:
            full = Path(dirpath) / fname
            kind = _classify_basename(fname, full)
            if kind is None:
                continue
            try:
                rel = full.relative_to(dest_path).as_posix()
            except ValueError:
                rel = fname
            out.append(GitArtifact(rel_path=rel, kind=kind))

    # Ordem deterministica (lexico por rel_path) — report estavel.
    out.sort(key=lambda a: a.rel_path)
    return out


__all__ = [
    "GitArtifact",
    "scan_git_history_artifacts",
]
