"""_fs_writer.py — SSOT de escrita no filesystem (ADR-020 + RS-002/RS-007/RS-010).

INV-1 reforcado 2x pelo [NOME]: TODO modulo do agente que escreve filesystem
DEVE passar por este helper. Modulos f1/f2/f3/f4 nao podem chamar
`Path.write_*`, `shutil.copy*`, `shutil.move`, `os.replace` diretamente.

Camadas defensivas:
1. ALLOWED_ROOTS whitelist (deve ser ancestor do destino resolvido).
2. FORBIDDEN_PATHS blacklist (nunca ancestor do destino).
3. source_path runtime ALWAYS adicionado a FORBIDDEN_PATHS (enforce INV-1).
4. Path.resolve(strict=False) ANTES de comparar (nunca str.startswith).
5. Rejeita symlink que aponta para FORBIDDEN.
6. Windows reserved names (NUL, CON, AUX, COM1..9, LPT1..9, PRN) rejeitados.
7. `..` traversal rejeitado via resolve canonical.
8. Atomic write via tempfile + os.replace para safe_write_bytes/text.

API publica:
    FsWriter(source_path, allowed_roots=None, extra_forbidden=None)
    fw.safe_write_bytes(dest, content)
    fw.safe_write_text(dest, content, encoding="utf-8")
    fw.safe_copy(src, dest)
    fw.safe_move(src, dest)
    fw.safe_mkdir(dest, exist_ok=False)
    fw.assert_allowed(dest)  # raise FsWriteOutOfBoundsError em violacao

Exit code recomendado em caller: 5 (FsWriteOutOfBoundsError; ver cli.py).
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path, PurePath

# Default canonico (Windows [NOME]):
DEFAULT_ALLOWED_ROOTS: tuple[Path, ...] = (
    Path("C:/VS Code/Git Hub - [NOME]").resolve(),
)

# Auditoria 2026-07: paths sensiveis derivados do AMBIENTE (Path.home() +
# env-vars de sistema) em vez de hardcode do username do operador — remove
# PII do codigo-fonte e torna a protecao portavel para qualquer maquina.
def _default_forbidden_paths() -> tuple[Path, ...]:
    home = Path.home()
    out: list[Path] = [
        Path("C:/VS Code/.env"),
        home / ".ssh",
        home / ".gnupg",
        home / "AppData",
    ]
    for env_var, fallback in (
        ("SystemRoot", "C:/Windows"),
        ("ProgramFiles", "C:/Program Files"),
        ("ProgramFiles(x86)", "C:/Program Files (x86)"),
    ):
        out.append(Path(os.environ.get(env_var) or fallback))
    return tuple(out)


DEFAULT_FORBIDDEN_PATHS: tuple[Path, ...] = _default_forbidden_paths()

# Windows reserved device names (case-insensitive; check stem only)
WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})

_WINDOWS_RESERVED_RE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$",
    re.IGNORECASE,
)


class FsWriteOutOfBoundsError(PermissionError):
    """Tentativa de escrita fora de ALLOWED_ROOTS ou em FORBIDDEN_PATH.

    Caller deve mapear para exit code 5 + audit-log entry `fs_write_blocked`.
    """


def _is_ancestor(parent: Path, child: Path) -> bool:
    """True sse `parent` e ancestor (ou igual) a `child`. Ambos ja resolvidos."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_safe(p: Path) -> Path:
    """Resolve canonico sem exigir existencia (Path.resolve(strict=False))."""
    return Path(p).resolve(strict=False)


def _has_windows_reserved_segment(p: PurePath) -> bool:
    """True sse algum segmento e nome reservado Windows (NUL/CON/COM1...)."""
    for part in p.parts:
        # ignore drive segments like "C:\\"
        if len(part) >= 2 and part[1] == ":":
            continue
        if part in {"/", "\\"}:
            continue
        if _WINDOWS_RESERVED_RE.match(part):
            return True
    return False


def _is_symlink_target_forbidden(p: Path, forbidden: Iterable[Path]) -> bool:
    """Se `p` for symlink, verifica se o target aponta para um forbidden."""
    if not p.exists() and not p.is_symlink():
        return False
    if not p.is_symlink():
        return False
    try:
        target = p.resolve(strict=False)
    except (OSError, RuntimeError):
        # symlink quebrado / loop -> trata como suspeito
        return True
    return any(_is_ancestor(_resolve_safe(f), target) for f in forbidden)


class FsWriter:
    """SSOT de escrita filesystem (ADR-020).

    Args:
        source_path: caminho do repo-fonte do run; SEMPRE adicionado a
            FORBIDDEN_PATHS para enforce INV-1 (read-only fonte).
        allowed_roots: override do default `DEFAULT_ALLOWED_ROOTS` (tests).
        extra_forbidden: paths extras a banir (tests / configs adicionais).

    Exemplo:
        fw = FsWriter(source_path=Path("C:/VS Code/meu-repo"))
        fw.safe_write_text(
            Path("C:/VS Code/Git Hub - [NOME]/GIT_meu-repo/README.md"),
            "# olar\\n",
        )
    """

    def __init__(
        self,
        source_path: Path,
        allowed_roots: Iterable[Path] | None = None,
        extra_forbidden: Iterable[Path] | None = None,
        override_forbidden: Iterable[Path] | None = None,
    ) -> None:
        roots = tuple(allowed_roots) if allowed_roots is not None else DEFAULT_ALLOWED_ROOTS
        self.allowed_roots: tuple[Path, ...] = tuple(_resolve_safe(r) for r in roots)

        if override_forbidden is not None:
            # tests podem precisar substituir defaults (ex: AppData inclui pytest tmp_path)
            forbidden = list(override_forbidden)
        else:
            forbidden = list(DEFAULT_FORBIDDEN_PATHS)
            if extra_forbidden is not None:
                forbidden.extend(extra_forbidden)
        # source_path SEMPRE adicionado (INV-1 reforcado 2x) — independente do override
        forbidden.append(source_path)
        self.forbidden_paths: tuple[Path, ...] = tuple(_resolve_safe(p) for p in forbidden)

        # opcional: pode armazenar para introspecao
        self.source_path: Path = _resolve_safe(source_path)

    # ----------------------------- guards -----------------------------

    def assert_allowed(self, dest: Path) -> Path:
        """Valida que `dest` pode receber escrita. Retorna o path resolvido.

        Raises:
            FsWriteOutOfBoundsError: violacao de uma das 7 camadas.
        """
        # Camada 6: Windows reserved name in any segment
        if _has_windows_reserved_segment(PurePath(dest)):
            raise FsWriteOutOfBoundsError(
                f"Nome reservado Windows em segmento do path: {dest}"
            )

        resolved = _resolve_safe(dest)

        # Camada 5: symlink existente do dest aponta para forbidden
        if _is_symlink_target_forbidden(Path(dest), self.forbidden_paths):
            raise FsWriteOutOfBoundsError(
                f"Symlink dest aponta para path proibido: {dest}"
            )

        # Camada 1: precisa estar dentro de algum ALLOWED_ROOT
        if not any(_is_ancestor(r, resolved) for r in self.allowed_roots):
            raise FsWriteOutOfBoundsError(
                f"Fora de ALLOWED_ROOTS: {resolved} (allowed={[str(r) for r in self.allowed_roots]})"
            )

        # Camada 2 + 3: nao pode estar dentro de FORBIDDEN_PATHS (inclui source_path runtime)
        for forbidden in self.forbidden_paths:
            if _is_ancestor(forbidden, resolved):
                raise FsWriteOutOfBoundsError(
                    f"Path proibido (sensivel ou INV-1): {resolved} dentro de {forbidden}"
                )

        return resolved

    # --------------------------- write APIs ---------------------------

    def safe_mkdir(self, dest: Path, exist_ok: bool = False, parents: bool = True) -> Path:
        """mkdir defensivo (ADR-008 + ADR-020). exist_ok=False mitiga RS-021."""
        resolved = self.assert_allowed(dest)
        resolved.mkdir(parents=parents, exist_ok=exist_ok)
        return resolved

    def safe_write_bytes(self, dest: Path, content: bytes) -> Path:
        """Escrita atomica (tempfile + os.replace) com gate de boundary."""
        resolved = self.assert_allowed(dest)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        # tempfile no MESMO diretorio = atomic rename garantido em Windows NTFS
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, dir=resolved.parent, prefix=".tmp_", suffix=".rsa"
        ) as tf:
            tf.write(content)
            tmp_path = Path(tf.name)
        try:
            os.replace(tmp_path, resolved)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        return resolved

    def safe_write_text(
        self,
        dest: Path,
        content: str,
        encoding: str = "utf-8",
        newline: str | None = "\n",
    ) -> Path:
        """Wrapper text de safe_write_bytes (newline default '\\n' anti-CRLF)."""
        if newline is not None and newline != "\n":
            content = content.replace("\n", newline)
        return self.safe_write_bytes(dest, content.encode(encoding))

    def safe_append_text(
        self,
        dest: Path,
        content: str,
        encoding: str = "utf-8",
    ) -> Path:
        """Append text com gate de boundary (usado por audit-log JSONL)."""
        resolved = self.assert_allowed(dest)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved, "ab") as fh:
            fh.write(content.encode(encoding))
        return resolved

    def safe_copy(self, src: Path, dest: Path) -> Path:
        """Copy file (src -> dest) com gate. NUNCA segue symlink."""
        resolved = self.assert_allowed(dest)
        src_resolved = _resolve_safe(src)
        if Path(src).is_symlink():
            raise FsWriteOutOfBoundsError(
                f"Recusa a copiar symlink (RS-006 + ADR-019): {src}"
            )
        if not src_resolved.exists():
            raise FileNotFoundError(f"safe_copy: src ausente: {src_resolved}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_resolved, resolved, follow_symlinks=False)
        return resolved

    def safe_move(self, src: Path, dest: Path) -> Path:
        """Move file (src -> dest) com gate. Atomic onde possivel (mesmo volume)."""
        resolved = self.assert_allowed(dest)
        # source tambem nao pode estar em FORBIDDEN (inclui INV-1 source_path)
        src_resolved = _resolve_safe(src)
        for forbidden in self.forbidden_paths:
            if _is_ancestor(forbidden, src_resolved):
                raise FsWriteOutOfBoundsError(
                    f"Tentativa de mover FROM path proibido (INV-1 ou sensivel): "
                    f"{src_resolved} dentro de {forbidden}"
                )
        if Path(src).is_symlink():
            raise FsWriteOutOfBoundsError(
                f"Recusa a mover symlink (RS-006 + ADR-019): {src}"
            )
        if not src_resolved.exists():
            raise FileNotFoundError(f"safe_move: src ausente: {src_resolved}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src_resolved), str(resolved))
        return resolved


__all__ = [
    "DEFAULT_ALLOWED_ROOTS",
    "DEFAULT_FORBIDDEN_PATHS",
    "WINDOWS_RESERVED_NAMES",
    "FsWriteOutOfBoundsError",
    "FsWriter",
]
