"""Fixtures factory functions para 5 repos canonicos do Bloco 02 INV-1 smoke."""
from __future__ import annotations

import contextlib
import os
from collections.abc import Callable
from pathlib import Path

REPO_NAMES = [
    "python_simple",
    "node_monorepo",
    "docs_only",
    "symlink_adversarial",
    "pii_in_paths",
]


def build_python_simple(root: Path) -> Path:
    """Repo Python tipico: src/, tests/, README, pyproject.toml + lixo (.git, __pycache__)."""
    repo = root / "python_simple"
    repo.mkdir()
    (repo / "README.md").write_text("# python-simple\n\nProjeto exemplo.\n", encoding="utf-8")
    (repo / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "python-simple"\nversion = "0.1.0"\n', encoding="utf-8",
    )
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\ndist/\n", encoding="utf-8")

    src = repo / "src" / "python_simple"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "main.py").write_text("def main():\n    print('hello')\n", encoding="utf-8")

    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_main.py").write_text(
        "from python_simple.main import main\n\ndef test_main():\n    main()\n",
        encoding="utf-8",
    )

    # Lixo determinstico (Grupo A)
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    pycache = src / "__pycache__"
    pycache.mkdir()
    (pycache / "main.cpython-311.pyc").write_bytes(b"\x00fake-pyc-content\x00")
    (repo / "debug.log").write_text("LOG\n", encoding="utf-8")

    return repo


def build_node_monorepo(root: Path) -> Path:
    """Repo Node.js monorepo: packages/, root package.json + node_modules (lixo)."""
    repo = root / "node_monorepo"
    repo.mkdir()
    (repo / "README.md").write_text("# node-monorepo\n", encoding="utf-8")
    (repo / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (repo / "package.json").write_text(
        '{"name": "monorepo", "private": true, "workspaces": ["packages/*"]}\n',
        encoding="utf-8",
    )
    (repo / "pnpm-workspace.yaml").write_text("packages:\n  - 'packages/*'\n", encoding="utf-8")
    (repo / ".gitignore").write_text("node_modules\ndist\n.next\n", encoding="utf-8")

    pkg_a = repo / "packages" / "ui"
    pkg_a.mkdir(parents=True)
    (pkg_a / "package.json").write_text('{"name": "@scope/ui"}\n', encoding="utf-8")
    (pkg_a / "index.ts").write_text("export const X = 1;\n", encoding="utf-8")

    pkg_b = repo / "packages" / "core"
    pkg_b.mkdir(parents=True)
    (pkg_b / "package.json").write_text('{"name": "@scope/core"}\n', encoding="utf-8")
    (pkg_b / "main.ts").write_text("export {};\n", encoding="utf-8")

    # Lixo (Grupo A)
    nm = repo / "node_modules"
    nm.mkdir()
    (nm / "lodash").mkdir()
    (nm / "lodash" / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
    dist = repo / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text("// build output\n", encoding="utf-8")

    return repo


def build_docs_only(root: Path) -> Path:
    """Repo so docs (sem codigo): README + docs/ extensos + nenhum codigo."""
    repo = root / "docs_only"
    repo.mkdir()
    (repo / "README.md").write_text("# docs-only\n\nProjeto so de documentacao.\n", encoding="utf-8")
    (repo / "LICENSE").write_text("CC-BY-SA\n", encoding="utf-8")

    docs = repo / "docs"
    docs.mkdir()
    for i in range(5):
        (docs / f"chapter_{i:02d}.md").write_text(f"# Chapter {i}\n\nConteudo.\n", encoding="utf-8")

    # Marker Grupo B (rascunho deve ser sinalizado)
    (docs / "draft-feature-X.md").write_text("# DRAFT — nao publicar\n", encoding="utf-8")

    return repo


def build_symlink_adversarial(root: Path) -> Path:
    """Repo com hardlink real + tentativa de symlink (skip se sem developer mode)."""
    repo = root / "symlink_adversarial"
    repo.mkdir()
    (repo / "README.md").write_text("# symlink-adversarial\n", encoding="utf-8")
    (repo / "real.txt").write_text("conteudo real\n", encoding="utf-8")

    # Hardlink real (Windows + POSIX aceitam sem admin)
    real = repo / "real.txt"
    link = repo / "linked.txt"
    with contextlib.suppress(OSError, NotImplementedError):
        os.link(real, link)
        # silent fallback — F1 ainda vai marcar real.txt como hardlink se nlink>1

    # Symlink best-effort
    with contextlib.suppress(OSError, NotImplementedError):
        os.symlink(real, repo / "symlinked.txt")

    # Junction best-effort (Windows)
    with contextlib.suppress(OSError, NotImplementedError):
        target_dir = repo / "target_dir"
        target_dir.mkdir()
        (target_dir / "inner.txt").write_text("inner\n", encoding="utf-8")
        if os.name == "nt":
            import subprocess
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(repo / "junction_dir"), str(target_dir)],
                capture_output=True, check=False,
            )

    return repo


def build_pii_in_paths(root: Path) -> Path:
    """Repo com paths contendo PII (CPF/CNPJ/email/nome)."""
    repo = root / "pii_in_paths"
    repo.mkdir()
    (repo / "README.md").write_text("# pii-in-paths\n", encoding="utf-8")

    # Path com nome proprio
    d_nome = repo / "users" / "Noma-Rabia"
    d_nome.mkdir(parents=True)
    (d_nome / "config.py").write_text("USER = 'noma'\n", encoding="utf-8")

    # Path com email
    d_email = repo / "data" / "john.doe@empresa.com"
    d_email.mkdir(parents=True)
    (d_email / "profile.json").write_text('{"name": "X"}\n', encoding="utf-8")

    # Path com CPF formatado
    d_cpf = repo / "exports" / "123.456.789-00"
    d_cpf.mkdir(parents=True)
    (d_cpf / "data.csv").write_text("col1,col2\n1,2\n", encoding="utf-8")

    # Path com CNPJ
    d_cnpj = repo / "clientes" / "12.345.678_0001-90"
    d_cnpj.mkdir(parents=True)
    (d_cnpj / "info.txt").write_text("ok\n", encoding="utf-8")

    return repo


REPO_FACTORIES: dict[str, Callable[[Path], Path]] = {
    "python_simple": build_python_simple,
    "node_monorepo": build_node_monorepo,
    "docs_only": build_docs_only,
    "symlink_adversarial": build_symlink_adversarial,
    "pii_in_paths": build_pii_in_paths,
}


def build_all(root: Path) -> dict[str, Path]:
    """Constroi todos os 5 fixtures dentro de root. Retorna dict slug -> path."""
    return {name: factory(root) for name, factory in REPO_FACTORIES.items()}


__all__ = [
    "REPO_FACTORIES",
    "REPO_NAMES",
    "build_all",
    "build_docs_only",
    "build_node_monorepo",
    "build_pii_in_paths",
    "build_python_simple",
    "build_symlink_adversarial",
]
