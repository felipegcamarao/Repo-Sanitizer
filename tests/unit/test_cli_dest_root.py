"""test_cli_dest_root.py — flags --dest-root/--relatorios-dir (Auditoria 2026-07).

Antes da auditoria, destino e relatorios eram HARDCODED para o workspace do
operador ("C:/VS Code/Git Hub - [NOME]") — sem override, qualquer teste de campo
escreveria fora da area de trabalho designada. Estes testes cobrem:

- parse das flags novas;
- cli.main() dry-run end-to-end com destino/relatorios customizados (exit 0);
- boundary FsWriter: relatorios em path proibido -> exit 5 (nunca escreve).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.cli import build_parser, main
from repo_sanitizer.helpers import _fs_writer as fsw_mod


def test_parser_aceita_dest_root_e_relatorios_dir() -> None:
    parser = build_parser()
    args = parser.parse_args([
        "--dest-root", "D:/saida",
        "--relatorios-dir", "D:/rel",
        "dry-run", "--source-path", "D:/fonte",
    ])
    assert args.dest_root == Path("D:/saida")
    assert args.relatorios_dir == Path("D:/rel")


def test_parser_dest_root_default_none() -> None:
    parser = build_parser()
    args = parser.parse_args(["dry-run", "--source-path", "D:/fonte"])
    assert args.dest_root is None
    assert args.relatorios_dir is None


def test_cli_dry_run_end_to_end_com_dest_root_custom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    src = tmp_path / "fonte"
    src.mkdir()
    (src / "README.md").write_text("# projeto exemplo\n", encoding="utf-8")
    (src / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    dest_root = tmp_path / "saida"
    relatorios = tmp_path / "relatorios"
    # tmp_path do pytest vive sob AppData (proibido por default) — libera só
    # para este teste, mantendo um proibido real para provar o boundary.
    monkeypatch.setattr(
        fsw_mod, "DEFAULT_FORBIDDEN_PATHS", (Path("C:/Windows"),),
    )
    rc = main([
        "--dest-root", str(dest_root),
        "--relatorios-dir", str(relatorios),
        "dry-run", "--source-path", str(src), "--slug", "exemplo",
    ])
    assert rc == 0
    diffs = list(relatorios.glob("FILTER_DIFF_exemplo_*.md"))
    assert diffs, "FILTER_DIFF deveria ter sido emitido no --relatorios-dir custom"
    # dry-run NUNCA cria destino
    assert not (dest_root / "GIT_exemplo").exists()


def test_cli_relatorios_em_path_proibido_exit_5(tmp_path: Path) -> None:
    src = tmp_path / "fonte"
    src.mkdir()
    (src / "README.md").write_text("# x\n", encoding="utf-8")
    rc = main([
        "--dest-root", str(tmp_path / "saida"),
        "--relatorios-dir", "C:/Windows/repo-sanitize-rel",
        "dry-run", "--source-path", str(src), "--slug", "exemplo",
    ])
    assert rc == 5, "escrita sob C:/Windows deve ser bloqueada pelo FsWriter (exit 5)"
    assert not Path("C:/Windows/repo-sanitize-rel").exists()
