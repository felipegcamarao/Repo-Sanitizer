"""test_git_history_gate.py — B3 / MV-02 / RS-NEW-038 / ADR-035 (security).

Gate BLOQUEANTE de historico Git no destino:
- injeta `.git/`+`packed-refs` no destino apos sanitizacao -> `run_f3` raise
  `GitHistoryInDestination`;
- injeta `.gitattributes` com `filter=lfs` -> raise;
- destino limpo -> nenhum raise;
- `raise_on_git_history=False` -> nao-bloqueante (log only, artefatos no result);
- exit code 8 verificado via mapeamento de excecao -> CLI.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f3_sanitizer import GitHistoryInDestination, run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _setup(tmp_path: Path, slug: str = "githist"):
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# demo\n", encoding="utf-8")
    (src / "main.py").write_text("print('ok')\n", encoding="utf-8")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    dest = allowed / f"GIT_{slug}-v1"
    dest.mkdir()
    fw = FsWriter(source_path=src, allowed_roots=[allowed], override_forbidden=[])
    audit = AuditLogger(
        audit_file=relatorios / "audit-log.jsonl", fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="0.3.0a1", sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64, slug=slug,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    return src, dest, fw, audit


def _run(src, dest, fw, audit, **kw):
    return run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
        **kw,
    )


def test_clean_dest_no_raise(tmp_path: Path) -> None:
    """Destino limpo -> nenhum raise; result.git_history_artifacts vazio."""
    src, dest, fw, audit = _setup(tmp_path, "clean")
    result = _run(src, dest, fw, audit)
    assert result.git_history_artifacts == []


def test_injected_git_dir_and_packed_refs_raises(tmp_path: Path) -> None:
    """`.git/`+`packed-refs` injetados no destino -> GitHistoryInDestination."""
    src, dest, fw, audit = _setup(tmp_path, "ghdir")
    # Roda F3 sem gate para popular o destino, depois injeta e re-roda o gate.
    _run(src, dest, fw, audit, raise_on_git_history=False)
    gitdir = dest / ".git"
    gitdir.mkdir(exist_ok=True)
    (gitdir / "config").write_text("[core]\n", encoding="utf-8")
    (dest / "packed-refs").write_text("# pack\n", encoding="utf-8")
    with pytest.raises(GitHistoryInDestination):
        _run(src, dest, fw, audit, raise_on_git_history=True)


def test_injected_gitattributes_filter_raises(tmp_path: Path) -> None:
    """`.gitattributes` com filtro `filter=lfs smudge=...` -> raise."""
    src, dest, fw, audit = _setup(tmp_path, "ghattr")
    _run(src, dest, fw, audit, raise_on_git_history=False)
    (dest / ".gitattributes").write_text(
        "*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8",
    )
    with pytest.raises(GitHistoryInDestination):
        _run(src, dest, fw, audit, raise_on_git_history=True)


def test_non_blocking_mode_logs_but_no_raise(tmp_path: Path) -> None:
    """`raise_on_git_history=False` -> nao-bloqueante; artefatos no result."""
    src, dest, fw, audit = _setup(tmp_path, "ghnb")
    _run(src, dest, fw, audit, raise_on_git_history=False)
    (dest / "history.patch").write_text("diff --git a b\n", encoding="utf-8")
    result = _run(src, dest, fw, audit, raise_on_git_history=False)
    assert any(a.rel_path == "history.patch" for a in result.git_history_artifacts)


def test_benign_gitignore_does_not_raise(tmp_path: Path) -> None:
    """`.gitignore` legitimo no destino NAO dispara o gate (allowlist)."""
    src, dest, fw, audit = _setup(tmp_path, "ghignore")
    _run(src, dest, fw, audit, raise_on_git_history=False)
    (dest / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    # Nao deve levantar.
    result = _run(src, dest, fw, audit, raise_on_git_history=True)
    assert result.git_history_artifacts == []


def test_exit_code_8_mapping_via_cli() -> None:
    """A excecao GitHistoryInDestination mapeia para exit 8 no fluxo CLI.

    Verifica o contrato de exit code sem rodar o pipeline completo: o handler
    de `cli.main` retorna 8 para essa excecao (espelha o teste de exit 7 do G2).
    """
    import repo_sanitizer.cli as cli_mod
    from repo_sanitizer.orchestrator import GitHistoryInDestination as OrchGH

    # A CLI importa a excecao do orchestrator (re-export) — mesmo objeto.
    assert OrchGH is GitHistoryInDestination

    # Patch run_apply para levantar a excecao; main deve retornar 8.
    import argparse

    def _boom(*_a, **_k):
        raise GitHistoryInDestination("historico git no destino (teste)")

    orig_apply = cli_mod.run_apply
    orig_preflight = cli_mod.pre_flight_integrity_check
    orig_ctx = cli_mod.make_orchestrator_context
    try:
        cli_mod.run_apply = _boom  # type: ignore[assignment]
        cli_mod.pre_flight_integrity_check = lambda *_a, **_k: {"ok": True}  # type: ignore[assignment]
        cli_mod.make_orchestrator_context = lambda **_k: argparse.Namespace(  # type: ignore[assignment]
            extra={},
        )
        rc = cli_mod.main([
            "sanitize-apply", "--slug", "x", "--source-path", ".",
        ])
        assert rc == 8
    finally:
        cli_mod.run_apply = orig_apply  # type: ignore[assignment]
        cli_mod.pre_flight_integrity_check = orig_preflight  # type: ignore[assignment]
        cli_mod.make_orchestrator_context = orig_ctx  # type: ignore[assignment]
