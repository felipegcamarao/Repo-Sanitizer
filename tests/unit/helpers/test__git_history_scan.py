"""test__git_history_scan.py — B3 / MV-02 / RS-NEW-038 / ADR-035 (unit).

Testa `scan_git_history_artifacts` isolado: deteccao por NOME e por CONTEUDO,
allowlist HARDCODED, e zero-FP em arquivos `.git*` legitimos. Cobertura ≥90%.
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.helpers._git_history_scan import (
    GitArtifact,
    scan_git_history_artifacts,
)


def _kinds(arts: list[GitArtifact]) -> set[str]:
    return {a.kind for a in arts}


def _rels(arts: list[GitArtifact]) -> set[str]:
    return {a.rel_path for a in arts}


def test_clean_dest_returns_empty(tmp_path: Path) -> None:
    """Destino limpo (so codigo) -> nenhum artefato."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# ok\n", encoding="utf-8")
    assert scan_git_history_artifacts(tmp_path) == []


def test_missing_dest_returns_empty(tmp_path: Path) -> None:
    """Destino inexistente -> lista vazia (sem raise)."""
    assert scan_git_history_artifacts(tmp_path / "nope") == []


def test_detects_git_dir(tmp_path: Path) -> None:
    """`.git/` (dir) detectado por nome; nao desce na arvore."""
    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "config").write_text("[core]\n", encoding="utf-8")
    (gitdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    assert "git_dir" in _kinds(arts)
    # NAO desce dentro de .git/ -> nao reporta config/HEAD internos.
    assert ".git/" in _rels(arts)
    assert not any(a.rel_path.startswith(".git/config") for a in arts)


def test_detects_nested_git_dir_submodule(tmp_path: Path) -> None:
    """`.git/` aninhado (submodule) detectado."""
    sub = tmp_path / "vendor" / "lib" / ".git"
    sub.mkdir(parents=True)
    (sub / "HEAD").write_text("ref: x\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    assert any(a.rel_path == "vendor/lib/.git/" and a.kind == "git_dir" for a in arts)


def test_detects_packed_refs_and_orig_head(tmp_path: Path) -> None:
    """`packed-refs`/`ORIG_HEAD`/`FETCH_HEAD` por nome (fora de .git/)."""
    (tmp_path / "packed-refs").write_text("# pack\n", encoding="utf-8")
    (tmp_path / "ORIG_HEAD").write_text("abc\n", encoding="utf-8")
    (tmp_path / "FETCH_HEAD").write_text("def\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    rels = _rels(arts)
    assert {"packed-refs", "ORIG_HEAD", "FETCH_HEAD"} <= rels


def test_detects_patch_diff_orig_rej_bundle(tmp_path: Path) -> None:
    """Sufixos de patch/bundle detectados (INV-5)."""
    for name in ("fix.patch", "x.diff", "merge.orig", "conflict.rej", "repo.bundle"):
        (tmp_path / name).write_text("data\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    assert {"fix.patch", "x.diff", "merge.orig", "conflict.rej", "repo.bundle"} <= _rels(arts)


def test_detects_git_file_pointer_by_content(tmp_path: Path) -> None:
    """Arquivo `.git` (nao-dir) com `gitdir:` -> detectado por CONTEUDO."""
    (tmp_path / ".git").write_text("gitdir: ../.git/modules/sub\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    assert any(a.kind == "git_dir_pointer" for a in arts)


def test_detects_gitattributes_with_filter_by_content(tmp_path: Path) -> None:
    """`.gitattributes` com `filter=`/`clean`/`smudge` -> detectado (vetor exfil)."""
    (tmp_path / ".gitattributes").write_text(
        "*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8",
    )
    arts = scan_git_history_artifacts(tmp_path)
    assert any(a.kind == "gitattributes_filter" for a in arts)


def test_gitattributes_smudge_clean(tmp_path: Path) -> None:
    """`.gitattributes` com clean/smudge tambem detectado."""
    (tmp_path / ".gitattributes").write_text(
        "*.txt clean=cat smudge=cat\n", encoding="utf-8",
    )
    arts = scan_git_history_artifacts(tmp_path)
    assert any(a.kind == "gitattributes_filter" for a in arts)


def test_allowlist_benign_git_files_not_flagged(tmp_path: Path) -> None:
    """`.gitignore`/`.gitkeep`/`.editorconfig`/`.gitattributes` benigno -> NAO flag."""
    (tmp_path / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (tmp_path / "pkg" / "data").mkdir(parents=True)
    (tmp_path / "pkg" / "data" / ".gitkeep").write_text("", encoding="utf-8")
    (tmp_path / ".editorconfig").write_text("root = true\n", encoding="utf-8")
    (tmp_path / ".gitattributes").write_text(
        "*.md text\n*.png binary\n", encoding="utf-8",  # SEM filtros
    )
    arts = scan_git_history_artifacts(tmp_path)
    assert arts == [], f"FALSO-POSITIVO em arquivos git legitimos: {arts}"


def test_anomalous_git_file_without_pointer(tmp_path: Path) -> None:
    """Arquivo `.git` (nao-dir) SEM `gitdir:` -> bloqueia como anomalo (git_file)."""
    (tmp_path / ".git").write_text("lixo aleatorio\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    assert any(a.kind == "git_file" for a in arts)


def test_head_and_merge_head_basenames(tmp_path: Path) -> None:
    """`HEAD`/`MERGE_HEAD`/`.gitmodules` soltos -> historico (modo paranoico)."""
    (tmp_path / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (tmp_path / "MERGE_HEAD").write_text("abc\n", encoding="utf-8")
    (tmp_path / ".gitmodules").write_text("[submodule \"x\"]\n", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    rels = _rels(arts)
    assert {"HEAD", "MERGE_HEAD", ".gitmodules"} <= rels


def test_read_sniff_oserror_returns_empty(tmp_path: Path, monkeypatch) -> None:
    """`_read_sniff` em erro de IO -> "" (degrade gracioso, linha OSError)."""
    import builtins

    from repo_sanitizer.helpers._git_history_scan import _read_sniff

    real_open = builtins.open

    def _boom(path, *a, **k):
        raise OSError("permission denied")

    monkeypatch.setattr(builtins, "open", _boom)
    try:
        assert _read_sniff(tmp_path / ".gitattributes") == ""
    finally:
        monkeypatch.setattr(builtins, "open", real_open)


def test_result_is_sorted_and_relative(tmp_path: Path) -> None:
    """`rel_path` e POSIX relativo (zero-leak) e a lista e ordenada."""
    (tmp_path / "b.patch").write_text("x", encoding="utf-8")
    (tmp_path / "a.orig").write_text("x", encoding="utf-8")
    arts = scan_git_history_artifacts(tmp_path)
    rels = [a.rel_path for a in arts]
    assert rels == sorted(rels)
    assert all(not Path(r).is_absolute() for r in rels)
