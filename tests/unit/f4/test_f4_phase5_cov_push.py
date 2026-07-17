"""test_f4_phase5_cov_push.py — Fase 5 cov push f4_readme.py >=85%.

Carry-over D-EX-30 (Bloco 05): f4_readme.py cov 84.95% -> meta 85%+.
Branches faltantes (subprocess scenarios) via subprocess.run mocks:

- _build_tree_outline com dest inexistente
- _extract_python_docstrings com SyntaxError / dest inexistente / cap limits
- _extract_cli_args sem argparse / cap limits
- _detect_license_status absent / present sem first_line / arquivo vazio
- _detect_changelog absent
- _read_readme_source com path nao-existente / file decode error
- _extract_features cap e module skip
- run_markdownlint PASS scenario (mock subprocess.run exit 0)
- run_markdownlint FAIL scenario (mock exit 1)
- run_markdownlint TimeoutExpired -> FAIL
- run_link_check PASS / FAIL / TimeoutExpired
- list_kit_jsons sem tmp
- reset_kit_cap_flag com flag nao existente
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Push 1 — _build_tree_outline dest inexistente
# ---------------------------------------------------------------------------


def test_build_tree_outline_dest_does_not_exist(tmp_path: Path) -> None:
    """_build_tree_outline retorna [] quando dest_path nao existe."""
    from repo_sanitizer.f4_readme import _build_tree_outline

    nonexistent = tmp_path / "nope"
    outline = _build_tree_outline(nonexistent)
    assert outline == []


# ---------------------------------------------------------------------------
# Push 2 — _build_tree_outline com >60 entries (cap)
# ---------------------------------------------------------------------------


def test_build_tree_outline_caps_at_max_entries(tmp_path: Path) -> None:
    """_TREE_OUTLINE_MAX_ENTRIES cap aplicado."""
    from repo_sanitizer.f4_readme import (
        _TREE_OUTLINE_MAX_ENTRIES,
        _build_tree_outline,
    )

    dest = tmp_path / "dest"
    dest.mkdir()
    # Create 70 files no top + 5 dirs com 10 files cada = 120
    for i in range(70):
        (dest / f"f_{i:03d}.py").write_text("# x\n", encoding="utf-8")
    for d in range(5):
        sub = dest / f"sub_{d}"
        sub.mkdir()
        for i in range(10):
            (sub / f"g_{i:02d}.py").write_text("# y\n", encoding="utf-8")

    outline = _build_tree_outline(dest)
    assert len(outline) <= _TREE_OUTLINE_MAX_ENTRIES


# ---------------------------------------------------------------------------
# Push 3 — _extract_python_docstrings com SyntaxError ignored
# ---------------------------------------------------------------------------


def test_extract_python_docstrings_skips_syntax_error(tmp_path: Path) -> None:
    """SyntaxError em .py nao crasha; arquivo skipped."""
    from repo_sanitizer.f4_readme import _extract_python_docstrings

    dest = tmp_path / "dest"
    dest.mkdir()
    # 1 arquivo valido
    (dest / "ok.py").write_text('"""Docstring valida."""\n', encoding="utf-8")
    # 1 arquivo invalido
    (dest / "broken.py").write_text("def x(:\n    pass\n", encoding="utf-8")

    docs = _extract_python_docstrings(dest)
    # Apenas ok.py contribui
    assert any(d["file"] == "ok.py" for d in docs)


# ---------------------------------------------------------------------------
# Push 4 — _extract_python_docstrings cap _DOCSTRING_FILE_LIMIT
# ---------------------------------------------------------------------------


def test_extract_python_docstrings_caps_at_file_limit(tmp_path: Path) -> None:
    """_DOCSTRING_FILE_LIMIT cap aplicado."""
    from repo_sanitizer.f4_readme import (
        _DOCSTRING_FILE_LIMIT,
        _extract_python_docstrings,
    )

    dest = tmp_path / "dest"
    dest.mkdir()
    n_files = _DOCSTRING_FILE_LIMIT + 5
    for i in range(n_files):
        (dest / f"m_{i:03d}.py").write_text(
            f'"""Mod {i}."""\ndef f_{i}():\n    """Func {i}."""\n    pass\n',
            encoding="utf-8",
        )

    docs = _extract_python_docstrings(dest)
    files_seen = {d["file"] for d in docs}
    assert len(files_seen) <= _DOCSTRING_FILE_LIMIT


# ---------------------------------------------------------------------------
# Push 5 — _extract_cli_args sem argparse / vazio
# ---------------------------------------------------------------------------


def test_extract_cli_args_skips_files_without_argparse(tmp_path: Path) -> None:
    """Arquivos sem 'argparse' nao contribuem."""
    from repo_sanitizer.f4_readme import _extract_cli_args

    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "no_argparse.py").write_text("print('hi')\n", encoding="utf-8")
    (dest / "yes_argparse.py").write_text(
        "import argparse\np = argparse.ArgumentParser()\n"
        "p.add_argument('--foo', help='do foo')\n",
        encoding="utf-8",
    )
    args = _extract_cli_args(dest)
    assert any(a["flag"] == "--foo" for a in args)


# ---------------------------------------------------------------------------
# Push 6 — _extract_cli_args dest inexistente
# ---------------------------------------------------------------------------


def test_extract_cli_args_dest_does_not_exist(tmp_path: Path) -> None:
    """_extract_cli_args retorna [] se dest nao existe."""
    from repo_sanitizer.f4_readme import _extract_cli_args

    args = _extract_cli_args(tmp_path / "nope")
    assert args == []


# ---------------------------------------------------------------------------
# Push 7 — _detect_license_status absent / unknown / present
# ---------------------------------------------------------------------------


def test_detect_license_status_states(tmp_path: Path) -> None:
    """unknown | absent | present statuses."""
    from repo_sanitizer.f4_readme import _detect_license_status

    # unknown: path nao existe
    assert _detect_license_status(tmp_path / "nope") == "unknown"

    # absent: dir vazio
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _detect_license_status(empty) == "absent"

    # present
    with_lic = tmp_path / "with_lic"
    with_lic.mkdir()
    (with_lic / "LICENSE").write_text("MIT License\nCopyright (c) 2026 [NOME]\n",
                                       encoding="utf-8")
    status = _detect_license_status(with_lic)
    assert status.startswith("present")


# ---------------------------------------------------------------------------
# Push 8 — _detect_changelog
# ---------------------------------------------------------------------------


def test_detect_changelog(tmp_path: Path) -> None:
    """has_changelog True/False."""
    from repo_sanitizer.f4_readme import _detect_changelog

    assert _detect_changelog(tmp_path / "nope") is False

    with_chg = tmp_path / "chg"
    with_chg.mkdir()
    (with_chg / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
    assert _detect_changelog(with_chg) is True

    no_chg = tmp_path / "no_chg"
    no_chg.mkdir()
    assert _detect_changelog(no_chg) is False


# ---------------------------------------------------------------------------
# Push 9 — _read_readme_source ausente / presente
# ---------------------------------------------------------------------------


def test_read_readme_source_paths(tmp_path: Path) -> None:
    """README ausente -> None; README presente -> conteudo."""
    from repo_sanitizer.f4_readme import _read_readme_source

    assert _read_readme_source(tmp_path / "nope") is None

    src = tmp_path / "src"
    src.mkdir()
    assert _read_readme_source(src) is None  # vazio

    (src / "README.md").write_text("# Hello\nworld\n", encoding="utf-8")
    content = _read_readme_source(src)
    assert content is not None
    assert "Hello" in content


# ---------------------------------------------------------------------------
# Push 10 — _extract_features skip module + empty first_sentence
# ---------------------------------------------------------------------------


def test_extract_features_skips_module_docstrings_and_empty() -> None:
    """_extract_features ignora module docstrings + empty docs."""
    from repo_sanitizer.f4_readme import _extract_features

    docs = [
        {"file": "a.py", "name": "<module>", "doc": "Module doc"},
        {"file": "a.py", "name": "f1", "doc": ""},
        {"file": "a.py", "name": "f2", "doc": "Feature 2 valida"},
        {"file": "a.py", "name": "f3", "doc": "......"},
    ]
    out = _extract_features(docs)
    # apenas f2 contribui
    assert any("f2" in s for s in out)
    assert all("<module>" not in s for s in out)


# ---------------------------------------------------------------------------
# Push 11 — run_markdownlint PASS / FAIL / NOT_AVAILABLE
# ---------------------------------------------------------------------------


def test_run_markdownlint_pass_scenario(tmp_path: Path) -> None:
    """run_markdownlint PASS quando subprocess retorna 0."""
    from repo_sanitizer.f4_readme import run_markdownlint

    readme = tmp_path / "README.md"
    readme.write_text("# title\n", encoding="utf-8")

    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = ""
    with (
        patch("repo_sanitizer.f4_readme._which", return_value="C:/fake/markdownlint.cmd"),
        patch("repo_sanitizer.f4_readme.subprocess.run", return_value=fake_result),
    ):
        status = run_markdownlint(readme)
    assert status == "PASS"


def test_run_markdownlint_fail_scenario(tmp_path: Path) -> None:
    """run_markdownlint FAIL quando subprocess retorna != 0."""
    from repo_sanitizer.f4_readme import run_markdownlint

    readme = tmp_path / "README.md"
    readme.write_text("# title\n", encoding="utf-8")

    fake_result = MagicMock()
    fake_result.returncode = 1
    fake_result.stdout = "line too long"
    with (
        patch("repo_sanitizer.f4_readme._which", return_value="C:/fake/markdownlint.cmd"),
        patch("repo_sanitizer.f4_readme.subprocess.run", return_value=fake_result),
    ):
        status = run_markdownlint(readme)
    assert status == "FAIL"


def test_run_markdownlint_timeout_scenario(tmp_path: Path) -> None:
    """run_markdownlint FAIL quando TimeoutExpired."""
    from repo_sanitizer.f4_readme import run_markdownlint

    readme = tmp_path / "README.md"
    readme.write_text("# title\n", encoding="utf-8")

    def raising(*a, **k):
        raise subprocess.TimeoutExpired(cmd="markdownlint", timeout=30)

    with (
        patch("repo_sanitizer.f4_readme._which", return_value="C:/fake/markdownlint.cmd"),
        patch("repo_sanitizer.f4_readme.subprocess.run", side_effect=raising),
    ):
        status = run_markdownlint(readme)
    assert status == "FAIL"


# ---------------------------------------------------------------------------
# Push 12 — run_link_check PASS / FAIL / NOT_AVAILABLE / TimeoutExpired
# ---------------------------------------------------------------------------


def test_run_link_check_pass_scenario(tmp_path: Path) -> None:
    """run_link_check PASS."""
    from repo_sanitizer.f4_readme import run_link_check

    readme = tmp_path / "README.md"
    readme.write_text("# x\n", encoding="utf-8")

    fake_result = MagicMock()
    fake_result.returncode = 0
    with (
        patch("repo_sanitizer.f4_readme._which", return_value="C:/fake/markdown-link-check.cmd"),
        patch("repo_sanitizer.f4_readme.subprocess.run", return_value=fake_result),
    ):
        status = run_link_check(readme)
    assert status == "PASS"


def test_run_link_check_fail_scenario(tmp_path: Path) -> None:
    """run_link_check FAIL exit != 0."""
    from repo_sanitizer.f4_readme import run_link_check

    readme = tmp_path / "README.md"
    readme.write_text("# x\n", encoding="utf-8")

    fake_result = MagicMock()
    fake_result.returncode = 1
    with (
        patch("repo_sanitizer.f4_readme._which", return_value="C:/fake/markdown-link-check.cmd"),
        patch("repo_sanitizer.f4_readme.subprocess.run", return_value=fake_result),
    ):
        status = run_link_check(readme)
    assert status == "FAIL"


def test_run_link_check_not_available(tmp_path: Path) -> None:
    """run_link_check NOT_AVAILABLE quando CLI ausente."""
    from repo_sanitizer.f4_readme import run_link_check

    readme = tmp_path / "README.md"
    readme.write_text("# x\n", encoding="utf-8")
    with patch("repo_sanitizer.f4_readme._which", return_value=None):
        status = run_link_check(readme)
    assert status == "NOT_AVAILABLE"


def test_run_link_check_timeout(tmp_path: Path) -> None:
    """run_link_check FAIL no TimeoutExpired."""
    from repo_sanitizer.f4_readme import run_link_check

    readme = tmp_path / "README.md"
    readme.write_text("# x\n", encoding="utf-8")

    def raising(*a, **k):
        raise subprocess.TimeoutExpired(cmd="markdown-link-check", timeout=60)

    with (
        patch("repo_sanitizer.f4_readme._which", return_value="C:/fake/markdown-link-check.cmd"),
        patch("repo_sanitizer.f4_readme.subprocess.run", side_effect=raising),
    ):
        status = run_link_check(readme)
    assert status == "FAIL"


# ---------------------------------------------------------------------------
# Push 13 — list_kit_jsons sem tmp dir
# ---------------------------------------------------------------------------


def test_list_kit_jsons_no_tmp(tmp_path: Path) -> None:
    """list_kit_jsons retorna [] quando .tmp/ nao existe."""
    from repo_sanitizer.f4_readme import list_kit_jsons

    relatorios = tmp_path / "Relatorios"
    relatorios.mkdir()
    out = list_kit_jsons(relatorios, "any-slug")
    assert out == []


# ---------------------------------------------------------------------------
# Push 14 — reset_kit_cap_flag idempotente (sem flag)
# ---------------------------------------------------------------------------


def test_reset_kit_cap_flag_no_flag(tmp_path: Path) -> None:
    """reset_kit_cap_flag retorna False quando flag nao existe."""
    from repo_sanitizer.f4_readme import reset_kit_cap_flag

    dest = tmp_path / "dest"
    dest.mkdir()
    assert reset_kit_cap_flag(dest) is False


# ---------------------------------------------------------------------------
# Push 15 — cleanup_tmp_kits tmp_dir nao existe
# ---------------------------------------------------------------------------


def test_cleanup_tmp_kits_no_tmp_dir(tmp_path: Path) -> None:
    """cleanup_tmp_kits retorna 0 quando .tmp/ nao existe."""
    from repo_sanitizer.f4_readme import cleanup_tmp_kits

    relatorios = tmp_path / "Relatorios"
    relatorios.mkdir()
    n = cleanup_tmp_kits(relatorios, "any-slug")
    assert n == 0
