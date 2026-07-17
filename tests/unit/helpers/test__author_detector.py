"""test__author_detector.py — C1 / MV-05 / RS-NEW-041 / ADR-038 (unit).

Testa `_author_detector` isolado:
- pyproject `authors` name+email redatados; `[project] name`/deps intactos;
- poetry `authors = ["Nome <email>"]` redatado;
- package.json `author`/`contributors` redatados; deps intactas; JSON ainda valido;
- Cargo.toml `authors` redatado;
- composer.json `authors` redatado;
- AUTHORS file redatado;
- manifest malformado -> fallback textual (sem crash);
- manifest sem autoria -> no-op;
- arquivo nao-manifest -> no-op;
- cobertura >=90%.
"""
from __future__ import annotations

import json

from repo_sanitizer.helpers._author_detector import (
    REDACTED_AUTHOR_EMAIL,
    REDACTED_AUTHOR_NAME,
    AuthorMatch,
    is_author_manifest,
    redact_authorship,
)


def _kinds(matches: list[AuthorMatch]) -> set[str]:
    return {m.kind for m in matches}


# ---------------------------------------------------------------------------
# pyproject.toml (PEP 621 + poetry)
# ---------------------------------------------------------------------------

def test_pyproject_pep621_authors_redacted_name_and_deps_intact() -> None:
    text = (
        "[project]\n"
        'name = "my-package"\n'
        'version = "1.0.0"\n'
        'authors = [{name = "Noma Nomao", email = "noma@acme.io"}]\n'
        'dependencies = ["requests>=2.0"]\n'
    )
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    assert "Noma Nomao" not in out
    assert "noma@acme.io" not in out
    assert REDACTED_AUTHOR_NAME in out
    assert REDACTED_AUTHOR_EMAIL in out
    # name do pacote e dependencias INTACTOS (G2).
    assert 'name = "my-package"' in out
    assert "requests>=2.0" in out
    assert _kinds(matches) == {"name", "email"}


def test_pyproject_maintainers_redacted() -> None:
    text = (
        "[project]\n"
        'name = "pkg"\n'
        'maintainers = [{name = "Jane Doe", email = "jane@x.com"}]\n'
    )
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    assert "Jane Doe" not in out and "jane@x.com" not in out
    assert 'name = "pkg"' in out
    assert len(matches) >= 2


def test_poetry_authors_string_redacted() -> None:
    text = (
        "[tool.poetry]\n"
        'name = "mypkg"\n'
        'authors = ["Noma Nomao <noma@acme.io>"]\n'
    )
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    assert "Noma Nomao" not in out and "noma@acme.io" not in out
    assert 'name = "mypkg"' in out
    assert _kinds(matches) == {"name", "email"}


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------

def test_package_json_author_object_redacted_json_valid() -> None:
    text = (
        "{\n"
        '  "name": "my-app",\n'
        '  "version": "2.0.0",\n'
        '  "author": {"name": "Noma Nomao", "email": "noma@acme.io"},\n'
        '  "dependencies": {"react": "^18.0.0"}\n'
        "}"
    )
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert "Noma Nomao" not in out and "noma@acme.io" not in out
    assert '"name": "my-app"' in out
    assert '"react": "^18.0.0"' in out
    # Output ainda e JSON valido (placeholder preserva estrutura -> G2).
    parsed = json.loads(out)
    assert parsed["name"] == "my-app"
    assert parsed["dependencies"]["react"] == "^18.0.0"
    assert _kinds(matches) == {"name", "email"}


def test_package_json_author_string_redacted() -> None:
    text = '{"name": "x", "author": "Noma Nomao <noma@acme.io>"}'
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert "Noma Nomao" not in out and "noma@acme.io" not in out
    assert json.loads(out)["name"] == "x"
    assert len(matches) >= 1


def test_package_json_author_string_email_only_redacted() -> None:
    """author string com email solto (sem `<>`) -> email redatado."""
    text = '{"name": "x", "author": "noma@acme.io"}'
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert "noma@acme.io" not in out
    assert json.loads(out)["name"] == "x"
    assert any(m.kind == "email" for m in matches)


def test_package_json_author_string_name_only_redacted() -> None:
    """author string apenas com nome (sem email) -> nome redatado."""
    text = '{"name": "x", "author": "Noma Nomao"}'
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert "Noma Nomao" not in out
    assert json.loads(out)["author"] == REDACTED_AUTHOR_NAME
    assert any(m.kind == "name" for m in matches)


def test_package_json_contributors_array_redacted() -> None:
    text = (
        "{\n"
        '  "name": "x",\n'
        '  "contributors": [{"name": "A B", "email": "a@b.com"}],\n'
        '  "dependencies": {"lodash": "1.0"}\n'
        "}"
    )
    out, _ = redact_authorship(text, "package.json", "package.json")
    assert "a@b.com" not in out and "A B" not in out
    assert json.loads(out)["dependencies"]["lodash"] == "1.0"


# ---------------------------------------------------------------------------
# Cargo.toml / composer.json
# ---------------------------------------------------------------------------

def test_cargo_authors_redacted() -> None:
    text = (
        "[package]\n"
        'name = "mycrate"\n'
        'version = "0.1.0"\n'
        'authors = ["Noma Nomao <noma@acme.io>"]\n'
        "[dependencies]\n"
        'serde = "1.0"\n'
    )
    out, matches = redact_authorship(text, "Cargo.toml", "Cargo.toml")
    assert "Noma Nomao" not in out and "noma@acme.io" not in out
    assert 'name = "mycrate"' in out
    assert 'serde = "1.0"' in out
    assert _kinds(matches) == {"name", "email"}


def test_composer_json_authors_redacted() -> None:
    text = (
        "{\n"
        '  "name": "vendor/pkg",\n'
        '  "authors": [{"name": "Noma Nomao", "email": "noma@acme.io"}],\n'
        '  "require": {"php": ">=8.0"}\n'
        "}"
    )
    out, _ = redact_authorship(text, "composer.json", "composer.json")
    assert "Noma Nomao" not in out and "noma@acme.io" not in out
    assert json.loads(out)["name"] == "vendor/pkg"
    assert json.loads(out)["require"]["php"] == ">=8.0"


# ---------------------------------------------------------------------------
# AUTHORS / CONTRIBUTORS plain file
# ---------------------------------------------------------------------------

def test_authors_file_redacted() -> None:
    text = "Noma Nomao <noma@acme.io>\nJane Doe <jane@x.com>\n"
    out, matches = redact_authorship(text, "AUTHORS", "AUTHORS")
    assert "noma@acme.io" not in out and "jane@x.com" not in out
    assert "Noma Nomao" not in out
    assert len(matches) >= 2


def test_citation_cff_redacted() -> None:
    text = (
        "cff-version: 1.2.0\n"
        "authors:\n"
        "  - family-names: Nomao\n"
        "    email: noma@acme.io\n"
    )
    out, _ = redact_authorship(text, "CITATION.cff", "CITATION.cff")
    assert "noma@acme.io" not in out


# ---------------------------------------------------------------------------
# Parsing defensivo / fallback
# ---------------------------------------------------------------------------

def test_malformed_toml_falls_back_to_textual() -> None:
    """TOML malformado -> fallback regex textual (sem crash, sem skip silente)."""
    text = 'authors = [{name = "Noma" email = noma@acme.io}  BROKEN'
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    # Email redatado via fallback.
    assert "noma@acme.io" not in out
    assert any(m.kind == "email" for m in matches)


def test_malformed_json_falls_back_to_textual() -> None:
    text = '{"author": {"email": "noma@acme.io" BROKEN'
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert "noma@acme.io" not in out
    assert any(m.kind == "email" for m in matches)


def test_toml_without_authorship_is_no_op() -> None:
    """pyproject SEM campos de autoria -> nada redatado (anti-FP)."""
    text = '[project]\nname = "x"\nversion = "1.0"\ndependencies = ["a"]\n'
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    assert out == text
    assert matches == []


def test_json_without_authorship_is_no_op() -> None:
    text = '{"name": "x", "dependencies": {"a": "1.0"}}'
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert out == text
    assert matches == []


# ---------------------------------------------------------------------------
# Non-manifest / guards
# ---------------------------------------------------------------------------

def test_non_manifest_file_is_no_op() -> None:
    """Arquivo que nao e manifest -> no-op (mesmo com email no conteudo)."""
    text = "contact me at noma@acme.io for questions\n"
    out, matches = redact_authorship(text, "main.py", "src/main.py")
    assert out == text
    assert matches == []


def test_is_author_manifest_helper() -> None:
    assert is_author_manifest("pyproject.toml") is True
    assert is_author_manifest("PACKAGE.JSON") is True
    assert is_author_manifest("AUTHORS") is True
    assert is_author_manifest("main.py") is False


def test_name_field_never_touched_even_when_authors_present() -> None:
    """Garante que o `name` do pacote NUNCA e redatado (G2 / MV05-B)."""
    text = (
        "[project]\n"
        'name = "noma-library"\n'  # nome do pacote contem "noma" — nao tocar
        'authors = [{name = "Noma Nomao", email = "noma@acme.io"}]\n'
    )
    out, _ = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    assert 'name = "noma-library"' in out  # name do PACOTE intacto
    assert "Noma Nomao" not in out  # name do AUTOR redatado
