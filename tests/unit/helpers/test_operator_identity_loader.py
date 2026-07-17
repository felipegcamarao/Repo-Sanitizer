"""Testes _operator_identity_loader (Passo 1.2 — Bloco 01 v1.1.0-alpha.1).

4 testes canônicos do plano:
1. arquivo ausente → defaults com auto-populate
2. arquivo presente E válido → parse correto
3. JSON malformado → warning + defaults
4. schema-fail (campo extra ou tipo errado) → warning + defaults

Plus extras polish-driven (cov 100% do loader):
5. operator_identity_path resolve corretamente
6. arquivo presente mas OSError na leitura → warning + defaults
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from repo_sanitizer.helpers._operator_identity_loader import (
    OPERATOR_IDENTITY_REL_PATH,
    load_operator_identity,
    operator_identity_path,
)
from repo_sanitizer.schemas.operator_identity_schema import (
    OperatorIdentitySchema,
    _detect_os_usernames,
)


def _make_fake_project_root(tmp_path: Path, identity_data: dict[str, Any] | None) -> Path:
    """Helper: cria estrutura `<tmp>/src/repo_sanitizer/` e opcionalmente popula o JSON."""
    inner = tmp_path / "src" / "repo_sanitizer"
    inner.mkdir(parents=True)
    if identity_data is not None:
        target = inner / "operator_identity.json"
        target.write_text(json.dumps(identity_data, ensure_ascii=False), encoding="utf-8")
    return tmp_path


class TestPathResolution:
    """Test 5 — `operator_identity_path` resolve corretamente."""

    def test_path_resolves_relative_to_project_root(self, tmp_path: Path) -> None:
        resolved = operator_identity_path(tmp_path)
        expected = tmp_path.joinpath(*OPERATOR_IDENTITY_REL_PATH)
        assert resolved == expected
        assert resolved.name == "operator_identity.json"


class TestFileAbsent:
    """Test 1 — arquivo ausente."""

    def test_missing_file_returns_defaults(self, tmp_path: Path) -> None:
        project_root = _make_fake_project_root(tmp_path, identity_data=None)
        identity = load_operator_identity(project_root)

        assert isinstance(identity, OperatorIdentitySchema)
        assert identity.names == []
        assert identity.domains == []
        assert identity.extra_redact_patterns == []
        assert identity.usernames == _detect_os_usernames()


class TestFileValid:
    """Test 2 — arquivo presente E válido."""

    def test_valid_file_parsed_correctly(self, tmp_path: Path) -> None:
        data = {
            "names": ["Noma Nomb Nomão"],
            "usernames": ["usra"],
            "domains": ["acme.io"],
            "extra_redact_patterns": [r"\bAB\d{4}\b"],
        }
        project_root = _make_fake_project_root(tmp_path, identity_data=data)
        identity = load_operator_identity(project_root)

        assert identity.names == ["Noma Nomb Nomão"]
        assert identity.usernames == ["usra"]
        assert identity.domains == ["acme.io"]
        assert identity.extra_redact_patterns == [r"\bAB\d{4}\b"]


class TestFileMalformed:
    """Test 3 — JSON malformado."""

    def test_malformed_json_warns_and_returns_defaults(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        inner = tmp_path / "src" / "repo_sanitizer"
        inner.mkdir(parents=True)
        target = inner / "operator_identity.json"
        target.write_text('{"names": ["broken",}', encoding="utf-8")  # JSON inválido

        identity = load_operator_identity(tmp_path)

        captured = capsys.readouterr()
        assert "JSON malformado" in captured.err
        assert isinstance(identity, OperatorIdentitySchema)
        assert identity.names == []  # defaults retornados


class TestSchemaFail:
    """Test 4 — schema-fail (campo extra rejeitado por extra=forbid)."""

    def test_schema_fail_warns_and_returns_defaults(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad_data = {
            "names": ["Noma"],
            "unknown_extra_field": "value",  # extra=forbid rejeita
        }
        project_root = _make_fake_project_root(tmp_path, identity_data=bad_data)

        identity = load_operator_identity(project_root)

        captured = capsys.readouterr()
        assert "schema-fail" in captured.err
        assert isinstance(identity, OperatorIdentitySchema)
        assert identity.names == []  # defaults retornados


class TestFileOSError:
    """Test 6 — OSError ao ler o arquivo (permissões, etc.)."""

    def test_oserror_on_read_warns_and_returns_defaults(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        project_root = _make_fake_project_root(
            tmp_path, identity_data={"names": ["ignored"]}
        )

        original_read = Path.read_text

        def raise_oserror(self: Path, *args: Any, **kwargs: Any) -> str:
            if self.name == "operator_identity.json":
                raise OSError("simulated permission denied")
            return original_read(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", raise_oserror)

        identity = load_operator_identity(project_root)
        captured = capsys.readouterr()
        assert "falha ao ler" in captured.err
        assert identity.names == []  # defaults retornados


class TestGitignoreEntry:
    """Test extra — confirma que .gitignore tem entry para operator_identity.json."""

    def test_gitignore_contains_operator_identity_entry(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        gitignore = repo_root / ".gitignore"
        content = gitignore.read_text(encoding="utf-8")

        assert "src/repo_sanitizer/operator_identity.json" in content
        assert "!src/repo_sanitizer/operator_identity.json.template" in content


class TestTemplateExists:
    """Test extra — template committed e parseável."""

    def test_template_file_exists_and_is_valid_json(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        template = repo_root / "src" / "repo_sanitizer" / "operator_identity.json.template"

        assert template.exists(), "template ausente — deve estar committed"
        data = json.loads(template.read_text(encoding="utf-8"))
        # Estrutura mínima
        assert "names" in data
        assert "usernames" in data
        assert "domains" in data
        assert "extra_redact_patterns" in data


class TestAugmentIdentityFromEnv:
    """MV-05 / RS-NEW-041 / §5-8 — augment_identity_from_env (sinais de ambiente)."""

    @staticmethod
    def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "EMAIL", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL",
            "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME", "USERPROFILE",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_git_author_email_adds_pattern_and_username(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from repo_sanitizer.helpers._operator_identity_loader import (
            augment_identity_from_env,
        )
        self._clear_env(monkeypatch)
        monkeypatch.setenv("GIT_AUTHOR_EMAIL", "noma@acme.io")
        aug = augment_identity_from_env(OperatorIdentitySchema())
        assert any("noma" in p for p in aug.extra_redact_patterns)
        assert "noma" in aug.usernames

    def test_git_committer_name_added_to_names(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from repo_sanitizer.helpers._operator_identity_loader import (
            augment_identity_from_env,
        )
        self._clear_env(monkeypatch)
        monkeypatch.setenv("GIT_COMMITTER_NAME", "Noma Nomb")
        aug = augment_identity_from_env(OperatorIdentitySchema())
        assert "Noma Nomb" in aug.names

    def test_userprofile_basename_added_as_username(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from repo_sanitizer.helpers._operator_identity_loader import (
            augment_identity_from_env,
        )
        self._clear_env(monkeypatch)
        monkeypatch.setenv("USERPROFILE", r"C:\Users\operatorx")
        aug = augment_identity_from_env(OperatorIdentitySchema())
        assert "operatorx" in aug.usernames

    def test_domains_preserved_from_base(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from repo_sanitizer.helpers._operator_identity_loader import (
            augment_identity_from_env,
        )
        self._clear_env(monkeypatch)
        base = OperatorIdentitySchema(domains=["acme.io"])
        aug = augment_identity_from_env(base)
        assert "acme.io" in aug.domains

    def test_existing_name_not_duplicated(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from repo_sanitizer.helpers._operator_identity_loader import (
            augment_identity_from_env,
        )
        self._clear_env(monkeypatch)
        monkeypatch.setenv("GIT_AUTHOR_NAME", "Noma Nomb")
        base = OperatorIdentitySchema(names=["Noma Nomb"])
        aug = augment_identity_from_env(base)
        assert aug.names.count("Noma Nomb") == 1
