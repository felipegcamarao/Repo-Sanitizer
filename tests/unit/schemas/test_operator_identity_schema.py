"""Testes OperatorIdentitySchema (Passo 1.1 — Bloco 01 v1.1.0-alpha.1).

5 testes canônicos:
1. defaults (sem args) → instancia OK; usernames auto-populated com fallback gracioso
2. extra=forbid → ValidationError em campo extra
3. regex válida em extra_redact_patterns → instancia OK
4. regex malformada → ValidationError com mensagem informativa
5. usernames=[] explícito → auto-populate dispara mesmo assim
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from repo_sanitizer.schemas.operator_identity_schema import (
    OperatorIdentitySchema,
    _detect_os_usernames,
)


class TestOperatorIdentityDefaults:
    """Test 1 — defaults."""

    def test_default_instance_has_empty_optional_lists(self) -> None:
        identity = OperatorIdentitySchema()
        assert identity.names == []
        assert identity.domains == []
        assert identity.extra_redact_patterns == []

    def test_default_instance_auto_populates_usernames(self) -> None:
        """Auto-populate é best-effort: se OS detection retornar [], usernames fica [].

        Não fazemos assert sobre conteúdo específico — apenas que o validator rodou
        (não raise). Em Windows típico, conterá pelo menos 1 user; em CI sem TTY
        pode estar vazio.
        """
        identity = OperatorIdentitySchema()
        detected = _detect_os_usernames()
        assert identity.usernames == detected, (
            f"usernames={identity.usernames} esperado={detected}"
        )


class TestExtraForbid:
    """Test 2 — ConfigDict(extra=forbid)."""

    def test_extra_field_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            OperatorIdentitySchema(unknown_field="value")  # type: ignore[call-arg]
        assert "unknown_field" in str(exc_info.value)


class TestExtraRedactPatternsRegex:
    """Tests 3 e 4 — validação regex em extra_redact_patterns."""

    def test_valid_regex_accepts(self) -> None:
        identity = OperatorIdentitySchema(
            extra_redact_patterns=[
                r"[NOME]@gmail\.com",
                r"\bAB\d{4}\b",
            ]
        )
        assert len(identity.extra_redact_patterns) == 2

    def test_malformed_regex_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            OperatorIdentitySchema(extra_redact_patterns=[r"["])  # unterminated set
        msg = str(exc_info.value)
        assert "Regex inválida" in msg
        assert "[" in msg


class TestUsernamesExplicitEmpty:
    """Test 5 — usernames=[] explícito dispara auto-populate."""

    def test_explicit_empty_usernames_triggers_autopopulate(self) -> None:
        identity = OperatorIdentitySchema(usernames=[])
        detected = _detect_os_usernames()
        assert identity.usernames == detected

    def test_explicit_usernames_preserved(self) -> None:
        """Operador passa lista NÃO-vazia → preservada (sem auto-populate sobrescrever)."""
        identity = OperatorIdentitySchema(usernames=["alice", "bob"])
        assert identity.usernames == ["alice", "bob"]


class TestDetectOsUsernamesGracefulDegradation:
    """Branches defensivos de _detect_os_usernames — best-effort R-01."""

    def test_getlogin_oserror_falls_back_to_getpass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OSError em os.getlogin não interrompe — getpass.getuser ainda tentado."""
        from repo_sanitizer.schemas import operator_identity_schema as mod

        def raise_oserror() -> str:
            raise OSError("no controlling terminal")

        monkeypatch.setattr(mod.os, "getlogin", raise_oserror)
        monkeypatch.setattr(mod.getpass, "getuser", lambda: "fallback_user")

        usernames = mod._detect_os_usernames()
        assert usernames == ["fallback_user"]

    def test_getpass_keyerror_returns_only_login(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """KeyError em getpass.getuser não interrompe — getlogin já capturado."""
        from repo_sanitizer.schemas import operator_identity_schema as mod

        def raise_keyerror() -> str:
            raise KeyError("USERNAME not set")

        monkeypatch.setattr(mod.os, "getlogin", lambda: "primary_user")
        monkeypatch.setattr(mod.getpass, "getuser", raise_keyerror)

        usernames = mod._detect_os_usernames()
        assert usernames == ["primary_user"]

    def test_both_sources_fail_returns_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ambas fontes falham → lista vazia (sem raise; degrade silencioso)."""
        from repo_sanitizer.schemas import operator_identity_schema as mod

        def raise_oserror() -> str:
            raise OSError("nope")

        monkeypatch.setattr(mod.os, "getlogin", raise_oserror)
        monkeypatch.setattr(mod.getpass, "getuser", raise_oserror)

        assert mod._detect_os_usernames() == []


class TestAutoPopulateNonDictValues:
    """Branch onde model_validator recebe valor não-dict (model_validate de instância)."""

    def test_validate_with_model_instance_skips_autopopulate(self) -> None:
        """`OperatorIdentitySchema.model_validate(instance)` → values não-dict; passa direto."""
        original = OperatorIdentitySchema(usernames=["explicit"])
        revalidated = OperatorIdentitySchema.model_validate(original)
        assert revalidated.usernames == ["explicit"]
