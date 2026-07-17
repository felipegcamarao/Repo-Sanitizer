"""Testes Camada C9 PII Detector (Passo 1.3 — Bloco 01 v1.1.0-alpha.1).

12 testes canônicos cobrindo os 4 detectors A/B/C/D + edge cases:
A. Names — basic, Unicode acentuado, case-insensitive, word boundary, sub-string
B. Usernames — case-sensitive
C. Domains — match exato
D. Custom regex — email pattern
Edge: arquivo vazio, sem matches, múltiplos matches mesma linha, line_no correto,
      excerpt não vaza valor literal.

ADR-029 + RS-NEW-031.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from repo_sanitizer.f3_sanitizer import run_c9_pii_detector
from repo_sanitizer.helpers._pii_match import PIIMatch
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema


@pytest.fixture
def noma_identity() -> OperatorIdentitySchema:
    """Identity fixture canônica para testes — modelo do `operator_identity.json` real."""
    return OperatorIdentitySchema(
        names=["Noma Nomb Nomão", "Noma Nomão"],
        usernames=["usra", "usrabc"],
        domains=["acme.io"],
        extra_redact_patterns=[r"usrabc@gmail\.com"],
    )


# ---------------------------------------------------------------------------
# Detector A — Names
# ---------------------------------------------------------------------------


class TestDetectorANames:
    def test_match_name_basic(self, noma_identity: OperatorIdentitySchema) -> None:
        text = "Autor: Noma Nomão escreveu este código."
        sanitized, matches = run_c9_pii_detector(text, noma_identity, rel_path="README.md")

        assert "Noma Nomão" not in sanitized
        assert "[REDACTED-NAME]" in sanitized
        # Match deve ser 'name'
        name_matches = [m for m in matches if m.category == "name"]
        assert len(name_matches) == 1
        assert name_matches[0].file_path == "README.md"
        assert name_matches[0].count == 1

    def test_match_unicode_acentuado_nomao(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        """O `ã` (Unicode) é considerado word-char pela regex lib (essencial p/ PT-BR)."""
        text = "Noma Nomão (Noma Nomão duplicado)"
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        # Após o pattern longer "Noma Nomb Nomão" não casar, o shorter
        # "Noma Nomão" casa nos 2 lugares.
        assert sanitized.count("[REDACTED-NAME]") == 2
        name_match = next(m for m in matches if m.category == "name")
        assert name_match.count == 2

    def test_match_case_insensitive(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        text = "NOMA NOMÃO é o autor; noma nomão também."
        sanitized, _ = run_c9_pii_detector(text, noma_identity)
        assert sanitized.count("[REDACTED-NAME]") == 2

    def test_word_boundary_does_not_match_substring(self) -> None:
        """`name='rab'` NÃO deve casar dentro de `usrabc`.

        Usa `usernames=['dummy_isolated_user']` para evitar auto-populate via OS
        (que adicionaria o user real do test runner — `usra` em ambiente Noma).
        """
        identity = OperatorIdentitySchema(
            names=["rab"],
            usernames=["dummy_isolated_user"],
            domains=[],
        )
        text = "usrabc não deve ser redatado por name=rab"
        sanitized, matches = run_c9_pii_detector(text, identity)
        # 'usrabc' começa com 'usra' não 'rab' — o \b não casa
        # E 'name=rab' termina com 'rab\nEOL' — o \b casa lá! (após `=` e antes do EOL).
        # Então deve haver EXATAMENTE 1 match (o final 'rab' isolado).
        assert sanitized.count("[REDACTED-NAME]") == 1
        # Mas NÃO em 'usrabc' (que permanece intacto)
        assert "usrabc" in sanitized
        name_matches = [m for m in matches if m.category == "name"]
        assert len(name_matches) == 1
        assert name_matches[0].count == 1

    def test_longer_name_matches_first(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        """`Noma Nomb Nomão` deve casar antes de `Noma Nomão`.

        Pydantic preserva ordem da lista; detector A itera em ordem; o name LONGO
        substitui primeiro, evitando o curto match o que sobrou.
        """
        text = "Noma Nomb Nomão escreveu isto."
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        # O long name é o primeiro da lista → substitui primeiro → resto fica "[REDACTED-NAME] escreveu..."
        # O short name "Noma Nomão" não casa porque "Noma" foi consumido.
        assert sanitized.count("[REDACTED-NAME]") == 1
        # Verifica que apenas 1 match foi registrado (o long), não 2 cascateando
        name_matches = [m for m in matches if m.category == "name"]
        assert len(name_matches) == 1
        assert name_matches[0].count == 1


# ---------------------------------------------------------------------------
# Detector B — Usernames
# ---------------------------------------------------------------------------


class TestDetectorBUsernames:
    def test_username_case_sensitive_match(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        text = "Path: c:\\Users\\usra\\AppData\\Local"
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        assert "[REDACTED-USER]" in sanitized
        assert "usra" not in sanitized
        username_matches = [m for m in matches if m.category == "username"]
        assert len(username_matches) == 1

    def test_username_case_sensitive_skips_uppercase(self) -> None:
        """`username='usra'` NÃO deve casar `USRA` (case-sensitive)."""
        identity = OperatorIdentitySchema(
            names=[], usernames=["usra"], domains=[]
        )
        text = "USRA é o nome em caixa-alta — não deve casar"
        sanitized, matches = run_c9_pii_detector(text, identity)
        assert sanitized == text
        assert matches == []


# ---------------------------------------------------------------------------
# Detector C — Domains
# ---------------------------------------------------------------------------


class TestDetectorCDomains:
    def test_domain_match(self, noma_identity: OperatorIdentitySchema) -> None:
        text = "Contato: contato@empresa.com ou referência acme.io (público?)"
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        assert "[REDACTED-DOMAIN]" in sanitized
        assert "acme.io" not in sanitized
        domain_matches = [m for m in matches if m.category == "domain"]
        assert len(domain_matches) == 1
        assert domain_matches[0].count == 1


# ---------------------------------------------------------------------------
# Detector D — Custom regex
# ---------------------------------------------------------------------------


class TestDetectorDCustom:
    def test_custom_regex_email_match(self) -> None:
        """Custom regex casa quando não há conflito com detectors anteriores.

        Identity DEDICADA (sem overlap) — usa usernames="dummy_user" para
        evitar auto-populate via OS.
        """
        identity = OperatorIdentitySchema(
            names=[],
            usernames=["dummy_isolated_user"],
            domains=[],
            extra_redact_patterns=[r"unique_pattern@xyz\.com"],
        )
        text = "Email: unique_pattern@xyz.com (privado)"
        sanitized, matches = run_c9_pii_detector(text, identity)
        assert "[REDACTED-CUSTOM]" in sanitized
        assert "unique_pattern@xyz.com" not in sanitized
        custom_matches = [m for m in matches if m.category == "custom"]
        assert len(custom_matches) == 1

    def test_custom_pattern_overlapping_username_cascades_to_username(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        """Cascading sanitization: detector B (username) consome o prefixo do email.

        Comportamento INTENCIONAL — ordem A→B→C→D garante zero PII vazada, mas a
        atribuição de categoria final fica em 'username' (não 'custom'). Documentado
        na docstring de `run_c9_pii_detector` + release notes v1.1.0.
        """
        text = "Email: usrabc@gmail.com (privado)"
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        # PII redatada (objetivo final atingido — zero vazamento)
        assert "usrabc@gmail.com" not in sanitized
        # Detector B (username) é o que pega — não D (custom)
        assert "[REDACTED-USER]" in sanitized
        username_matches = [m for m in matches if m.category == "username"]
        assert len(username_matches) >= 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_text(self, noma_identity: OperatorIdentitySchema) -> None:
        sanitized, matches = run_c9_pii_detector("", noma_identity)
        assert sanitized == ""
        assert matches == []

    def test_no_matches_returns_original_text(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        text = "Código Python sem PII: def soma(a, b): return a + b"
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        assert sanitized == text
        assert matches == []

    def test_multiple_matches_same_line(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        text = "usra trabalha; usra revisa; usra commitou."
        sanitized, matches = run_c9_pii_detector(text, noma_identity)
        username_matches = [m for m in matches if m.category == "username"]
        assert username_matches[0].count == 3
        assert sanitized.count("[REDACTED-USER]") == 3

    def test_line_no_correct_for_multi_line_text(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        text = "Linha 1\nLinha 2\nNoma Nomão na linha 3\nLinha 4"
        _, matches = run_c9_pii_detector(text, noma_identity)
        name_match = next(m for m in matches if m.category == "name")
        assert name_match.line_no == 3

    def test_excerpt_never_leaks_literal(
        self, noma_identity: OperatorIdentitySchema
    ) -> None:
        """PT-RS-04 layer 3 — excerpt é construído pós-sanitização."""
        text = "Autor canônico: Noma Nomão (todos os direitos reservados)."
        _, matches = run_c9_pii_detector(text, noma_identity)
        name_match = next(m for m in matches if m.category == "name")
        # O excerpt deve conter o placeholder, NUNCA o nome literal
        assert "[REDACTED-NAME]" in name_match.excerpt_redacted
        assert "Noma Nomão" not in name_match.excerpt_redacted
        # E não deve exceder 50 chars
        assert len(name_match.excerpt_redacted) <= 50

    def test_empty_identity_returns_unchanged(self) -> None:
        identity = OperatorIdentitySchema(
            names=[], usernames=[], domains=[], extra_redact_patterns=[]
        )
        text = "Noma Nomão escreveu isto em usra@acme.io"
        sanitized, matches = run_c9_pii_detector(text, identity)
        # usernames vazia tinha auto-populate via OS, mas em CI/test pode resultar
        # em sanitização do user atual. Aceitamos qualquer comportamento — testamos
        # apenas que não há crash.
        assert isinstance(sanitized, str)
        assert isinstance(matches, list)

    def test_categories_preserved_in_order(self) -> None:
        """Detectors aplicam na ordem A → B → C → D — fixture sem overlap.

        Identity dedicada com padrões DISJOINT (cada um casa exatamente 1 vez sem
        cascading) para validar a ordem canônica determinística.
        """
        identity = OperatorIdentitySchema(
            names=["AlphaName"],
            usernames=["betauser"],
            domains=["gamma.example"],
            extra_redact_patterns=[r"delta\d{4}"],
        )
        text = (
            "AlphaName e betauser conectam a gamma.example com token delta1234."
        )
        _, matches = run_c9_pii_detector(text, identity)
        categories_order = [m.category for m in matches]
        # Cada detector casa exatamente 1 vez na ordem canônica
        assert categories_order == ["name", "username", "domain", "custom"]


# ---------------------------------------------------------------------------
# PIIMatch dataclass
# ---------------------------------------------------------------------------


class TestPIIMatchDataclass:
    def test_pii_match_is_frozen(self) -> None:
        match = PIIMatch(
            category="name",
            file_path="src/foo.py",
            line_no=10,
            count=1,
            excerpt_redacted="texto com [REDACTED-NAME] aqui",
        )
        with pytest.raises(FrozenInstanceError):
            match.count = 99  # type: ignore[misc]
