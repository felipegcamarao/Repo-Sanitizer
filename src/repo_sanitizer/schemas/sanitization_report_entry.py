"""SanitizationReportEntry — Pydantic v2 schema para entries do SANITIZATION_REPORT.md.

ADR-003 + ADR-004 + ADR-024 + RS-005.

INVARIANTE: nenhum campo pode conter VALOR LITERAL do segredo detectado.
Representacao = tipo + path_redacted + linha + acao. `validate_artifact` aplica
SECRET_REGEXES sobre toda a serializacao pre-write (defesa em camadas).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from repo_sanitizer.schemas._secrets_gate import assert_no_literal_secrets

SanitizationCategory = Literal[
    "C1",  # .env*
    "C2",  # API keys hardcoded
    "C3",  # JWT/OAuth tokens
    "C4",  # DB credentials
    "C5",  # PII textual (LGPD)
    "C6",  # secrets em config (.json/.yml)
    "C7",  # certs/private keys
    "C8",  # client data exports (csv/db)
    "C9",  # URLs internas / hostnames sensiveis
    "C10", # comments TODO remover
]


SanitizationAction = Literal[
    "remove_file",
    "placeholder",
    "redact_inline",
    "envexample",
    "remove_line",
]


EncodingDetected = Literal[
    "utf-8",
    "utf-8-bom",
    "utf-16-le",
    "utf-16-be",
    "latin-1",
    "binary",
]


class SanitizationReportEntry(BaseModel):
    """Uma linha do SANITIZATION_REPORT.md emitida por F3.

    INVARIANTE (ADR-004 + RS-005): `tipo` e label canonico (ex: 'API_KEY_ghp_'),
    NUNCA o valor literal. `linha` e numero (1-based) ou None se aplicacao
    file-level (remove_file).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path_redacted: str = Field(
        ..., min_length=1,
        description="Path no destino sanitizado, redacted (ADR-028).",
    )
    linha: int | None = Field(
        default=None, ge=1,
        description="Linha (1-based) do match; None se acao file-level.",
    )
    categoria: SanitizationCategory
    tipo: str = Field(
        ..., min_length=1, max_length=80,
        description="Label canonico do tipo (ex: 'API_KEY_ghp_', 'CPF_FORMATADO', 'DATABASE_URL_postgres'). NUNCA valor literal.",
    )
    acao: SanitizationAction
    encoding_detected: EncodingDetected

    @model_validator(mode="after")
    def no_literal_secrets(self) -> SanitizationReportEntry:
        """ADR-004 INVIOLAVEL: aplica SECRET_REGEXES sobre dump. RS-005 enforce.

        S-OBS-01 v1.0.1: nome plural padronizado com `audit_entry.py` +
        `filter_diff_entry.py` (D-FF-02).
        """
        assert_no_literal_secrets(self.model_dump())
        return self


__all__ = [
    "EncodingDetected",
    "SanitizationAction",
    "SanitizationCategory",
    "SanitizationReportEntry",
]
