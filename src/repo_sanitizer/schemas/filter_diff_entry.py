"""FilterDiffEntry — Pydantic v2 schema para entries do FILTER_DIFF.md (ADR-005 + ADR-028 + RS-018).

Cada arquivo classificado por F1 e emitido como FilterDiffEntry. `path_redacted`
e gerado por _pii_redactor; entry inteira passa por validate_artifact que aplica
SECRET_REGEXES sobre serializacao (defesa em camadas; nao deve ter segredo na
linha de path, mas redundancia mitiga edge case).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from repo_sanitizer.schemas._secrets_gate import assert_no_literal_secrets

GroupLabel = Literal["A", "B", "C"]
"""A = lixo deterministico (exclui); B = ambiguo (warn / requer review); C = whitelist."""

ActionLabel = Literal["incluir", "excluir", "symlink_excluded"]


class FilterDiffEntry(BaseModel):
    """Uma linha do FILTER_DIFF.md emitida por F1."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path_redacted: str = Field(
        ..., min_length=1,
        description="Path relativo ao destino, redacted via _pii_redactor (ADR-028).",
    )
    grupo: GroupLabel
    motivo: str = Field(
        ..., min_length=1,
        description="Razao curta da classificacao (ex: '.git deterministico', 'whitelist LICENSE').",
    )
    acao: ActionLabel
    is_binary: bool = Field(
        default=False,
        description="Classificacao por magic-bytes (_binary_detector). Default False.",
    )
    size_bytes: int = Field(..., ge=0, description="Tamanho do arquivo em bytes.")
    grupo_reason_detail: str | None = Field(
        default=None,
        description="Detalhe adicional opcional (ex: heuristica Grupo B match).",
    )

    @model_validator(mode="after")
    def no_literal_secrets(self) -> FilterDiffEntry:
        """RS-005 + ADR-004 + ADR-024: rejeita literal secret em qualquer string."""
        assert_no_literal_secrets(self.model_dump())
        return self


__all__ = ["ActionLabel", "FilterDiffEntry", "GroupLabel"]
