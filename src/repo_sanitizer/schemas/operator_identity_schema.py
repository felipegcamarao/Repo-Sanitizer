"""OperatorIdentitySchema — Pydantic v2 schema para Camada C9 PII Detector (ADR-029 + RS-NEW-031).

Identidade do operador que alimenta a Camada C9 do F3 sanitizer (v1.1.0). Lista
hardcoded configurável via `src/repo_sanitizer/operator_identity.json` (gitignored,
per-operator) + auto-detect via `os.getlogin()`/`getpass.getuser()` em runtime.

Diferença em relação aos outros schemas:
- **Mutável** (não frozen=True): este schema é configuração local, não audit-entry.
- **Sem `no_literal_secrets`**: o conteúdo daqui ALIMENTA a sanitização — gate de secret
  rejeitaria nome próprio do operador como falso-positivo se ele acidentalmente
  coincidir com um pattern (`api_key`...) — irrelevante na prática mas evita acoplamento.
- **@model_validator(mode="before")** auto-popula usernames se vazio (ADR-029).
- **@field_validator(extra_redact_patterns)** valida via `re.compile` cada pattern
  rejeitando regex malformado pre-commit.

Carregado por `helpers/_operator_identity_loader.load_operator_identity(project_root)`.
"""
from __future__ import annotations

import getpass
import os
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _detect_os_usernames() -> list[str]:
    """Detecta usernames do SO via os.getlogin + getpass.getuser (dedup; ordem preservada).

    Retorna lista vazia se ambas as fontes falharem (CI sem TTY, ambiente atípico).
    NUNCA raise — best-effort por design (R-01 + ADR-013).
    """
    found: list[str] = []
    try:
        login = os.getlogin()
        if login:
            found.append(login)
    except OSError:
        pass
    try:
        user = getpass.getuser()
        if user and user not in found:
            found.append(user)
    except (OSError, KeyError):
        pass
    return found


class OperatorIdentitySchema(BaseModel):
    """Identidade do operador — alimenta Camada C9 PII Detector (ADR-029).

    Campos default vazios; `usernames` auto-popula via OS quando vazio na construção
    (model_validator mode=before). Operador edita via JSON gitignored para adicionar
    nomes próprios + domínios privados + regex custom.

    Caps (max_length) replicam o modelo de dados do 00-INDEX.md:
    - names: até 20 (cap defensivo; operador típico ≤5 variações)
    - usernames: até 10 (auto-detect + manual; SO costuma ter 1-2)
    - domains: até 10 (domínios privados)
    - extra_redact_patterns: até 20 regex custom
    """

    model_config = ConfigDict(extra="forbid")

    names: list[str] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "Nomes próprios do operador (case-insensitive match Unicode-aware "
            "via regex lib). Ex.: ['[NOME]']."
        ),
    )
    usernames: list[str] = Field(
        default_factory=list,
        max_length=10,
        description=(
            "Usernames de SO (case-sensitive match). Auto-populated via "
            "os.getlogin + getpass.getuser quando construído vazio (ADR-029)."
        ),
    )
    domains: list[str] = Field(
        default_factory=list,
        max_length=10,
        description=(
            "Domínios privados a redatar (ex.: ['acme.io']). NÃO se aplica a "
            "domínios públicos canônicos (github.com, python.org, etc.)."
        ),
    )
    extra_redact_patterns: list[str] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "Regex adicionais opt-in (validados por re.compile na construção). "
            "Use para emails específicos ou strings idiossincráticas do operador."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _auto_populate_usernames(cls, values: Any) -> Any:
        """ADR-029: se usernames vazio (ou ausente), auto-populate via OS detection.

        Permite que o operador passe `usernames=[]` explicitamente e ainda receba
        auto-populate — comportamento canônico documentado no manifesto.
        """
        if isinstance(values, dict):
            current = values.get("usernames")
            if not current:  # None, [], ou ausente
                detected = _detect_os_usernames()
                if detected:
                    values = {**values, "usernames": detected}
        return values

    @field_validator("extra_redact_patterns", mode="after")
    @classmethod
    def _validate_regex_patterns(cls, patterns: list[str]) -> list[str]:
        """ADR-029: cada pattern em extra_redact_patterns DEVE compilar via re.compile.

        Raises:
            ValueError: regex malformada (mensagem inclui pattern + reason original).
        """
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"Regex inválida em extra_redact_patterns: {pattern!r} "
                    f"(reason: {exc})"
                ) from exc
        return patterns


__all__ = ["OperatorIdentitySchema"]
