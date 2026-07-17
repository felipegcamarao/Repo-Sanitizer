"""_pii_redactor.py — redaction de PII em path strings (ADR-028 + RS-018).

Bloco 02 FULL impl. Aplica regex CPF/CNPJ/email/nome-proprio em path strings,
substituindo segmentos por `[REDACTED-PII]`. Usado em:
- FILTER_DIFF.md (paths listados — AT-03).
- SANITIZATION_REPORT.md (paths listados — AT-18).
- RepoSanitizerAuditEntry.{source,dest}_path_redacted (AT-40).

INV-12 LGPD aplicavel. INV-5 Modo Paranoico — aceita FP (preferimos redact em
excesso a vazar PII).

Patterns canonicos (ordem de aplicacao deliberada para evitar overlap):
1. CNPJ formatado (`12.345.678/0001-90`).
2. CPF formatado (`123.456.789-00`).
3. Email RFC5322-lite.
4. CPF cru (11 digitos isolados em path segment).
5. Nome proprio (heuristica `Nome-Sobrenome` / `Nome_Sobrenome` / `Nome Sobrenome`).

API publica:
    REDACTED_TOKEN: str
    redact_path(path: str) -> str
    redact_paths(paths: Iterable[str]) -> list[str]
    has_pii(path: str) -> bool
    summary(path: str) -> dict[str, int]   # contagem por categoria
"""
from __future__ import annotations

import re
from collections.abc import Iterable

# Patterns canonicos — defesa em camadas; aceita FP per INV-5 Modo Paranoico.
# Ordem deliberada: CNPJ antes CPF (evita match parcial do CNPJ pelo CPF cru).
_CNPJ_RE = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
_CPF_FORMATADO_RE = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# CPF cru: 11 digitos consecutivos NAO precedidos/seguidos por outro digito;
# usado apos CNPJ/CPF formatado para evitar overlap.
_CPF_CRU_RE = re.compile(r"(?<!\d)\d{11}(?!\d)")
# Nome proprio (heuristica conservadora):
# - Sequencias `Nome-Sobrenome`, `Nome_Sobrenome`, `Nome Sobrenome`
# - Inicial maiuscula (incluindo acentos PT-BR), >=3 chars cada palavra
# - Aceita FP em paths como "[NOME]-Alvia" mesmo quando publico aceitavel.
_NOME_PROPRIO_RE = re.compile(
    r"\b[A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç]{2,}([-_\s])[A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç]{2,}\b"
)

REDACTED_TOKEN = "[REDACTED-PII]"


def redact_path(path: str) -> str:
    """Aplica as 5 regexes sobre uma string de path; substitui por REDACTED_TOKEN.

    Ordem aplicacao: CNPJ -> CPF formatado -> email -> CPF cru -> nome proprio.
    """
    if not path:
        return path
    s = path
    s = _CNPJ_RE.sub(REDACTED_TOKEN, s)
    s = _CPF_FORMATADO_RE.sub(REDACTED_TOKEN, s)
    s = _EMAIL_RE.sub(REDACTED_TOKEN, s)
    s = _CPF_CRU_RE.sub(REDACTED_TOKEN, s)
    s = _NOME_PROPRIO_RE.sub(REDACTED_TOKEN, s)
    return s


def redact_paths(paths: Iterable[str]) -> list[str]:
    """Aplica `redact_path` em batch."""
    return [redact_path(p) for p in paths]


def has_pii(path: str) -> bool:
    """True sse alguma regex PII matcha. Util para tests/asserts."""
    if not path:
        return False
    return (
        _CNPJ_RE.search(path) is not None
        or _CPF_FORMATADO_RE.search(path) is not None
        or _EMAIL_RE.search(path) is not None
        or _CPF_CRU_RE.search(path) is not None
        or _NOME_PROPRIO_RE.search(path) is not None
    )


def summary(path: str) -> dict[str, int]:
    """Conta matches por categoria. Util para audit-log/relatorios."""
    return {
        "cnpj": len(_CNPJ_RE.findall(path)),
        "cpf_formatado": len(_CPF_FORMATADO_RE.findall(path)),
        "email": len(_EMAIL_RE.findall(path)),
        "cpf_cru": len(_CPF_CRU_RE.findall(path)),
        "nome_proprio": len(_NOME_PROPRIO_RE.findall(path)),
    }


__all__ = [
    "REDACTED_TOKEN",
    "has_pii",
    "redact_path",
    "redact_paths",
    "summary",
]
