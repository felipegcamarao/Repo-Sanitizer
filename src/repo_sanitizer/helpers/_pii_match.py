"""_pii_match.py — Dataclass PIIMatch para Camada C9 (ADR-029 + RS-NEW-031).

Representa um match de PII do operador no destino sanitizado. NUNCA contém o
valor literal — apenas categoria + path + contexto redatado (PT-RS-04 triple-layer
defesa: schema + secrets-gate + PII redact pre-construção).

Categorias canônicas:
- "name"     → match em OperatorIdentity.names (case-insensitive Unicode)
- "username" → match em OperatorIdentity.usernames (case-sensitive)
- "domain"   → match em OperatorIdentity.domains (case-sensitive)
- "custom"   → match em OperatorIdentity.extra_redact_patterns (regex custom)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PIICategory = Literal["name", "username", "domain", "custom"]


@dataclass(frozen=True)
class PIIMatch:
    """Um agregado de matches PII em um arquivo (1 entry por (file, categoria)).

    Atributos:
        category: categoria canônica.
        file_path: rel path POSIX no destino (NÃO o caminho absoluto fonte).
        line_no: linha 1-based do PRIMEIRO match. None se contexto file-level (raro em C9).
        count: número total de matches DA MESMA CATEGORIA no arquivo.
        excerpt_redacted: ±20 chars de contexto AO REDOR do primeiro match, JÁ
            com placeholder aplicado (NUNCA contém valor literal). Máximo 50 chars.
    """

    category: PIICategory
    file_path: str
    line_no: int | None
    count: int
    excerpt_redacted: str


__all__ = ["PIICategory", "PIIMatch"]
