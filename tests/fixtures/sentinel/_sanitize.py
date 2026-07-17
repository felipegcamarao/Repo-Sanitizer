#!/usr/bin/env python3
"""_sanitize.py — Sanitização de credenciais e redação de payload (Pipeline A+).

Extraído de helpers/web_search.py (Sentinel v1.2.0 — ADR-013 + ADR-014).

Responsabilidades:
- SECRET_REGEXES (RS-002 + RS-018): regex de credenciais a redigir antes de output.
- sanitize_for_output(text): aplica SECRET_REGEXES; retorna (texto_redigido, n_redacoes).
- sanitize_report_output(content): wrapper para pipeline de relatório (F08).
- _redact_in_place(obj): percurso recursivo de objeto Python pós-parse (ADR-014).
- _safe_redact_payload(payload): redação de dict via percurso recursivo (Refactor B).

Não-objetivos:
- NÃO contém engines (Tavily/DDG) — vivem em _search_engines.py.
- NÃO contém CLI nem load_dotenv — permanecem em web_search.py.
- NÃO logga (responsabilidade do caller via safelog).
"""
from __future__ import annotations

__version__ = "1.0.0"

import copy
import re

# RS-002 + RS-018: regex de credenciais que devem ser redigidos antes de qualquer output.
SECRET_REGEXES = [
    re.compile(r"tvly-[A-Za-z0-9]+"),
    re.compile(r"AKIA[A-Z0-9]+"),
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)(api[_-]?key|password|secret)\s*[:=]\s*[^\s\"]+"),
]


def sanitize_for_output(text: str):
    """Retorna (texto_redigido, n_redacoes). RS-002 + RS-018."""
    n = 0
    for r in SECRET_REGEXES:
        text, count = r.subn("[REDACTED]", text)
        n += count
    return text, n


def sanitize_report_output(content: str):
    """RS-018: redige credenciais no relatório antes do save.

    Retorna (content_redigido, n_redacoes). O caller (F08) decide se inclui o
    rodapé '⚠️ N credenciais redigidas no relatório.'
    """
    return sanitize_for_output(content)


def _redact_in_place(obj):
    """Percorre recursivamente dict/list/scalar; redige strings que matchem SECRET_REGEXES.

    ADR-014 (Sentinel v1.2.0): substitui o regex `[^\\s\"]+` aplicado sobre
    serialização (v1.0.x) por percurso de objeto Python pós-parse. Elimina
    edge cases de regex sobre JSON serializado (Retro v1.0.0 lição #3).

    Mutação in-place de dict/list (eficiência). Strings retornam novo objeto
    (imutáveis em Python). Tipos não-string passam intactos.
    """
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            obj[k] = _redact_in_place(obj[k])
        return obj
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i] = _redact_in_place(v)
        return obj
    if isinstance(obj, str):
        new, _n = sanitize_for_output(obj)
        return new
    return obj  # int/float/bool/None: nada a redigir


def _safe_redact_payload(payload: dict) -> dict:
    """Refactor B (ADR-014): redação por percurso de objeto Python.

    Compatibilidade: preserva contrato `out["redactions"] = n` quando n > 0,
    via contagem auxiliar (visitor pattern leve).

    Não muta o input — sempre retorna deep-copy via copy.deepcopy() (evita
    overhead de json.dumps→json.loads).
    """
    total_n = [0]  # closure cell

    def _visit(o):
        if isinstance(o, dict):
            for k in list(o.keys()):
                o[k] = _visit(o[k])
            return o
        if isinstance(o, list):
            for i, v in enumerate(o):
                o[i] = _visit(v)
            return o
        if isinstance(o, str):
            new, n = sanitize_for_output(o)
            total_n[0] += n
            return new
        return o

    out = copy.deepcopy(payload)
    out = _visit(out)
    if total_n[0] > 0:
        out["redactions"] = total_n[0]
    return out
