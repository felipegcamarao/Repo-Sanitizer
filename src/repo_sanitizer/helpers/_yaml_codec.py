#!/usr/bin/env python3
"""_yaml_codec.py — SSOT para frontmatter YAML mínimo (Pipeline A+).

Extraído de memory_writer.py (serialize) + memory_reader.py (parse) — Sentinel
v1.2.0 ADR-015. Elimina duplicação identificada pelo STAFF-004 (v1.1.0).

Contrato: top-level escalares + nested 1 nível (ex.: `origem`).
Não suporta listas top-level, anchors YAML, multi-document.

API pública:
- parse_frontmatter(text: str) -> dict
- serialize_frontmatter(d: dict) -> str

Property invariante:
- parse_frontmatter(serialize_frontmatter(d)) == d, para top-level escalar
  + nested 1 nível com chaves str e valores escalares JSON-serializáveis.

Não-objetivos:
- NÃO contém logging, hashing, validação de patterns ou audit trail —
  responsabilidade de memory_writer/memory_reader.
- NÃO usa yaml.unsafe_load nem eval — só `re` + `json` (RS-013).
"""
from __future__ import annotations

__version__ = "1.0.0"

import json
import re

# Helper privado migrado de memory_writer.py (preserva regex literal existente).
_SCALAR_NEEDS_QUOTE_RE = re.compile(r'[:#\[\]\{\}"\n]')


def _emit_scalar(v) -> str:
    """Serializa um escalar para YAML/JSON (memory_writer-compatible)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, str):
        if not v or _SCALAR_NEEDS_QUOTE_RE.search(v):
            return json.dumps(v, ensure_ascii=False)
        return v
    return json.dumps(v, ensure_ascii=False)


def _parse_scalar(v: str):
    """Parser inverso de _emit_scalar (memory_reader-compatible)."""
    s = v.strip()
    if s == "" or s.lower() == "null":
        return None
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    if (s.startswith("[") and s.endswith("]")) or (
        s.startswith("{") and s.endswith("}")
    ):
        try:
            return json.loads(s)
        except Exception:
            return s
    if s.startswith('"') and s.endswith('"'):
        try:
            return json.loads(s)
        except Exception:
            return s[1:-1]
    if s.startswith("'") and s.endswith("'"):
        return s[1:-1].replace("''", "'")
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


def serialize_frontmatter(d: dict) -> str:
    """Serializa dict (top-level + nested 1 nível) para frontmatter YAML."""
    lines = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{k}:")
            for k2, v2 in v.items():
                lines.append(f"  {k2}: {_emit_scalar(v2)}")
        else:
            lines.append(f"{k}: {_emit_scalar(v)}")
    return "\n".join(lines)


def parse_frontmatter(text: str) -> dict:
    """Parser mínimo: top-level escalares + nested 1 nível (`origem`)."""
    lines = text.splitlines()
    result = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if line.startswith(" "):
            i += 1
            continue
        if ":" not in line:
            i += 1
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val == "":
            nested = {}
            j = i + 1
            while j < len(lines) and (
                lines[j].startswith("  ") or not lines[j].strip()
            ):
                if not lines[j].strip():
                    j += 1
                    continue
                inner = lines[j][2:]
                if ":" in inner:
                    nk, _, nv = inner.partition(":")
                    nested[nk.strip()] = _parse_scalar(nv.strip())
                j += 1
            result[key] = nested
            i = j
            continue
        result[key] = _parse_scalar(val)
        i += 1
    return result
