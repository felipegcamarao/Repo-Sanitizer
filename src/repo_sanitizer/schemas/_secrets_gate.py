"""_secrets_gate.py — gate compartilhado de validacao Pydantic v2 (ADR-024 + RS-005 + RS-011).

Aplica SECRET_REGEXES (cópia local Sentinel via tests/fixtures/sentinel/_sanitize.py)
sobre uma representacao serializada de um modelo Pydantic, rejeitando qualquer match
literal antes da escrita.

INVARIANTE (RS-005 + RS-011): nenhuma string em payload pode bater com SECRET_REGEXES.
Em match: raise SecretLeakInArtifactError com tipo + path (mas NUNCA o valor literal).

Reuso: importado por filter_diff_entry + sanitization_report_entry + audit_entry.

NOTA Bloco 01: importamos as regexes da copia local (tests/fixtures/sentinel/_sanitize.py).
Em Bloco 03 a matriz sera estendida via secret_patterns.py local (10 categorias).
"""
from __future__ import annotations

import sys
from pathlib import Path
from re import Pattern
from typing import Any

_SENTINEL_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests" / "fixtures" / "sentinel" / "_sanitize.py"
)


class SecretLeakInArtifactError(ValueError):
    """RS-005 + RS-011 enforce: valor literal de secret detectado em artefato."""


def _load_sentinel_regexes() -> list[Pattern[str]]:
    """Carrega SECRET_REGEXES da copia local Sentinel via importlib explicito.

    Estrategia: nao usa `import` direto porque o file vive fora do sys.path
    (tests/fixtures/sentinel/). Le e compila via exec controlado das constantes.

    Alternativa Bloco 03+: poderemos popular este modulo via importlib.util
    apos o secret_patterns.py local estar disponivel.
    """
    if not _SENTINEL_FIXTURE_PATH.exists():
        # Bootstrap ainda nao rodou — gate falha-safe = no-op + warning.
        sys.stderr.write(
            "[_secrets_gate] WARN: tests/fixtures/sentinel/_sanitize.py ausente. "
            "Execute scripts/bootstrap_local_copies.py para habilitar gate.\n"
        )
        return []
    # Carrega via importlib.util (file-system path -> module)
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_sentinel_sanitize_local", _SENTINEL_FIXTURE_PATH,
    )
    if spec is None or spec.loader is None:
        return []
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return list(getattr(module, "SECRET_REGEXES", []))


# Cache lazy (carregado on-demand 1x)
_CACHED_REGEXES: list[Pattern[str]] | None = None


def get_secret_regexes() -> list[Pattern[str]]:
    """Retorna a lista de regex de secret-detection (Sentinel copia local)."""
    global _CACHED_REGEXES
    if _CACHED_REGEXES is None:
        _CACHED_REGEXES = _load_sentinel_regexes()
    return _CACHED_REGEXES


def reload_secret_regexes() -> list[Pattern[str]]:
    """Forca recarga das regexes (uso em tests apos rebuild)."""
    global _CACHED_REGEXES
    _CACHED_REGEXES = None
    return get_secret_regexes()


def assert_no_literal_secrets(payload: Any) -> None:
    """Walks recursivo: rejeita match literal em qualquer string.

    Raises:
        SecretLeakInArtifactError: se algum campo string bater com SECRET_REGEXES.
            A mensagem inclui contexto MAS nao o valor literal (RS-005 + RS-011).
    """
    regexes = get_secret_regexes()
    if not regexes:
        return  # gate em modo no-op (pre-bootstrap)

    def _walk(obj: Any, path: str = "$") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                _walk(v, f"{path}.{k}")
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                _walk(v, f"{path}[{i}]")
        elif isinstance(obj, str):
            for rx in regexes:
                m = rx.search(obj)
                if m is not None:
                    raise SecretLeakInArtifactError(
                        f"RS-005/RS-011: valor literal de secret detectado em "
                        f"{path} (regex={rx.pattern!r}, len={m.end() - m.start()}). "
                        f"Use tipo + path + linha em vez do valor literal (ADR-004)."
                    )
        # int / float / bool / None / datetime / etc: nada a checar
        return

    _walk(payload)


# Aliases curtos (compat com naming Pipeline A+ pattern)
validate_artifact = assert_no_literal_secrets


__all__ = [
    "SecretLeakInArtifactError",
    "assert_no_literal_secrets",
    "get_secret_regexes",
    "reload_secret_regexes",
    "validate_artifact",
]
