"""_runtime_guard.py — heuristica header check para detectar runtime Claude Code (DEF-07 + INV-9 + RS-025).

[NOME] e single-user; criptografia de runtime e overkill (DEF-07). Heuristica
zero-dep: inspeciona env vars + marker stdin opcional + nome do processo pai.

API publica:
    detect_runtime() -> RuntimeKind
    is_claude_code() -> bool
    runtime_marker() -> str  # string descritiva (audit-log)

RuntimeKind:
    "claude_code"     # Claude Code chat agente detectado
    "claude_cli"      # Claude Code CLI fora do chat (degrade gracioso possivel)
    "vs_code_terminal" # VS Code terminal sem Claude Code chat
    "unknown"         # [NOME] rodando standalone (pode degradar F4)

Bloco 05 (F4 README) usa detect_runtime() para decidir entre:
- Modo full: emite kit JSON + instrucao /generate-readme para [NOME] invocar
  Claude Code chat (INV-9 canonico).
- Modo degrade: gera stub PT-BR + warning no SANITIZATION_REPORT (ADR-013).
"""
from __future__ import annotations

import os
from typing import Literal

RuntimeKind = Literal["claude_code", "claude_cli", "vs_code_terminal", "unknown"]


# Env vars que indicam Claude Code chat agente ativo (heuristica).
# [NOME] pode setar `CLAUDE_CODE_RUNTIME=chat` manualmente se ambiente nao detectar.
_CLAUDE_CODE_ENV_MARKERS = (
    "CLAUDE_CODE_RUNTIME",        # override explicito [NOME]
    "CLAUDECODE",                  # marker Claude Code chat
    "CLAUDE_CODE_SESSION_ID",     # potencial marker futuro
    "ANTHROPIC_CLI_SESSION",       # CLI fora do chat
)

_VS_CODE_ENV_MARKERS = (
    "VSCODE_PID",
    "VSCODE_IPC_HOOK_CLI",
    "TERM_PROGRAM",  # value = "vscode"
)


def detect_runtime() -> RuntimeKind:
    """Heuristica header check: inspeciona env vars (DEF-07).

    Ordem de precedencia:
    1. Override [NOME] (`CLAUDE_CODE_RUNTIME=chat|cli|degrade`).
    2. Markers Claude Code chat.
    3. Markers VS Code terminal (sem chat).
    4. Unknown (degrade Bloco 05 F4).
    """
    # 1. Override [NOME] explicito
    override = os.environ.get("CLAUDE_CODE_RUNTIME", "").strip().lower()
    if override == "chat":
        return "claude_code"
    if override == "cli":
        return "claude_cli"
    if override == "degrade":
        return "unknown"

    # 2. Markers Claude Code chat
    if os.environ.get("CLAUDECODE", "").strip() in {"1", "true", "yes"}:
        return "claude_code"
    if os.environ.get("CLAUDE_CODE_SESSION_ID"):
        return "claude_code"

    # 3. Markers VS Code terminal
    if os.environ.get("TERM_PROGRAM", "").lower() == "vscode":
        return "vs_code_terminal"
    if os.environ.get("VSCODE_PID"):
        return "vs_code_terminal"

    # 4. Unknown
    if os.environ.get("ANTHROPIC_CLI_SESSION"):
        return "claude_cli"

    return "unknown"


def is_claude_code() -> bool:
    """Atalho boolean: True sse runtime e Claude Code chat agente."""
    return detect_runtime() == "claude_code"


def runtime_marker() -> str:
    """String descritiva para audit-log / SANITIZATION_REPORT footer."""
    kind = detect_runtime()
    detail = {
        "claude_code": "Claude Code chat agente (INV-9 canonico).",
        "claude_cli": "Claude Code CLI (degrade parcial; chat preferivel).",
        "vs_code_terminal": "VS Code terminal sem Claude Code chat (F4 degrade ativo).",
        "unknown": "Runtime nao detectado (F4 degrade gracioso ADR-013).",
    }
    return f"{kind}: {detail[kind]}"


__all__ = [
    "RuntimeKind",
    "detect_runtime",
    "is_claude_code",
    "runtime_marker",
]
