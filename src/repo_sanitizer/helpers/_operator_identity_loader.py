"""_operator_identity_loader.py — Loader de OperatorIdentitySchema (ADR-029 + RS-NEW-031).

Carrega `src/repo_sanitizer/operator_identity.json` (gitignored, per-operator) e
retorna `OperatorIdentitySchema` validado. Best-effort degrade-gracioso (ADR-013):
- Arquivo ausente → defaults com auto-populate de usernames via OS.
- JSON malformado → warning em stderr + defaults.
- Schema-fail → warning em stderr + defaults.

NUNCA raise. Garante que o pipeline F3 nunca quebra por config ausente/inválida —
o pior caso é Camada C9 redatar apenas o username do SO (mitigação parcial).

Path canônico (relativo a `project_root`):
    project_root / "src" / "repo_sanitizer" / "operator_identity.json"

Setup para o operador:
1. Copie `operator_identity.json.template` para `operator_identity.json` (mesma pasta).
2. Preencha `names`, `domains`, `extra_redact_patterns` com seus dados reais.
3. O arquivo é gitignored — NUNCA será commitado mesmo que seja modificado.
"""
from __future__ import annotations

import contextlib
import getpass
import json
import os
import re
import sys
from pathlib import Path

from pydantic import ValidationError

from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

OPERATOR_IDENTITY_REL_PATH = ("src", "repo_sanitizer", "operator_identity.json")

# MV-05 / RS-NEW-041 / ADR-038 / §5-8 — sinais de ambiente para augment de
# identidade. HARDCODED: lidos SO do AMBIENTE do operador, NUNCA do repo-fonte
# (anti-bypass RS-NEW-035). Sem subprocess git (INV-8 / §5-8).
_ENV_EMAIL_VARS = ("EMAIL", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")
_ENV_NAME_VARS = ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME")

# email RFC-ish ancorado (validacao defensiva do valor de env-var).
_EMAIL_VALIDATE_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$"
)


def operator_identity_path(project_root: Path) -> Path:
    """Resolve o path canônico do JSON do operador.

    Args:
        project_root: raiz do agente (ex.: `C:/VS Code/1A Agentes Pessoais/Repo Sanitizer Agent`).

    Returns:
        Path absoluto para `operator_identity.json` (pode não existir).
    """
    return project_root.joinpath(*OPERATOR_IDENTITY_REL_PATH)


def load_operator_identity(project_root: Path) -> OperatorIdentitySchema:
    """Carrega OperatorIdentitySchema do JSON gitignored — best-effort.

    Args:
        project_root: raiz do agente. Usado para resolver o path canônico.

    Returns:
        OperatorIdentitySchema validado. Em qualquer cenário de erro,
        retorna `OperatorIdentitySchema()` (defaults com auto-populate).

    Never raises: degrade gracioso em todos os cenários de erro (ADR-013).
    """
    target = operator_identity_path(project_root)
    if not target.exists():
        return OperatorIdentitySchema()

    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(
            f"[_operator_identity_loader] WARN: falha ao ler "
            f"{target.name} ({exc}); usando defaults.\n"
        )
        return OperatorIdentitySchema()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(
            f"[_operator_identity_loader] WARN: JSON malformado em "
            f"{target.name} (linha {exc.lineno}, col {exc.colno}); usando defaults.\n"
        )
        return OperatorIdentitySchema()

    try:
        return OperatorIdentitySchema.model_validate(data)
    except ValidationError as exc:
        sys.stderr.write(
            f"[_operator_identity_loader] WARN: schema-fail em "
            f"{target.name} ({exc.error_count()} erros); usando defaults.\n"
        )
        return OperatorIdentitySchema()


def _username_part_of_email(email: str) -> str:
    """Parte local do email (`[NOME]@acme.io` -> `[NOME]`). "" se invalido."""
    if "@" not in email:
        return ""
    local = email.split("@", 1)[0].strip()
    return local


def augment_identity_from_env(
    identity: OperatorIdentitySchema,
) -> OperatorIdentitySchema:
    """Amplia a identidade do operador com sinais do AMBIENTE (MV-05 / §5-8).

    Deriva nomes/usernames/emails do AMBIENTE do operador de forma HARDCODED:
    - `EMAIL` / `GIT_AUTHOR_EMAIL` / `GIT_COMMITTER_EMAIL` -> email + username local.
    - `GIT_AUTHOR_NAME` / `GIT_COMMITTER_NAME` -> nome proprio.
    - `os.getlogin()` / `getpass.getuser()` / `USERPROFILE` basename -> usernames.

    NUNCA le config do repo-fonte (anti-bypass RS-NEW-035); NUNCA roda subprocess
    git (INV-8 / §5-8). Best-effort: qualquer falha de leitura e ignorada (ADR-013,
    never-raise). Idempotente: dedup contra a identidade existente.

    Args:
        identity: identidade-base (do JSON gitignored ou defaults).

    Returns:
        Novo `OperatorIdentitySchema` com os sinais de ambiente agregados (sem
        mutar o original). Em qualquer erro de validacao, retorna o original.
    """
    extra_names = list(identity.names)
    extra_usernames = list(identity.usernames)
    extra_patterns = list(identity.extra_redact_patterns)

    def _add_username(u: str) -> None:
        u = u.strip()
        if u and u not in extra_usernames:
            extra_usernames.append(u)

    def _add_name(n: str) -> None:
        n = n.strip()
        if n and n not in extra_names:
            extra_names.append(n)

    def _add_email_pattern(e: str) -> None:
        if not e:
            return
        escaped = re.escape(e)
        if escaped not in extra_patterns:
            extra_patterns.append(escaped)

    # 1) Emails de ambiente -> pattern de redacao + username local.
    for var in _ENV_EMAIL_VARS:
        val = os.environ.get(var, "").strip()
        if val and _EMAIL_VALIDATE_RE.match(val):
            _add_email_pattern(val)
            local = _username_part_of_email(val)
            if local:
                _add_username(local)

    # 2) Nomes proprios de ambiente (git config exportado como env-var).
    for var in _ENV_NAME_VARS:
        val = os.environ.get(var, "").strip()
        if val:
            _add_name(val)

    # 3) Usernames de SO (sem TTY-dependencia critica; best-effort).
    try:
        login = os.getlogin()
        if login:
            _add_username(login)
    except OSError:
        pass
    with contextlib.suppress(OSError, KeyError):
        _add_username(getpass.getuser())

    # 4) USERPROFILE basename (Windows: `C:\Users\[NOME]` -> `[NOME]`).
    userprofile = os.environ.get("USERPROFILE", "").strip()
    if userprofile:
        base = Path(userprofile).name
        if base:
            _add_username(base)

    # Respeita os caps do schema (max_length); trunca defensivamente.
    try:
        return OperatorIdentitySchema(
            names=extra_names[:20],
            usernames=extra_usernames[:10],
            domains=list(identity.domains),
            extra_redact_patterns=extra_patterns[:20],
        )
    except ValidationError:
        return identity


__all__ = [
    "OPERATOR_IDENTITY_REL_PATH",
    "augment_identity_from_env",
    "load_operator_identity",
    "operator_identity_path",
]
