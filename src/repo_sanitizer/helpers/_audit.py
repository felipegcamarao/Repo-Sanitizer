"""_audit.py — writer append-only do audit-log.jsonl (ADR-016 + ADR-024).

Audit-log proprio do repo-sanitizer-agent (separado do SafeLog Pipeline A+;
D-T2-06 + RS-027). Gravacao via FsWriter SSOT (ADR-020). Cada entry e validada
contra RepoSanitizerAuditEntry Pydantic v2 que aplica SECRET_REGEXES gate
pre-write.

API publica:
    make_audit_entry(...) -> RepoSanitizerAuditEntry
    append_audit(audit_file, entry, fs_writer) -> None
    AuditLogger(audit_file, fs_writer, run_id, agent_version, ...).log(action, ...)

Storage: `/Relatorios/audit-log.jsonl` (append-only; DEF-05 only-append no MVP).
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from repo_sanitizer.schemas.audit_entry import (
    AuditAction,
    RepoSanitizerAuditEntry,
)

if TYPE_CHECKING:
    from repo_sanitizer.helpers._fs_writer import FsWriter


def now_iso8601() -> str:
    """ISO 8601 UTC timestamp (compat com _integrity local-copy)."""
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def make_audit_entry(
    *,
    run_id: str,
    agent_version: str,
    sentinel_sanitize_version: str,
    secret_patterns_hash: str,
    action: AuditAction,
    slug: str,
    source_path_redacted: str,
    dest_path_redacted: str,
    detail: dict[str, Any] | None = None,
    timestamp: _dt.datetime | None = None,
) -> RepoSanitizerAuditEntry:
    """Constroi RepoSanitizerAuditEntry validado (pre-write gate via Pydantic)."""
    return RepoSanitizerAuditEntry(
        run_id=run_id,
        timestamp=timestamp or _dt.datetime.now(_dt.UTC),
        agent_version=agent_version,
        sentinel_sanitize_version=sentinel_sanitize_version,
        secret_patterns_hash=secret_patterns_hash,
        action=action,
        slug=slug,
        source_path_redacted=source_path_redacted,
        dest_path_redacted=dest_path_redacted,
        detail=detail or {},
    )


def append_audit(
    audit_file: Path,
    entry: RepoSanitizerAuditEntry,
    fs_writer: FsWriter,
) -> None:
    """Append uma entry validada ao JSONL via FsWriter.safe_append_text.

    Args:
        audit_file: path `/Relatorios/audit-log.jsonl`.
        entry: RepoSanitizerAuditEntry ja validada.
        fs_writer: FsWriter instance (gate boundary).
    """
    line = entry.model_dump_json() + "\n"
    fs_writer.safe_append_text(audit_file, line)


class AuditLogger:
    """Conveniencia para emitir audit entries com metadata default fixa.

    Uso:
        logger = AuditLogger(
            audit_file=Path("/path/Relatorios/audit-log.jsonl"),
            fs_writer=fw,
            run_id="...",
            agent_version="0.1.0a1",
            sentinel_sanitize_version="v1.2.0",
            secret_patterns_hash="abc...",
            slug="meu-repo",
            source_path_redacted="C:/VS Code/[REDACTED-PII]/repo",
            dest_path_redacted="C:/VS Code/Git Hub - [NOME]/GIT_meu-repo",
        )
        logger.log("dry_run_start", detail={"k": "v"})
    """

    def __init__(
        self,
        audit_file: Path,
        fs_writer: FsWriter,
        run_id: str,
        agent_version: str,
        sentinel_sanitize_version: str,
        secret_patterns_hash: str,
        slug: str,
        source_path_redacted: str,
        dest_path_redacted: str,
    ) -> None:
        self.audit_file = audit_file
        self.fs_writer = fs_writer
        self.run_id = run_id
        self.agent_version = agent_version
        self.sentinel_sanitize_version = sentinel_sanitize_version
        self.secret_patterns_hash = secret_patterns_hash
        self.slug = slug
        self.source_path_redacted = source_path_redacted
        self.dest_path_redacted = dest_path_redacted

    def log(
        self,
        action: AuditAction,
        detail: dict[str, Any] | None = None,
    ) -> RepoSanitizerAuditEntry:
        """Constroi + valida + grava entry."""
        entry = make_audit_entry(
            run_id=self.run_id,
            agent_version=self.agent_version,
            sentinel_sanitize_version=self.sentinel_sanitize_version,
            secret_patterns_hash=self.secret_patterns_hash,
            action=action,
            slug=self.slug,
            source_path_redacted=self.source_path_redacted,
            dest_path_redacted=self.dest_path_redacted,
            detail=detail or {},
        )
        append_audit(self.audit_file, entry, self.fs_writer)
        return entry


def read_audit_jsonl(audit_file: Path) -> list[dict[str, Any]]:
    """Le audit-log.jsonl + retorna lista de dicts (uso em testes/dashboards)."""
    if not audit_file.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


__all__ = [
    "AuditLogger",
    "append_audit",
    "make_audit_entry",
    "now_iso8601",
    "read_audit_jsonl",
]
