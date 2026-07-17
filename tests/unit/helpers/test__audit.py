"""test__audit.py — append-only audit-log + validate_artifact gate."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from repo_sanitizer.helpers._audit import (
    AuditLogger,
    append_audit,
    make_audit_entry,
    read_audit_jsonl,
)
from repo_sanitizer.helpers._fs_writer import FsWriter


def _fw(tmp_path: Path) -> tuple[FsWriter, Path]:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir(exist_ok=True)
    fw = FsWriter(
        source_path=tmp_path / "fake",
        allowed_roots=[allowed],
        override_forbidden=[],  # tmp_path em AppData; bypass defaults em testes
    )
    return fw, allowed / "Relatorios" / "audit-log.jsonl"


def _entry_kwargs(**overrides):
    base = {
        "run_id": "00e9aaa5-5517-4775-aee8-56d17ec75732",
        "agent_version": "0.1.0a1",
        "sentinel_sanitize_version": "v1.2.0",
        "secret_patterns_hash": "0" * 64,
        "action": "bootstrap_local_copies",
        "slug": "test",
        "source_path_redacted": "C:/VS Code/[REDACTED-PII]/repo",
        "dest_path_redacted": "C:/VS Code/Git Hub - [NOME]/GIT_test",
        "detail": {"x": "y"},
    }
    base.update(overrides)
    return base


def test_make_audit_entry_valida(tmp_path: Path) -> None:
    e = make_audit_entry(**_entry_kwargs())
    assert e.action == "bootstrap_local_copies"
    assert e.run_id.startswith("00e9aaa5")


def test_append_audit_idempotente(tmp_path: Path) -> None:
    fw, audit_file = _fw(tmp_path)
    e1 = make_audit_entry(**_entry_kwargs(action="dry_run_start"))
    e2 = make_audit_entry(**_entry_kwargs(action="dry_run_done"))
    append_audit(audit_file, e1, fw)
    append_audit(audit_file, e2, fw)
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["action"] == "dry_run_start"
    assert json.loads(lines[1])["action"] == "dry_run_done"


def test_audit_logger_facade(tmp_path: Path) -> None:
    fw, audit_file = _fw(tmp_path)
    logger = AuditLogger(
        audit_file=audit_file,
        fs_writer=fw,
        run_id="00e9aaa5-5517-4775-aee8-56d17ec75732",
        agent_version="0.1.0a1",
        sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="0" * 64,
        slug="test",
        source_path_redacted="src",
        dest_path_redacted="dest",
    )
    logger.log("dry_run_start", detail={"k": "v"})
    logger.log("dry_run_done")
    entries = read_audit_jsonl(audit_file)
    assert len(entries) == 2
    assert entries[0]["action"] == "dry_run_start"


def test_audit_entry_rejects_literal_secret(tmp_path: Path) -> None:
    """ADR-024 gate: literal ghp_xxxx em detail -> ValidationError."""
    with pytest.raises(ValidationError, match="secret detectado"):
        make_audit_entry(**_entry_kwargs(detail={"leaked": "ghp_abc123def456ghi789"}))


def test_audit_entry_rejects_bad_run_id() -> None:
    with pytest.raises(ValidationError):
        make_audit_entry(**_entry_kwargs(run_id="not-a-uuid"))


def test_audit_entry_rejects_bad_secret_patterns_hash() -> None:
    with pytest.raises(ValidationError):
        make_audit_entry(**_entry_kwargs(secret_patterns_hash="too-short"))


def test_audit_entry_extra_field_forbidden() -> None:
    # extra="forbid" deve rejeitar campos extras
    from repo_sanitizer.schemas.audit_entry import RepoSanitizerAuditEntry
    with pytest.raises(ValidationError):
        RepoSanitizerAuditEntry(**_entry_kwargs(), extra_field="x")  # type: ignore[call-arg]


def test_read_audit_jsonl_missing_file_returns_empty(tmp_path: Path) -> None:
    assert read_audit_jsonl(tmp_path / "nope.jsonl") == []
