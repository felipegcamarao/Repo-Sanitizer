"""test_pydantic_gates.py — 3 schemas Pydantic v2 + validate_artifact (ADR-024)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from repo_sanitizer.schemas import (
    FilterDiffEntry,
    RepoSanitizerAuditEntry,
    SanitizationReportEntry,
)
from repo_sanitizer.schemas._secrets_gate import (
    SecretLeakInArtifactError,
    assert_no_literal_secrets,
)

# ----------------------- FilterDiffEntry -----------------------


def test_filter_diff_entry_ok() -> None:
    e = FilterDiffEntry(
        path_redacted="README.md",
        grupo="C",
        motivo="whitelist canonica",
        acao="incluir",
        is_binary=False,
        size_bytes=42,
    )
    assert e.path_redacted == "README.md"


def test_filter_diff_entry_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        FilterDiffEntry(  # type: ignore[call-arg]
            path_redacted="README.md", grupo="C", motivo="x",
            acao="incluir", size_bytes=1, junk="bad",
        )


def test_filter_diff_entry_bad_grupo() -> None:
    with pytest.raises(ValidationError):
        FilterDiffEntry(
            path_redacted="x", grupo="Z", motivo="x",  # type: ignore[arg-type]
            acao="incluir", size_bytes=1,
        )


def test_filter_diff_entry_negative_size_forbidden() -> None:
    with pytest.raises(ValidationError):
        FilterDiffEntry(
            path_redacted="x", grupo="A", motivo="x",
            acao="excluir", size_bytes=-1,
        )


# ----------------------- SanitizationReportEntry -----------------------


def test_sanitization_report_entry_ok() -> None:
    e = SanitizationReportEntry(
        path_redacted="config.json", linha=12,
        categoria="C2", tipo="API_KEY_ghp_",
        acao="placeholder", encoding_detected="utf-8",
    )
    assert e.categoria == "C2"


def test_sanitization_report_entry_rejects_literal_secret() -> None:
    with pytest.raises(ValidationError, match="secret detectado"):
        SanitizationReportEntry(
            path_redacted="x.py", linha=1, categoria="C2",
            tipo="ghp_abc123def456ghi789jkl",  # valor literal proibido
            acao="placeholder", encoding_detected="utf-8",
        )


def test_sanitization_report_entry_categoria_invalid() -> None:
    with pytest.raises(ValidationError):
        SanitizationReportEntry(
            path_redacted="x", linha=None, categoria="CXX",  # type: ignore[arg-type]
            tipo="X", acao="placeholder", encoding_detected="utf-8",
        )


def test_sanitization_report_entry_acao_invalid() -> None:
    with pytest.raises(ValidationError):
        SanitizationReportEntry(
            path_redacted="x", linha=None, categoria="C1",
            tipo="ENV_FILE", acao="purge_with_fire",  # type: ignore[arg-type]
            encoding_detected="utf-8",
        )


# ----------------------- RepoSanitizerAuditEntry -----------------------


def _audit_kwargs(**overrides):
    base = {
        "run_id": "00e9aaa5-5517-4775-aee8-56d17ec75732",
        "timestamp": datetime.now(UTC),
        "agent_version": "0.1.0a1",
        "sentinel_sanitize_version": "v1.2.0",
        "secret_patterns_hash": "a" * 64,
        "action": "bootstrap_local_copies",
        "slug": "test",
        "source_path_redacted": "C:/VS Code/[REDACTED-PII]/repo",
        "dest_path_redacted": "C:/VS Code/Git Hub - [NOME]/GIT_test",
        "detail": {"x": "y"},
    }
    base.update(overrides)
    return base


def test_audit_entry_ok() -> None:
    e = RepoSanitizerAuditEntry(**_audit_kwargs())
    assert e.action == "bootstrap_local_copies"


def test_audit_entry_frozen() -> None:
    e = RepoSanitizerAuditEntry(**_audit_kwargs())
    with pytest.raises(ValidationError):
        e.action = "f1_filter_done"  # type: ignore[misc]


def test_audit_entry_run_id_uuid_only() -> None:
    with pytest.raises(ValidationError):
        RepoSanitizerAuditEntry(**_audit_kwargs(run_id="not-uuid"))


def test_audit_entry_secret_patterns_hash_required_hex() -> None:
    with pytest.raises(ValidationError):
        RepoSanitizerAuditEntry(**_audit_kwargs(secret_patterns_hash="zz" * 32))


# ----------------------- _secrets_gate -----------------------


def test_assert_no_literal_secrets_passes_safe() -> None:
    assert_no_literal_secrets({"foo": "bar", "n": 42, "li": ["safe", 1, None]})


def test_assert_no_literal_secrets_detects_ghp() -> None:
    with pytest.raises(SecretLeakInArtifactError):
        assert_no_literal_secrets({"x": "ghp_abc123def456ghi789jkl"})


def test_assert_no_literal_secrets_detects_nested() -> None:
    payload = {
        "outer": {
            "inner": ["safe", "ghp_abc123def456ghi789jkl", "also safe"],
        },
    }
    with pytest.raises(SecretLeakInArtifactError, match=r"inner\[1\]"):
        assert_no_literal_secrets(payload)
