"""schemas/ — Pydantic v2 extra='forbid' canonizados (ADR-024 + ADR-029).

- FilterDiffEntry (Bloco 02 v1.0)
- SanitizationReportEntry (Bloco 03 v1.0)
- RepoSanitizerAuditEntry (Bloco 01..05 v1.0)
- OperatorIdentitySchema (Bloco 01 v1.1.0 — ADR-029)
"""
from __future__ import annotations

from repo_sanitizer.schemas.audit_entry import (
    AuditAction,
    RepoSanitizerAuditEntry,
)
from repo_sanitizer.schemas.filter_diff_entry import FilterDiffEntry
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema
from repo_sanitizer.schemas.sanitization_report_entry import (
    SanitizationCategory,
    SanitizationReportEntry,
)

__all__ = [
    "AuditAction",
    "FilterDiffEntry",
    "OperatorIdentitySchema",
    "RepoSanitizerAuditEntry",
    "SanitizationCategory",
    "SanitizationReportEntry",
]
