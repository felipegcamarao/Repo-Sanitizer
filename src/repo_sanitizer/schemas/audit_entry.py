"""RepoSanitizerAuditEntry — Pydantic v2 schema para audit-log.jsonl (ADR-016 + ADR-024).

Audit-log proprio (separado do SafeLog Pipeline A+; D-T2-06 + RS-027). Cada
acao do agente emite uma entry validada via validate_artifact que aplica
SECRET_REGEXES sobre TODO o dump serializado pre-write.

Schema versioned (`schema_version`); RS-027 enforce metadata canonica
(run_id + agent_version + sentinel_sanitize_version + secret_patterns_hash).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from repo_sanitizer.schemas._secrets_gate import assert_no_literal_secrets

AuditAction = Literal[
    # Bootstrap / integrity (Bloco 01)
    "bootstrap_local_copies",
    "integrity_verify_ok",
    "integrity_verify_fail",

    # Dry-run / apply lifecycle (Bloco 02)
    "dry_run_start",
    "dry_run_done",
    "apply_start",
    "apply_done",

    # F1 / F2 / F3 (Blocos 02..04)
    "f1_filter_start",
    "f1_filter_done",
    "f1_5_cross_project_done",
    "f2_organize_start",
    "f2_organize_done",
    "f2_template_generated",
    "f2_file_moved",
    "f3_sanitize_start",
    "f3_sanitize_done",
    "f3_c9_pii_done",
    "f3_c10_paths_done",
    "leak_smoke_pass",
    "leak_smoke_fail",
    # MV-02 / RS-NEW-038 / ADR-035 (v1.2.0): gate de historico Git no destino
    "git_history_detected",
    "git_history_clean",
    # MV-05 / RS-NEW-041 / ADR-038 (v1.2.0): autoria estrutural (manifests)
    "f3_author_done",
    # MV-04 / RS-NEW-035/036/037 / ADR-034 (v1.2.0): entropia Shannon (ultima camada)
    "f3_entropy_done",

    # F4 (Bloco 05)
    "f4_kit_emitted",
    "f4_readme_received",
    "f4_finalize_done",
    "f4_g2_done",  # Bloco 04 v1.1.0-rc.1: Gate G2 Replica Funcional (ADR-032)

    # INV-1 / boundary / FSM (cross-cutting)
    "inv1_snapshot_pre",
    "inv1_snapshot_pos",
    "inv1_violation",
    "fs_write_blocked",
    "state_transition_valid",
    "state_transition_invalid",

    # Security alerts (Blocos 03 + 05)
    "fp_overload_alert",
    "injection_redacted",
    "f3_timeout_skip",
]


class RepoSanitizerAuditEntry(BaseModel):
    """Uma entry do audit-log.jsonl. Append-only via helpers/_audit.append_audit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0.0", pattern=r"^\d+\.\d+\.\d+$")
    run_id: str = Field(..., min_length=36, max_length=36,
                        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    timestamp: datetime
    agent_version: str = Field(..., min_length=1)
    sentinel_sanitize_version: str = Field(..., min_length=1,
                                           description="Pin de _sanitize.py local-copy (.versions.json).")
    secret_patterns_hash: str = Field(..., min_length=64, max_length=64,
                                      pattern=r"^[a-f0-9]{64}$",
                                      description="SHA-256 hex de secret_patterns.py local (ADR-015).")
    action: AuditAction
    slug: str = Field(..., min_length=1, max_length=120)
    source_path_redacted: str = Field(..., min_length=1)
    dest_path_redacted: str = Field(..., min_length=1)
    detail: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def no_literal_secrets(self) -> RepoSanitizerAuditEntry:
        """ADR-024 + RS-011: aplica SECRET_REGEXES sobre dump (defesa-em-camadas)."""
        assert_no_literal_secrets(self.model_dump(mode="json"))
        return self


__all__ = ["AuditAction", "RepoSanitizerAuditEntry"]
