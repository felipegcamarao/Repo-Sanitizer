"""Wrapper one-shot: retoma generate-readme + finalize apontando para o destino
existente `GIT_a-plus-agents` (workaround conhecido — CLI re-computa next_versioned_dest
em cada invocacao, perdendo o dest criado por sanitize-apply na sessao anterior).

Uso interno desta sessao Pipeline A+ — nao integrar ao runtime canonico do agente.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

from repo_sanitizer.helpers._versioning import iter_existing_versions
from repo_sanitizer.orchestrator import (
    OrchestratorContext,
    make_orchestrator_context,
    pre_flight_integrity_check,
    run_finalize,
    run_generate_readme,
)
from repo_sanitizer.orchestrator import _read_secret_patterns_hash, _read_sentinel_pin


def build_ctx(*, action: str) -> OrchestratorContext:
    source = Path("C:/VS Code/A+ AGENTS").resolve()
    slug = "a-plus-agents"
    base_root = Path("C:/VS Code/Git Hub - [NOME]")
    relatorios = base_root / "Relatorios"
    project_root = Path("C:/VS Code/1A Agentes Pessoais/Repo Sanitizer Agent").resolve()

    # Pre-flight integrity (ADR-015) sempre
    pre_flight_integrity_check(project_root)

    existing = iter_existing_versions(base_root, slug)
    if not existing:
        raise SystemExit(
            "[resume] Nenhuma versao existente para slug=a-plus-agents — execute sanitize-apply primeiro."
        )
    dest = existing[0]  # primeira = GIT_a-plus-agents (sem sufixo)
    print(f"[resume] action={action} dest={dest}")

    ctx = OrchestratorContext(
        run_id=str(uuid.uuid4()),
        slug=slug,
        source_path=source,
        dest_path=dest,
        relatorios_path=relatorios,
        project_root=project_root,
        base_destinos_root=base_root,
        secret_patterns_hash=_read_secret_patterns_hash(project_root),
        sentinel_sanitize_version=_read_sentinel_pin(project_root),
    )
    return ctx


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in {"generate-readme", "finalize"}:
        sys.stderr.write("uso: _resume_pipeline_a_plus_agents.py {generate-readme|finalize}\n")
        return 1
    action = argv[0]
    ctx = build_ctx(action=action)
    if action == "generate-readme":
        return run_generate_readme(ctx)
    return run_finalize(ctx)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
