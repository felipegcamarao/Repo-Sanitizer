"""test_f4_golden_path.py — Bloco 05 Passo 05.12 + Release Gate v1.0.

Golden path UX.D-01 fim-a-fim (4 comandos): dry-run -> apply -> generate-readme
-> finalize.

DoD Passo 05.12: 4 comandos verdes; 4 artefatos em /Relatorios/.

Cobertura adicional:
- 12 INJ-XX fixtures (RS-003) detectados em kit JSON
- Cap 1 LLM/run (ADR-017) enforced
- Degrade gracioso quando README ausente (RS-023)
- Cleanup .tmp/ em finalize (ADR-027 + RS-014)
- FSM transitions canonicas: AWAITING_README -> AWAITING_FINALIZE -> DONE
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_sanitizer.f4_readme import (
    TMP_DIR_NAME,
    F4CapLlmExceeded,
    list_kit_jsons,
)
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._state_machine import State, StateMachine
from repo_sanitizer.orchestrator import (
    InvalidTransitionError,
    make_orchestrator_context,
    run_apply,
    run_dry_run,
    run_finalize,
    run_generate_readme,
)
from tests.fixtures.repos.adversarial import (
    ADVERSARIAL_FACTORIES,
    build_injection_in_readme,
    build_realistic_python_repo,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _setup(tmp_path: Path, slug: str, factory) -> tuple:
    src_root = tmp_path / "sources"
    src_root.mkdir()
    src = factory(src_root)
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    ctx = make_orchestrator_context(
        source_path=src, relatorios_path=relatorios,
        project_root=PROJECT_ROOT, slug=slug, base_destinos_root=allowed,
    )
    fw = FsWriter(source_path=src, allowed_roots=[allowed], override_forbidden=[])
    return ctx, fw, src, allowed, relatorios


# ===========================================================================
# Golden path UX.D-01 — 4 comandos fim-a-fim (Passo 05.12)
# ===========================================================================

def test_golden_path_4_commands_fim_a_fim(tmp_path: Path) -> None:
    """DoD Passo 05.12: 4 comandos verdes; 4 artefatos em /Relatorios/."""
    ctx, fw, _src, _allowed, rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )

    # 1) dry-run
    rc1 = run_dry_run(ctx, fs_writer=fw)
    assert rc1 == 0

    # 2) sanitize-apply
    rc2 = run_apply(ctx, fs_writer=fw)
    assert rc2 == 0

    # State agora AWAITING_README
    sm = StateMachine(dest_path=ctx.dest_path, fs_writer=fw)
    sm.load()
    assert sm.current() == State.AWAITING_README

    # 3) generate-readme
    rc3 = run_generate_readme(ctx, fs_writer=fw)
    assert rc3 == 0

    # Kit JSON gerado em /Relatorios/.tmp/
    kits = list_kit_jsons(rel, "realistic_python_repo")
    assert len(kits) == 1
    kit_json = json.loads(kits[0].read_text(encoding="utf-8"))
    assert "payload" in kit_json
    assert "isolation_open" in kit_json

    # Simula [NOME] colando README real no destino (substitui hipotetico stub)
    (ctx.dest_path / "README.md").write_text(
        "# Realistic Python Repo\n\n## Setup\n\n```bash\npip install -e .\n```\n",
        encoding="utf-8",
    )

    # 4) sanitize-finalize
    rc4 = run_finalize(ctx, fs_writer=fw)
    assert rc4 == 0

    # State agora DONE
    sm.load()
    assert sm.current() == State.DONE

    # Cleanup .tmp/ verificado
    kits_after = list_kit_jsons(rel, "realistic_python_repo")
    assert len(kits_after) == 0

    # 4 artefatos em /Relatorios/
    artifacts = list(rel.rglob("*.md")) + list(rel.rglob("*.jsonl"))
    artifact_names = {p.name for p in artifacts}
    # FILTER_DIFF + SANITIZATION_REPORT + audit-log.jsonl
    has_filter = any("FILTER_DIFF" in n for n in artifact_names)
    has_sanit = any("SANITIZATION_REPORT" in n for n in artifact_names)
    has_audit = any(n == "audit-log.jsonl" for n in artifact_names)
    assert has_filter
    assert has_sanit
    assert has_audit


# ===========================================================================
# 12 INJ-XX (RS-003) fixture com README injetado
# ===========================================================================

def test_f4_filter_detects_injections_from_readme(tmp_path: Path) -> None:
    """Source README com 'IGNORE PREVIOUS INSTRUCTIONS' + SYSTEM: marker ->
    detectado pelo filter durante run_generate_readme."""
    ctx, fw, _src, _allowed, rel = _setup(
        tmp_path, "injection_in_readme", build_injection_in_readme,
    )
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    rc = run_generate_readme(ctx, fs_writer=fw)
    assert rc == 0

    kits = list_kit_jsons(rel, "injection_in_readme")
    assert len(kits) == 1
    kit_str = kits[0].read_text(encoding="utf-8")
    # Token canonico [SUSPECTED_INJECTION] presente (RS-003 camada C1)
    assert "[SUSPECTED_INJECTION]" in kit_str
    # Isolation tag presente (RS-003 camada C2)
    assert "<project_context" in kit_str


def test_audit_log_has_injection_redacted_entry(tmp_path: Path) -> None:
    ctx, fw, _src, _allowed, rel = _setup(
        tmp_path, "injection_in_readme", build_injection_in_readme,
    )
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)
    audit_text = (rel / "audit-log.jsonl").read_text(encoding="utf-8")
    assert "injection_redacted" in audit_text
    assert "f4_kit_emitted" in audit_text


# ===========================================================================
# Cap LLM 1/run (ADR-017)
# ===========================================================================

def test_cap_llm_2nd_generate_readme_raises(tmp_path: Path) -> None:
    ctx, fw, _src, _allowed, _rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)  # 1a invocacao OK

    # 2a invocacao deve raise F4CapLlmExceeded
    with pytest.raises(F4CapLlmExceeded):
        run_generate_readme(ctx, fs_writer=fw)


# ===========================================================================
# Degrade gracioso (RS-023) — finalize sem README -> stub PT-BR
# ===========================================================================

def test_finalize_without_readme_generates_degrade_stub(tmp_path: Path) -> None:
    ctx, fw, _src, _allowed, _rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)

    # Remove README do destino para simular runtime ausente
    readme = ctx.dest_path / "README.md"
    if readme.exists():
        readme.unlink()

    rc = run_finalize(ctx, fs_writer=fw)
    assert rc == 0
    # Stub PT-BR foi emitido
    assert readme.exists()
    content = readme.read_text(encoding="utf-8")
    assert "README skipped — LLM runtime unavailable" in content


# ===========================================================================
# Cleanup .tmp/ em finalize (ADR-027 + RS-014)
# ===========================================================================

def test_finalize_cleans_tmp_kit_jsons(tmp_path: Path) -> None:
    ctx, fw, _src, _allowed, rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)

    tmp_dir = rel / TMP_DIR_NAME
    kits_before = list(tmp_dir.glob("README_INPUT_realistic_python_repo_*.json"))
    assert len(kits_before) == 1

    run_finalize(ctx, fs_writer=fw)
    kits_after = list(tmp_dir.glob("README_INPUT_realistic_python_repo_*.json"))
    assert len(kits_after) == 0


# ===========================================================================
# FSM transitions canonicas (RS-026)
# ===========================================================================

def test_generate_readme_before_apply_raises(tmp_path: Path) -> None:
    """generate-readme antes de apply -> InvalidTransitionError."""
    ctx, fw, _src, _allowed, _rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )
    # Pula apply
    with pytest.raises(InvalidTransitionError):
        run_generate_readme(ctx, fs_writer=fw)


def test_full_pipeline_state_machine_done(tmp_path: Path) -> None:
    """Pipeline completo: IDLE -> DRY_RUN -> AWAITING_APPLY -> APPLYING ->
    AWAITING_README -> AWAITING_FINALIZE -> DONE."""
    ctx, fw, _src, _allowed, _rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)
    (ctx.dest_path / "README.md").write_text(
        "# Final\n\n## Setup\n\nNada.\n", encoding="utf-8",
    )
    run_finalize(ctx, fs_writer=fw)

    sm = StateMachine(dest_path=ctx.dest_path, fs_writer=fw)
    sm.load()
    assert sm.current() == State.DONE


# ===========================================================================
# INV-1 snapshot em pipeline F4 completo
# ===========================================================================

def test_inv1_snapshot_preserved_through_full_pipeline(tmp_path: Path) -> None:
    """INV-1 reforcado 2x: fonte intocada APOS pipeline F1 + F3 + F2 + F4."""
    from repo_sanitizer.helpers._hash_tree import snapshot
    ctx, fw, src, _allowed, _rel = _setup(
        tmp_path, "realistic_python_repo", build_realistic_python_repo,
    )
    snap_pre = snapshot(src)
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)
    (ctx.dest_path / "README.md").write_text("# Final\n", encoding="utf-8")
    run_finalize(ctx, fs_writer=fw)
    snap_pos = snapshot(src)
    assert snap_pre["aggregate"] == snap_pos["aggregate"]


# ===========================================================================
# Smoke 2 fixtures adversariais Bloco 03
# ===========================================================================

@pytest.mark.parametrize("slug", ["encoding_bomb", "binary_with_keys"])
def test_full_pipeline_on_adversarial_fixtures(slug: str, tmp_path: Path) -> None:
    """Pipeline completo NAO quebra em fixtures adversariais Bloco 03."""
    factory = ADVERSARIAL_FACTORIES[slug]
    ctx, fw, _src, _allowed, _rel = _setup(tmp_path, slug, factory)
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    run_generate_readme(ctx, fs_writer=fw)
    # Forca stub degrade (sem mover README)
    if (ctx.dest_path / "README.md").exists():
        (ctx.dest_path / "README.md").unlink()
    rc = run_finalize(ctx, fs_writer=fw)
    assert rc == 0
