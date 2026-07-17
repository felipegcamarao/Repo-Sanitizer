"""orchestrator.py — coordena F1->F3->F2->F4 (ADR-006 INVARIANTE).

Bloco 02 (atual): F1 real + FILTER_DIFF emit + auto-versionamento + race
detection gate apply. F3/F2/F4 ainda skeleton (Blocos 03/04/05).

Exit codes canonicos (cli.py mapeia exceptions -> exit):
    0  sucesso
    1  erro generico (bad args, IOError generico)
    2  INV-1 violation (snapshot mismatch fonte)
    3  integrity mismatch (qualquer copia local OU secret_patterns)
    4  state machine invalid transition
    5  FsWriteOutOfBoundsError
    6  F3 timeout exceeded em arquivo
    7  Gate G2 bloqueante (paths absolutos OU PII no destino)
    8  Historico Git detectado no destino (GitHistoryInDestination; MV-02)
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repo_sanitizer import __version__
from repo_sanitizer.f1_filter import run_filter
from repo_sanitizer.f2_organizer import F2Result, run_f2
from repo_sanitizer.f3_sanitizer import (
    GitHistoryInDestination,
    LeakDetectedInDestination,
    run_f3,
)
from repo_sanitizer.f4_readme import (
    F4CapLlmExceeded,
    F4FinalizeResult,
    F4MissingReadme,
    G2Result,
    emit_generate_readme_instruction,
    run_f4_emit_kit,
    run_f4_finalize,
    run_g2_replica_funcional,
)
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._hash_tree import diff_snapshots, snapshot
from repo_sanitizer.helpers._integrity import verify_integrity
from repo_sanitizer.helpers._pii_redactor import redact_path
from repo_sanitizer.helpers._runtime_guard import detect_runtime
from repo_sanitizer.helpers._state_machine import (
    InvalidTransitionError,
    State,
    StateMachine,
)
from repo_sanitizer.helpers._versioning import (
    atomic_create_versioned_dest,
    iter_existing_versions,
    next_versioned_dest,
)
from repo_sanitizer.reports.filter_diff_writer import (
    extract_hash_tree_snapshot,
    write_filter_diff,
)
from repo_sanitizer.reports.sanitization_report_writer import (
    append_g2_section_to_report,
    compute_delta,
    find_latest_report,
    write_sanitization_report,
)

DEFAULT_GIT_HUB_ROOT = Path("C:/VS Code/Git Hub - [NOME]")


@dataclass
class OrchestratorContext:
    """Contexto persistente entre invocacoes do agente para um mesmo destino."""

    run_id: str
    slug: str
    source_path: Path
    dest_path: Path  # alvo computado (pode ainda nao existir; vN computado)
    relatorios_path: Path
    project_root: Path
    base_destinos_root: Path = DEFAULT_GIT_HUB_ROOT
    secret_patterns_hash: str = ""
    sentinel_sanitize_version: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def audit_file(self) -> Path:
        return self.relatorios_path / "audit-log.jsonl"


class IntegrityFailure(RuntimeError):  # noqa: N818  nome canonico no plano
    """integrity.md mismatch (ADR-015). Caller mapeia para exit 3."""


class Inv1Violation(RuntimeError):  # noqa: N818  nome canonico no plano
    """Hash-tree fonte pre/pos mismatch (RS-002). Caller mapeia para exit 2."""


class F3Timeout(RuntimeError):  # noqa: N818  nome canonico no plano
    """Timeout F3 (ADR-026). Caller mapeia para exit 6."""


class G2BlockingFailure(RuntimeError):  # noqa: N818  nome canonico no plano
    """Gate G2 bloqueante (ADR-032): paths absolutos OU PII no destino.

    Caller mapeia para exit 7. Mensagem deve listar blocking_failures
    em PT-BR para [NOME] ler diretamente no terminal.
    """


# ===========================================================================
# Bootstrap helpers
# ===========================================================================

def _read_secret_patterns_hash(project_root: Path) -> str:
    """SHA-256 do `src/repo_sanitizer/secret_patterns.py` (RS-027 metadata)."""
    p = project_root / "src" / "repo_sanitizer" / "secret_patterns.py"
    if not p.exists():
        return "0" * 64
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _read_sentinel_pin(project_root: Path) -> str:
    """Pin do _sanitize.py local-copy (`tests/fixtures/sentinel/.versions.json`)."""
    import json as _j
    versions_file = project_root / "tests" / "fixtures" / "sentinel" / ".versions.json"
    if not versions_file.exists():
        return "v0.0.0-unpinned"
    try:
        data = _j.loads(versions_file.read_text(encoding="utf-8"))
        # Estrutura: { sentinel_sanitize: "v1.2.0" } ou similar
        return str(data.get("sentinel_sanitize_version") or
                   data.get("sentinel_sanitize") or "v0.0.0-unpinned")
    except (OSError, _j.JSONDecodeError):
        return "v0.0.0-unpinned"


def make_orchestrator_context(
    *,
    source_path: Path,
    relatorios_path: Path,
    project_root: Path,
    slug: str | None = None,
    run_id: str | None = None,
    base_destinos_root: Path | None = None,
) -> OrchestratorContext:
    """Helper para construir contexto com defaults sane.

    `dest_path` e computado via `next_versioned_dest` mas NAO criado ainda.
    """
    base_root = base_destinos_root or DEFAULT_GIT_HUB_ROOT
    slug_final = slug or source_path.name.replace(" ", "-")
    dest = next_versioned_dest(base_root, slug_final)
    return OrchestratorContext(
        run_id=run_id or str(uuid.uuid4()),
        slug=slug_final,
        source_path=source_path.resolve(),
        dest_path=dest,
        relatorios_path=relatorios_path,
        project_root=project_root,
        base_destinos_root=base_root,
        secret_patterns_hash=_read_secret_patterns_hash(project_root),
        sentinel_sanitize_version=_read_sentinel_pin(project_root),
    )


def pre_flight_integrity_check(project_root: Path) -> dict[str, Any]:
    """Bloco 01: verifica integrity.md em CADA invocacao (ADR-015 + RS-004).

    Raises:
        IntegrityFailure: mismatch detectado. Caller mapeia para exit 3.
    """
    integrity_md = project_root / "integrity.md"
    result = verify_integrity(integrity_md, project_root, audit_file=None)
    if not result["ok"]:
        names = [m["file"] for m in result["mismatches"]]
        raise IntegrityFailure(
            f"integrity verify FAIL: {len(names)} mismatch(es): {names[:5]}"
        )
    return result


def make_audit_logger(
    ctx: OrchestratorContext,
    fs_writer: FsWriter,
) -> AuditLogger:
    """Cria AuditLogger com metadata canonica (RS-027 enforce)."""
    return AuditLogger(
        audit_file=ctx.audit_file,
        fs_writer=fs_writer,
        run_id=ctx.run_id,
        agent_version=__version__,
        sentinel_sanitize_version=ctx.sentinel_sanitize_version or "v0.0.0-unpinned",
        secret_patterns_hash=ctx.secret_patterns_hash or ("0" * 64),
        slug=ctx.slug,
        source_path_redacted=redact_path(ctx.source_path.as_posix()),
        dest_path_redacted=redact_path(ctx.dest_path.as_posix()),
    )


def _make_fs_writer_for_run(
    ctx: OrchestratorContext,
    *,
    extra_allowed: list[Path] | None = None,
    override_forbidden: list[Path] | None = None,
) -> FsWriter:
    """FsWriter com defaults canonicos do agente; tests podem injetar paths."""
    allowed = list(extra_allowed) if extra_allowed else []
    # Por padrao, ALLOWED_ROOTS = base_destinos_root (default canonico ADR-020).
    if ctx.base_destinos_root not in allowed:
        allowed.append(ctx.base_destinos_root)
    # Auditoria 2026-07: --relatorios-dir pode apontar para fora do dest_root;
    # os writers de relatorio/audit-log precisam de permissao explicita.
    if ctx.relatorios_path not in allowed:
        allowed.append(ctx.relatorios_path)
    return FsWriter(
        source_path=ctx.source_path,
        allowed_roots=allowed,
        override_forbidden=override_forbidden,
    )


# ===========================================================================
# Bloco 02: dry-run + apply gate (race detection)
# ===========================================================================

def run_dry_run(
    ctx: OrchestratorContext,
    *,
    fs_writer: FsWriter | None = None,
) -> int:
    """Executa F1 dry-run real: walk fonte -> classifica -> emite FILTER_DIFF.md.

    Bloco 02. Pipeline:
    1. FsWriter SSOT (ADR-020) com source_path no FORBIDDEN_PATHS (INV-1).
    2. AuditLogger.log('dry_run_start') + 'inv1_snapshot_pre'.
    3. f1_filter.run_filter(source) -> FilterResult (snapshot embedded).
    4. write_filter_diff(...) em /Relatorios/FILTER_DIFF_<slug>_<ts>.md.
    5. snapshot pos + INV-1 verify (RS-002 enforce; raise Inv1Violation se mudou).
    6. StateMachine.transition('dry_run_done').
    7. AuditLogger.log('f1_filter_done', detail={counts...}) + 'dry_run_done'.

    Returns: exit code 0 sucesso; raises Inv1Violation/InvalidTransitionError em falha.
    """
    fw = fs_writer or _make_fs_writer_for_run(ctx)
    audit = make_audit_logger(ctx, fw)
    # NOTA D-EX-08 (Bloco 02): dry-run NAO instancia StateMachine porque seu
    # state file moraria em <dest_path>/.sanitizer-state.json — isso CRIARIA a
    # pasta destino prematuramente, quebrando ADR-008 auto-versionamento atomic
    # mkdir(exist_ok=False). Transicao FSM real comeca em run_apply.

    # 1) Audit start
    audit.log("dry_run_start", detail={"source_resolved": redact_path(ctx.source_path.as_posix())})

    # 2) INV-1 snapshot pre (gate canonico)
    snap_pre = snapshot(ctx.source_path)
    audit.log("inv1_snapshot_pre", detail={
        "aggregate_prefix": snap_pre["aggregate"][:16],
        "file_count": snap_pre["file_count"],
    })

    # 3) F1 filter run (read-only)
    result = run_filter(ctx.source_path)

    # 4) FILTER_DIFF.md write
    written = write_filter_diff(
        result,
        slug=ctx.slug,
        run_id=ctx.run_id,
        fs_writer=fw,
        relatorios_dir=ctx.relatorios_path,
        source_path_redacted=redact_path(ctx.source_path.as_posix()),
        dest_path_redacted=redact_path(ctx.dest_path.as_posix()),
    )

    # 5) INV-1 snapshot pos + gate
    snap_pos = snapshot(ctx.source_path)
    if snap_pre["aggregate"] != snap_pos["aggregate"]:
        diff = diff_snapshots(snap_pre, snap_pos)
        audit.log("inv1_violation", detail={"phase": "dry_run", **diff})
        raise Inv1Violation(
            f"INV-1 violation pre/pos dry-run: aggregate mismatch "
            f"({snap_pre['aggregate'][:16]} vs {snap_pos['aggregate'][:16]})"
        )
    audit.log("inv1_snapshot_pos", detail={
        "aggregate_prefix": snap_pos["aggregate"][:16],
        "file_count": snap_pos["file_count"],
    })

    # 6) State machine transition (D-EX-08: pulada em dry-run; comeca em apply)

    # 7) Audit done + counts
    audit.log("f1_filter_done", detail={
        "counts_by_group": result.counts_by_group,
        "counts_by_acao": result.counts_by_acao,
        "grupo_b_excedeu_threshold": result.grupo_b_excedeu_threshold,
        "filter_diff_filename": written.name,
    })
    # ADR-031 / RS-NEW-033 — F1.5 cross-project promocoes
    audit.log("f1_5_cross_project_done", detail={
        "project_slug": result.project_slug,
        "f1_5_counts": result.f1_5_counts,
    })
    audit.log("dry_run_done", detail={"filter_diff_path": redact_path(written.as_posix())})

    print(f"[orchestrator] FILTER_DIFF emitido: {written}")
    print(
        f"[orchestrator] counts: A={result.counts_by_group.get('A', 0)} "
        f"B={result.counts_by_group.get('B', 0)} "
        f"C={result.counts_by_group.get('C', 0)} "
        f"symlink_excluded={result.counts_by_acao.get('symlink_excluded', 0)}"
    )
    if result.grupo_b_excedeu_threshold:
        print(
            f"[orchestrator] ⚠️ Grupo B excedeu threshold "
            f"({result.review_threshold}). Revise antes de /sanitize-apply."
        )
    return 0


def find_latest_filter_diff(relatorios_path: Path, slug: str) -> Path | None:
    """Acha o FILTER_DIFF.md mais recente para um slug (RS-016 race gate)."""
    if not relatorios_path.exists():
        return None
    candidates = sorted(
        relatorios_path.glob(f"FILTER_DIFF_{slug}_*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def race_detection_gate(
    ctx: OrchestratorContext,
    *,
    fs_writer: FsWriter,
    audit: AuditLogger,
) -> dict[str, Any]:
    """RS-016 + ADR-025: re-snapshot fonte, compara com hash-tree embebido no
    FILTER_DIFF mais recente. Mismatch = race detected -> Inv1Violation.

    Returns: snapshot atual (caller pode reusar para apply).
    Raises: Inv1Violation se race detectada.
    """
    latest_filter_diff = find_latest_filter_diff(ctx.relatorios_path, ctx.slug)
    if latest_filter_diff is None:
        raise Inv1Violation(
            f"race_detection_gate: nenhum FILTER_DIFF encontrado para slug={ctx.slug!r}. "
            "Execute `dry-run` antes de `sanitize-apply`."
        )
    md = latest_filter_diff.read_text(encoding="utf-8")
    embedded_snap = extract_hash_tree_snapshot(md)
    if embedded_snap is None:
        raise Inv1Violation(
            f"race_detection_gate: FILTER_DIFF {latest_filter_diff.name} sem snapshot embedded. "
            "Re-execute `dry-run`."
        )
    current_snap = snapshot(ctx.source_path)
    if embedded_snap.get("aggregate") != current_snap["aggregate"]:
        # Race detected: fonte mudou entre dry-run e apply.
        audit.log("inv1_violation", detail={
            "phase": "race_detection_gate",
            "filter_diff_filename": latest_filter_diff.name,
            "embedded_aggregate_prefix": embedded_snap.get("aggregate", "")[:16],
            "current_aggregate_prefix": current_snap["aggregate"][:16],
            "embedded_file_count": embedded_snap.get("file_count", 0),
            "current_file_count": current_snap["file_count"],
        })
        raise Inv1Violation(
            f"INV-1 violation (race detection): fonte mudou entre dry-run "
            f"e apply. embedded={embedded_snap.get('aggregate', '')[:16]} "
            f"current={current_snap['aggregate'][:16]}. "
            "Re-execute `dry-run` apos verificar fonte."
        )
    return current_snap


def run_apply(
    ctx: OrchestratorContext,
    *,
    fs_writer: FsWriter | None = None,
    raise_on_leak: bool = True,
) -> int:
    """Bloco 03 (Modo Completo AGRAVADO 3x): race gate + auto-versionamento +
    F3 sanitizer + SANITIZATION_REPORT + state machine -> APPLYING.

    Bloco 04 vai estender com F2 e fazer transicao APPLYING -> AWAITING_README.

    Pipeline:
    1. Race detection gate (RS-016 + ADR-025)
    2. Auto-versionamento atomic (ADR-008 + RS-021)
    3. StateMachine: idle -> dry_run -> awaiting_apply -> applying (replay)
    4. F3 sanitizer: 7 camadas C1..C7 (RS-001) + INV-1 snapshot + Camada C6 re-scan
    5. SANITIZATION_REPORT.md em /Relatorios/ via FsWriter (ADR-020 boundary)
    6. Audit f3_sanitize_done + apply_start
    """
    fw = fs_writer or _make_fs_writer_for_run(ctx)
    audit = make_audit_logger(ctx, fw)

    # 1) Race detection gate (RS-016 + ADR-025) ANTES de criar destino
    race_detection_gate(ctx, fs_writer=fw, audit=audit)

    # 2) Auto-versionamento real (cria pasta destino atomicamente; ADR-008 + RS-021)
    final_dest = atomic_create_versioned_dest(
        ctx.base_destinos_root, ctx.slug, fw,
    )
    if final_dest != ctx.dest_path:
        audit.log("apply_start", detail={
            "dest_path_changed": True,
            "computed": redact_path(ctx.dest_path.as_posix()),
            "final": redact_path(final_dest.as_posix()),
        })
        ctx.dest_path = final_dest

    # 3) StateMachine inicializa SOMENTE apos destino existir (D-EX-08).
    # Pipeline FSM canonico: idle -> dry_run -> awaiting_apply -> applying.
    sm = StateMachine(dest_path=ctx.dest_path, fs_writer=fw)
    try:
        sm.transition("dry_run_done", reason="dry-run concluiu (replay)")
        # Auditoria 2026-07: reason vai para .sanitizer-state.json DENTRO do
        # destino — nunca pode conter nome do operador.
        sm.transition("dry_run_apply_review", reason="operador aprovou via /sanitize-apply")
        sm.transition("apply_start", reason="apply iniciando")
    except InvalidTransitionError as exc:
        audit.log("state_transition_invalid", detail={"action": "apply_start", "error": str(exc)})
        raise

    audit.log("apply_start", detail={"dest_path_redacted": redact_path(ctx.dest_path.as_posix())})

    # 4) F3 sanitizer (Bloco 03; Modo Completo AGRAVADO 3x)
    # MV-04 / ADR-034 / C3: flag `--entropy` propagada via ctx.extra (default ON).
    entropy_enabled = bool(ctx.extra.get("entropy_enabled", True))
    try:
        f3_result = run_f3(
            source_path=ctx.source_path,
            dest_path=ctx.dest_path,
            fs_writer=fw,
            audit=audit,
            project_root=ctx.project_root,
            integrity_md=ctx.project_root / "integrity.md",
            raise_on_leak=raise_on_leak,
            entropy_enabled=entropy_enabled,
        )
    except LeakDetectedInDestination:
        # Camada C6 falhou — leak no destino. Pipeline aborta.
        raise
    except GitHistoryInDestination:
        # MV-02 / RS-NEW-038: artefato de historico Git no destino. Aborta.
        # Caller (cli.py) mapeia para exit 8.
        raise

    # 5) F2 Organizer (Bloco 04; Modo Padrao AgenteIA)
    f2_result: F2Result = run_f2(
        dest_path=ctx.dest_path,
        fs_writer=fw,
        audit=audit,
    )

    # 6) SANITIZATION_REPORT.md (passo 03.10 + 03.12 + 04.10 secao F2)
    # Computa delta vs run anterior (se existir)
    delta = None
    prev = find_latest_report(ctx.relatorios_path, ctx.slug)
    if prev is not None:
        delta = compute_delta(prev, f3_result.matches)

    # MV-08 / D2 — args do Checklist de Publicacao FIEIS ao estado real do run.
    # git_history_clean: B3 scan achou 0 artefatos no destino (gate ja teria
    #   raised GitHistoryInDestination se houvesse e raise_on_leak=True).
    git_history_clean = len(f3_result.git_history_artifacts) == 0
    # gitignore_emitted: F2 garantiu `.gitignore` no destino (D1 merge aditivo).
    gitignore_present = (ctx.dest_path / ".gitignore").exists()
    # g2_outcome: ainda nao rodou em run_apply -> item 10 = SKIPPED; atualizado
    #   no finalize via append_g2_section_to_report (idempotente).
    written_report = write_sanitization_report(
        f3_result,
        slug=ctx.slug,
        run_id=ctx.run_id,
        fs_writer=fw,
        relatorios_dir=ctx.relatorios_path,
        source_path_redacted=redact_path(ctx.source_path.as_posix()),
        dest_path_redacted=redact_path(ctx.dest_path.as_posix()),
        sentinel_sanitize_version=ctx.sentinel_sanitize_version or "v0.0.0-unpinned",
        secret_patterns_hash=ctx.secret_patterns_hash or ("0" * 64),
        delta=delta,
        f2_result=f2_result,
        git_history_clean=git_history_clean,
        gitignore_emitted=gitignore_present,
        entropy_enabled=entropy_enabled,
        g2_outcome=None,
    )

    # 7) FSM transition: applying -> awaiting_readme (Bloco 04 fecha F2)
    try:
        sm.transition("apply_done", reason="F3 + F2 concluidos; aguardando F4")
    except InvalidTransitionError as exc:
        audit.log("state_transition_invalid", detail={"action": "apply_done", "error": str(exc)})
        raise

    print(f"[orchestrator] sanitize-apply: destino criado em {final_dest}")
    print(f"[orchestrator] F3 done: {f3_result.files_processed} arquivos processados, "
          f"{f3_result.files_with_secrets} com secrets, "
          f"Camada C6 re-scan={'PASS' if f3_result.rescan_destination_zero else 'FAIL'}")
    if f2_result.score:
        print(f"[orchestrator] F2 done: score {f2_result.score.total}/{f2_result.score.max} "
              f"(language={f2_result.detection.primary if f2_result.detection else '?'}, "
              f"monorepo={f2_result.detection.is_monorepo if f2_result.detection else False}), "
              f"templates={len(f2_result.templates_generated)} geradas, "
              f"moves={sum(1 for m in f2_result.moves if m.action == 'moved')}")
    print(f"[orchestrator] SANITIZATION_REPORT: {written_report}")
    # Estado pos-Bloco 04: AWAITING_README. Bloco 05 (F4) fara generate-readme.
    return 0


def run_generate_readme(
    ctx: OrchestratorContext,
    *,
    fs_writer: FsWriter | None = None,
) -> int:
    """Bloco 05 Passos 05.1..05.4 + 05.8 + 05.10 — emite kit JSON + instrucao.

    Pipeline:
    1. FSM load (espera state == AWAITING_README; senao InvalidTransitionError)
    2. Cap LLM 1/run enforced (ADR-017 + RS-017 via flag file)
    3. collect_kit + filter_and_isolate (RS-003 + 12 INJ-XX)
    4. Write kit JSON em /Relatorios/.tmp/
    5. Stdout instrucao /generate-readme {slug}
    6. Audit f4_kit_emitted
    """
    fw = fs_writer or _make_fs_writer_for_run(ctx)
    audit = make_audit_logger(ctx, fw)

    # FSM gate: expects AWAITING_README
    sm = StateMachine(dest_path=ctx.dest_path, fs_writer=fw)
    sm.load()
    if sm.current() != State.AWAITING_README:
        audit.log("state_transition_invalid", detail={
            "expected": State.AWAITING_README.value,
            "actual": sm.current().value,
            "action": "generate_readme",
        })
        raise InvalidTransitionError(
            f"generate-readme exige state=AWAITING_README; atual={sm.current().value}. "
            "Execute /sanitize-apply primeiro."
        )

    try:
        kit_path, kit, matches = run_f4_emit_kit(
            source_path=ctx.source_path,
            dest_path=ctx.dest_path,
            slug=ctx.slug,
            run_id=ctx.run_id,
            fs_writer=fw,
            audit=audit,
            relatorios_path=ctx.relatorios_path,
        )
    except F4CapLlmExceeded:
        raise

    instruction = emit_generate_readme_instruction(
        slug=ctx.slug, kit_path=kit_path, matches=matches,
    )
    print(instruction)
    print(f"[orchestrator] runtime detectado: {detect_runtime()}")
    print(f"[orchestrator] kit: language={kit.language}, "
          f"docstrings={len(kit.docstrings)}, features={len(kit.features)}")
    # NOTA: NAO transitamos FSM aqui. [NOME] deve colar README.md gerado pelo
    # Claude Code chat no destino e executar /sanitize-finalize, que vai
    # transition AWAITING_README -> AWAITING_FINALIZE.
    return 0


def run_finalize(
    ctx: OrchestratorContext,
    *,
    fs_writer: FsWriter | None = None,
    raise_on_missing_readme: bool = False,
) -> int:
    """Bloco 05 Passos 05.5 + 05.6 + 05.7 + 05.9 + Bloco 04 Gate G2 (ADR-032).

    Pipeline:
    1. FSM load (espera AWAITING_README ou AWAITING_FINALIZE)
    2. Transition readme_received -> AWAITING_FINALIZE (se AWAITING_README)
    3. run_f4_finalize: README valido + markdownlint + link-check + cleanup .tmp
    4. Gate G2 (Bloco 04): boilerplate + LICENSE + zero paths + zero PII
       - (a)/(b) auto-gen -> finalize_done_with_warnings (exit 0)
       - (c)/(d) fail     -> G2BlockingFailure (caller mapeia exit 7)
       - todos OK         -> finalize_done (exit 0)
    5. Audit f4_finalize_done + f4_g2_done
    """
    fw = fs_writer or _make_fs_writer_for_run(ctx)
    audit = make_audit_logger(ctx, fw)

    sm = StateMachine(dest_path=ctx.dest_path, fs_writer=fw)
    sm.load()

    if sm.current() == State.AWAITING_README:
        # [NOME] gerou README ou degrade gracioso vai gerar stub
        try:
            sm.transition("readme_received", reason="finalize: aplicando README")
        except InvalidTransitionError as exc:
            audit.log("state_transition_invalid", detail={
                "action": "readme_received", "error": str(exc),
            })
            raise
    elif sm.current() != State.AWAITING_FINALIZE:
        raise InvalidTransitionError(
            f"finalize exige state=AWAITING_README ou AWAITING_FINALIZE; "
            f"atual={sm.current().value}. Execute /sanitize-apply + "
            "/generate-readme antes."
        )

    audit.log("f4_readme_received", detail={
        "state_transition": "applying_to_awaiting_finalize",
    })

    try:
        result: F4FinalizeResult = run_f4_finalize(
            dest_path=ctx.dest_path,
            slug=ctx.slug,
            run_id=ctx.run_id,
            fs_writer=fw,
            audit=audit,
            relatorios_path=ctx.relatorios_path,
            raise_on_missing_readme=raise_on_missing_readme,
        )
    except F4MissingReadme:
        sm.transition("fail", reason="README ausente")
        raise

    # ---------------- Bloco 04: Gate G2 Replica Funcional (ADR-032) ----------------
    license_override = ctx.extra.get("license_override", "MIT")
    # Reuso slug do contexto (Bloco 03 ja extrai project_slug em FilterResult;
    # fallback para ctx.slug que e basename sanitizado da fonte).
    project_slug = ctx.extra.get("project_slug") or ctx.slug

    g2: G2Result = run_g2_replica_funcional(
        dest_path=ctx.dest_path,
        project_root=ctx.project_root,
        fs_writer=fw,
        audit=audit,
        project_slug=project_slug,
        license_override=license_override,
    )

    # Anexa seção G2 ao SANITIZATION_REPORT.md (Bloco 04 sub-plano 4.5)
    latest_report = find_latest_report(ctx.relatorios_path, ctx.slug)
    if latest_report is not None and latest_report.exists():
        try:
            append_g2_section_to_report(latest_report, g2, fw)
        except Exception as exc:
            print(f"[orchestrator] WARN: falha ao anexar G2 ao report: {exc}")

    # Print canonico stdout (PT-BR + emoji-free; INV-11)
    print(
        f"[orchestrator] G2 Gate: a={'OK' if g2.check_a_boilerplate else 'FAIL'} "
        f"b={'OK' if g2.check_b_license else 'FAIL'} "
        f"c={'OK' if g2.check_c_paths_zero else 'FAIL'} "
        f"d={'OK' if g2.check_d_pii_zero else 'FAIL'} "
        f"(outcome={g2.outcome})"
    )
    if g2.auto_generated_files:
        for p in g2.auto_generated_files:
            print(f"[orchestrator] G2 auto-gen: {p.name} "
                  "(ADR-033; revise antes de publicar)")

    # FSM transition baseado em outcome
    if g2.outcome == "done_with_failure":
        sm.transition(
            "finalize_done_with_failure",
            reason=f"G2 bloqueante: {'; '.join(g2.blocking_failures)[:200]}",
        )
        # Print stderr-friendly resumo das falhas
        for blk in g2.blocking_failures:
            print(f"[orchestrator] G2 BLOCKING: {blk}")
        raise G2BlockingFailure(
            f"Gate G2 bloqueante (ADR-032): "
            f"{len(g2.blocking_failures)} falha(s); "
            f"{'; '.join(g2.blocking_failures)}"
        )

    if g2.outcome == "done_with_warnings":
        sm.transition(
            "finalize_done_with_warnings",
            reason=f"G2 auto-gen: {[p.name for p in g2.auto_generated_files]}",
        )
    else:
        sm.transition("finalize_done", reason="F4 finalize + G2 todos OK")

    print(f"[orchestrator] finalize: README={result.readme_path} "
          f"({result.readme_bytes} bytes); "
          f"markdownlint={result.markdownlint_status}; "
          f"link_check={result.link_check_status}; "
          f"degrade_stub={result.degrade_stub_used}; "
          f"tmp_cleaned={result.tmp_cleaned}")
    return 0


# ===========================================================================
# Helpers para tests integration
# ===========================================================================

def list_versions(ctx: OrchestratorContext) -> list[Path]:
    """Lista versoes existentes para o slug (debug + tests)."""
    return iter_existing_versions(ctx.base_destinos_root, ctx.slug)


__all__ = [
    "DEFAULT_GIT_HUB_ROOT",
    "F3Timeout",
    "G2BlockingFailure",
    "GitHistoryInDestination",
    "IntegrityFailure",
    "Inv1Violation",
    "OrchestratorContext",
    "find_latest_filter_diff",
    "list_versions",
    "make_audit_logger",
    "make_orchestrator_context",
    "pre_flight_integrity_check",
    "race_detection_gate",
    "run_apply",
    "run_dry_run",
    "run_finalize",
    "run_generate_readme",
]
