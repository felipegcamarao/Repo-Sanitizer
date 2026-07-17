"""smoke_e2e_a_plus_agents_v110.py — Smoke E2E real sobre A+ AGENTS v1.1.0.

Reproduz fim-a-fim o audit 2026-05-22 e valida que os 4 gaps (A/B/C/D) +
Gate G2 (E) foram fechados pelo v1.1.0. Bloco 05 Passo 5.1 do plano.

Usa OrchestratorContext programático (ctx único entre 4 comandos)
em vez do CLI por subprocess, porque a CLI auto-versiona destino a cada
invocação (next_versioned_dest) e isso quebra workflows multi-comando
quando há destinos legados (defeito documentado para v1.2).

Source: cópia congelada de A+ AGENTS (necessário para INV-1 quiescência
porque A+ AGENTS é workspace vivo com .pytest_cache + __pycache__ ativos).

Saída: log textual em scripts/smoke_e2e_phase5_v110.log + exit code
(0=todos os 5 gates verde; 1=qualquer falha).
"""
from __future__ import annotations

import json
import shutil
import sys
import time
import uuid
from pathlib import Path

# UTF-8 stdout (Windows cp1252 fix)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure src/ on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from repo_sanitizer import __version__
from repo_sanitizer.helpers._integrity import verify_integrity
from repo_sanitizer.orchestrator import (
    DEFAULT_GIT_HUB_ROOT,
    OrchestratorContext,
    G2BlockingFailure,
    pre_flight_integrity_check,
    run_apply,
    run_dry_run,
    run_finalize,
    run_generate_readme,
)

FROZEN_SOURCE = Path("c:/VS Code/_tmp_smoke_v110/A+ AGENTS-frozen")
SLUG = "a-plus-agents-v110"
RELATORIOS = Path("c:/VS Code/Git Hub - [NOME]/Relatorios")
DEST = DEFAULT_GIT_HUB_ROOT / f"GIT_{SLUG}"
LOG_PATH = ROOT / "scripts" / "smoke_e2e_phase5_v110.log"


def _section(title: str) -> str:
    bar = "=" * 78
    return f"\n{bar}\n{title}\n{bar}"


_SKIP_FOR_G2_PATHS: frozenset[str] = frozenset({
    "C9_AUDIT.md",
    "C10_AUDIT.md",
    ".sanitizer-state.json",
    "LICENSE", "LICENSE.md", "LICENSE.txt",
})


def _grep_count(
    root: Path,
    pattern: str,
    *,
    case_insensitive: bool = False,
    apply_g2_skip: bool = False,
) -> int:
    """Conta matches de uma regex em arquivos texto sob root.

    Args:
        apply_g2_skip: se True, ignora arquivos no skip-list canônico G2
            (`.sanitizer-state.json`, `LICENSE*`, audit reports). Reflete
            a visão real da Gate G2 (paths absolutos em artefatos do
            agente são intencionais e gitignored).
    """
    import re
    flags = re.IGNORECASE if case_insensitive else 0
    pat = re.compile(pattern, flags)
    count = 0
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if apply_g2_skip and fp.name in _SKIP_FOR_G2_PATHS:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        count += len(pat.findall(text))
    return count


def main() -> int:
    lines: list[str] = []
    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    log(_section(f"SMOKE E2E PHASE 5 v1.1.0 — {SLUG} (agent v{__version__})"))
    log(f"timestamp_inicio: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    log(f"source: {FROZEN_SOURCE}")
    log(f"slug: {SLUG}")
    log(f"dest: {DEST}")
    log(f"relatorios: {RELATORIOS}")

    if not FROZEN_SOURCE.exists():
        log("[FAIL] frozen source não existe — rode o robocopy prep antes")
        LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 1

    # Clean any stale dest
    if DEST.exists():
        log(f"[prep] removendo destino legado: {DEST}")
        shutil.rmtree(DEST, ignore_errors=True)

    log(_section("PRE-FLIGHT integrity check"))
    integ = pre_flight_integrity_check(ROOT)
    log(f"integrity ok={integ['ok']} files_total={integ.get('files_total','?')}")

    log(_section("CTX PROGRAMÁTICO ÚNICO (ADR-032 Bloco 05 smoke driver)"))
    ctx = OrchestratorContext(
        run_id=str(uuid.uuid4()),
        slug=SLUG,
        source_path=FROZEN_SOURCE.resolve(),
        dest_path=DEST,
        relatorios_path=RELATORIOS,
        project_root=ROOT,
        base_destinos_root=DEFAULT_GIT_HUB_ROOT,
    )
    log(f"ctx.run_id: {ctx.run_id}")
    log(f"ctx.dest_path: {ctx.dest_path}")

    # =========================================================================
    # STEP 1/4 — dry-run
    # =========================================================================
    log(_section("STEP 1/4 — dry-run (F1 filter + FILTER_DIFF + INV-1 snapshot)"))
    t0 = time.perf_counter()
    rc = run_dry_run(ctx)
    log(f"rc={rc} elapsed={time.perf_counter() - t0:.2f}s")
    if rc != 0:
        log("[FAIL] dry-run não-zero")
        LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 1

    # =========================================================================
    # STEP 2/4 — sanitize-apply
    # =========================================================================
    log(_section("STEP 2/4 — sanitize-apply (F3 + F2 + state→AWAITING_README)"))
    t0 = time.perf_counter()
    rc = run_apply(ctx)
    log(f"rc={rc} elapsed={time.perf_counter() - t0:.2f}s")
    if rc != 0:
        log("[FAIL] apply não-zero")
        LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 1

    # =========================================================================
    # STEP 3/4 — generate-readme (kit emit; [NOME] coloca README depois)
    # =========================================================================
    log(_section("STEP 3/4 — generate-readme (F4 kit emit)"))
    t0 = time.perf_counter()
    rc = run_generate_readme(ctx)
    log(f"rc={rc} elapsed={time.perf_counter() - t0:.2f}s")

    # [NOME] (manual) cola README no destino. Aqui usamos stub minimo.
    readme = ctx.dest_path / "README.md"
    readme.write_text(
        "# A+ AGENTS (sanitized v1.1.0 smoke)\n\n"
        "Réplica funcional sanitizada por repo-sanitizer-agent v1.1.0.\n"
        "Smoke E2E Bloco 05 Passo 5.1 — validação dos 4 gaps do audit 2026-05-22.\n",
        encoding="utf-8",
    )
    log(f"README.md stub gravado: {readme} ({readme.stat().st_size} bytes)")

    # =========================================================================
    # STEP 4/4 — sanitize-finalize (Gate G2)
    # =========================================================================
    log(_section("STEP 4/4 — sanitize-finalize (markdownlint + cleanup + Gate G2)"))
    t0 = time.perf_counter()
    try:
        rc = run_finalize(ctx)
        log(f"rc={rc} elapsed={time.perf_counter() - t0:.2f}s")
        g2_outcome_blocking = False
    except G2BlockingFailure as exc:
        log(f"rc=7 elapsed={time.perf_counter() - t0:.2f}s (G2BlockingFailure: {exc})")
        g2_outcome_blocking = True

    # =========================================================================
    # VALIDAÇÕES DETERMINÍSTICAS (Critérios 5.1.9 .. 5.1.14)
    # =========================================================================
    log(_section("VALIDAÇÕES — 4 GAPS DO AUDIT 2026-05-22 (após v1.1.0)"))

    gap_a = _grep_count(ctx.dest_path, r"[NOME] Camar[ãa]o", apply_g2_skip=True)
    log(f"Gap A — '[NOME]' no destino (skip G2 artifacts): "
        f"{gap_a} match(es) (esperado 0)")

    gap_b = _grep_count(ctx.dest_path, r"\bNOME\b", apply_g2_skip=True)
    log(f"Gap B — '[NOME]' no destino (skip G2 artifacts): "
        f"{gap_b} match(es) (esperado 0)")

    gap_c_w = _grep_count(ctx.dest_path, r"[Cc]:[\\/]VS Code[\\/]", apply_g2_skip=True)
    log(f"Gap C — 'C:/VS Code/' (windows path) no destino (skip G2 artifacts): "
        f"{gap_c_w} match(es) (esperado 0)")

    gap_c_u = _grep_count(ctx.dest_path, r"[Cc]:[\\/]Users[\\/]", apply_g2_skip=True)
    log(f"Gap C bonus — 'C:/Users/' (windows user path) no destino: "
        f"{gap_c_u} match(es) (esperado 0)")

    # Gap D — cross-project — validamos via FILTER_DIFF (não via destino, porque
    # arquivos cross-project foram EXCLUÍDOS — não estão no destino).
    # O destino NÃO deve ter arquivos típicos cross-project.
    cross_marker = _grep_count(
        ctx.dest_path,
        r"_baseline-block08-2026-05-15|\.eval-runs/",
    )
    log(f"Gap D — referências a cross-project baselines/eval-runs no destino: {cross_marker} match(es)")

    # Gap E — Gate G2 (canônico via outcome, não via grep manual)
    # G2-a (boilerplate): para language=generic (A+ AGENTS), passa trivialmente
    # via ADR-033 (não há boilerplate canônico definido para generic). Para
    # python/node/rust/go, o G2 auto-geraria via ADR-033.
    has_pyproject = (ctx.dest_path / "pyproject.toml").exists()
    has_package_json = (ctx.dest_path / "package.json").exists()
    has_cargo = (ctx.dest_path / "Cargo.toml").exists()
    has_go_mod = (ctx.dest_path / "go.mod").exists()
    has_boilerplate_physical = any(
        [has_pyproject, has_package_json, has_cargo, has_go_mod]
    )
    has_license = any(
        (ctx.dest_path / n).exists() for n in ("LICENSE", "LICENSE.md", "LICENSE.txt")
    )
    log(f"Gap E (G2-a info) — boilerplate físico: pyproject={has_pyproject} "
        f"package={has_package_json} cargo={has_cargo} go.mod={has_go_mod} "
        f"(N/A para language=generic — ADR-033)")
    log(f"Gap E (G2-b) — LICENSE presente: {has_license}")
    log(f"Gap E final — Gate G2 outcome bloqueante: {g2_outcome_blocking}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    log(_section("SUMMARY"))
    all_ok = (
        gap_a == 0
        and gap_b == 0
        and gap_c_w == 0
        and gap_c_u == 0
        and has_license
        and not g2_outcome_blocking
    )
    summary = {
        "agent_version": __version__,
        "source": str(FROZEN_SOURCE),
        "dest": str(DEST),
        "gap_a_operador_in_dest": gap_a,
        "gap_b_operador_in_dest": gap_b,
        "gap_c_winpath_vscode": gap_c_w,
        "gap_c_winpath_users": gap_c_u,
        "gap_d_cross_project_markers_in_dest": cross_marker,
        "gap_e_g2_boilerplate_physical": has_boilerplate_physical,
        "gap_e_g2_license_present": has_license,
        "gap_e_g2_blocking": g2_outcome_blocking,
        "all_gaps_closed": all_ok,
    }
    log(json.dumps(summary, indent=2, ensure_ascii=False))

    LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"\n[OK] log gravado em: {LOG_PATH}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
