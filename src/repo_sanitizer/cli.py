"""cli.py — argparse + 4 subcomandos UX.D-01 + exit codes 0..8.

Subcomandos canonicos:
    repo-sanitize dry-run --source-path <repo>          # default; F1 + FILTER_DIFF
    repo-sanitize sanitize-apply --slug <nome>          # F3 + F2 + stub README
    repo-sanitize generate-readme --slug <nome>         # delega Claude Code chat
    repo-sanitize sanitize-finalize --slug <nome>       # markdownlint + cleanup

Flags globais: --slug, --source-path, --verbose, --no-color.

Bloco 01 = skeleton stdout + exit codes corretos. Blocos 02..05 hidratam.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from repo_sanitizer import __version__
from repo_sanitizer.helpers._boilerplate_generator import ALLOWED_LICENSES
from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError
from repo_sanitizer.helpers._state_machine import InvalidTransitionError
from repo_sanitizer.orchestrator import (
    F3Timeout,
    G2BlockingFailure,
    GitHistoryInDestination,
    IntegrityFailure,
    Inv1Violation,
    make_orchestrator_context,
    pre_flight_integrity_check,
    run_apply,
    run_dry_run,
    run_finalize,
    run_generate_readme,
)

PROG = "repo-sanitize"


def build_parser() -> argparse.ArgumentParser:
    """Constroi o argparse com 4 subcomandos canonicos."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "GitHub Repo Sanitizer & Publisher Agent (Pipeline A+ v4.1.x). "
            "AgenteIA local-first PT-BR; R$ 0 inviolavel; Windows 11 first."
        ),
        epilog=(
            "Golden path 4 comandos UX.D-01: dry-run -> sanitize-apply -> "
            "generate-readme -> sanitize-finalize. O operador revisa o README pre-push."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument("--no-color", action="store_true", help="Desativa rich (degrade gracioso).")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    # Auditoria 2026-07: destino e relatorios configuraveis (antes hardcoded).
    parser.add_argument(
        "--dest-root", type=Path, default=None,
        help=(
            "Pasta-base onde os destinos GIT_[slug] sao criados "
            "(default: C:/VS Code/Git Hub - [NOME])."
        ),
    )
    parser.add_argument(
        "--relatorios-dir", type=Path, default=None,
        help=(
            "Pasta dos relatorios FILTER_DIFF/SANITIZATION_REPORT/audit-log "
            "(default: <dest-root>/Relatorios)."
        ),
    )

    sub = parser.add_subparsers(dest="cmd", required=True, metavar="<comando>")

    # 1) dry-run (default invocacao inicial)
    p_dry = sub.add_parser(
        "dry-run",
        help="F1 filtro + FILTER_DIFF (zero escrita destino).",
        description="Executa F1 em modo dry-run; emite FILTER_DIFF.md em /Relatorios/. INV-1 read-only.",
    )
    p_dry.add_argument("--source-path", required=True, type=Path,
                       help="Path do repo-fonte (read-only INV-1).")
    p_dry.add_argument("--slug", required=False, type=str,
                       help="Nome do destino (default: basename do source-path).")

    # 2) sanitize-apply
    p_apply = sub.add_parser(
        "sanitize-apply",
        help="Duplica + F3 (sanitiza) + F2 (organiza) + stub README.",
        description="Aplica F3 + F2 sobre duplicado; nao toca fonte (INV-1).",
    )
    p_apply.add_argument("--slug", required=True, type=str)
    p_apply.add_argument("--source-path", required=True, type=Path)
    p_apply.add_argument(
        "--entropy",
        choices=("on", "off"),
        default="on",
        help=(
            "Camada ADITIVA de deteccao por entropia de Shannon (MV-04 / ADR-034). "
            "Default 'on' (cobertura maxima de chaves custom sem prefixo, com "
            "allowlist dura HARDCODED que protege git-SHA/UUID/SRI/lockfile). "
            "'off' -> camada SKIPPED no checklist de publicacao."
        ),
    )

    # 3) generate-readme (delega Claude Code chat)
    p_rd = sub.add_parser(
        "generate-readme",
        help="Emite kit JSON e instrucao para [NOME] invocar Claude Code chat.",
        description="Bloco 05; INV-9 runtime Claude Code.",
    )
    p_rd.add_argument("--slug", required=True, type=str)
    p_rd.add_argument("--source-path", required=True, type=Path)

    # 4) sanitize-finalize
    p_fin = sub.add_parser(
        "sanitize-finalize",
        help="markdownlint + link-check + cleanup .tmp/ + Gate G2 (ADR-032).",
        description=(
            "Bloco 05; degrade gracioso (ADR-013). "
            "Aplica Gate G2 (Replica Funcional Verified): boilerplate publicavel, "
            "LICENSE, zero paths absolutos, zero PII operador. "
            "Exit 7 se gate (c)/(d) falhar; exit 0 com warnings se (a)/(b) auto-gerados."
        ),
    )
    p_fin.add_argument("--slug", required=True, type=str)
    p_fin.add_argument("--source-path", required=True, type=Path)
    p_fin.add_argument(
        "--license",
        choices=list(ALLOWED_LICENSES),
        default="MIT",
        help=(
            "ID da licenca a ser auto-gerada quando LICENSE estiver ausente no "
            "destino (Gate G2 check (b), ADR-033). Default: MIT."
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry-point CLI. Exit codes 0..8 (ver orchestrator.py).

    7 = Gate G2 bloqueante; 8 = historico Git no destino (MV-02 / RS-NEW-038).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    project_root = Path(__file__).resolve().parent.parent.parent
    from repo_sanitizer.orchestrator import DEFAULT_GIT_HUB_ROOT
    dest_root = args.dest_root or DEFAULT_GIT_HUB_ROOT
    relatorios_path = args.relatorios_dir or (dest_root / "Relatorios")

    # Pre-flight integrity gate (Bloco 01 RS-004 + ADR-015): aplicado em TODA invocacao.
    try:
        pre_flight_integrity_check(project_root)
    except IntegrityFailure as exc:
        sys.stderr.write(f"[cli] FAIL integrity: {exc}\n")
        sys.stderr.write(
            "[cli] Recurso provavel: alguem editou local-copy sem rebuild. "
            "Execute: python scripts/bootstrap_local_copies.py --rebuild (se intencional).\n"
        )
        return 3

    try:
        ctx = make_orchestrator_context(
            source_path=args.source_path,
            relatorios_path=relatorios_path,
            project_root=project_root,
            slug=getattr(args, "slug", None),
            base_destinos_root=dest_root,
        )
        # Propagar override de licenca (Bloco 04 ADR-033) se aplicavel
        if args.cmd == "sanitize-finalize":
            ctx.extra["license_override"] = args.license
        # Propagar flag de entropia (MV-04 / ADR-034 / C3) ao F3 via ctx.extra.
        if args.cmd == "sanitize-apply":
            ctx.extra["entropy_enabled"] = (args.entropy == "on")
        if args.cmd == "dry-run":
            return run_dry_run(ctx)
        if args.cmd == "sanitize-apply":
            return run_apply(ctx)
        if args.cmd == "generate-readme":
            return run_generate_readme(ctx)
        if args.cmd == "sanitize-finalize":
            return run_finalize(ctx)
        parser.error(f"Subcomando desconhecido: {args.cmd}")
        return 1

    except Inv1Violation as exc:
        sys.stderr.write(f"[cli] INV-1 violation: {exc}\n")
        return 2
    except IntegrityFailure as exc:
        sys.stderr.write(f"[cli] integrity mismatch: {exc}\n")
        return 3
    except InvalidTransitionError as exc:
        sys.stderr.write(f"[cli] state machine invalid transition: {exc}\n")
        return 4
    except FsWriteOutOfBoundsError as exc:
        sys.stderr.write(f"[cli] FsWriteOutOfBoundsError: {exc}\n")
        return 5
    except F3Timeout as exc:
        sys.stderr.write(f"[cli] F3 timeout: {exc}\n")
        return 6
    except G2BlockingFailure as exc:
        sys.stderr.write(f"[cli] Gate G2 bloqueante: {exc}\n")
        sys.stderr.write(
            "[cli] Recurso provavel: re-execute /sanitize-apply (Bloco F3 deve "
            "ter deixado paths absolutos ou PII no destino). Inspecione o "
            "SANITIZATION_REPORT.md seção 'Gate G2 — Replica Funcional'.\n"
        )
        return 7
    except GitHistoryInDestination as exc:
        sys.stderr.write(f"[cli] Historico Git no destino: {exc}\n")
        sys.stderr.write(
            "[cli] Gate BLOQUEANTE (MV-02 / RS-NEW-038): a replica sanitizada "
            "contem artefatos de historico Git (.git/, packed-refs, *.patch, "
            ".gitattributes com filtros, etc.). NAO publique. Remova os "
            "artefatos do destino e re-execute /sanitize-apply.\n"
        )
        return 8
    except Exception as exc:
        sys.stderr.write(f"[cli] erro generico: {type(exc).__name__}: {exc}\n")
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
