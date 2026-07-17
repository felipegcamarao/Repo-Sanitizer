"""smoke_e2e_phase5.py — Orquestrador Fase 5 (05-Test-Agent v1.x).

Executa em 1 comando os DoDs 3+4+5+6 da Fase 5:

  DoD 3: smoke proxy 14 fixtures + golden path 4 comandos UX.D-01
  DoD 4: performance baselines (4 budgets)
  DoD 5: cross-platform Windows 11 (5+ cenarios)
  DoD 6: fuzzing adversarial 35 entradas

Saida: report textual stdout + exit code (0 = todos verde).

Pattern WF-V03-14 LinkedIn Bloco 10 + adaptado a repo-sanitizer-agent v1.0.0.
INV-1 preservado: SOURCE NUNCA modificada; tudo em pytest tmp_path.
Modo PROXY canonico (14 fixtures); modo REAL desbloqueado se [NOME] fornecer
--real-repos C:/VS Code/<repo1>,C:/VS Code/<repo2>,...

Uso:
    python scripts/smoke_e2e_phase5.py                  # PROXY canonico
    python scripts/smoke_e2e_phase5.py --real-repos ... # REAL (futuro v1.1)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

# UTF-8 stdout (Windows cp1252 fix; heritage D-EX-29)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


# ---------------------------------------------------------------------------
# Test groups (label + pytest-nodeid + expected count)
# ---------------------------------------------------------------------------


PROXY_GROUPS: list[dict[str, str | int]] = [
    {
        "label": "DoD 2 - 16 RS isolated smokes",
        "nodeid": "tests/security/test_phase5_rs_isolated_smokes.py",
        "expected_min": 16,
    },
    {
        "label": "DoD 3 - 14 fixtures Bloco 02+03+04 (INV-1 12 fixtures)",
        "nodeid": "tests/integration/test_inv1_snapshot.py tests/integration/test_inv1_snapshot_f3.py",
        "expected_min": 18,
    },
    {
        "label": "DoD 3 - RS-001 multi-pass 7 fixtures adversariais",
        "nodeid": "tests/integration/test_rs001_multi_pass.py",
        "expected_min": 7,
    },
    {
        "label": "DoD 3 - F2 score 5 fixtures + F4 golden path",
        "nodeid": "tests/integration/test_f2_score_5_fixtures.py tests/integration/test_f4_golden_path.py",
        "expected_min": 16,
    },
    {
        "label": "DoD 4 - performance baselines (4 budgets)",
        "nodeid": "tests/integration/test_phase5_performance_baselines.py",
        "expected_min": 4,
    },
    {
        "label": "DoD 5 - cross-platform Windows 11 (5+ cenarios)",
        "nodeid": "tests/integration/test_phase5_cross_platform_win11.py",
        "expected_min": 14,
    },
    {
        "label": "DoD 6 - fuzzing adversarial 35 entradas",
        "nodeid": "tests/integration/test_phase5_fuzzing_adversarial.py",
        "expected_min": 35,
    },
    {
        "label": "DoD 7 - f3_sanitizer.py cov push >=88% (12 mock-based)",
        "nodeid": "tests/unit/f3/test_f3_phase5_cov_push.py",
        "expected_min": 12,
    },
    {
        "label": "DoD 8 - f4_readme.py cov push >=85% (20 subprocess mocks)",
        "nodeid": "tests/unit/f4/test_f4_phase5_cov_push.py",
        "expected_min": 20,
    },
    # ----- v1.1.0 (Bloco 05 Passo 5.2) — 3 novos cenarios canonicos -----
    {
        "label": "v1.1.0 - C9 PII Detector (unit + threat-tree)",
        "nodeid": "tests/unit/test_f3_c9_pii_detector.py tests/security/test_threat_tree_C9_pii.py",
        "expected_min": 15,
    },
    {
        "label": "v1.1.0 - C10 Path Sanitizer (unit helper + F3 integration + threat-tree)",
        "nodeid": "tests/unit/helpers/test__path_sanitizer.py tests/integration/test_f3_c10_integration.py tests/security/test_threat_tree_C10.py",
        "expected_min": 30,
    },
    {
        "label": "v1.1.0 - F1.5 Cross-Project Detection (unit classifier + integration + threat-tree)",
        "nodeid": "tests/unit/helpers/test__cross_project_classifier.py tests/integration/test_f1_5_cross_project.py tests/security/test_threat_tree_F1_5.py",
        "expected_min": 25,
    },
]


def run_group(group: dict[str, str | int]) -> tuple[bool, str]:
    """Roda 1 grupo pytest. Returns (ok, summary_line)."""
    cmd = [sys.executable, "-m", "pytest", *str(group["nodeid"]).split(), "--tb=line", "-q", "--no-header"]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    elapsed = time.perf_counter() - t0
    last = proc.stdout.strip().splitlines()[-1] if proc.stdout else ""
    ok = proc.returncode == 0
    summary = f"{last} ({elapsed:.2f}s)"
    return ok, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fase 5 smoke E2E orchestrator (DoD 3+4+5+6 + cov push).",
    )
    parser.add_argument(
        "--real-repos",
        type=str,
        default=None,
        help="(Futuro v1.1) Lista de repos reais [NOME]; modo REAL (DoD 3.5 repos).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit relatorio JSON ao final.",
    )
    args = parser.parse_args()

    mode = "REAL" if args.real_repos else "PROXY"
    print(f"[smoke_e2e_phase5] Modo: {mode}")
    if mode == "REAL":
        print("[smoke_e2e_phase5] AVISO: modo REAL ainda nao implementado; defaulting PROXY")
        mode = "PROXY"

    print(f"[smoke_e2e_phase5] Executando {len(PROXY_GROUPS)} grupos de testes...\n")

    results: list[dict[str, object]] = []
    all_ok = True
    for grp in PROXY_GROUPS:
        ok, summary = run_group(grp)
        status = "[OK]" if ok else "[FAIL]"
        line = f"  {status} {grp['label']!s:<70} | {summary}"
        print(line)
        results.append({
            "label": grp["label"],
            "ok": ok,
            "summary": summary,
            "expected_min": grp["expected_min"],
        })
        if not ok:
            all_ok = False

    print()
    total_passed = sum(1 for r in results if r["ok"])
    print(
        f"[smoke_e2e_phase5] Resultado: "
        f"{total_passed}/{len(PROXY_GROUPS)} grupos verde "
        f"({'TODOS VERDE' if all_ok else 'FALHA - VER ACIMA'}).",
    )

    if args.json:
        report = {
            "mode": mode,
            "groups_total": len(PROXY_GROUPS),
            "groups_passing": total_passed,
            "all_ok": all_ok,
            "results": results,
        }
        report_path = Path("Relatorios") / "smoke-e2e-phase5-report.json"
        report_path.parent.mkdir(exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[smoke_e2e_phase5] JSON report: {report_path}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
