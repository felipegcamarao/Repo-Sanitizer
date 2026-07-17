"""security_audit_phase6.py — Orquestrador da Fase 6 (06-Security-Auditor v1.x).

Re-valida em 1 comando:
- Release Gate v1.0 (20/20)
- smoke_e2e_phase5 (9/9 grupos)
- 3 suites Fase 6: tests/security/test_phase6_*.py
- pip-audit runtime + integrity manifest verify

Saida: rich console + JSON em ./security-audit-phase6-output.json.

Exit codes:
- 0 = todos os checks verdes (handoff 07-Staff = VERDE)
- 1 = qualquer falha (handoff 07-Staff = bloqueado)
"""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import time
from pathlib import Path

# Fix Windows cp1252 stdout (heritage D-EX-29)
with contextlib.suppress(AttributeError, OSError):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Executa subprocess; retorna (exit_code, stdout_tail, stderr_tail)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            cwd=str(PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    # Cap tails to keep output readable
    return proc.returncode, out[-500:], err[-500:]


def _print(label: str, status: str, info: str = "") -> None:
    """Linha de progresso visual."""
    icon = "[OK]  " if status == "OK" else "[FAIL]" if status == "FAIL" else "[--] "
    print(f"  {icon} {label:<60} | {info}")


def main() -> int:
    print("[security_audit_phase6] Iniciando auditoria Fase 6 (06-Security-Auditor v1.x)...")
    print()

    results: list[dict] = []
    t0 = time.perf_counter()

    # ----- 1) Release Gate v1.0 (20/20) -----
    print("[1/5] Re-rodando Release Gate v1.0...")
    # S-OBS-03 v1.0.1 (D-FF-04): timeout 120 -> 300 (WF-18: >= 3x max_step_wall_time;
    # Gate Crit 16 pytest --cov leva ~75s direto + overhead nested subprocess ~60s).
    rc, out, err = _run([sys.executable, "scripts/release_gate_v1_0.py"], timeout=300)
    gate_ok = rc == 0
    _print("Release Gate v1.0 (20 criterios)", "OK" if gate_ok else "FAIL",
           "20/20 verde" if gate_ok else f"exit={rc}")
    results.append({"check": "release_gate_v1_0", "ok": gate_ok, "exit": rc})
    if not gate_ok:
        print(out[-300:])
        print(err[-300:])

    # ----- 2) smoke_e2e_phase5 (9/9 grupos) -----
    print()
    print("[2/5] Re-rodando smoke_e2e_phase5...")
    rc, out, err = _run([sys.executable, "scripts/smoke_e2e_phase5.py"], timeout=120)
    smoke_ok = rc == 0
    _print("smoke_e2e_phase5 (9 grupos)", "OK" if smoke_ok else "FAIL",
           "9/9 verde" if smoke_ok else f"exit={rc}")
    results.append({"check": "smoke_e2e_phase5", "ok": smoke_ok, "exit": rc})

    # ----- 3) 3 suites Fase 6 -----
    print()
    print("[3/5] Rodando 3 suites tests/security/test_phase6_*.py...")
    phase6_suites = [
        ("F3 7 camadas zero leak (RS-001)",
         "tests/security/test_phase6_f3_zero_leak.py"),
        ("INV-1 + FsWriter + supply chain (RS-002+007)",
         "tests/security/test_phase6_inv1_and_writer.py"),
        ("F4 + Pydantic + LGPD + audit + 6 Threat Trees (RS-003+005+011+018)",
         "tests/security/test_phase6_f4_injection_and_pydantic.py"),
    ]
    suites_ok = True
    for label, path in phase6_suites:
        rc, out, err = _run(
            [sys.executable, "-m", "pytest", path, "-q", "--tb=line"], timeout=60,
        )
        ok = rc == 0
        suites_ok = suites_ok and ok
        # Last line typically contains "N passed"
        last = out.splitlines()[-1] if out else ""
        _print(label, "OK" if ok else "FAIL", last[:80])
        results.append({"check": f"phase6_suite::{path}", "ok": ok, "exit": rc})

    # ----- 4) integrity manifest verify -----
    print()
    print("[4/5] Verificando integrity manifest...")
    rc, out, err = _run(
        [sys.executable, "scripts/verify_integrity_manifest.py"], timeout=30,
    )
    integ_ok = rc == 0
    _print("integrity.md verify (5 arquivos)", "OK" if integ_ok else "FAIL", out[:80])
    results.append({"check": "integrity_manifest", "ok": integ_ok, "exit": rc})

    # ----- 5) pip-audit (delegado a Release Gate Criterio 15 acima) -----
    print()
    print("[5/5] pip-audit runtime deps (delegado a Release Gate Criterio 15)...")
    # Gate Crit 15 ja valida; nao re-roda aqui para evitar ambiguidade
    # (D-EX-05 carry-over: toolchain venv tem 5 CVE; runtime deps 0 CVE)
    _print("pip-audit runtime (delegado)", "OK" if gate_ok else "FAIL",
           "via Release Gate Crit 15 (D-EX-05 carry-over imutavel)")
    results.append({
        "check": "pip_audit_via_gate_crit_15",
        "ok": gate_ok,
        "note": "delegado a Release Gate Criterio 15 (D-EX-05 carry-over)",
    })

    # ----- Sumario -----
    t1 = time.perf_counter()
    all_ok = all(r["ok"] for r in results)
    print()
    print("=" * 70)
    print(
        f"[security_audit_phase6] Resultado: "
        f"{'TODOS VERDE' if all_ok else 'BLOQUEADO'} | "
        f"wall-time {t1 - t0:.1f}s"
    )
    print("=" * 70)

    # JSON output (auditoria + automacao)
    output = {
        "phase": 6,
        "agent": "06-Security-Auditor",
        "agent_version": "1.x",
        "wall_time_seconds": round(t1 - t0, 2),
        "all_ok": all_ok,
        "handoff_07_staff": "VERDE" if all_ok else "BLOQUEADO",
        "checks": results,
    }
    out_path = PROJECT_ROOT / "security-audit-phase6-output.json"
    out_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"[security_audit_phase6] JSON gravado em: {out_path}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
