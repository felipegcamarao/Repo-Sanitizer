#!/usr/bin/env python3
"""verify_integrity_manifest.py — Gate pre-commit (ADR-015 + ADR-022 + ADR-023).

Verifica que os 4 local-copies + secret_patterns.py (quando existir) batem com
o SHA-256 registrado em `integrity.md`.

Exit codes:
    0 = todos os hashes ok
    3 = mismatch detectado (qualquer arquivo)
    2 = integrity.md ausente / vazio
    1 = erro generico

Uso (pre-commit / CI local):

    python scripts/verify_integrity_manifest.py
    # ou via Bloco 01.7: helpers/_integrity.py CLI:
    python -m repo_sanitizer.helpers._integrity verify \\
        --integrity-md integrity.md --project-root .
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INTEGRITY_MD = PROJECT_ROOT / "integrity.md"


def main(argv: list[str]) -> int:
    if not INTEGRITY_MD.exists():
        sys.stderr.write(
            f"[verify_integrity] integrity.md ausente em {INTEGRITY_MD}.\n"
            f"Execute primeiro: python scripts/bootstrap_local_copies.py\n"
        )
        return 2

    # Late import para permitir que este script funcione mesmo se helpers/
    # ainda nao estiver instalado (ex: pre-pip install -e .)
    try:
        from repo_sanitizer.helpers._integrity import verify_integrity
    except ImportError as exc:
        sys.stderr.write(
            f"[verify_integrity] Falha ao importar repo_sanitizer.helpers._integrity: {exc}\n"
            f"Execute: pip install -e .\n"
        )
        return 1

    result = verify_integrity(INTEGRITY_MD, PROJECT_ROOT, audit_file=None)

    if result["ok"]:
        print(f"[verify_integrity] OK: {result['checked']} arquivo(s) verificados.")
        return 0

    sys.stderr.write(
        f"[verify_integrity] FAIL: {len(result['mismatches'])} mismatch(es) detectado(s):\n"
    )
    for m in result["mismatches"]:
        sys.stderr.write(f"  - {m['file']}: {m['reason']}\n")
        if "expected" in m:
            sys.stderr.write(f"      expected: {m['expected']}\n")
            sys.stderr.write(f"      actual:   {m['actual']}\n")
    sys.stderr.write(
        "\nCausa provavel: arquivo modificado sem re-run do bootstrap.\n"
        "Se mudanca intencional: python scripts/bootstrap_local_copies.py --rebuild\n"
        "Se inesperada: investigue (possivel tampering, ADR-015 + RS-004).\n"
    )
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
