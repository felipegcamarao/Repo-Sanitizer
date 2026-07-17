#!/usr/bin/env python3
"""_integrity.py — hashes SHA-256 de arquivos sensíveis (RS-011).

Schema do `integrity.md`:

    ---
    last_setup: <ISO8601>
    ---

    # Hashes de Integridade
    - file: web_search.py
      sha256: <sha256_hex>
      recorded_at: <ISO8601>
    - file: memory_writer.py
      sha256: <sha256_hex>
      recorded_at: <ISO8601>
    - file: memory_reader.py
      sha256: <sha256_hex>
      recorded_at: <ISO8601>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# Adaptado por bootstrap_local_copies.py (ADR-015): import lazy + now_iso8601 local.
import datetime as _dt


def now_iso8601():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _lazy_audit():
    """Tenta importar repo_sanitizer.helpers._audit em runtime; falha = no-op."""
    try:
        from repo_sanitizer.helpers._audit import append_audit, make_audit_entry
        return append_audit, make_audit_entry
    except Exception:
        return None, None

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def compute_file_sha256(path: Path) -> str:
    """SHA-256 hex de um arquivo binário."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def record_integrity(file_paths: list, integrity_md: Path) -> dict:
    """Recompõe `integrity.md` com hashes de cada arquivo da lista."""
    now = now_iso8601()
    lines = [
        "---",
        f"last_setup: {now}",
        "---",
        "",
        "# Hashes de Integridade",
    ]
    recorded = []
    for fp in file_paths:
        path = Path(fp)
        if not path.exists():
            raise FileNotFoundError(f"_integrity: arquivo ausente: {fp}")
        h = compute_file_sha256(path)
        lines.append(f"- file: {path.name}")
        lines.append(f"  sha256: {h}")
        lines.append(f"  recorded_at: {now}")
        recorded.append({"file": path.name, "sha256": h})
    integrity_md.parent.mkdir(parents=True, exist_ok=True)
    integrity_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"last_setup": now, "files": recorded}


_INTEGRITY_ENTRY_RE = re.compile(
    r"-\s*file:\s*(?P<file>\S+)\s*\n\s*sha256:\s*(?P<sha256>[a-f0-9]{64})",
    re.MULTILINE,
)


def parse_integrity(integrity_md: Path) -> list:
    """Parse mínimo de `integrity.md` → lista [{file, sha256}, ...]."""
    if not integrity_md.exists():
        return []
    text = integrity_md.read_text(encoding="utf-8")
    return [
        {"file": m.group("file"), "sha256": m.group("sha256")}
        for m in _INTEGRITY_ENTRY_RE.finditer(text)
    ]


def verify_integrity(
    integrity_md: Path,
    project_root: Path,
    audit_file: Path | None = None,
) -> dict:
    """RS-011: recomputa hashes e compara com `integrity.md`.

    Retorna {ok: bool, mismatches: list[dict], checked: int}.
    Se audit_file != None e algum mismatch, anexa entry `integrity_check status: fail`.
    """
    recorded = parse_integrity(integrity_md)
    if not recorded:
        return {"ok": False, "mismatches": [], "checked": 0,
                "reason": "integrity.md vazio ou ausente — execute setup"}
    mismatches = []
    for item in recorded:
        path = project_root / item["file"]
        if not path.exists():
            mismatches.append({"file": item["file"], "reason": "arquivo ausente"})
            continue
        current = compute_file_sha256(path)
        if current != item["sha256"]:
            mismatches.append({
                "file": item["file"],
                "reason": "hash mismatch",
                "expected": item["sha256"],
                "actual": current,
            })
    ok = len(mismatches) == 0
    if not ok and audit_file is not None:
        append_audit, make_audit_entry = _lazy_audit()
        if append_audit is not None and make_audit_entry is not None:
            try:
                append_audit(
                    audit_file,
                    make_audit_entry(
                        action="integrity_check",
                        entry_id="integrity",
                        module="agent",
                        status="fail",
                        detail=f"mismatches={[m['file'] for m in mismatches]}",
                    ),
                )
            except Exception:
                pass
    return {"ok": ok, "mismatches": mismatches, "checked": len(recorded)}


def main(argv) -> int:
    parser = argparse.ArgumentParser(prog="_integrity.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_record = sub.add_parser("record", help="Grava hashes em integrity.md.")
    p_record.add_argument("--integrity-md", required=True)
    p_record.add_argument("--files", required=True,
                          help="Lista de paths separada por vírgula.")

    p_verify = sub.add_parser("verify", help="Verifica hashes de integrity.md.")
    p_verify.add_argument("--integrity-md", required=True)
    p_verify.add_argument("--project-root", required=True)
    p_verify.add_argument("--audit-file", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "record":
        files = [s.strip() for s in args.files.split(",") if s.strip()]
        result = record_integrity(files, Path(args.integrity_md))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "verify":
        audit = Path(args.audit_file) if args.audit_file else None
        result = verify_integrity(
            Path(args.integrity_md), Path(args.project_root), audit
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 3

    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
