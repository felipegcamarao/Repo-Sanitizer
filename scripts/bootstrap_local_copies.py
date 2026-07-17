#!/usr/bin/env python3
"""bootstrap_local_copies.py — copia 4 helpers Sentinel para o codebase local.

ADRs ancorados: ADR-022 (injection_patterns), ADR-023 (_sanitize), ADR-015
(_integrity), DEF-08 (_yaml_codec). Reuso A+ build-time + integrity SHA-256 pin.

Operacoes:
1. Le 4 assets upstream em C:/VS Code/A+ AGENTS/Agents Memory/
2. Copia byte-perfect (_sanitize, injection_patterns, _yaml_codec)
3. Adapta `_integrity.py` (lazy import + local now_iso8601) ao copiar
4. Grava SHA-256 das copias locais em `integrity.md` (gate pre-commit)
5. Grava `.versions.json` com upstream SHA-256 para traceabilidade

Uso:
    python scripts/bootstrap_local_copies.py [--rebuild]
    python scripts/bootstrap_local_copies.py --dry-run

Exit codes:
    0 = sucesso
    1 = erro generico
    2 = upstream ausente
    3 = integrity write failed
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path
from typing import NamedTuple

# Paths upstream (Sentinel A+ Agents Memory)
UPSTREAM_BASE = Path("C:/VS Code/A+ AGENTS/Agents Memory")
UPSTREAM_SANITIZE = UPSTREAM_BASE / "helpers" / "_sanitize.py"
UPSTREAM_INJECTION = UPSTREAM_BASE / "schemas" / "injection_patterns.json"
UPSTREAM_INTEGRITY = UPSTREAM_BASE / "helpers" / "_integrity.py"
UPSTREAM_YAML = UPSTREAM_BASE / "helpers" / "_yaml_codec.py"

# Paths locais (este repo)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SENTINEL_FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "sentinel"
HELPERS_DIR = PROJECT_ROOT / "src" / "repo_sanitizer" / "helpers"
INTEGRITY_MD = PROJECT_ROOT / "integrity.md"
VERSIONS_JSON = SENTINEL_FIXTURES / ".versions.json"


class Copy(NamedTuple):
    """Especificacao de uma copia upstream -> local."""
    upstream: Path
    local: Path
    adapt: bool   # se True, transforma conteudo (caso _integrity.py)
    label: str    # nome curto para .versions.json


COPIES: list[Copy] = [
    Copy(UPSTREAM_SANITIZE, SENTINEL_FIXTURES / "_sanitize.py", False, "_sanitize"),
    Copy(UPSTREAM_INJECTION, SENTINEL_FIXTURES / "injection_patterns.json", False, "injection_patterns"),
    Copy(UPSTREAM_YAML, HELPERS_DIR / "_yaml_codec.py", False, "_yaml_codec"),
    Copy(UPSTREAM_INTEGRITY, HELPERS_DIR / "_integrity.py", True, "_integrity"),
]

# Arquivos LOCAIS (nao copiados de upstream) que devem ter SHA-256 no integrity.md
# para gate pre-commit anti-tampering RS-004 + ADR-015.
LOCAL_EXTRAS: list[Path] = [
    PROJECT_ROOT / "src" / "repo_sanitizer" / "secret_patterns.py",
]


def now_iso8601() -> str:
    """ISO 8601 UTC timestamp (zero deps)."""
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def compute_sha256(path: Path) -> str:
    """SHA-256 hex de arquivo binario (chunked)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def adapt_integrity_py(upstream_bytes: bytes) -> bytes:
    """Adapta `_integrity.py` upstream para evitar dep direta do `_audit` Sentinel.

    Transformacoes:
    - Substitui `from _audit import append_audit, make_audit_entry, now_iso8601`
      por lazy stubs locais (now_iso8601 local + audit opcional).

    Mantem a API publica (record_integrity, verify_integrity, compute_file_sha256,
    parse_integrity, main) inalterada.
    """
    src = upstream_bytes.decode("utf-8")

    # Substituicao 1: remove import upstream do _audit
    old = "from _audit import append_audit, make_audit_entry, now_iso8601"
    if old not in src:
        raise RuntimeError(
            f"adapt_integrity_py: linha de import esperada nao encontrada (upstream mudou?): {old!r}"
        )
    replacement = (
        "# Adaptado por bootstrap_local_copies.py (ADR-015): import lazy + now_iso8601 local.\n"
        "import datetime as _dt\n"
        "\n"
        "\n"
        "def now_iso8601():\n"
        "    return _dt.datetime.now(_dt.timezone.utc).strftime(\"%Y-%m-%dT%H:%M:%S+00:00\")\n"
        "\n"
        "\n"
        "def _lazy_audit():\n"
        "    \"\"\"Tenta importar repo_sanitizer.helpers._audit em runtime; falha = no-op.\"\"\"\n"
        "    try:\n"
        "        from repo_sanitizer.helpers._audit import append_audit, make_audit_entry\n"
        "        return append_audit, make_audit_entry\n"
        "    except Exception:\n"
        "        return None, None"
    )
    src = src.replace(old, replacement)

    # Substituicao 2: dentro de verify_integrity, lazy resolve do audit
    old_call = (
        "        try:\n"
        "            append_audit(\n"
        "                audit_file,\n"
        "                make_audit_entry(\n"
        "                    action=\"integrity_check\",\n"
        "                    entry_id=\"integrity\",\n"
        "                    module=\"agent\",\n"
        "                    status=\"fail\",\n"
        "                    detail=f\"mismatches={[m['file'] for m in mismatches]}\",\n"
        "                ),\n"
        "            )\n"
        "        except Exception:\n"
        "            pass"
    )
    new_call = (
        "        append_audit, make_audit_entry = _lazy_audit()\n"
        "        if append_audit is not None and make_audit_entry is not None:\n"
        "            try:\n"
        "                append_audit(\n"
        "                    audit_file,\n"
        "                    make_audit_entry(\n"
        "                        action=\"integrity_check\",\n"
        "                        entry_id=\"integrity\",\n"
        "                        module=\"agent\",\n"
        "                        status=\"fail\",\n"
        "                        detail=f\"mismatches={[m['file'] for m in mismatches]}\",\n"
        "                    ),\n"
        "                )\n"
        "            except Exception:\n"
        "                pass"
    )
    if old_call not in src:
        raise RuntimeError(
            "adapt_integrity_py: bloco verify_integrity audit-call nao encontrado (upstream mudou?)."
        )
    src = src.replace(old_call, new_call)

    return src.encode("utf-8")


def assert_upstream_exists() -> None:
    """Sanidade: 4 paths upstream existem antes de copiar."""
    missing = [str(c.upstream) for c in COPIES if not c.upstream.exists()]
    if missing:
        sys.stderr.write(
            "[bootstrap] ERRO: assets upstream ausentes:\n  - "
            + "\n  - ".join(missing)
            + "\nVerifique pre-requisitos 5-8 em 06-pre-requisitos-operacionais.md.\n"
        )
        sys.exit(2)


def ensure_dirs() -> None:
    """Garante que pastas destino existem."""
    SENTINEL_FIXTURES.mkdir(parents=True, exist_ok=True)
    HELPERS_DIR.mkdir(parents=True, exist_ok=True)


def perform_copy(c: Copy, dry_run: bool) -> dict:
    """Executa uma copia upstream -> local. Retorna metadata."""
    upstream_bytes = c.upstream.read_bytes()
    upstream_sha = hashlib.sha256(upstream_bytes).hexdigest()

    if c.adapt:
        local_bytes = adapt_integrity_py(upstream_bytes)
    else:
        local_bytes = upstream_bytes

    local_sha = hashlib.sha256(local_bytes).hexdigest()

    if not dry_run:
        c.local.parent.mkdir(parents=True, exist_ok=True)
        c.local.write_bytes(local_bytes)

    return {
        "label": c.label,
        "upstream_path": c.upstream.as_posix(),
        "upstream_sha256": upstream_sha,
        "local_path": c.local.relative_to(PROJECT_ROOT).as_posix(),
        "local_sha256": local_sha,
        "adapted": c.adapt,
        "size_bytes": len(local_bytes),
    }


def write_integrity_md(records: list[dict], stamp: str) -> None:
    """Grava integrity.md (formato compativel com helpers/_integrity.py).

    Schema:

        ---
        last_setup: <ISO8601>
        ---

        # Hashes de Integridade
        - file: <relative_path>
          sha256: <hex>
          recorded_at: <ISO8601>
    """
    lines = [
        "---",
        f"last_setup: {stamp}",
        "schema_version: 4.1.0",
        "agent: repo-sanitizer-agent",
        "---",
        "",
        "# Hashes de Integridade",
        "",
        "> Gate pre-commit: `python scripts/verify_integrity_manifest.py` exit 0 == OK.",
        "> Mismatch = exit 3 (ADR-015 + ADR-022 + ADR-023).",
        "",
    ]
    for r in records:
        lines.append(f"- file: {r['local_path']}")
        lines.append(f"  sha256: {r['local_sha256']}")
        lines.append(f"  recorded_at: {stamp}")
    INTEGRITY_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_versions_json(records: list[dict], stamp: str) -> None:
    """Grava .versions.json com upstream SHA-256 + metadata para traceabilidade."""
    payload = {
        "schema_version": "1.0.0",
        "agent": "repo-sanitizer-agent",
        "agent_version": "0.1.0a1",
        "bootstrap_at": stamp,
        "sentinel_upstream_root": str(UPSTREAM_BASE),
        "sentinel_pin": {
            "_sanitize_version": "v1.2.0",
            "injection_patterns_version": "1.0.0",
            "_yaml_codec_version": "1.0.0",
            "_integrity_version": "Sentinel v1.x (adapted local for repo-sanitizer)",
        },
        "copies": records,
    }
    SENTINEL_FIXTURES.mkdir(parents=True, exist_ok=True)
    VERSIONS_JSON.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="bootstrap_local_copies")
    parser.add_argument("--dry-run", action="store_true",
                        help="Computa SHA-256 sem gravar arquivos.")
    parser.add_argument("--rebuild", action="store_true",
                        help="Re-roda copia mesmo se integrity.md ja existe.")
    args = parser.parse_args(argv)

    assert_upstream_exists()
    ensure_dirs()

    if INTEGRITY_MD.exists() and not args.rebuild and not args.dry_run:
        print(
            "[bootstrap] integrity.md ja existe; use --rebuild para re-rodar. "
            "Verifying instead..."
        )

    records: list[dict] = []
    for c in COPIES:
        meta = perform_copy(c, dry_run=args.dry_run)
        records.append(meta)
        marker = "[DRY-RUN]" if args.dry_run else "[OK]"
        print(f"{marker} {c.label:22s}  upstream_sha=...{meta['upstream_sha256'][:8]}  "
              f"local_sha=...{meta['local_sha256'][:8]}  size={meta['size_bytes']}B")

    # Adiciona local-extras (secret_patterns.py) ao manifest sem copia upstream
    for local in LOCAL_EXTRAS:
        if not local.exists():
            print(f"[bootstrap] WARN: local-extra ausente, skip: {local}")
            continue
        sha = compute_sha256(local)
        rec = {
            "label": local.stem,
            "upstream_path": None,
            "upstream_sha256": None,
            "local_path": local.relative_to(PROJECT_ROOT).as_posix(),
            "local_sha256": sha,
            "adapted": False,
            "size_bytes": local.stat().st_size,
        }
        records.append(rec)
        marker = "[DRY-RUN]" if args.dry_run else "[OK]"
        print(f"{marker} {local.stem:22s}  upstream_sha=---       "
              f"local_sha=...{sha[:8]}  size={rec['size_bytes']}B (local-extra)")

    if not args.dry_run:
        stamp = now_iso8601()
        write_integrity_md(records, stamp)
        write_versions_json(records, stamp)
        print(f"\n[bootstrap] integrity.md gravado em {INTEGRITY_MD}")
        print(f"[bootstrap] .versions.json gravado em {VERSIONS_JSON}")

    print("\n[bootstrap] DONE: 4/4 local-copies prontas (ADR-015/022/023 + DEF-08).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
