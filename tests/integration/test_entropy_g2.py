"""test_entropy_g2.py — C2 / MV-04 / RS-NEW-036/037 / T-01 (integration).

Pipeline F3 end-to-end com a Camada de entropia:
- replica realista com lockfile (SRI/UUID/SHA) permanece `done` no Gate G2
  (RS-NEW-036 / T-01 — entropia NAO quebra a replica funcional);
- token custom de alta entropia em arquivo de codigo -> redatado (RS-NEW-037);
- `--entropy off` (entropy_enabled=False) -> camada SKIPPED (token NAO redatado).
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f3_sanitizer import run_f3
from repo_sanitizer.f4_readme import run_g2_replica_funcional
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._entropy_detector import ENTROPY_PLACEHOLDER
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CUSTOM_TOKEN = "aB3xQ9zK7mP2wV5nL8rT4yU6sD1fG0hJ"
SRI_HASH = "sha512-abcDEF0123456789+/abcDEF0123456789ghijklMNOPqrstuvwx=="
UUID_V4 = "550e8400-e29b-41d4-a716-446655440000"
GIT_SHA40 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"


def _setup(tmp_path: Path, slug: str = "entg2") -> tuple[Path, Path, FsWriter, AuditLogger]:
    src = tmp_path / "src"
    src.mkdir()
    # Repo Python valido (G2 language detection).
    (src / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    (src / "README.md").write_text("# demo\n\nA demo project.\n", encoding="utf-8")
    pkg = src / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    # Arquivo de codigo com token custom de alta entropia (deve ser redatado
    # PELA ENTROPIA, nao pela matriz regex — nome de variavel NEUTRO, sem
    # `secret`/`token`/`key`/`password`/`auth` que dispararia CONFIG_KEY_GENERIC).
    (pkg / "config.py").write_text(
        f'BLOB_VALUE = "{CUSTOM_TOKEN}"\nVERSION = "1.0.0"\n',
        encoding="utf-8",
    )
    # Lockfile com SRI hash (NAO pode ser redatado — quebraria o build).
    (src / "package-lock.json").write_text(
        '{\n'
        '  "name": "demo",\n'
        '  "lockfileVersion": 3,\n'
        '  "packages": {\n'
        '    "node_modules/left-pad": {\n'
        f'      "integrity": "{SRI_HASH}"\n'
        '    }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    # Arquivo de codigo com UUID e git-SHA legitimos (allowlist -> intactos).
    (pkg / "ids.py").write_text(
        f'SESSION_ID = "{UUID_V4}"\nBUILD_COMMIT = "{GIT_SHA40}"\n',
        encoding="utf-8",
    )

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    dest = allowed / f"GIT_{slug}-v1"
    dest.mkdir()
    fw = FsWriter(source_path=src, allowed_roots=[allowed], override_forbidden=[])
    audit = AuditLogger(
        audit_file=relatorios / "audit-log.jsonl", fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="0.3.0a1", sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64, slug=slug,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    return src, dest, fw, audit


def test_custom_token_redacted_lockfile_and_allowlist_intact(tmp_path: Path) -> None:
    """Entropia ON: token custom redatado; SRI/UUID/SHA40 preservados."""
    src, dest, fw, audit = _setup(tmp_path)
    result = run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
        entropy_enabled=True,
    )
    config_out = (dest / "app" / "config.py").read_text(encoding="utf-8")
    assert CUSTOM_TOKEN not in config_out
    assert ENTROPY_PLACEHOLDER in config_out
    assert result.entropy_count >= 1

    # T-01: lockfile SRI hash INTACTO (build nao quebra).
    lock_out = (dest / "package-lock.json").read_text(encoding="utf-8")
    assert SRI_HASH in lock_out
    assert ENTROPY_PLACEHOLDER not in lock_out

    # UUID e git-SHA40 (allowlist) preservados no codigo.
    ids_out = (dest / "app" / "ids.py").read_text(encoding="utf-8")
    assert UUID_V4 in ids_out
    assert GIT_SHA40 in ids_out


def test_replica_passes_g2_done_with_entropy(tmp_path: Path) -> None:
    """RS-NEW-036 / T-01: replica realista com lockfile permanece `done` em G2."""
    src, dest, fw, audit = _setup(tmp_path, "entg2done")
    run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
        entropy_enabled=True,
    )
    g2 = run_g2_replica_funcional(
        dest_path=dest, project_root=PROJECT_ROOT, fs_writer=fw, audit=audit,
        project_slug="demo",
    )
    # Nenhum bloqueio (c)/(d): zero paths absolutos, zero PII operador.
    assert g2.outcome in ("done", "done_with_warnings")
    assert g2.outcome != "done_with_failure"


def test_entropy_off_skips_layer(tmp_path: Path) -> None:
    """`--entropy off` (entropy_enabled=False): token custom NAO redatado."""
    src, dest, fw, audit = _setup(tmp_path, "entoff")
    result = run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
        entropy_enabled=False,
    )
    config_out = (dest / "app" / "config.py").read_text(encoding="utf-8")
    # Camada SKIPPED -> token de alta entropia permanece (sem prefixo conhecido).
    assert CUSTOM_TOKEN in config_out
    assert result.entropy_count == 0
    assert result.entropy_enabled is False
