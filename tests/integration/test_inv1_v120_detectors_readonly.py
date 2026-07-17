"""test_inv1_v120_detectors_readonly.py — RS-NEW-045 / INV-1 (integration).

Reforco INV-1 EXPLICITO dos detectores v1.2.0 (#05-Test, fecha gap PARCIAL).

Criterio de verificacao do #02 (RS-NEW-045): "rodar pipeline completo com os
detectores v1.2.0 ativos; SHA-256 de cada arquivo do source identico antes/depois".

Os testes INV-1 pre-existentes (`test_inv1_snapshot_f3.py`) ja provam que o source
fica intocado apos `run_f3`, MAS suas fixtures nao contem campo de autoria nem token
de alta entropia, logo os detectores novos (autoria/entropia) so exercitam o caminho
NO-OP. Este teste fecha a lacuna: monta um source que FORCA o caminho de REDACAO de
AMBOS os detectores v1.2.0 (autoria estrutural em `pyproject.toml` + token custom de
alta entropia em `.py`) e prova que:

  (a) os detectores REALMENTE dispararam (destino contem os placeholders canonicos),
  (b) a arvore do source permanece byte-a-byte IDENTICA (SHA-256) pre/pos — nenhuma
      escrita in-place na fonte (T-INV / INV-1 / RS-NEW-045).
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f3_sanitizer import run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._author_detector import (
    REDACTED_AUTHOR_EMAIL,
    REDACTED_AUTHOR_NAME,
)
from repo_sanitizer.helpers._entropy_detector import ENTROPY_PLACEHOLDER
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._hash_tree import assert_unchanged, snapshot

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Token custom de alta entropia SEM prefixo conhecido (so a entropia pega).
# Sintetico — nao e um segredo real.
CUSTOM_TOKEN = "aB3xQ9zK7mP2wV5nL8rT4yU6sD1fG0hJ"
# PII de autoria sintetica (nome + email do "operador").
AUTHOR_NAME = "Fulano de Tal"
AUTHOR_EMAIL = "fulano@example.com"


def _setup(tmp_path: Path, slug: str = "inv1v120") -> tuple[Path, Path, FsWriter, AuditLogger]:
    """Source que FORCA autoria + entropia a redatar (nao no-op)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# demo\n\nA demo project.\n", encoding="utf-8")
    (src / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    # Manifest com campo de autoria -> forca redact_authorship a DISPARAR.
    (src / "pyproject.toml").write_text(
        "[project]\n"
        'name = "demo"\n'
        'version = "1.0.0"\n'
        f'authors = [{{ name = "{AUTHOR_NAME}", email = "{AUTHOR_EMAIL}" }}]\n',
        encoding="utf-8",
    )
    pkg = src / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    # Codigo com token de alta entropia em variavel NEUTRA (so a entropia pega;
    # nome sem secret/token/key/password/auth que dispararia CONFIG_KEY_GENERIC).
    (pkg / "config.py").write_text(
        f'BLOB_VALUE = "{CUSTOM_TOKEN}"\nVERSION = "1.0.0"\n',
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


def test_v120_detectors_active_source_sha256_unchanged(tmp_path: Path) -> None:
    """RS-NEW-045: autoria + entropia DISPARAM no destino; source intocado (INV-1)."""
    src, dest, fw, audit = _setup(tmp_path)

    snap_pre = snapshot(src)
    result = run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
        entropy_enabled=True,
    )
    snap_pos = snapshot(src)

    # (a) Os detectores v1.2.0 REALMENTE dispararam (caminho de REDACAO, nao no-op):
    #     entropia redatou o token custom no destino...
    config_out = (dest / "app" / "config.py").read_text(encoding="utf-8")
    assert CUSTOM_TOKEN not in config_out
    assert ENTROPY_PLACEHOLDER in config_out
    assert result.entropy_count >= 1
    #     ...e a autoria redatou nome/email do manifest no destino.
    pyproject_out = (dest / "pyproject.toml").read_text(encoding="utf-8")
    assert AUTHOR_NAME not in pyproject_out
    assert AUTHOR_EMAIL not in pyproject_out
    assert REDACTED_AUTHOR_NAME in pyproject_out
    assert REDACTED_AUTHOR_EMAIL in pyproject_out
    assert sum(result.author_by_field.values()) >= 1
    # name/version (NAO-autoria) preservados — estrutura do manifest intacta (G2).
    assert 'name = "demo"' in pyproject_out
    assert 'version = "1.0.0"' in pyproject_out

    # (b) INV-1 / RS-NEW-045: com os detectores ATIVOS e DISPARANDO, a arvore do
    #     source permanece byte-a-byte identica (nenhuma escrita in-place na fonte).
    assert_unchanged(snap_pre, snap_pos)
    assert snap_pre["aggregate"] == snap_pos["aggregate"]

    # Sanidade: o token/PII de autoria continuam INTACTOS no SOURCE (read-only).
    src_config = (src / "app" / "config.py").read_text(encoding="utf-8")
    src_pyproject = (src / "pyproject.toml").read_text(encoding="utf-8")
    assert CUSTOM_TOKEN in src_config
    assert AUTHOR_NAME in src_pyproject
    assert AUTHOR_EMAIL in src_pyproject
