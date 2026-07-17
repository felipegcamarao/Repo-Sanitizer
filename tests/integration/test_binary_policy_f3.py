"""test_binary_policy_f3.py — B4 / MV-06 / RS-NEW-042 / ADR-036 (integration).

Pipeline F3 end-to-end com politica binaria 3-tier:
- `.sqlite`/`.csv`/`.jks`/`.pem` -> EXCLUIDOS do destino (data/credential);
- `.png` -> MANTIDO + flag "EXIF nao inspecionado" no result;
- `.wasm`/`.ico` (neutro) -> MANTIDOS (regressao de FP — nao excluir necessario).
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f3_sanitizer import run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Magic-bytes minimas para forcar deteccao binaria correta.
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
_WASM_MAGIC = b"\x00asm" + b"\x01\x00\x00\x00" + b"\x00" * 16
_ICO_MAGIC = b"\x00\x00\x01\x00" + b"\x00" * 32
_SQLITE_MAGIC = b"SQLite format 3\x00" + b"\x00" * 64


def _setup(tmp_path: Path, slug: str = "binpol"):
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# demo\n", encoding="utf-8")
    # Tier credential -> excluir
    (src / "server.pem").write_bytes(
        b"-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n",
    )
    (src / "keystore.jks").write_bytes(b"\xfe\xed\xfe\xed" + b"\x00" * 64)
    # Tier data -> excluir
    (src / "clientes.sqlite").write_bytes(_SQLITE_MAGIC)
    (src / "export.csv").write_text(
        "nome,email\nAlice,alice@x.com\n", encoding="utf-8",
    )
    (src / "model.parquet").write_bytes(b"PAR1" + b"\x00" * 64)
    # Tier safe (imagem) -> manter + flag EXIF
    (src / "logo.png").write_bytes(_PNG_MAGIC)
    # Tier safe (neutro) -> manter, sem flag
    (src / "mod.wasm").write_bytes(_WASM_MAGIC)
    (src / "favicon.ico").write_bytes(_ICO_MAGIC)

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


def test_data_and_credential_excluded_neutral_kept(tmp_path: Path) -> None:
    src, dest, fw, audit = _setup(tmp_path)
    result = run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
    )

    # Credenciais excluidas -> 0 no destino.
    assert not (dest / "server.pem").exists()
    assert not (dest / "keystore.jks").exists()
    # Dados excluidos -> 0 no destino.
    assert not (dest / "clientes.sqlite").exists()
    assert not (dest / "export.csv").exists()
    assert not (dest / "model.parquet").exists()

    # Neutros e imagem MANTIDOS (anti-FP).
    assert (dest / "logo.png").exists()
    assert (dest / "mod.wasm").exists()
    assert (dest / "favicon.ico").exists()
    assert (dest / "README.md").exists()

    # Flag EXIF apenas na imagem (.png), nao nos neutros.
    assert "logo.png" in result.exif_uninspected
    assert "mod.wasm" not in result.exif_uninspected
    assert "favicon.ico" not in result.exif_uninspected

    # Contagem por tier no result: data >= 3 (sqlite/csv/parquet) via politica
    # binaria; credential >= 1 (jks via tier). server.pem e excluido pela
    # decisao file-level C7 PRE-existente (CERT_FILE_EXT) — defesa-em-camadas.
    assert result.binary_excluded_by_tier.get("data", 0) >= 3
    assert result.binary_excluded_by_tier.get("credential", 0) >= 1


def test_excluded_binaries_reported_with_canonical_tipo(tmp_path: Path) -> None:
    """Report tem matches `remove_file` com tipo canonico (zero-literal)."""
    src, dest, fw, audit = _setup(tmp_path, "binrep")
    result = run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
    )
    tipos = {m.tipo for m in result.matches}
    assert "BINARY_DATA_EXCLUDED" in tipos
    assert "BINARY_CREDENTIAL_EXCLUDED" in tipos
    # Nenhum match de binario carrega conteudo literal (so tipo canonico).
    for m in result.matches:
        if m.tipo in ("BINARY_DATA_EXCLUDED", "BINARY_CREDENTIAL_EXCLUDED"):
            assert m.acao == "remove_file"
            assert m.line is None


def test_rescan_destination_clean_after_binary_exclusion(tmp_path: Path) -> None:
    """Apos excluir data/credential, Camada C6 re-scan = 0 (sem leak)."""
    src, dest, fw, audit = _setup(tmp_path, "binclean")
    result = run_f3(
        source_path=src, dest_path=dest, fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT, integrity_md=PROJECT_ROOT / "integrity.md",
    )
    assert result.rescan_destination_zero is True
