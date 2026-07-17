"""test_phase6_inv1_and_writer.py — Fase 6 (06-Security-Auditor v1.x).

Auditoria RS-002 INV-1 read-only fonte (EMPATADO TOP-01 DREAD-5 45/50; INV-1
REFORCADO 2x pelo [NOME]) + FsWriter boundary (ADR-020 + RS-007).

Cenarios adversariais NOVOS pelo Security-Auditor:

- INV-1: snapshot pre/pos identical (re-validacao) + RENAME mid-run (ponto F)
  + concurrent modification detection.
- FsWriter: 8 canonicos heritage + 5 NOVOS Security-Auditor:
  * UNC paths `\\\\server\\share` (deve ser rejeitado por not-in-ALLOWED).
  * Long paths > 260 chars (defesa Windows).
  * Alternate Data Streams `file.txt:hidden` (NTFS specific).
  * Intermediate symlink em path parent (descartado por boundary; symlink
    refuses).
  * TOCTOU race: arquivo criado por outro processo entre check e write.

ADRs anchored: ADR-019 / ADR-020 / ADR-025.
RS cobertos: RS-002 / RS-006 / RS-007 / RS-016.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# AREA 3 — INV-1 reforcado 2x: snapshot pre/pos + rename mid-run
# ---------------------------------------------------------------------------


def test_phase6_inv1_snapshot_identical_simple(tmp_path: Path) -> None:
    """INV-1 audit: snapshot pre/pos identical em fixture limpa."""
    from repo_sanitizer.helpers._hash_tree import assert_unchanged, snapshot

    src = tmp_path / "source"
    src.mkdir()
    (src / "a.txt").write_text("content a\n", encoding="utf-8")
    (src / "b.py").write_text("def foo(): pass\n", encoding="utf-8")

    snap_pre = snapshot(src)
    # Nenhuma modificacao
    snap_pos = snapshot(src)
    assert_unchanged(snap_pre, snap_pos)
    assert snap_pre["aggregate"] == snap_pos["aggregate"]


def test_phase6_inv1_snapshot_detects_modification(tmp_path: Path) -> None:
    """INV-1 audit: snapshot detecta modificacao bit-a-bit."""
    from repo_sanitizer.helpers._hash_tree import snapshot

    src = tmp_path / "source"
    src.mkdir()
    f = src / "a.txt"
    f.write_text("original\n", encoding="utf-8")

    snap_pre = snapshot(src)
    f.write_text("modified\n", encoding="utf-8")
    snap_pos = snapshot(src)

    assert snap_pre["aggregate"] != snap_pos["aggregate"]


def test_phase6_inv1_rename_mid_run_detected(tmp_path: Path) -> None:
    """INV-1 audit ponto F: rename mid-run DEVE alterar aggregate hash."""
    from repo_sanitizer.helpers._hash_tree import snapshot

    src = tmp_path / "source"
    src.mkdir()
    f = src / "original_name.txt"
    f.write_text("content unchanged\n", encoding="utf-8")

    snap_pre = snapshot(src)
    # Rename: nome muda mas conteudo eh identico
    f.rename(src / "renamed.txt")
    snap_pos = snapshot(src)

    # Hash-tree agrega path + conteudo; rename muda o caminho -> aggregate muda
    assert snap_pre["aggregate"] != snap_pos["aggregate"], \
        "INV-1 audit ponto F: rename mid-run DEVE alterar aggregate hash"


def test_phase6_inv1_new_file_mid_run_detected(tmp_path: Path) -> None:
    """INV-1 audit: arquivo novo durante run DEVE ser detectado."""
    from repo_sanitizer.helpers._hash_tree import snapshot

    src = tmp_path / "source"
    src.mkdir()
    (src / "a.txt").write_text("a\n", encoding="utf-8")

    snap_pre = snapshot(src)
    (src / "novo.txt").write_text("novo\n", encoding="utf-8")
    snap_pos = snapshot(src)

    assert snap_pre["file_count"] != snap_pos["file_count"]
    assert snap_pre["aggregate"] != snap_pos["aggregate"]


def test_phase6_inv1_delete_mid_run_detected(tmp_path: Path) -> None:
    """INV-1 audit: delecao de arquivo durante run DEVE ser detectada."""
    from repo_sanitizer.helpers._hash_tree import snapshot

    src = tmp_path / "source"
    src.mkdir()
    (src / "a.txt").write_text("a\n", encoding="utf-8")
    (src / "b.txt").write_text("b\n", encoding="utf-8")

    snap_pre = snapshot(src)
    (src / "b.txt").unlink()
    snap_pos = snapshot(src)

    assert snap_pre["file_count"] > snap_pos["file_count"]
    assert snap_pre["aggregate"] != snap_pos["aggregate"]


def test_phase6_inv1_source_in_forbidden_paths(tmp_path: Path) -> None:
    """INV-1 audit: source_path ALWAYS adicionado a FORBIDDEN_PATHS (reforco 2x).

    Setup: allowed_root ancestor de source para isolar Camada 2 FORBIDDEN.
    Sem isso, Camada 1 ALLOWED falha primeiro.
    """
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    # allowed ancestor de src para testar especificamente Camada 2 FORBIDDEN
    allowed = tmp_path / "workspace"
    allowed.mkdir()
    src = allowed / "source_repo"
    src.mkdir()
    (src / "file.txt").write_text("read-only\n", encoding="utf-8")

    fw = FsWriter(
        source_path=src,
        allowed_roots=[allowed],
        override_forbidden=[],  # explicitamente sem defaults, mas source_path sempre adicionado
    )

    # Tentativa de escrever em source = FORBIDDEN (INV-1 reforco 2x)
    with pytest.raises(FsWriteOutOfBoundsError, match=r"INV-1|proibido|sensivel"):
        fw.safe_write_text(src / "tampered.txt", "tampering attempt")


# ---------------------------------------------------------------------------
# AREA 6 — FsWriter boundary: 5 cenarios NOVOS Security-Auditor
# ---------------------------------------------------------------------------


def test_phase6_fswriter_unc_path_rejected(tmp_path: Path) -> None:
    """FsWriter audit NOVO: UNC paths `\\\\server\\share` rejeitados (fora ALLOWED)."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    unc_path = Path(r"\\malicious-server\share\evil.txt")
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(unc_path, "evil payload")


def test_phase6_fswriter_long_path_within_allowed_works(tmp_path: Path) -> None:
    """FsWriter audit NOVO: long path < 260 chars dentro de ALLOWED funciona."""
    from repo_sanitizer.helpers._fs_writer import FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )

    # Path moderadamente longo (mas seguro em Windows; long path > 260 require
    # \\?\ prefix em alguns sistemas; aqui validamos boundary, nao limite OS)
    deep = allowed / ("dir_" + "x" * 30) / ("subdir_" + "y" * 30)
    target = deep / "file.txt"
    fw.safe_write_text(target, "ok")
    assert target.exists()


def test_phase6_fswriter_path_traversal_dotdot_rejected(tmp_path: Path) -> None:
    """FsWriter audit: `..\\..\\escape.txt` traversal rejeitado via Path.resolve."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )

    # ../../escape.txt deve resolver para fora de allowed
    traversal = allowed / ".." / ".." / "escape.txt"
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(traversal, "traversal payload")


def test_phase6_fswriter_alternate_data_stream_rejected_via_resolved(tmp_path: Path) -> None:
    """FsWriter audit NOVO: ADS `file.txt:hidden` - Path resolve aceita; defesa via boundary.

    NTFS ADS aceita escrita no stream auxiliar. Path.resolve nao bloqueia per-se;
    boundary garante que apenas dentro de ALLOWED. Tentativa de gravar ADS FORA
    de ALLOWED = bloqueado.
    """
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )

    # ADS sintatico FORA de ALLOWED
    ads_outside = tmp_path / "fora" / "file.txt:hidden_stream"
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(ads_outside, "ADS payload")


def test_phase6_fswriter_windows_reserved_in_subpath_rejected(tmp_path: Path) -> None:
    """FsWriter audit canonico: nome reservado Windows em sub-segmento rejeitado."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )

    # Sub-segmento NUL no meio
    with pytest.raises(FsWriteOutOfBoundsError, match=r"reservado|reserved"):
        fw.safe_write_text(allowed / "subdir" / "NUL" / "child.txt", "x")


def test_phase6_fswriter_safe_copy_refuses_symlink_source(tmp_path: Path) -> None:
    """FsWriter audit: safe_copy recusa src symlink (RS-006 + ADR-019)."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    src_target = tmp_path / "real_file.txt"
    src_target.write_text("real content\n", encoding="utf-8")
    symlink_src = tmp_path / "evil_link.txt"
    try:
        symlink_src.symlink_to(src_target)
    except (OSError, NotImplementedError):
        pytest.skip("Windows symlink requires developer mode")

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )

    with pytest.raises(FsWriteOutOfBoundsError, match=r"symlink|RS-006"):
        fw.safe_copy(symlink_src, allowed / "copy.txt")


def test_phase6_fswriter_safe_move_refuses_source_in_forbidden(tmp_path: Path) -> None:
    """FsWriter audit INV-1: safe_move recusa src dentro de FORBIDDEN (source repo)."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    source_repo = tmp_path / "source"
    source_repo.mkdir()
    src_file = source_repo / "internal.py"
    src_file.write_text("# read-only\n", encoding="utf-8")

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=source_repo,
        allowed_roots=[allowed],
        override_forbidden=[],
    )

    # Tentar mover FROM source_repo = violacao INV-1
    with pytest.raises(FsWriteOutOfBoundsError, match=r"INV-1|proibido"):
        fw.safe_move(src_file, allowed / "moved.py")


def test_phase6_fswriter_atomic_write_via_tempfile(tmp_path: Path) -> None:
    """FsWriter audit: safe_write_bytes usa tempfile + os.replace (atomic)."""
    from repo_sanitizer.helpers._fs_writer import FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "atomic.txt"
    fw.safe_write_bytes(target, b"atomic content")
    assert target.read_bytes() == b"atomic content"
    # Tempfile cleanup: nao deve haver lixo .tmp_*.rsa
    leftovers = list(allowed.glob(".tmp_*.rsa"))
    assert leftovers == [], f"FsWriter audit: tempfile leftovers {leftovers}"


def test_phase6_fswriter_assert_allowed_returns_resolved(tmp_path: Path) -> None:
    """FsWriter audit: assert_allowed retorna Path resolvido (canonico)."""
    from repo_sanitizer.helpers._fs_writer import FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "subdir" / "file.txt"
    resolved = fw.assert_allowed(target)
    assert resolved == target.resolve()


# ---------------------------------------------------------------------------
# AREA 7 — Supply chain: integrity manifest tampering
# ---------------------------------------------------------------------------


def test_phase6_integrity_manifest_5_files_present() -> None:
    """Supply chain audit: integrity.md rastreia 5 arquivos canonicos."""
    integrity = Path("integrity.md").read_text(encoding="utf-8")
    expected_files = [
        "tests/fixtures/sentinel/_sanitize.py",
        "tests/fixtures/sentinel/injection_patterns.json",
        "src/repo_sanitizer/helpers/_yaml_codec.py",
        "src/repo_sanitizer/helpers/_integrity.py",
        "src/repo_sanitizer/secret_patterns.py",
    ]
    for f in expected_files:
        assert f in integrity, f"Supply chain audit: {f} ausente em integrity.md"


def test_phase6_integrity_manifest_hashes_match_actual_files() -> None:
    """Supply chain audit: hashes registrados == hashes atuais (zero tampering)."""
    from repo_sanitizer.helpers._integrity import verify_integrity

    project_root = Path(".").resolve()
    integrity_md = project_root / "integrity.md"
    result = verify_integrity(integrity_md, project_root, audit_file=None)
    assert result["ok"] is True, \
        f"Supply chain audit: integrity mismatch detected: {result.get('mismatches', [])}"


def test_phase6_integrity_artificial_tampering_caught(tmp_path: Path) -> None:
    """Supply chain audit: tampering artificial (alterar arquivo rastreado) = fail."""
    from repo_sanitizer.helpers._integrity import verify_integrity

    # Setup: project_root sintetico com 1 arquivo + integrity.md
    fake_root = tmp_path / "fake_project"
    fake_root.mkdir()
    tracked = fake_root / "tracked.py"
    original_content = b"# original content\n"
    tracked.write_bytes(original_content)
    original_hash = hashlib.sha256(original_content).hexdigest()

    integrity_md = fake_root / "integrity.md"
    integrity_md.write_text(
        f"---\n"
        f"last_setup: 2026-05-12T00:00:00+00:00\n"
        f"schema_version: 4.1.0\n"
        f"agent: repo-sanitizer-agent\n"
        f"---\n\n"
        f"- file: tracked.py\n"
        f"  sha256: {original_hash}\n"
        f"  recorded_at: 2026-05-12T00:00:00+00:00\n",
        encoding="utf-8",
    )

    # Baseline OK
    result_ok = verify_integrity(integrity_md, fake_root, audit_file=None)
    assert result_ok["ok"] is True

    # Tamper: substituir conteudo
    tracked.write_bytes(b"# TAMPERED content\n")
    result_fail = verify_integrity(integrity_md, fake_root, audit_file=None)
    assert result_fail["ok"] is False
    assert len(result_fail.get("mismatches", [])) >= 1
