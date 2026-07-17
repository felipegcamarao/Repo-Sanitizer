"""test__integrity.py — record + verify integrity (ADR-015)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from repo_sanitizer.helpers._integrity import (
    compute_file_sha256,
    parse_integrity,
    verify_integrity,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_integrity_md_exists() -> None:
    """Bootstrap deve ter rodado antes — integrity.md presente."""
    assert (PROJECT_ROOT / "integrity.md").exists()


def test_compute_file_sha256_deterministico(tmp_path: Path) -> None:
    f = tmp_path / "x.txt"
    f.write_bytes(b"hello\n")
    h1 = compute_file_sha256(f)
    h2 = compute_file_sha256(f)
    assert h1 == h2
    assert len(h1) == 64


def test_parse_integrity_returns_entries() -> None:
    integrity_md = PROJECT_ROOT / "integrity.md"
    entries = parse_integrity(integrity_md)
    assert len(entries) >= 4
    # Verifica 4 local-copies + secret_patterns presentes
    files = {e["file"].lower() for e in entries}
    assert any("_sanitize.py" in f for f in files)
    assert any("injection_patterns.json" in f for f in files)
    assert any("_yaml_codec.py" in f for f in files)
    assert any("_integrity.py" in f for f in files)
    assert any("secret_patterns.py" in f for f in files)


def test_verify_integrity_ok() -> None:
    integrity_md = PROJECT_ROOT / "integrity.md"
    result = verify_integrity(integrity_md, PROJECT_ROOT, audit_file=None)
    assert result["ok"] is True
    assert result["checked"] >= 5


def test_verify_integrity_mismatch_returns_false(tmp_path: Path) -> None:
    """Simula tampering via copia + mutacao localizada."""
    # Cria fake integrity.md com hash conhecido + mutacao
    fake_file = tmp_path / "tracked.py"
    fake_file.write_bytes(b"original\n")
    sha_original = compute_file_sha256(fake_file)
    integrity_md = tmp_path / "integrity.md"
    integrity_md.write_text(
        f"---\nlast_setup: 2026-01-01T00:00:00\n---\n\n# Hashes\n"
        f"- file: tracked.py\n  sha256: {sha_original}\n  recorded_at: 2026-01-01T00:00:00\n",
        encoding="utf-8",
    )
    # Verify OK inicial
    r1 = verify_integrity(integrity_md, tmp_path, audit_file=None)
    assert r1["ok"] is True
    # Tamper
    fake_file.write_bytes(b"tampered\n")
    r2 = verify_integrity(integrity_md, tmp_path, audit_file=None)
    assert r2["ok"] is False
    assert len(r2["mismatches"]) == 1
    assert r2["mismatches"][0]["reason"] == "hash mismatch"


def test_verify_integrity_script_smoke() -> None:
    """Smoke: scripts/verify_integrity_manifest.py exit 0."""
    result = subprocess.run(
        [sys.executable, "scripts/verify_integrity_manifest.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout


def test_verify_integrity_script_exit_3_on_tampering(tmp_path: Path) -> None:
    """Smoke: tamper local-copy + verify retorna exit 3."""
    target = PROJECT_ROOT / "src" / "repo_sanitizer" / "helpers" / "_yaml_codec.py"
    orig = target.read_bytes()
    target.write_bytes(orig + b"\n# tamper smoke\n")
    try:
        result = subprocess.run(
            [sys.executable, "scripts/verify_integrity_manifest.py"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 3, f"expected 3, got {result.returncode}"
        assert "mismatch" in result.stderr.lower()
    finally:
        target.write_bytes(orig)  # restore
