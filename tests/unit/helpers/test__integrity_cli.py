"""test__integrity_cli.py — exercita CLI + funcoes restantes do _integrity.py."""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.helpers._integrity import (
    main,
    now_iso8601,
    parse_integrity,
    record_integrity,
    verify_integrity,
)


def test_now_iso8601_format() -> None:
    s = now_iso8601()
    assert s.endswith("+00:00")
    assert "T" in s


def test_record_integrity_creates_file(tmp_path: Path) -> None:
    f = tmp_path / "tracked.py"
    f.write_bytes(b"hello\n")
    integrity_md = tmp_path / "integrity.md"
    result = record_integrity([str(f)], integrity_md)
    assert integrity_md.exists()
    assert result["files"][0]["file"] == "tracked.py"
    assert len(result["files"][0]["sha256"]) == 64


def test_record_integrity_raises_on_missing(tmp_path: Path) -> None:
    integrity_md = tmp_path / "integrity.md"
    try:
        record_integrity([str(tmp_path / "missing.py")], integrity_md)
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError:
        pass


def test_parse_integrity_empty_file_returns_empty(tmp_path: Path) -> None:
    nonexistent = tmp_path / "no.md"
    assert parse_integrity(nonexistent) == []


def test_verify_integrity_missing_file_in_record(tmp_path: Path) -> None:
    integrity_md = tmp_path / "integrity.md"
    integrity_md.write_text(
        f"---\nlast_setup: 2026-01-01T00:00:00\n---\n\n# Hashes\n"
        f"- file: missing.py\n  sha256: {'a'*64}\n  recorded_at: 2026-01-01\n",
        encoding="utf-8",
    )
    result = verify_integrity(integrity_md, tmp_path, audit_file=None)
    assert result["ok"] is False
    assert result["mismatches"][0]["reason"] == "arquivo ausente"


def test_verify_integrity_empty_returns_ok_false(tmp_path: Path) -> None:
    empty = tmp_path / "integrity.md"
    empty.write_text("---\nlast_setup: 2026-01-01\n---\n", encoding="utf-8")
    r = verify_integrity(empty, tmp_path, audit_file=None)
    assert r["ok"] is False
    assert r["checked"] == 0


def test_integrity_main_record_cli(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_bytes(b"x")
    integrity_md = tmp_path / "integrity.md"
    rc = main(["record", "--integrity-md", str(integrity_md), "--files", str(f)])
    assert rc == 0
    assert integrity_md.exists()


def test_integrity_main_verify_cli(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_bytes(b"x")
    integrity_md = tmp_path / "integrity.md"
    main(["record", "--integrity-md", str(integrity_md), "--files", str(f)])
    rc = main(["verify", "--integrity-md", str(integrity_md), "--project-root", str(tmp_path)])
    assert rc == 0


def test_integrity_main_verify_mismatch_cli(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_bytes(b"x")
    integrity_md = tmp_path / "integrity.md"
    main(["record", "--integrity-md", str(integrity_md), "--files", str(f)])
    f.write_bytes(b"tampered")
    rc = main(["verify", "--integrity-md", str(integrity_md), "--project-root", str(tmp_path)])
    assert rc == 3
