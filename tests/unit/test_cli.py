"""test_cli.py — argparse + flag --license + exit codes (Bloco 04 ADR-032/033)."""
from __future__ import annotations

import pytest

from repo_sanitizer.cli import build_parser

# -------------------- Flag --license (sanitize-finalize) --------------------


def test_sanitize_finalize_license_default_mit(tmp_path) -> None:
    """sanitize-finalize sem --license deve default MIT."""
    parser = build_parser()
    args = parser.parse_args([
        "sanitize-finalize",
        "--slug", "demo",
        "--source-path", str(tmp_path),
    ])
    assert args.license == "MIT"


def test_sanitize_finalize_license_override_apache(tmp_path) -> None:
    """sanitize-finalize --license APACHE-2.0 deve aceitar override."""
    parser = build_parser()
    args = parser.parse_args([
        "sanitize-finalize",
        "--slug", "demo",
        "--source-path", str(tmp_path),
        "--license", "APACHE-2.0",
    ])
    assert args.license == "APACHE-2.0"


def test_sanitize_finalize_license_invalid_choice_raises(tmp_path) -> None:
    """sanitize-finalize --license INVALID deve falhar via argparse."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "sanitize-finalize",
            "--slug", "demo",
            "--source-path", str(tmp_path),
            "--license", "ZLIB",
        ])


def test_sanitize_finalize_help_mentions_g2_gate(capsys) -> None:
    """help da subcommand sanitize-finalize mencionar 'Gate G2'."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["sanitize-finalize", "--help"])
    captured = capsys.readouterr()
    # Tanto stdout (help) quanto checagem de mention
    assert "Gate G2" in captured.out
    assert "--license" in captured.out


# -------------------- Flag --entropy (sanitize-apply, MV-04 / C3) --------------------


def test_sanitize_apply_entropy_default_on(tmp_path) -> None:
    """sanitize-apply sem --entropy deve default 'on' (cobertura maxima)."""
    parser = build_parser()
    args = parser.parse_args([
        "sanitize-apply",
        "--slug", "demo",
        "--source-path", str(tmp_path),
    ])
    assert args.entropy == "on"


def test_sanitize_apply_entropy_off(tmp_path) -> None:
    """sanitize-apply --entropy off deve aceitar e armazenar 'off'."""
    parser = build_parser()
    args = parser.parse_args([
        "sanitize-apply",
        "--slug", "demo",
        "--source-path", str(tmp_path),
        "--entropy", "off",
    ])
    assert args.entropy == "off"


def test_sanitize_apply_entropy_invalid_choice_raises(tmp_path) -> None:
    """--entropy aceita apenas {on, off}."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "sanitize-apply",
            "--slug", "demo",
            "--source-path", str(tmp_path),
            "--entropy", "maybe",
        ])
