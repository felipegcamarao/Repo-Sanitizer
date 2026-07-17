"""test__boilerplate_generator.py — Auto-geracao de boilerplate (ADR-033)."""
from __future__ import annotations

import json

import pytest

from repo_sanitizer.helpers._boilerplate_generator import (
    ALLOWED_LICENSES,
    generate_cargo_toml,
    generate_go_mod,
    generate_license,
    generate_package_json,
    generate_pyproject,
)

# -------------------- Generators (4) --------------------


def test_generate_pyproject_canonical_slug() -> None:
    out = generate_pyproject("repo-sanitizer-agent")
    assert "[REPO-SANITIZER NOTICE — INFERRED BOILERPLATE]" in out
    assert "[build-system]" in out
    assert "[project]" in out
    assert 'name = "repo-sanitizer-agent"' in out
    assert 'version = "0.0.0"' in out
    assert 'requires-python = ">=3.11"' in out
    assert "dependencies = []" in out


def test_generate_package_json_minimal_node() -> None:
    out = generate_package_json("my-cli-tool")
    payload = json.loads(out)
    assert payload["name"] == "my-cli-tool"
    assert payload["version"] == "0.0.0"
    assert payload["private"] is True
    assert payload["scripts"] == {"test": "echo todo"}
    assert "INFERRED BOILERPLATE" in payload["_notice"]


def test_generate_cargo_toml_minimal_rust() -> None:
    out = generate_cargo_toml("my-rust-crate")
    assert "[REPO-SANITIZER NOTICE — INFERRED BOILERPLATE]" in out
    assert "[package]" in out
    assert 'name = "my-rust-crate"' in out
    assert 'edition = "2021"' in out
    assert "[dependencies]" in out


def test_generate_go_mod_minimal_go() -> None:
    out = generate_go_mod("my-go-service")
    assert "[REPO-SANITIZER NOTICE — INFERRED BOILERPLATE]" in out
    assert "module my-go-service" in out
    assert "go 1.21" in out


# -------------------- LICENSE variants (4) --------------------


def test_generate_license_mit_default() -> None:
    out = generate_license("MIT", year=2026)
    assert "[REPO-SANITIZER NOTICE — INFERRED LICENSE]" in out
    assert "MIT License" in out
    assert "Copyright (c) 2026 TODO <TITULAR-DO-COPYRIGHT>" in out
    # Texto canonico MIT
    assert "AS IS" in out
    assert "NONINFRINGEMENT" in out


def test_generate_license_apache_2_0() -> None:
    out = generate_license("APACHE-2.0", year=2026)
    assert "Apache License" in out
    assert "Version 2.0" in out
    assert "Copyright 2026 TODO <TITULAR-DO-COPYRIGHT>" in out


def test_generate_license_bsd_3() -> None:
    out = generate_license("BSD-3", year=2026)
    assert "BSD 3-Clause License" in out
    assert "Copyright (c) 2026, TODO <TITULAR-DO-COPYRIGHT>" in out
    assert "Redistribution and use in source and binary forms" in out


def test_generate_license_gpl_3_0() -> None:
    out = generate_license("GPL-3.0", year=2026)
    assert "GNU GENERAL PUBLIC LICENSE" in out
    assert "Version 3" in out
    assert "Copyright (C) 2026 TODO <TITULAR-DO-COPYRIGHT>" in out


def test_generate_license_invalid_raises() -> None:
    with pytest.raises(ValueError, match="license_id invalido"):
        generate_license("INVALID-LICENSE", year=2026)  # type: ignore[arg-type]


# -------------------- Edge cases --------------------


def test_slug_sanitization_for_special_chars() -> None:
    """Slugs com chars invalidos para package-name sao sanitizados."""
    # 'A+ AGENTS' -> sanitize_slug -> 'a-agents' (espacos+plus viram hifens)
    out = generate_pyproject("A+ AGENTS")
    assert 'name = "a-agents"' in out


def test_slug_empty_fallback_to_project() -> None:
    """String vazia (ou apenas chars invalidos) cai em 'project'."""
    out = generate_pyproject("")
    assert 'name = "project"' in out
    # apenas separadores -> tambem cai em 'project'
    out2 = generate_package_json("---")
    payload = json.loads(out2)
    assert payload["name"] == "project"


def test_slug_unicode_accents_normalized() -> None:
    """Slugs com acentos sao normalizados via NFKD."""
    out = generate_cargo_toml("Nomão Project")
    assert 'name = "nomao-project"' in out


def test_allowed_licenses_constant() -> None:
    """Sanity: tupla constante reflete as 4 licencas suportadas."""
    assert ALLOWED_LICENSES == ("MIT", "APACHE-2.0", "BSD-3", "GPL-3.0")
