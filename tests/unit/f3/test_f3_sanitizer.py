"""test_f3_sanitizer.py — unit tests do f3_sanitizer.py (Bloco 03).

Cobre helpers granulares (decide_filename_action / sanitize_text_content /
scan_binary_deep / rescan_destination / safe_finditer / safe_sub) +
preflight_integrity gate.

Integration end-to-end fica em tests/integration/test_rs001_multi_pass.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f3_sanitizer import (
    DEEP_SCAN_BYTES,
    F3Timeout,
    IntegrityFailure,
    decide_filename_action,
    preflight_integrity,
    rescan_destination,
    safe_finditer,
    safe_sub,
    sanitize_text_content,
    scan_binary_deep,
)

# ===========================================================================
# decide_filename_action — file-level Camada C1 + C7
# ===========================================================================

def test_decide_filename_dotenv_returns_envexample() -> None:
    d = decide_filename_action(".env", ".env")
    assert d is not None
    assert d.categoria == "C1"
    assert d.acao == "envexample"


def test_decide_filename_pem_returns_remove_file() -> None:
    d = decide_filename_action("server.pem", "certs/server.pem")
    assert d is not None
    assert d.categoria == "C7"
    assert d.acao == "remove_file"


def test_decide_filename_readme_returns_none() -> None:
    assert decide_filename_action("README.md", "README.md") is None


def test_decide_filename_key_file_returns_remove() -> None:
    d = decide_filename_action("private.key", "secrets/private.key")
    assert d is not None and d.acao == "remove_file"


# ===========================================================================
# sanitize_text_content — line-level redact + remove_line + skip_file
# ===========================================================================

def test_sanitize_text_redacts_ghp_inline() -> None:
    # Caso 1: ghp_ standalone (C2 deve casar antes que C6 generico)
    text = "see also ghp_abcdef123456789012345 in docs\nother\n"
    result = sanitize_text_content(text, "utf-8")
    assert "ghp_abcdef123456789012345" not in result.sanitized_text
    # Modo Paranoico: aceita qualquer placeholder canonico (C2 ou C6)
    assert "<REDACTED-" in result.sanitized_text
    assert result.skip_file is False


def test_sanitize_text_redacts_ghp_with_assignment() -> None:
    # Caso 2: API_KEY = ghp_ (C6 generic config key sobrescreve a linha inteira;
    # zero falso-negativo). Aceita qualquer placeholder.
    text = "API_KEY = ghp_abcdef123456789012345\nother\n"
    result = sanitize_text_content(text, "utf-8")
    assert "ghp_abcdef123456789012345" not in result.sanitized_text
    assert "<REDACTED-" in result.sanitized_text


def test_sanitize_text_remove_line_for_todo_marker() -> None:
    text = "ok line 1\n# TODO: remover api_key antes do commit\nok line 3\n"
    result = sanitize_text_content(text, "utf-8")
    # linha removida
    assert "TODO" not in result.sanitized_text
    assert "ok line 1" in result.sanitized_text
    assert "ok line 3" in result.sanitized_text


def test_sanitize_text_pem_triggers_skip_file() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF...\n-----END RSA PRIVATE KEY-----\n"
    result = sanitize_text_content(text, "utf-8")
    assert result.skip_file is True
    assert "PRIVATE_KEY_PEM_BLOCK" in result.skip_reason


def test_sanitize_text_csv_header_triggers_skip_file() -> None:
    text = "nome,cpf,email\n[NOME],123.456.789-00,a@b.com\n"
    result = sanitize_text_content(text, "utf-8")
    assert result.skip_file is True


def test_sanitize_text_no_matches_unchanged() -> None:
    text = "# documento normal\nprint('hello')\n"
    result = sanitize_text_content(text, "utf-8")
    assert result.sanitized_text == text
    assert not result.matches


def test_sanitize_text_redacts_cpf() -> None:
    text = "Cliente CPF: 123.456.789-00 contato\n"
    result = sanitize_text_content(text, "utf-8")
    assert "123.456.789-00" not in result.sanitized_text


def test_sanitize_text_redacts_internal_url() -> None:
    text = "DB at db.acme.internal:5432 active\n"
    result = sanitize_text_content(text, "utf-8")
    assert "db.acme.internal" not in result.sanitized_text


# ===========================================================================
# scan_binary_deep — Camada C5
# ===========================================================================

def test_scan_binary_finds_akia_in_pdf_payload() -> None:
    """AKIA key embedded em primeiros 64 KB de um PDF-like."""
    payload = b"%PDF-1.4\n" + b"x" * 1000 + b"AKIAIOSFODNN7EXAMPLE" + b"x" * 1000
    matches, timeouts = scan_binary_deep("test.pdf", payload)
    assert any(rule.tipo == "API_KEY_aws_AKIA" for rule, _ in matches)
    assert not timeouts


def test_scan_binary_finds_ghp_in_zip_payload() -> None:
    payload = b"PK\x03\x04" + b"\x00\x00" + b"\nghp_abcdef123456789012345\n" + b"\x00" * 100
    matches, _ = scan_binary_deep("archive.xlsx", payload)
    assert any(rule.tipo == "API_KEY_github_ghp" for rule, _ in matches)


def test_scan_binary_empty_returns_no_matches() -> None:
    matches, _ = scan_binary_deep("empty.bin", b"")
    assert not matches


def test_deep_scan_bytes_constant() -> None:
    """Camada C5 limit canonico = 64 KB."""
    assert DEEP_SCAN_BYTES == 64 * 1024


# ===========================================================================
# safe_finditer / safe_sub — regex lib timeout wrapper (ADR-026 + RS-022)
# ===========================================================================

def test_safe_finditer_finds_simple_match() -> None:
    import re
    pat = re.compile(r"hello")
    matches = safe_finditer(pat, "hello world hello again")
    assert len(matches) == 2


def test_safe_finditer_no_match_returns_empty() -> None:
    import re
    pat = re.compile(r"xyz")
    matches = safe_finditer(pat, "abc def ghi")
    assert matches == []


def test_safe_sub_replaces_pattern() -> None:
    import re
    pat = re.compile(r"\d+")
    result = safe_sub(pat, "N", "abc 123 def 456")
    assert result == "abc N def N"


def test_safe_finditer_timeout_raises_f3timeout() -> None:
    """ReDoS smoke: pattern catastrofica (a+)+! contra entrada longa de 'a's
    sem '!' deve disparar timeout. Usamos timeout muito baixo (0.5s) para
    garantir o trigger sem esperar 30s."""
    import re
    catastrophic = re.compile(r"(a+)+!")
    payload = "a" * 5000  # adversarial: 5k 'a's sem '!' final
    with pytest.raises(F3Timeout):
        safe_finditer(catastrophic, payload, timeout_seconds=1)


# ===========================================================================
# rescan_destination — Camada C6
# ===========================================================================

def test_rescan_destination_clean_returns_zero(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "README.md").write_text("# clean repo\n", encoding="utf-8")
    (dest / "main.py").write_text("print('hi')\n", encoding="utf-8")
    n, matches = rescan_destination(dest)
    assert n == 0
    assert not matches


def test_rescan_destination_detects_leaked_env_file(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / ".env").write_text("KEY=value\n", encoding="utf-8")
    n, matches = rescan_destination(dest)
    assert n >= 1
    assert any(m.categoria == "C1" for m in matches)


def test_rescan_destination_detects_ghp_leak(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "config.txt").write_text("TOKEN=ghp_abcdef123456789012345\n", encoding="utf-8")
    n, _matches = rescan_destination(dest)
    assert n >= 1


def test_rescan_destination_excludes_state_file(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    # state file canonico nao deve ser escaneado para evitar falso-positivo
    # do proprio state file (futuro)
    (dest / ".sanitizer-state.json").write_text('{"current_state": "applying"}\n', encoding="utf-8")
    (dest / "ok.md").write_text("# ok\n", encoding="utf-8")
    n, _matches_state = rescan_destination(dest, exclude_paths={".sanitizer-state.json"})
    # Pode haver 0 matches (state file excluido)
    assert n == 0


# ===========================================================================
# preflight_integrity — Camadas C2 + C3
# ===========================================================================

def test_preflight_integrity_passes_in_clean_project_root(project_root: Path) -> None:
    """Integrity manifest do project root (real) deve estar verde por construcao."""
    result = preflight_integrity(project_root)
    assert result["ok"] is True
    assert result["checked"] >= 1


def test_preflight_integrity_fails_with_tampered_manifest(tmp_path: Path) -> None:
    """Cria projeto fake com integrity.md desatualizado -> raise IntegrityFailure."""
    fake_root = tmp_path / "fake"
    fake_root.mkdir()
    (fake_root / "file_a.txt").write_text("contents A v1\n", encoding="utf-8")
    integrity_md = fake_root / "integrity.md"
    # Hash fake propositalmente errado
    integrity_md.write_text(
        "---\nlast_setup: 2026-05-12T00:00:00+00:00\n---\n\n"
        "# Hashes\n- file: file_a.txt\n  sha256: " + "0" * 64 + "\n"
        "  recorded_at: 2026-05-12T00:00:00+00:00\n",
        encoding="utf-8",
    )
    with pytest.raises(IntegrityFailure):
        preflight_integrity(fake_root, integrity_md)
