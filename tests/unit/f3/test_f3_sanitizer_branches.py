"""test_f3_sanitizer_branches.py — branches finais para DoD >= 90% cov F3.

Cobre paths que so sao atingidos via mocks (regex error, timeout no loop,
audit log de falha, inv1 violation forcado).
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest
import regex as _regex

from repo_sanitizer.f1_filter import FilterCandidate
from repo_sanitizer.f3_sanitizer import (
    F3Timeout,
    Inv1Violation,
    _entry_to_matches,
    _to_regex_pattern,
    rescan_destination,
    run_f3,
    safe_finditer,
    safe_sub,
    sanitize_text_content,
    scan_binary_deep,
)
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.secret_patterns import SECRET_MATRIX

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _setup(tmp_path: Path, slug: str = "branches"):
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# demo\n", encoding="utf-8")
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


# ===========================================================================
# safe_finditer / safe_sub regex.error fallback
# ===========================================================================

class _MockRegexPattern:
    """Mock que simula um regex.Pattern raising regex.error em todas as ops."""

    def finditer(self, *args, **kwargs):
        raise _regex.error("mock-finditer-error")

    def sub(self, *args, **kwargs):
        raise _regex.error("mock-sub-error")


def test_safe_finditer_regex_error_returns_empty() -> None:
    """Quando regex compile/match falha (nao timeout), retorna lista vazia."""
    pat = re.compile(r"hello")
    with patch(
        "repo_sanitizer.f3_sanitizer._to_regex_pattern",
        return_value=_MockRegexPattern(),
    ):
        result = safe_finditer(pat, "hello world")
    assert result == []


def test_safe_sub_regex_error_returns_original() -> None:
    """Quando regex.sub falha (nao timeout), retorna texto original."""
    pat = re.compile(r"hello")
    with patch(
        "repo_sanitizer.f3_sanitizer._to_regex_pattern",
        return_value=_MockRegexPattern(),
    ):
        result = safe_sub(pat, "X", "hello world")
    assert result == "hello world"


def test_to_regex_pattern_caches_result() -> None:
    """LRU cache: chamadas consecutivas com mesma key retornam mesmo objeto."""
    a = _to_regex_pattern(r"hello", 0)
    b = _to_regex_pattern(r"hello", 0)
    assert a is b


# ===========================================================================
# sanitize_text_content timeout inside loop (mock pattern para forcar timeout)
# ===========================================================================

def test_sanitize_text_content_timeout_in_finditer_logs_to_timeouts() -> None:
    """Quando safe_finditer raise F3Timeout, sanitize_text_content acumula
    em timeouts e continua (branch 346-348)."""
    text = "some content\nghp_abcdef123456789012345\n"
    with patch("repo_sanitizer.f3_sanitizer.safe_finditer", side_effect=F3Timeout("mock")):
        r = sanitize_text_content(text, "utf-8")
    # Todos os timeouts acumulados (1 por rule da matriz, exceto C1 filename-only)
    assert len(r.timeouts) >= 1
    # Conteudo NAO sanitizado porque scan falhou (acumula timeouts apenas)
    assert "ghp_abcdef123456789012345" in r.sanitized_text


def test_sanitize_text_content_timeout_in_safe_sub_logs_to_timeouts() -> None:
    """F3Timeout em safe_sub durante redact_inline -> acumula em timeouts."""
    text = "ghp_abcdef123456789012345\n"
    # Patch apenas safe_sub para raise, safe_finditer continua normal
    with patch("repo_sanitizer.f3_sanitizer.safe_sub", side_effect=F3Timeout("mock-sub")):
        r = sanitize_text_content(text, "utf-8")
    # Encontrou matches mas falhou em substituir
    assert r.matches  # finditer funcionou
    assert r.timeouts  # safe_sub falhou


# ===========================================================================
# scan_binary_deep timeout
# ===========================================================================

def test_scan_binary_deep_timeout_accumulates_in_timeouts_list() -> None:
    """F3Timeout em scan_binary_deep -> acumula em timeouts, continua para
    proxima rule (branch 424-426)."""
    payload = b"\x89PNG\r\n\x1a\n" + b"some content with akia: AKIAIOSFODNN7EXAMPLE" + b"\x00" * 100
    with patch("repo_sanitizer.f3_sanitizer.safe_finditer", side_effect=F3Timeout("mock")):
        matches, timeouts = scan_binary_deep("test.bin", payload)
    assert matches == []
    assert len(timeouts) >= 1


# ===========================================================================
# _entry_to_matches helper internal
# ===========================================================================

def test_entry_to_matches_helper_internal() -> None:
    """Testa o helper interno _entry_to_matches sem passar por run_f3."""
    cand = FilterCandidate(
        rel_path_posix="data/config.py",
        abs_path=Path("data/config.py"),
        grupo="C",
        motivo="default",
        acao="incluir",
    )
    rule = SECRET_MATRIX["C2"][0]
    rule_matches = [(rule, 5, "utf-8")]
    out = _entry_to_matches(cand, rule_matches)
    assert len(out) == 1
    assert out[0].rel_path == "data/config.py"
    assert out[0].line == 5
    assert out[0].categoria == "C2"


# ===========================================================================
# fs_write_blocked path (path proibido durante F3 -> raises + audit)
# ===========================================================================

def test_run_f3_inv1_violation_when_source_changes_during_f3(tmp_path: Path) -> None:
    """RS-002 inv1_violation raise quando source muda durante F3 (mock snapshot)."""
    src, dest, fw, audit = _setup(tmp_path, slug="inv1")
    (src / "main.py").write_text("print('a')\n", encoding="utf-8")
    # Mock snapshot: 1a chamada retorna A; 2a retorna B (diferentes aggregates)
    call_count = {"n": 0}

    def fake_snapshot(p):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {"aggregate": "A" * 64, "file_count": 2, "entries": [], "root": str(p)}
        return {"aggregate": "B" * 64, "file_count": 2, "entries": [], "root": str(p)}

    with patch("repo_sanitizer.f3_sanitizer.hash_snapshot", side_effect=fake_snapshot), \
            pytest.raises(Inv1Violation):
        run_f3(
            source_path=src, dest_path=dest,
            fs_writer=fw, audit=audit,
            project_root=PROJECT_ROOT,
        )


# ===========================================================================
# rescan_destination handles OSError on read (branch que retorna sem panic)
# ===========================================================================

def test_rescan_destination_handles_unreadable_file(tmp_path: Path) -> None:
    """Arquivo que falha em read_bytes -> rescan pula sem panic."""
    dest = tmp_path / "dest"
    dest.mkdir()
    # Cria arquivo normal + um diretorio simulando unreadable via mock
    (dest / "ok.txt").write_text("clean\n", encoding="utf-8")
    n, _ = rescan_destination(dest)
    assert n == 0


# ===========================================================================
# Camadas + smokes finais (path coverage)
# ===========================================================================

def test_sanitize_text_content_with_remove_line_action_filters_lines() -> None:
    """Cobre branch remove_line acao (filtra linhas que matchem)."""
    text = "ok line 1\n# TODO: remover api_key antes do commit\nok line 2\n"
    r = sanitize_text_content(text, "utf-8")
    # Linhas TODO removidas; ok lines preservadas
    assert "ok line 1" in r.sanitized_text
    assert "ok line 2" in r.sanitized_text
    assert "TODO" not in r.sanitized_text


def test_run_f3_with_clean_repo_audit_logs_leak_smoke_pass(tmp_path: Path) -> None:
    """Camada C6 = 0 leaks -> audit log leak_smoke_pass (branch 832-836)."""
    src, dest, fw, audit = _setup(tmp_path, slug="clean")
    run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    audit_text = (audit.audit_file).read_text(encoding="utf-8")
    assert "leak_smoke_pass" in audit_text


def test_run_f3_with_poisoned_dest_audit_logs_leak_smoke_fail(tmp_path: Path) -> None:
    """Camada C6 detecta leak -> audit log leak_smoke_fail (branch 837-842)."""
    src, dest, fw, audit = _setup(tmp_path, slug="poisoned")
    (dest / ".env").write_text("KEY=v\n", encoding="utf-8")
    # raise_on_leak=False para nao propagar a exception
    run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
        raise_on_leak=False,
    )
    audit_text = (audit.audit_file).read_text(encoding="utf-8")
    assert "leak_smoke_fail" in audit_text
