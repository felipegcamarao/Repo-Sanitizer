"""test__runtime_guard.py — heuristica Claude Code header (DEF-07 + INV-9)."""
from __future__ import annotations

import pytest

from repo_sanitizer.helpers._runtime_guard import (
    detect_runtime,
    is_claude_code,
    runtime_marker,
)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Limpa env vars antes de cada teste."""
    for k in (
        "CLAUDE_CODE_RUNTIME", "CLAUDECODE", "CLAUDE_CODE_SESSION_ID",
        "ANTHROPIC_CLI_SESSION", "TERM_PROGRAM", "VSCODE_PID",
    ):
        monkeypatch.delenv(k, raising=False)


def test_override_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_RUNTIME", "chat")
    assert detect_runtime() == "claude_code"
    assert is_claude_code() is True


def test_override_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_RUNTIME", "cli")
    assert detect_runtime() == "claude_cli"


def test_override_degrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_RUNTIME", "degrade")
    assert detect_runtime() == "unknown"


def test_claudecode_marker_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDECODE", "1")
    assert detect_runtime() == "claude_code"


def test_vs_code_terminal_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM_PROGRAM", "vscode")
    assert detect_runtime() == "vs_code_terminal"


def test_unknown_default() -> None:
    assert detect_runtime() == "unknown"
    assert is_claude_code() is False


def test_runtime_marker_returns_pt_br_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_RUNTIME", "chat")
    marker = runtime_marker()
    assert "claude_code" in marker
    assert "INV-9" in marker
