"""test__state_machine.py — FSM 7 estados (RS-026)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._state_machine import (
    InvalidTransitionError,
    State,
    StateMachine,
)


def _make_sm(tmp_path: Path) -> StateMachine:
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir(exist_ok=True)
    fw = FsWriter(
        source_path=tmp_path / "fake-source",
        allowed_roots=[allowed],
        override_forbidden=[],  # tmp_path em AppData (Windows)
    )
    dest = allowed / "GIT_test"
    dest.mkdir(parents=True, exist_ok=True)
    return StateMachine(dest_path=dest, fs_writer=fw)


def test_initial_state_is_idle(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    assert sm.current() == State.IDLE


def test_transition_idle_to_dry_run(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    sm.transition("dry_run_done")
    assert sm.current() == State.DRY_RUN


def test_transition_invalid_action_raises(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    with pytest.raises(InvalidTransitionError, match="Acao desconhecida"):
        sm.transition("not_a_real_action")


def test_transition_invalid_for_state_raises(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    # idle -> apply_done e invalido (idle so aceita dry_run_done ou fail)
    with pytest.raises(InvalidTransitionError, match="Transicao invalida"):
        sm.transition("apply_done")


def test_full_happy_path(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    assert sm.transition("dry_run_done") == State.DRY_RUN
    assert sm.transition("dry_run_apply_review") == State.AWAITING_APPLY
    assert sm.transition("apply_start") == State.APPLYING
    assert sm.transition("apply_done") == State.AWAITING_README
    assert sm.transition("readme_received") == State.AWAITING_FINALIZE
    assert sm.transition("finalize_done") == State.DONE
    assert sm.transition("reset") == State.IDLE


def test_persistence_save_load(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    sm.transition("dry_run_done", reason="initial dry-run")
    # carrega novo FSM no mesmo path
    sm2 = _make_sm(tmp_path)
    sm2.load()
    assert sm2.current() == State.DRY_RUN
    assert sm2.history()[-1]["action"] == "dry_run_done"


def test_persistence_file_has_schema_version(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    sm.transition("dry_run_done")
    payload = json.loads(sm.state_file.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0.0"
    assert payload["agent"] == "repo-sanitizer-agent"
    assert payload["current_state"] == "dry_run"


def test_failure_state_can_reset(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    sm.transition("fail", reason="smoke test")
    assert sm.current() == State.FAILED
    sm.transition("reset")
    assert sm.current() == State.IDLE


def test_done_terminal_except_reset(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    sm.transition("dry_run_done")
    sm.transition("dry_run_apply_review")
    sm.transition("apply_start")
    sm.transition("apply_done")
    sm.transition("readme_received")
    sm.transition("finalize_done")
    assert sm.current() == State.DONE
    # done -> apply_start e invalido
    with pytest.raises(InvalidTransitionError):
        sm.transition("apply_start")
    # done -> reset funciona
    sm.transition("reset")
    assert sm.current() == State.IDLE


# -------------------- Bloco 04 — Gate G2 (ADR-032) --------------------


def _advance_to_awaiting_finalize(sm: StateMachine) -> None:
    sm.transition("dry_run_done")
    sm.transition("dry_run_apply_review")
    sm.transition("apply_start")
    sm.transition("apply_done")
    sm.transition("readme_received")


def test_finalize_done_with_warnings_transition(tmp_path: Path) -> None:
    """G2: (a)/(b) auto-gerados -> done_with_warnings (exit 0)."""
    sm = _make_sm(tmp_path)
    _advance_to_awaiting_finalize(sm)
    sm.transition("finalize_done_with_warnings", reason="boilerplate auto-gerado")
    assert sm.current() == State.DONE_WITH_WARNINGS


def test_finalize_done_with_failure_transition(tmp_path: Path) -> None:
    """G2: (c) paths absolutos ou (d) PII presentes -> done_with_failure (exit 7)."""
    sm = _make_sm(tmp_path)
    _advance_to_awaiting_finalize(sm)
    sm.transition("finalize_done_with_failure", reason="paths absolutos no destino")
    assert sm.current() == State.DONE_WITH_FAILURE


def test_finalize_done_legacy_still_valid(tmp_path: Path) -> None:
    """Backward-compat: outcome 'done' (G2 todos OK) continua valido."""
    sm = _make_sm(tmp_path)
    _advance_to_awaiting_finalize(sm)
    sm.transition("finalize_done")
    assert sm.current() == State.DONE


def test_done_with_warnings_only_accepts_reset(tmp_path: Path) -> None:
    """done_with_warnings e terminal: so 'reset' e valido."""
    sm = _make_sm(tmp_path)
    _advance_to_awaiting_finalize(sm)
    sm.transition("finalize_done_with_warnings")
    assert sm.current() == State.DONE_WITH_WARNINGS
    with pytest.raises(InvalidTransitionError):
        sm.transition("apply_start")
    sm.transition("reset")
    assert sm.current() == State.IDLE


def test_done_with_failure_only_accepts_reset(tmp_path: Path) -> None:
    """done_with_failure e terminal: so 'reset' e valido."""
    sm = _make_sm(tmp_path)
    _advance_to_awaiting_finalize(sm)
    sm.transition("finalize_done_with_failure")
    assert sm.current() == State.DONE_WITH_FAILURE
    with pytest.raises(InvalidTransitionError):
        sm.transition("finalize_done")
    sm.transition("reset")
    assert sm.current() == State.IDLE
