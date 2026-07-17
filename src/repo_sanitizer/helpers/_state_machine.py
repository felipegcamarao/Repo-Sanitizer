"""_state_machine.py — FSM 7 estados (RS-026 + ADR-006).

Pipeline canonico INVARIANTE: F1 -> F3 -> F2 -> F4.

Estados:
    idle                 # FSM nao iniciada para este destino
    dry_run              # F1 executou em modo dry-run; FILTER_DIFF emitido
    awaiting_apply       # [NOME] revisou FILTER_DIFF; aguarda /sanitize-apply
    applying             # /sanitize-apply em curso (F3 -> F2 -> stub README)
    awaiting_readme      # stub README + estado salvo; [NOME] roda /generate-readme
    awaiting_finalize    # README final gravado; aguarda /sanitize-finalize
    done                 # /sanitize-finalize ok + Gate G2 com (a)+(b) presentes na fonte + (c)+(d) zero
    done_with_warnings   # /sanitize-finalize ok + Gate G2 (a) e/ou (b) auto-gerados (ADR-032/033)
    done_with_failure    # Gate G2 bloqueante: (c) paths absolutos > 0 OU (d) PII operador > 0
    failed               # qualquer falha intermediaria

Outcomes do Gate G2 (ADR-032):
    done                  -> exit 0  (replica totalmente funcional + verified)
    done_with_warnings    -> exit 0  (replica funcional; auto-gen de boilerplate/LICENSE)
    done_with_failure     -> exit 7  (replica NAO publicavel; bloqueante).

Tentativa de transicao invalida -> exit code 4 (state_transition_invalid).

API publica:
    State (Enum)
    StateMachine(dest_path, fs_writer)
    sm.current() -> State
    sm.transition(action: str) -> State        # raise InvalidTransitionError em violacao
    sm.load() -> State                          # carrega de .sanitizer-state.json
    sm.save(reason: str | None = None) -> None  # persiste atomico via FsWriter

State file: `<dest_path>/.sanitizer-state.json` (atomic write).

NAO contem audit-log: caller (orchestrator) emite RepoSanitizerAuditEntry
`state_transition_invalid` em falha.
"""
from __future__ import annotations

import datetime as _dt
import json
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from repo_sanitizer.helpers._pii_redactor import redact_path

if TYPE_CHECKING:
    from repo_sanitizer.helpers._fs_writer import FsWriter


class State(StrEnum):
    """Estados canonicos do sanitizer pipeline (FSM 7 estados + erro)."""

    IDLE = "idle"
    DRY_RUN = "dry_run"
    AWAITING_APPLY = "awaiting_apply"
    APPLYING = "applying"
    AWAITING_README = "awaiting_readme"
    AWAITING_FINALIZE = "awaiting_finalize"
    DONE = "done"
    DONE_WITH_WARNINGS = "done_with_warnings"
    DONE_WITH_FAILURE = "done_with_failure"
    FAILED = "failed"


# Acoes que disparam transicoes (mapeiam para argparse subcommands + sub-passos):
TRANSITION_ACTIONS = {
    "dry_run_done",                   # idle  -> dry_run
    "dry_run_apply_review",           # dry_run -> awaiting_apply ([NOME] revisou FILTER_DIFF)
    "apply_start",                    # awaiting_apply -> applying
    "apply_done",                     # applying -> awaiting_readme
    "readme_received",                # awaiting_readme -> awaiting_finalize
    "finalize_done",                  # awaiting_finalize -> done            (Gate G2 todos OK)
    "finalize_done_with_warnings",    # awaiting_finalize -> done_with_warnings (G2 (a)/(b) auto-gen)
    "finalize_done_with_failure",     # awaiting_finalize -> done_with_failure  (G2 (c)/(d) bloqueante)
    "fail",                           # qualquer -> failed
    "reset",                          # failed/done* -> idle (operacional manual)
}


# Transicoes validas (origem -> {acao: destino})
TRANSITIONS: dict[State, dict[str, State]] = {
    State.IDLE: {
        "dry_run_done": State.DRY_RUN,
        "fail": State.FAILED,
    },
    State.DRY_RUN: {
        "dry_run_apply_review": State.AWAITING_APPLY,
        "dry_run_done": State.DRY_RUN,  # idempotente (re-run dry-run)
        "fail": State.FAILED,
    },
    State.AWAITING_APPLY: {
        "apply_start": State.APPLYING,
        "fail": State.FAILED,
    },
    State.APPLYING: {
        "apply_done": State.AWAITING_README,
        "fail": State.FAILED,
    },
    State.AWAITING_README: {
        "readme_received": State.AWAITING_FINALIZE,
        "fail": State.FAILED,
    },
    State.AWAITING_FINALIZE: {
        "finalize_done": State.DONE,
        "finalize_done_with_warnings": State.DONE_WITH_WARNINGS,
        "finalize_done_with_failure": State.DONE_WITH_FAILURE,
        "fail": State.FAILED,
    },
    State.DONE: {
        # terminal — exceto reset operacional manual
        "reset": State.IDLE,
    },
    State.DONE_WITH_WARNINGS: {
        # terminal — exceto reset operacional manual
        "reset": State.IDLE,
    },
    State.DONE_WITH_FAILURE: {
        # terminal — exceto reset operacional manual
        "reset": State.IDLE,
    },
    State.FAILED: {
        "reset": State.IDLE,
    },
}


class InvalidTransitionError(RuntimeError):
    """Tentativa de transicao invalida. Caller mapeia para exit 4."""


class StateMachine:
    """FSM persistente por destino (state file por GIT_NOME).

    Args:
        dest_path: pasta destino (GIT_[NOME]-vN). State file e
            `<dest_path>/.sanitizer-state.json`.
        fs_writer: instancia FsWriter para escrita atomica do state file.
        initial_state: estado inicial em criacao (default IDLE).
    """

    STATE_FILENAME = ".sanitizer-state.json"

    def __init__(
        self,
        dest_path: Path,
        fs_writer: FsWriter,
        initial_state: State = State.IDLE,
    ) -> None:
        self.dest_path: Path = Path(dest_path)
        self.state_file: Path = self.dest_path / self.STATE_FILENAME
        self.fs_writer = fs_writer
        self._state: State = initial_state
        self._history: list[dict[str, str]] = []

    # ---------------------- query ----------------------

    def current(self) -> State:
        return self._state

    def history(self) -> list[dict[str, str]]:
        return list(self._history)

    # ---------------------- transitions ----------------------

    def transition(self, action: str, reason: str | None = None) -> State:
        """Aplica acao -> nova state. Persiste atomicamente."""
        if action not in TRANSITION_ACTIONS:
            raise InvalidTransitionError(
                f"Acao desconhecida: {action!r}. Validas: {sorted(TRANSITION_ACTIONS)}"
            )
        allowed = TRANSITIONS.get(self._state, {})
        if action not in allowed:
            raise InvalidTransitionError(
                f"Transicao invalida: state={self._state.value} acao={action}; "
                f"validas a partir deste estado: {sorted(allowed.keys())}"
            )
        new_state = allowed[action]
        self._history.append({
            "from": self._state.value,
            "action": action,
            "to": new_state.value,
            "at": _now_iso8601(),
            "reason": reason or "",
        })
        self._state = new_state
        self.save(reason=reason)
        return new_state

    # ---------------------- persistence ----------------------

    def save(self, reason: str | None = None) -> None:
        """Grava state file via FsWriter (atomico).

        v1.2.0 / MV-07 / RS-NEW-044 (mitigacao §5-10): o `.sanitizer-state.json`
        e gitignorado (fecha C-V11-05), mas se [NOME] forcar `git add -f` o
        arquivo NAO pode vazar o path ABSOLUTO da fonte/destino nem PII
        (MV07-B). Por isso so persistimos o BASENAME do destino (nome da pasta
        versionada `GIT_[slug]-vN`, sem segmentos de usuario/drive) + um filtro
        `redact_path` defensivo. O `current_state` continua sendo a fonte de
        verdade da FSM (basename basta para identificar o destino corrente).
        """
        payload = {
            "schema_version": "1.0.0",
            "agent": "repo-sanitizer-agent",
            # RELATIVIZADO/REDATADO (MV07-B): so o nome da pasta destino.
            "dest_name": redact_path(self.dest_path.name),
            "current_state": self._state.value,
            "history": self._history[-50:],  # cap historico para 50 entries
            "updated_at": _now_iso8601(),
            "reason": reason or "",
        }
        self.fs_writer.safe_write_text(
            self.state_file,
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        )

    def load(self) -> State:
        """Carrega state do arquivo. Ausente = IDLE."""
        if not self.state_file.exists():
            self._state = State.IDLE
            self._history = []
            return self._state
        payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        self._state = State(payload["current_state"])
        self._history = list(payload.get("history", []))
        return self._state


def _now_iso8601() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


__all__ = [
    "TRANSITIONS",
    "TRANSITION_ACTIONS",
    "InvalidTransitionError",
    "State",
    "StateMachine",
]
