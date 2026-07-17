"""test_phase5_rs_isolated_smokes.py — Fase 5 (05-Test-Agent v1.x).

Gap analysis Fase 5: cobrir RSs sem tag textual "RS-XXX" em test files com
smoke ISOLADO comportamental. 16 RSs identificados sem tag explicita:

  RS-004 (secret_patterns integrity), RS-005 (report nunca literal),
  RS-007 (path boundary), RS-009 (pipeline ordering FSM),
  RS-010 (INV-7 enforce), RS-012 (injection_patterns integrity),
  RS-013 (_sanitize integrity), RS-015 (markdownlint degrade),
  RS-017 (cap LLM 1/run), RS-020 (F2 dry-run),
  RS-024 (templates versionados), RS-025 (runtime guard),
  RS-027 (metadata canonica), RS-028 (LGPD aviso),
  RS-029 (Grupo C spoofing), RS-030 (SECURITY contact)

Cada smoke verifica o comportamento canonico via API publica do modulo
responsavel (sem mockar producao; INV-1 preservado via tmp_path).

ADRs ancorados: ADR-001..028 (smoke isolado por RS canonico).
Modo HIBRIDO Modo Completo AGRAVADO 3x (RS-001 catastrofico irreversivel).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# RS-004 — secret_patterns integrity SHA-256 (ADR-015)
# ---------------------------------------------------------------------------


def test_rs004_secret_patterns_integrity_hash_stable() -> None:
    """RS-004: secret_patterns.py hash SHA-256 atual igual ao registrado em integrity.md."""
    import repo_sanitizer.secret_patterns as sp
    src_file = Path(sp.__file__)
    h = hashlib.sha256(src_file.read_bytes()).hexdigest()
    integrity_md = Path("integrity.md").read_text(encoding="utf-8")
    # secret_patterns.py deve ser um dos arquivos rastreados; hash atual nao deve diferir
    assert "secret_patterns.py" in integrity_md, "RS-004: secret_patterns.py deve estar em integrity.md"
    assert h in integrity_md, f"RS-004: hash atual SHA-256 {h[:12]}... deve estar em integrity.md"


# ---------------------------------------------------------------------------
# RS-005 — Report NUNCA contem valor literal (ADR-004)
# ---------------------------------------------------------------------------


def test_rs005_sanitization_report_blocks_literal_secret() -> None:
    """RS-005 + ADR-004: SanitizationReportEntry bloqueia valor literal via no_literal_secret."""
    from pydantic import ValidationError

    from repo_sanitizer.schemas.sanitization_report_entry import (
        SanitizationReportEntry,
    )

    entry_valid = SanitizationReportEntry(
        categoria="C1",
        tipo="ENV_FILE",
        path_redacted="/x/.env",
        linha=None,
        acao="envexample",
        encoding_detected="utf-8",
    )
    # Validacao defensiva: dump nao deve conter literal
    artifact = json.dumps(entry_valid.model_dump())
    assert "ghp_" not in artifact

    # Construct invalid: literal injected em path_redacted (campo free-form)
    with pytest.raises(ValidationError, match=r"valor literal de secret|ghp_"):
        SanitizationReportEntry(
            categoria="C2",
            tipo="GITHUB_TOKEN",
            path_redacted="/x/ghp_1234567890abcdef1234567890abcdef1234.py",
            linha=10,
            acao="placeholder",
            encoding_detected="utf-8",
        )


# ---------------------------------------------------------------------------
# RS-007 — Path boundary reject (ADR-020)
# ---------------------------------------------------------------------------


def test_rs007_fs_writer_reject_outside_allowed(tmp_path: Path) -> None:
    """RS-007: FsWriter recusa escrita FORA de ALLOWED_ROOTS."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    outside = tmp_path / "fora" / "leak.txt"
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(outside, "leak")


# ---------------------------------------------------------------------------
# RS-009 — Pipeline F1→F3→F2→F4 ordering via FSM (ADR-006 + RS-026)
# ---------------------------------------------------------------------------


def test_rs009_pipeline_ordering_fsm_invalid_transition(tmp_path: Path) -> None:
    """RS-009 + RS-026: FSM rejeita transicao invalida fora da ordem F1->F3->F2->F4."""
    from repo_sanitizer.helpers._fs_writer import FsWriter
    from repo_sanitizer.helpers._state_machine import (
        InvalidTransitionError,
        StateMachine,
    )

    dest = tmp_path / "dest"
    dest.mkdir()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    fsm = StateMachine(dest_path=dest, fs_writer=fw)
    # Cannot finalize before reaching AWAITING_FINALIZE
    with pytest.raises(InvalidTransitionError):
        fsm.transition("finalize_done")


# ---------------------------------------------------------------------------
# RS-010 — INV-7 enforce (Relatorios path separado; ADR-020)
# ---------------------------------------------------------------------------


def test_rs010_inv7_enforce_relatorios_isolated(tmp_path: Path) -> None:
    """RS-010: escrita fora do allowed_roots Relatorios raise out-of-bounds."""
    from repo_sanitizer.helpers._fs_writer import FsWriteOutOfBoundsError, FsWriter

    git_hub = tmp_path / "git-hub-[NOME]"
    git_hub.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "src",
        allowed_roots=[git_hub],
        override_forbidden=[],
    )
    rel = tmp_path / "Relatorios-fake" / "rel.md"
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(rel, "fake report")


# ---------------------------------------------------------------------------
# RS-012 — injection_patterns local-copy integrity (ADR-022)
# ---------------------------------------------------------------------------


def test_rs012_injection_patterns_integrity_listed() -> None:
    """RS-012: injection_patterns.json local-copy esta no integrity.md."""
    integrity_md = Path("integrity.md").read_text(encoding="utf-8")
    assert "injection_patterns.json" in integrity_md, (
        "RS-012: injection_patterns.json deve estar listado em integrity.md"
    )


# ---------------------------------------------------------------------------
# RS-013 — _sanitize local-copy integrity (ADR-023)
# ---------------------------------------------------------------------------


def test_rs013_sanitize_integrity_listed() -> None:
    """RS-013: _sanitize.py local-copy esta no integrity.md."""
    integrity_md = Path("integrity.md").read_text(encoding="utf-8")
    assert "_sanitize.py" in integrity_md, (
        "RS-013: tests/fixtures/sentinel/_sanitize.py deve estar em integrity.md"
    )


# ---------------------------------------------------------------------------
# RS-015 — markdownlint degrade gracioso (ADR-013)
# ---------------------------------------------------------------------------


def test_rs015_markdownlint_degrade_gracious(tmp_path: Path) -> None:
    """RS-015: ausencia de CLI markdownlint -> retorna NOT_AVAILABLE."""
    from repo_sanitizer.f4_readme import run_markdownlint

    fake_readme = tmp_path / "README.md"
    fake_readme.write_text("# title\n", encoding="utf-8")
    # Force which() to return None
    with patch("repo_sanitizer.f4_readme._which", return_value=None):
        status = run_markdownlint(fake_readme)
    assert status == "NOT_AVAILABLE", f"RS-015: degrade gracioso retorna NOT_AVAILABLE; got {status}"


# ---------------------------------------------------------------------------
# RS-017 — Cap LLM 1/run (ADR-017)
# ---------------------------------------------------------------------------


def test_rs017_cap_llm_1_per_run(tmp_path: Path) -> None:
    """RS-017: cap_llm_kit_emitted True apos flag file existir."""
    from repo_sanitizer.f4_readme import cap_llm_kit_emitted

    dest = tmp_path / "dest"
    dest.mkdir()
    assert not cap_llm_kit_emitted(dest), "RS-017: cap inicial deve ser False"
    (dest / ".f4_kit_emitted").write_text("1", encoding="utf-8")
    assert cap_llm_kit_emitted(dest), "RS-017: cap True apos flag file existir"


# ---------------------------------------------------------------------------
# RS-020 — F2 movimentacao imports relativos => sugestao apenas (ADR-005)
# ---------------------------------------------------------------------------


def test_rs020_f2_relative_imports_only_suggestion() -> None:
    """RS-020: arquivo test_x.py com imports relativos NUNCA e movido auto."""
    from repo_sanitizer.f2_organizer import decide_move

    rel_content = "from .main import main\n\ndef test_x():\n    assert True\n"
    decision = decide_move("test_main.py", rel_content)
    assert decision is not None, "RS-020: test no root deve retornar decision"
    assert decision.action == "suggested", (
        f"RS-020: imports relativos => action=suggested, got={decision.action}"
    )

    # Sanity check: imports absolutos => moved
    abs_content = "from mypkg.main import main\n\ndef test_x():\n    assert True\n"
    decision2 = decide_move("test_main.py", abs_content)
    assert decision2 is not None
    assert decision2.action == "moved", (
        f"RS-020 sanity: imports absolutos => moved, got={decision2.action}"
    )


# ---------------------------------------------------------------------------
# RS-024 — Templates versionados via importlib.resources (ADR-010)
# ---------------------------------------------------------------------------


def test_rs024_templates_versioned_pt_br_render(tmp_path: Path) -> None:
    """RS-024: 3 templates PT-BR + 9 .gitignore renderizam via importlib.resources."""
    from importlib import resources

    package = "repo_sanitizer.templates"
    # 3 PT-BR templates
    for name in ("code_of_conduct_pt_br.md", "contributing_pt_br.md", "security_pt_br.md"):
        content = resources.files(package).joinpath(name).read_text(encoding="utf-8")
        assert len(content) > 0, f"RS-024: template {name} nao pode ser vazio"
        sec_content = (
            resources.files(package).joinpath("security_pt_br.md").read_text(encoding="utf-8")
        )
        # P1-a (GAP-S07-03): o template NUNCA pode estampar PII real do operador;
        # deve usar placeholder neutro para o mantenedor preencher.
        assert "<EMAIL-DO-MANTENEDOR>" in sec_content, (
            "RS-024 + RS-030: SECURITY template deve usar placeholder <EMAIL-DO-MANTENEDOR>"
        )
        assert "tecnologia@acme.io" not in sec_content, (
            "P1-a: SECURITY template NAO pode conter email real do operador"
        )

    # 9 .gitignore
    git_pkg = f"{package}.gitignore"
    for lang in ("python", "node", "rust", "go", "java", "csharp", "php", "ruby", "generic"):
        content = resources.files(git_pkg).joinpath(f"{lang}.gitignore").read_text(encoding="utf-8")
        assert len(content) > 0, f"RS-024: .gitignore {lang} nao pode ser vazio"


# ---------------------------------------------------------------------------
# RS-025 — Runtime guard (ADR-018)
# ---------------------------------------------------------------------------


def test_rs025_runtime_guard_detect_canonical() -> None:
    """RS-025: detect_runtime retorna label canonico (sem auto-detect agressivo)."""
    from repo_sanitizer.helpers._runtime_guard import detect_runtime, runtime_marker

    runtime = detect_runtime()
    # ADR-018: sem auto-detect agressivo; resultado deve ser string nao-vazia
    assert isinstance(runtime, str)
    assert len(runtime) > 0

    marker = runtime_marker()
    assert isinstance(marker, str)
    assert len(marker) > 0


# ---------------------------------------------------------------------------
# RS-027 — Metadata canonica em report (ADR-016)
# ---------------------------------------------------------------------------


def test_rs027_metadata_canonica_audit_entry() -> None:
    """RS-027: RepoSanitizerAuditEntry exige run_id + agent_version + timestamp + secret_patterns_hash."""
    import datetime as _dt

    from repo_sanitizer.schemas.audit_entry import RepoSanitizerAuditEntry

    fake_hash = "a" * 64
    entry = RepoSanitizerAuditEntry(
        run_id="00000000-0000-0000-0000-000000000000",
        timestamp=_dt.datetime.now(_dt.UTC),
        agent_version="1.0.0",
        sentinel_sanitize_version="1.2.0",
        secret_patterns_hash=fake_hash,
        action="f3_sanitize_done",
        slug="test",
        source_path_redacted="/x",
        dest_path_redacted="/y",
        detail={"files_processed": 10},
    )
    dump = entry.model_dump()
    # Metadata canonica RS-027 (ADR-016)
    for required in (
        "run_id", "agent_version", "sentinel_sanitize_version",
        "secret_patterns_hash", "timestamp", "action", "slug",
    ):
        assert required in dump, f"RS-027: campo canonico {required!r} ausente em audit dump"


# ---------------------------------------------------------------------------
# RS-028 — LGPD aviso em SANITIZATION_REPORT (categoria C5)
# ---------------------------------------------------------------------------


def test_rs028_lgpd_aviso_template_in_report_writer() -> None:
    """RS-028: report writer module contem string LGPD canonica."""
    import repo_sanitizer.reports.sanitization_report_writer as srw
    src = Path(srw.__file__).read_text(encoding="utf-8")
    assert "LGPD" in src, "RS-028: report writer deve mencionar LGPD"


# ---------------------------------------------------------------------------
# RS-029 — Grupo C spoofing detect via F3 (ADR-005)
# ---------------------------------------------------------------------------


def test_rs029_group_c_spoofed_secret_caught_by_f3() -> None:
    """RS-029: arquivo aparentemente canonico (.gitignore) com secret e flagado por F3 C2."""
    from repo_sanitizer.f3_sanitizer import sanitize_text_content

    # Arquivo de aparencia inocente com chave GitHub embutida
    text = "# .gitignore\nGITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890abcd\n"
    tsr = sanitize_text_content(text, "utf-8")
    assert len(tsr.matches) >= 1, (
        "RS-029: Grupo C spoofado deve ser detectado pela camada F3 (defesa em pipeline)"
    )


# ---------------------------------------------------------------------------
# RS-030 — SECURITY contact canonico (ADR-010)
# ---------------------------------------------------------------------------


def test_rs030_security_contact_canonical_email() -> None:
    """RS-030 (P1-a/GAP-S07-03): SECURITY usa placeholder, nunca PII real do operador."""
    from importlib import resources

    content = resources.files("repo_sanitizer.templates").joinpath(
        "security_pt_br.md",
    ).read_text(encoding="utf-8")
    assert "<EMAIL-DO-MANTENEDOR>" in content, (
        "RS-030: SECURITY template DEVE usar placeholder <EMAIL-DO-MANTENEDOR>"
    )
    assert "tecnologia@acme.io" not in content, (
        "P1-a: SECURITY template NAO pode conter email real do operador (PII leak)"
    )
