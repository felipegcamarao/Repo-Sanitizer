"""test_sanitization_report_writer.py — Bloco 03 Passo 03.10 + 03.12 + 03.13.

Cobre:
- build_sanitization_report_md (header YAML + categorias + LGPD + rotacao + gitleaks).
- AT-14 BLOCK: leaked-report fixture (valor literal escapa) -> raise.
- compute_delta vs run anterior.
- write_sanitization_report via FsWriter.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f3_sanitizer import F3ContentMatch, F3Result
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.reports.sanitization_report_writer import (
    GITLEAKS_OPERATIONAL_PT_BR,
    LGPD_WARNING_PT_BR,
    ROTATION_CHECKLIST_PT_BR,
    build_sanitization_report_md,
    compute_delta,
    find_latest_report,
    parse_report_entries_signature,
    sanitization_report_filename,
    write_sanitization_report,
)
from repo_sanitizer.schemas._secrets_gate import SecretLeakInArtifactError


def _make_result(matches: list[F3ContentMatch], **kw) -> F3Result:
    r = F3Result(matches=matches)
    r.files_processed = kw.get("files_processed", len(matches))
    r.files_written = kw.get("files_written", len(matches))
    r.rescan_destination_zero = kw.get("rescan_destination_zero", True)
    r.integrity_ok = kw.get("integrity_ok", True)
    r.snapshot_pre = kw.get("snapshot_pre", {"aggregate": "a" * 64, "file_count": len(matches)})
    r.snapshot_pos = kw.get("snapshot_pos", r.snapshot_pre)
    r.secrets_by_category = kw.get("secrets_by_category", {"C5": 1} if matches else {})
    return r


# ===========================================================================
# build_sanitization_report_md — estrutura canonica
# ===========================================================================

def test_build_md_contains_yaml_header() -> None:
    result = _make_result([])
    md = build_sanitization_report_md(
        result, slug="demo", run_id="11111111-1111-1111-1111-111111111111",
        source_path_redacted="C:/VS Code/[REDACTED]/demo",
        dest_path_redacted="C:/VS Code/Git Hub - [NOME]/GIT_demo",
        sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64,
    )
    assert md.startswith("---\n")
    assert 'schema_version: "1.0.0"' in md
    assert 'agent: "repo-sanitizer-agent"' in md
    assert "secret_patterns_hash:" in md
    assert "sentinel_sanitize_version:" in md


def test_build_md_contains_10_categories() -> None:
    result = _make_result([])
    md = build_sanitization_report_md(
        result, slug="demo", run_id="11111111-1111-1111-1111-111111111111",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    for cat in ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"]:
        assert f"## Categoria {cat} " in md, f"Faltou {cat} no report"


def test_build_md_includes_lgpd_when_c5_present() -> None:
    matches = [F3ContentMatch(
        rel_path="data/clientes.csv", line=5,
        categoria="C5", tipo="CPF_FORMATADO",
        acao="redact_inline", encoding_detected="utf-8",
    )]
    result = _make_result(matches)
    md = build_sanitization_report_md(
        result, slug="demo", run_id="22222222-2222-2222-2222-222222222222",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    # Verifica que aviso LGPD aparece com keywords canonicas (Art. 48)
    assert "LGPD" in md
    assert "Art. 48" in md


def test_build_md_includes_rotation_checklist() -> None:
    result = _make_result([])
    md = build_sanitization_report_md(
        result, slug="demo", run_id="33333333-3333-3333-3333-333333333333",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    # Checklist rotacao canonico
    assert "Checklist de Rotacao" in md
    assert "C2 (API keys)" in md


def test_build_md_includes_gitleaks_camada_c7_footer() -> None:
    result = _make_result([])
    md = build_sanitization_report_md(
        result, slug="my-project", run_id="44444444-4444-4444-4444-444444444444",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    assert "gitleaks" in md.lower()
    assert "my-project" in md  # slug interpolado no comando


def test_build_md_includes_inv1_snapshot_prefixes() -> None:
    pre = "abc123" + "0" * 58
    pos = "abc123" + "0" * 58
    result = _make_result([],
        snapshot_pre={"aggregate": pre, "file_count": 5},
        snapshot_pos={"aggregate": pos, "file_count": 5},
    )
    md = build_sanitization_report_md(
        result, slug="demo", run_id="55555555-5555-5555-5555-555555555555",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    assert "abc123" in md


# ===========================================================================
# AT-14 BLOCK — leaked-report fixture (valor literal escapa) -> raise
# ===========================================================================

def test_at14_blocks_literal_secret_in_report() -> None:
    """AT-14: se um match tem valor literal por algum motivo, o gate Pydantic
    SanitizationReportEntry.validate_artifact deve raise antes do write.

    Aqui simulamos diretamente: criamos um F3ContentMatch com `tipo` contendo
    valor literal AKIA. O `build_sanitization_report_md` chama
    `assert_no_literal_secrets(md)` ao final que detecta e raise.
    """
    leaked_matches = [F3ContentMatch(
        rel_path="config.py",
        line=10,
        categoria="C2",
        tipo="LITERAL_LEAK_AKIAIOSFODNN7EXAMPLE",  # erro proposital: literal em tipo
        acao="redact_inline",
        encoding_detected="utf-8",
    )]
    result = _make_result(leaked_matches)
    with pytest.raises(SecretLeakInArtifactError):
        build_sanitization_report_md(
            result, slug="demo", run_id="66666666-6666-6666-6666-666666666666",
            source_path_redacted="src", dest_path_redacted="dst",
            sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        )


# ===========================================================================
# compute_delta — F3.D-08 (passo 03.12)
# ===========================================================================

def test_compute_delta_no_prior_report_all_new(tmp_path: Path) -> None:
    matches = [F3ContentMatch(
        rel_path="a.py", line=1, categoria="C2", tipo="API_KEY_github_ghp",
        acao="redact_inline", encoding_detected="utf-8",
    )]
    no_file = tmp_path / "nonexistent.md"
    delta = compute_delta(no_file, matches)
    assert delta["new"] == 1
    assert delta["carryover"] == 0
    assert delta["resolved"] == 0


def test_compute_delta_resolved_and_carryover(tmp_path: Path) -> None:
    """Cria report anterior com (a.py, C2) e (b.py, C5). Atual: apenas (a.py, C2)
    + (c.py, C9). Esperado: resolved=1 (b.py C5), carryover=1 (a.py C2), new=1 (c.py C9)."""
    prev_md = (
        "# old\n\n"
        "| path | linha | tipo | acao | encoding |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| a.py | 1 | API_KEY_github_ghp | redact_inline | utf-8 |\n"
        "| b.py | 2 | CPF_FORMATADO | redact_inline | utf-8 |\n"
    )
    prev_file = tmp_path / "SANITIZATION_REPORT_demo_old.md"
    prev_file.write_text(prev_md, encoding="utf-8")

    curr_matches = [
        F3ContentMatch(
            rel_path="a.py", line=1, categoria="C2", tipo="API_KEY_github_ghp",
            acao="redact_inline", encoding_detected="utf-8",
        ),
        F3ContentMatch(
            rel_path="c.py", line=3, categoria="C9", tipo="INTERNAL_HOSTNAME",
            acao="redact_inline", encoding_detected="utf-8",
        ),
    ]
    delta = compute_delta(prev_file, curr_matches)
    assert delta["resolved"] == 1
    assert delta["carryover"] == 1
    assert delta["new"] == 1


def test_parse_report_entries_signature_extracts_path_tipo() -> None:
    md = (
        "## Categoria C2\n"
        "| path | linha | tipo | acao | encoding |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| src/config.py | 5 | API_KEY_github_ghp | redact_inline | utf-8 |\n"
    )
    sigs = parse_report_entries_signature(md)
    assert "src/config.py::API_KEY_github_ghp" in sigs


# ===========================================================================
# write_sanitization_report — gravacao via FsWriter
# ===========================================================================

def test_write_sanitization_report_creates_file(tmp_path: Path) -> None:
    src = tmp_path / "src_fake"
    src.mkdir()
    (src / "README.md").write_text("# fake\n", encoding="utf-8")

    dest = tmp_path / "dest_fake"
    dest.mkdir()
    relatorios = tmp_path / "Relatorios"
    relatorios.mkdir()

    fw = FsWriter(
        source_path=src,
        allowed_roots=[tmp_path],
        override_forbidden=[src],
    )
    result = _make_result([])
    written = write_sanitization_report(
        result, slug="demo", run_id="77777777-7777-7777-7777-777777777777",
        fs_writer=fw, relatorios_dir=relatorios,
        source_path_redacted=str(src), dest_path_redacted=str(dest),
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    assert written.exists()
    md = written.read_text(encoding="utf-8")
    assert "SANITIZATION_REPORT" in md
    assert "## Categoria C1 " in md


def test_find_latest_report_returns_most_recent(tmp_path: Path) -> None:
    relatorios = tmp_path / "Relatorios"
    relatorios.mkdir()
    # Cria 2 reports com timestamps diferentes (em sequencia)
    p1 = relatorios / "SANITIZATION_REPORT_demo_20260512T000000Z.md"
    p1.write_text("old\n", encoding="utf-8")
    p2 = relatorios / "SANITIZATION_REPORT_demo_20260512T010000Z.md"
    p2.write_text("new\n", encoding="utf-8")
    # Garante mtime diferentes
    import os
    os.utime(p1, (0, 1_700_000_000))
    os.utime(p2, (0, 1_800_000_000))
    latest = find_latest_report(relatorios, "demo")
    assert latest == p2


# ===========================================================================
# Filename canonico
# ===========================================================================

def test_sanitization_report_filename_pattern() -> None:
    name = sanitization_report_filename("my-slug", run_id_prefix="abcdef12")
    assert name.startswith("SANITIZATION_REPORT_my-slug_")
    assert name.endswith("_abcdef12.md")


# ===========================================================================
# Constantes canonicas
# ===========================================================================

def test_lgpd_warning_contains_canonical_terms() -> None:
    assert "LGPD" in LGPD_WARNING_PT_BR
    assert "Art. 48" in LGPD_WARNING_PT_BR


def test_rotation_checklist_covers_all_10_categories() -> None:
    for cat in ["C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"]:
        assert f"**{cat}" in ROTATION_CHECKLIST_PT_BR, f"Falta {cat} no checklist"


def test_gitleaks_pt_br_contains_keywords() -> None:
    assert "gitleaks" in GITLEAKS_OPERATIONAL_PT_BR


# ===========================================================================
# Camada C9 PII Detector (ADR-029 v1.1.0 — Passo 1.4)
# ===========================================================================


def test_build_md_c9_pii_yaml_header_always_present() -> None:
    """Bloco `pii_by_category:` aparece no YAML mesmo quando vazio (boilerplate visível)."""
    result = _make_result([])  # sem matches → pii_by_category vazio
    md = build_sanitization_report_md(
        result, slug="demo", run_id="11111111-1111-1111-1111-111111111111",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )
    assert "pii_by_category:" in md
    # Todas as 4 categorias canônicas presentes mesmo vazias
    assert "  name: 0" in md
    assert "  username: 0" in md
    assert "  domain: 0" in md
    assert "  custom: 0" in md
    # Seção body
    assert "## Camada C9 — PII Detector (Operator Identity)" in md
    assert "Total de matches PII: **0**" in md


def test_build_md_c9_pii_section_with_matches() -> None:
    """Quando há PIIMatch em F3Result.pii_matches, a tabela canônica aparece."""
    from repo_sanitizer.helpers._pii_match import PIIMatch

    result = _make_result([])
    result.pii_matches = [
        PIIMatch(
            category="name", file_path="README.md", line_no=3, count=2,
            excerpt_redacted="Autor: [REDACTED-NAME] escreveu",
        ),
        PIIMatch(
            category="username", file_path="config.py", line_no=10, count=1,
            excerpt_redacted='USERNAME = "[REDACTED-USER]"',
        ),
    ]
    result.pii_by_category = {"name": 2, "username": 1}

    md = build_sanitization_report_md(
        result, slug="demo", run_id="22222222-2222-2222-2222-222222222222",
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
    )

    # YAML reflete os counts
    assert "  name: 2" in md
    assert "  username: 1" in md
    # Body com tabela
    assert "## Camada C9 — PII Detector (Operator Identity)" in md
    assert "Total de matches PII: **3**" in md
    assert "Arquivos afetados: **2**" in md
    # Tabela header
    assert "| Categoria | Count | Sample (50 chars) | Tipos de arquivo |" in md
    # Linhas
    assert "| name | 2 |" in md
    assert "| username | 1 |" in md
    # Samples preservados (com placeholders, sem literal)
    assert "[REDACTED-NAME]" in md
    assert "[REDACTED-USER]" in md


# ===========================================================================
# Bloco 04 — Gate G2 Replica Funcional (ADR-032 + ADR-033)
# ===========================================================================


class _G2ResultStub:
    """Stub mínimo com attrs canônicos de f4_readme.G2Result (evita import circular)."""

    def __init__(
        self,
        *,
        check_a_boilerplate=True,
        check_b_license=True,
        check_c_paths_zero=True,
        check_d_pii_zero=True,
        outcome="done",
        auto_generated_files=None,
        blocking_failures=None,
        language_detected="python",
        paths_found=None,
        pii_found=None,
    ):
        self.check_a_boilerplate = check_a_boilerplate
        self.check_b_license = check_b_license
        self.check_c_paths_zero = check_c_paths_zero
        self.check_d_pii_zero = check_d_pii_zero
        self.outcome = outcome
        self.auto_generated_files = auto_generated_files or []
        self.blocking_failures = blocking_failures or []
        self.language_detected = language_detected
        self.paths_found = paths_found or []
        self.pii_found = pii_found or []


def test_build_g2_section_outcome_done() -> None:
    from repo_sanitizer.reports.sanitization_report_writer import build_g2_report_section

    g2 = _G2ResultStub(outcome="done")
    md = build_g2_report_section(g2)
    assert "## Gate G2 — Replica Funcional Verified" in md
    assert "**Outcome:** `done`" in md
    assert "| (a) |" in md and "**OK**" in md
    assert "| (b) |" in md
    assert "| (c) |" in md
    assert "| (d) |" in md
    # Sem auto-gen → sem subsecao
    assert "### Arquivos auto-gerados" not in md
    assert "### Falhas Bloqueantes" not in md


def test_build_g2_section_outcome_done_with_warnings() -> None:
    from pathlib import Path

    from repo_sanitizer.reports.sanitization_report_writer import build_g2_report_section

    g2 = _G2ResultStub(
        outcome="done_with_warnings",
        auto_generated_files=[Path("/tmp/dest/pyproject.toml"), Path("/tmp/dest/LICENSE")],
    )
    md = build_g2_report_section(g2)
    assert "**Outcome:** `done_with_warnings`" in md
    assert "### Arquivos auto-gerados (ADR-033)" in md
    assert "`pyproject.toml`" in md
    assert "`LICENSE`" in md


def test_build_g2_section_outcome_done_with_failure() -> None:
    from repo_sanitizer.reports.sanitization_report_writer import build_g2_report_section

    g2 = _G2ResultStub(
        outcome="done_with_failure",
        check_c_paths_zero=False,
        check_d_pii_zero=False,
        blocking_failures=[
            "Paths absolutos detectados no destino: 3 amostra(s).",
            "PII operador detectado no destino: 2 amostra(s).",
        ],
        paths_found=["src/x.py:5:C:/Users/[NOME]"],
        pii_found=["src/y.py:9:[NOME]"],
    )
    md = build_g2_report_section(g2)
    assert "**Outcome:** `done_with_failure`" in md
    assert "### Falhas Bloqueantes (exit code 7)" in md
    assert "Paths absolutos detectados" in md
    assert "**Amostras de paths absolutos detectados:**" in md
    assert "**Amostras de PII operador detectado:**" in md
    assert "`src/x.py:5:C:/Users/[NOME]`" in md


def test_append_g2_section_to_report_idempotent(tmp_path: Path) -> None:
    """Re-aplicar append substitui a seção G2 anterior (idempotência)."""
    from repo_sanitizer.reports.sanitization_report_writer import append_g2_section_to_report

    src = tmp_path / "src_fake"
    src.mkdir()
    (src / "README.md").write_text("# fake\n", encoding="utf-8")
    fw = FsWriter(source_path=src, allowed_roots=[tmp_path], override_forbidden=[src])

    rpt = tmp_path / "SANITIZATION_REPORT_demo_20260526T000000Z.md"
    rpt.write_text("# DEMO REPORT\n\nfoo body\n", encoding="utf-8")

    g2_a = _G2ResultStub(outcome="done_with_warnings")
    append_g2_section_to_report(rpt, g2_a, fw)
    content_after_a = rpt.read_text(encoding="utf-8")
    assert content_after_a.count("## Gate G2 — Replica Funcional Verified") == 1
    assert "done_with_warnings" in content_after_a

    g2_b = _G2ResultStub(
        outcome="done_with_failure",
        check_c_paths_zero=False,
        blocking_failures=["Paths absolutos detectados no destino: 1 amostra(s)."],
    )
    append_g2_section_to_report(rpt, g2_b, fw)
    content_after_b = rpt.read_text(encoding="utf-8")
    # Header ainda aparece UMA vez (substituido)
    assert content_after_b.count("## Gate G2 — Replica Funcional Verified") == 1
    # Outcome novo presente; antigo removido
    assert "done_with_failure" in content_after_b
    assert "done_with_warnings" not in content_after_b
    # Body original preservado
    assert "foo body" in content_after_b
