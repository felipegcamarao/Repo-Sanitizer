"""test_publication_checklist.py — Bloco D / Passo D2 (MV-08 / RS-NEW-043 + 047).

Cobre o Checklist de Publicacao AUDITAVEL:
  - >=8 checks com estado PASS/FAIL/SKIPPED.
  - destino limpo -> todos PASS (exceto SKIPPED legitimo).
  - destino com segredo residual injetado -> check correspondente = FAIL.
  - `--entropy off` -> check de entropia = SKIPPED.
  - g2_outcome None -> item 10 = SKIPPED(aguardando finalize); done -> PASS.
  - zero-literal: nenhum valor sensivel no texto do checklist (RS-NEW-047).
  - integra na secao do SANITIZATION_REPORT.md (assert_no_literal_secrets passa).
"""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from repo_sanitizer.f3_sanitizer import F3Result
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.reports.sanitization_report_writer import (
    append_g2_section_to_report,
    build_publication_checklist,
    build_sanitization_report_md,
    write_sanitization_report,
)


def _clean_result(**kw: object) -> F3Result:
    r = F3Result()
    r.rescan_destination_zero = True
    r.entropy_enabled = True
    r.entropy_count = 2
    r.pii_by_category = {"name": 1}
    r.path_by_category = {"user_path": 3}
    r.author_by_field = {"author": 1}
    r.binary_excluded_by_tier = {"data": 1, "credential": 1}
    for k, v in kw.items():
        setattr(r, k, v)
    return r


# ===========================================================================
# build_publication_checklist — estrutura + estados
# ===========================================================================

def test_checklist_has_at_least_8_checks() -> None:
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        g2_outcome="done",
    )
    assert len(checks) >= 8
    # cada check e (id, descricao, estado)
    for cid, desc, state in checks:
        assert cid and desc and state


def test_clean_dest_all_pass() -> None:
    """Destino limpo + G2 done -> todos PASS (nenhum FAIL/SKIPPED)."""
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        entropy_enabled=True, g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert all(s == "PASS" for s in states.values()), states


def test_residual_secret_makes_check3_fail() -> None:
    """Segredo residual no destino (re-scan FAIL) -> check '0 segredos' = FAIL."""
    r = _clean_result(rescan_destination_zero=False)
    checks = build_publication_checklist(
        r, git_history_clean=True, gitignore_emitted=True, g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["3"] == "FAIL"


# ===========================================================================
# P1-b (GAP-S07-01) — INDEPENDENCIA por categoria.
# Um FP de UMA categoria -> SO o check daquela categoria vira FAIL; os demais
# permanecem PASS (sem cascata espuria a partir de `secrets_zero`).
# ===========================================================================

def _states(**kw: object) -> dict[str, str]:
    checks = build_publication_checklist(
        _clean_result(**kw), git_history_clean=True, gitignore_emitted=True,
        entropy_enabled=True, g2_outcome="done",
    )
    return {cid: state for cid, _, state in checks}


def test_independence_c6_fp_only_fails_check3() -> None:
    """1 FP de C6 (config) NAO derruba caches/PII/autoria/paths/binarios/entropia.

    Reproduz o cenario do GAP-S07-01: `.env.example` de chaves vazias dispara C6.
    ANTES: itens 2/4/5/6/7/9 viravam FAIL por herdar `secrets_zero`. AGORA: so o
    item 3 (segredos) FAIL; o resto PASS.
    """
    states = _states(
        rescan_destination_zero=False,
        rescan_residual_by_category={"C6": 1},
    )
    assert states["3"] == "FAIL"           # categoria propria do FP
    # itens independentes permanecem PASS
    for cid in ("2", "4", "5", "6", "7"):
        assert states[cid] == "PASS", (cid, states)
    assert states["9"] == "PASS", states   # entropia executada


def test_independence_c5_pii_residual_only_fails_check4() -> None:
    """Residual REAL de PII (C5) -> SO o item 4 (PII operador) FAIL; item 3 PASS."""
    states = _states(
        rescan_destination_zero=False,
        rescan_residual_by_category={"C5": 2},
    )
    assert states["4"] == "FAIL"           # PII operador residual
    assert states["3"] == "PASS"           # nenhuma categoria de segredo vazou
    for cid in ("2", "5", "6", "7", "9"):
        assert states[cid] == "PASS", (cid, states)


def test_independence_c2_secret_residual_fails_check3_not_check4() -> None:
    """Residual de segredo real (C2 API key) -> item 3 FAIL, item 4 (PII) PASS."""
    states = _states(
        rescan_destination_zero=False,
        rescan_residual_by_category={"C2": 1},
    )
    assert states["3"] == "FAIL"
    assert states["4"] == "PASS"
    for cid in ("2", "5", "6", "7", "9"):
        assert states[cid] == "PASS", (cid, states)


def test_cache_residual_only_fails_check2() -> None:
    """Cache residual (cache_rescan_clean=False) -> SO item 2 FAIL; resto PASS."""
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        entropy_enabled=True, g2_outcome="done", cache_rescan_clean=False,
    )
    states = {cid: state for cid, _, state in checks}
    assert states["2"] == "FAIL"
    for cid in ("3", "4", "5", "6", "7", "9"):
        assert states[cid] == "PASS", (cid, states)


def test_git_history_residual_makes_check1_fail() -> None:
    """Historico Git no destino -> check 1 = FAIL."""
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=False, gitignore_emitted=True,
        g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["1"] == "FAIL"


def test_missing_gitignore_makes_check8_fail() -> None:
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=False,
        g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["8"] == "FAIL"


def test_entropy_off_makes_check9_skipped() -> None:
    """`--entropy off` -> check de entropia = SKIPPED (nunca PASS — MV08-C)."""
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        entropy_enabled=False, g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["9"].startswith("SKIPPED")
    assert "entropy off" in states["9"]


def test_entropy_off_derived_from_result_flag() -> None:
    """entropy_enabled=None deriva de F3Result.entropy_enabled."""
    r = _clean_result(entropy_enabled=False)
    checks = build_publication_checklist(
        r, git_history_clean=True, gitignore_emitted=True, g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["9"].startswith("SKIPPED")


def test_g2_none_makes_check10_skipped() -> None:
    """g2_outcome None (run_apply) -> item 10 = SKIPPED(aguardando finalize)."""
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        g2_outcome=None,
    )
    states = {cid: state for cid, _, state in checks}
    assert states["10"].startswith("SKIPPED")


def test_g2_done_makes_check10_pass() -> None:
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["10"] == "PASS"


def test_g2_failure_makes_check10_fail() -> None:
    checks = build_publication_checklist(
        _clean_result(), git_history_clean=True, gitignore_emitted=True,
        g2_outcome="done_with_failure",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["10"] == "FAIL"


def test_git_history_derived_from_result_when_none() -> None:
    """git_history_clean=None deriva de F3Result.git_history_artifacts."""
    from repo_sanitizer.helpers._git_history_scan import GitArtifact
    r = _clean_result(git_history_artifacts=[GitArtifact(rel_path=".git/", kind="git_dir")])
    checks = build_publication_checklist(
        r, git_history_clean=None, gitignore_emitted=True, g2_outcome="done",
    )
    states = {cid: state for cid, _, state in checks}
    assert states["1"] == "FAIL"


# ===========================================================================
# Zero-literal (RS-NEW-047 / MV08-B)
# ===========================================================================

def test_checklist_zero_literal_no_secret_value() -> None:
    """Checklist so tem contagens/categorias/estados — nunca um valor sensivel."""
    r = _clean_result()
    checks = build_publication_checklist(
        r, git_history_clean=True, gitignore_emitted=True, g2_outcome="done",
    )
    blob = " ".join(f"{cid} {desc} {st}" for cid, desc, st in checks)
    # heuristica: nenhum prefixo de segredo conhecido no texto
    for forbidden in ("ghp_", "sk-proj-", "AKIA", "xoxb-", "-----BEGIN"):
        assert forbidden not in blob


# ===========================================================================
# Integracao no report markdown
# ===========================================================================

def test_report_md_has_checklist_section() -> None:
    md = build_sanitization_report_md(
        _clean_result(), slug="demo", run_id="1" * 36,
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        git_history_clean=True, gitignore_emitted=True, g2_outcome=None,
    )
    assert "Checklist de Publicacao" in md
    assert "| 10 |" in md
    assert "SKIPPED(aguardando finalize)" in md


def test_report_md_checklist_zero_literal_gate_passes() -> None:
    """build_sanitization_report_md aplica assert_no_literal_secrets sem raise."""
    # se o checklist vazasse literal, build levantaria SecretLeakInArtifactError
    md = build_sanitization_report_md(
        _clean_result(rescan_destination_zero=False), slug="demo",
        run_id="1" * 36, source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        git_history_clean=False, gitignore_emitted=False, entropy_enabled=False,
        g2_outcome=None,
    )
    assert "FAIL" in md  # checagens FAIL refletidas


def _make_fw(tmp_path: Path) -> FsWriter:
    source_path = tmp_path / "fake_src"
    source_path.mkdir()
    return FsWriter(
        source_path=source_path,
        allowed_roots=[tmp_path],
        override_forbidden=[source_path],
    )


def test_write_report_then_g2_refreshes_item10(tmp_path: Path) -> None:
    """Pipeline D2: F3 report item10=SKIPPED -> finalize refresca p/ PASS."""
    rel = tmp_path / "Relatorios"
    rel.mkdir()
    fw = _make_fw(tmp_path)
    written = write_sanitization_report(
        _clean_result(), slug="demo", run_id="abcd1234" + "0" * 28,
        fs_writer=fw, relatorios_dir=rel,
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        git_history_clean=True, gitignore_emitted=True, g2_outcome=None,
    )
    md_pre = written.read_text(encoding="utf-8")
    assert "SKIPPED(aguardando finalize)" in md_pre

    # G2 done -> append + refresh item 10
    class _G2:
        outcome = "done"
        language_detected = "python"
        check_a_boilerplate = True
        check_b_license = True
        check_c_paths_zero = True
        check_d_pii_zero = True
        auto_generated_files: ClassVar[list[Path]] = []
        blocking_failures: ClassVar[list[str]] = []
        paths_found: ClassVar[list[str]] = []
        pii_found: ClassVar[list[str]] = []

    append_g2_section_to_report(written, _G2(), fw)
    md_pos = written.read_text(encoding="utf-8")
    assert "SKIPPED(aguardando finalize)" not in md_pos
    # item 10 agora PASS com outcome real
    line10 = [ln for ln in md_pos.splitlines() if ln.startswith("| 10 |")]
    assert line10 and "PASS" in line10[0]
    assert "outcome=done" in line10[0]


# ===========================================================================
# Flag EXIF — imagens/midia mantidas sem inspecao de metadados (MV-06 / G-04)
# ===========================================================================

def test_exif_flag_rendered_when_uninspected_present() -> None:
    """G-04: com exif_uninspected>0 o report mostra contagem + aviso + nomes."""
    r = _clean_result(exif_uninspected=["docs/foto.png", "assets/logo.jpg"])
    md = build_sanitization_report_md(
        r, slug="demo", run_id="1" * 36,
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        git_history_clean=True, gitignore_emitted=True, g2_outcome=None,
    )
    assert "## Flag EXIF" in md
    # contagem real (2 imagens)
    assert "mantidas sem inspecao de metadados: **2**" in md
    # aviso PT-BR exato
    assert (
        "2 arquivo(s) de imagem/midia mantidos SEM inspecao de metadados "
        "(EXIF/autor/GPS). Revise antes de publicar." in md
    )
    # nomes dos arquivos-imagem afetados aparecem (paths de midia sao ok)
    assert "docs/foto.png" in md
    assert "assets/logo.jpg" in md


def test_exif_flag_clean_does_not_pollute_report() -> None:
    """G-04: com 0 imagens nao-inspecionadas, sem aviso/lista (mostra '0 / nenhum')."""
    md = build_sanitization_report_md(
        _clean_result(), slug="demo", run_id="1" * 36,
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        git_history_clean=True, gitignore_emitted=True, g2_outcome=None,
    )
    # secao presente (boilerplate visivel) mas SEM aviso/lista
    assert "## Flag EXIF" in md
    assert "**0** (nenhum)" in md
    assert "Revise antes de publicar" not in md
    # a lista EXIF-especifica de arquivos afetados nao aparece quando vazio
    assert "Arquivos afetados (paths relativos" not in md


def test_exif_flag_redacts_pii_in_image_names() -> None:
    """Zero-literal: PII embutida em nome de arquivo de midia e redatada."""
    r = _clean_result(exif_uninspected=["fotos/Joao-Silva.jpg"])
    md = build_sanitization_report_md(
        r, slug="demo", run_id="1" * 36,
        source_path_redacted="src", dest_path_redacted="dst",
        sentinel_sanitize_version="v1.2.0", secret_patterns_hash="a" * 64,
        git_history_clean=True, gitignore_emitted=True, g2_outcome=None,
    )
    assert "Flag EXIF" in md
    # nome proprio redatado pelo redact_path (heuristica Nome-Sobrenome)
    assert "Joao-Silva" not in md
    assert "[REDACTED-PII]" in md
    # ainda mostra contagem + aviso
    assert "mantidas sem inspecao de metadados: **1**" in md
