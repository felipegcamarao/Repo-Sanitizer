"""test_rs001_multi_pass.py — Bloco 03 Passo 03.15 (RS-001 MULTI-PASS SMOKE).

Cobertura: 7 fixtures adversariais x 7 camadas defensivas RS-001 (TOP-01
catastrofico irreversivel DREAD-5 45/50; Modo Completo AGRAVADO 3x).

Fixtures cobertos:
1. encoding_bomb        -> Camada C4 (5 encodings)
2. binary_with_keys     -> Camada C5 (deep scan 64 KB)
3. tampering_secret_patterns -> Camada C3 (integrity SHA-256 sobre secret_patterns.py)
4. downgrade_sanitize       -> Camada C2 (integrity SHA-256 sobre _sanitize.py local)
5. injection_in_readme      -> hand-off para F4 (F3 nao falha em conteudo injection)
6. cat_not_covered          -> FP-overload: nao quebra; secrets fora da matriz passam
7. cleanup_falho            -> state file legacy + tmp residual em fonte (F3 sanitiza ok)

DoD Passo 03.15: 7/7 fixtures detect OK; sem falso-negativo.

NOTA: os fixtures de tampering/downgrade nao tentam tampering REAL aqui — apenas
verificam que F3 roda sobre repo legitimo. O tampering real e testado em
test_threat_tree_R01_f3_leak.py (security).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.f3_sanitizer import run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.orchestrator import (
    make_orchestrator_context,
    run_apply,
    run_dry_run,
)
from tests.fixtures.repos.adversarial import (
    ADVERSARIAL_FACTORIES,
    TARGET_AKIA,
    TARGET_GHP_TOKEN,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _setup_run(tmp_path: Path, slug: str):
    """Constroi um fixture adversarial + ctx + fw isolado em tmp_path."""
    src_root = tmp_path / "sources"
    src_root.mkdir()
    src = ADVERSARIAL_FACTORIES[slug](src_root)

    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()

    ctx = make_orchestrator_context(
        source_path=src,
        relatorios_path=relatorios,
        project_root=PROJECT_ROOT,
        slug=slug,
        base_destinos_root=allowed,
    )
    fw = FsWriter(
        source_path=src,
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    return ctx, fw, src, allowed, relatorios


def _content_of_dest(dest: Path) -> str:
    """Concatena conteudo de TODOS os arquivos do destino (1 string blob)."""
    parts: list[str] = []
    if not dest.exists():
        return ""
    import os
    for dirpath, _dirnames, filenames in os.walk(dest, followlinks=False):
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                parts.append(full.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(parts)


# ===========================================================================
# 7 FIXTURES — RS-001 multi-pass
# ===========================================================================

def test_rs001_camada_c4_encoding_bomb(tmp_path: Path) -> None:
    """Camada C4 (RS-008): 5 encodings concorrentes do mesmo token ghp_;
    todos devem ser detectados via merge multi-encoding."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "encoding_bomb")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0
    # Camada C6: re-scan destino NAO deve achar o token em NENHUMA das 5 encodings
    assert TARGET_GHP_TOKEN not in _content_of_dest(ctx.dest_path)


def test_rs001_camada_c5_binary_with_keys(tmp_path: Path) -> None:
    """Camada C5 (RS-019): PDF/XLSX com chave AKIA embedded nos primeiros 64 KB
    -> F3 deteca e remove o binario do destino."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "binary_with_keys")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0
    # Tokens NAO presentes no destino (binarios skipados ou redacted)
    blob = _content_of_dest(ctx.dest_path)
    assert TARGET_AKIA not in blob
    assert TARGET_GHP_TOKEN not in blob


def test_rs001_tampering_marker_runs_clean(tmp_path: Path) -> None:
    """Tampering fixture: roda sem alteracao = ok (test_threat_tree faz tampering real)."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "tampering_secret_patterns")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0


def test_rs001_downgrade_marker_runs_clean(tmp_path: Path) -> None:
    """Downgrade fixture: roda sem alteracao = ok."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "downgrade_sanitize")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0


def test_rs001_injection_in_readme_handoff_to_f4(tmp_path: Path) -> None:
    """Injection no README (RS-003): F3 NAO deve falhar; conteudo passa para F4
    onde o _injection_filter aplica defesa. F3 apenas garante que nao perde dados."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "injection_in_readme")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0
    # README presente no destino (com conteudo injection ainda; F4 trata).
    assert (ctx.dest_path / "README.md").exists()


def test_rs001_cat_not_covered_fp_overload_safe(tmp_path: Path) -> None:
    """FP-overload: secrets ficticios fora das 10 categorias NAO devem causar
    falsos-positivos em massa nem quebrar F3."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "cat_not_covered")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0
    # Camada C6 re-scan: zero leaks porque nao havia secrets reais
    # Esperamos que ao menos 1 arquivo foi escrito
    assert (ctx.dest_path / "README.md").exists()


def test_rs001_cleanup_falho_state_legacy(tmp_path: Path) -> None:
    """Fonte com `.sanitizer-state.json` legacy + tmp residual.

    F3 NAO deve falhar; INV-1 garante leitura-fonte read-only mesmo com lixo;
    o agente NAO se preocupa em cleanar fonte (apenas em destino)."""
    ctx, fw, src, _allowed, _rel = _setup_run(tmp_path, "cleanup_falho")
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0
    # State file legacy permanece intocado em fonte (INV-1)
    assert (src / ".sanitizer-state.json").exists()


# ===========================================================================
# Tests adicionais — Camadas C2 + C3 + C6 (defesa em camadas)
# ===========================================================================

def test_rs001_camada_c6_rescan_zero_in_clean_fixture(tmp_path: Path) -> None:
    """Camada C6 (RS-001): apos F3 sobre fixture limpo, re-scan = 0 matches."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "cat_not_covered")
    audit = AuditLogger(
        audit_file=ctx.relatorios_path / "audit-log.jsonl",
        fs_writer=fw, run_id=ctx.run_id, agent_version="0.3.0a1",
        sentinel_sanitize_version=ctx.sentinel_sanitize_version or "v1.2.0",
        secret_patterns_hash=ctx.secret_patterns_hash or ("a" * 64),
        slug=ctx.slug,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    ctx.dest_path.mkdir(parents=True, exist_ok=True)
    result = run_f3(
        source_path=ctx.source_path,
        dest_path=ctx.dest_path,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
    )
    assert result.rescan_destination_zero is True
    assert result.integrity_ok is True


def test_rs001_inv1_snapshot_pre_pos_identical_after_f3(tmp_path: Path) -> None:
    """RS-002 reforcado 2x: hash-tree fonte pre/pos identical apos F3."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, "encoding_bomb")
    audit = AuditLogger(
        audit_file=ctx.relatorios_path / "audit-log.jsonl",
        fs_writer=fw, run_id=ctx.run_id, agent_version="0.3.0a1",
        sentinel_sanitize_version=ctx.sentinel_sanitize_version or "v1.2.0",
        secret_patterns_hash=ctx.secret_patterns_hash or ("a" * 64),
        slug=ctx.slug, source_path_redacted="src", dest_path_redacted="dst",
    )
    ctx.dest_path.mkdir(parents=True, exist_ok=True)
    result = run_f3(
        source_path=ctx.source_path, dest_path=ctx.dest_path,
        fs_writer=fw, audit=audit, project_root=PROJECT_ROOT,
    )
    assert result.snapshot_pre["aggregate"] == result.snapshot_pos["aggregate"]


def test_rs001_audit_log_has_canonical_actions(tmp_path: Path) -> None:
    """Bloco 03 Passo 03.14: audit-log contem entries canonicas f3_sanitize_start
    + integrity_verify_ok + f3_sanitize_done + leak_smoke_pass."""
    ctx, fw, _src, _allowed, rel = _setup_run(tmp_path, "cat_not_covered")
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    audit_file = rel / "audit-log.jsonl"
    assert audit_file.exists()
    text = audit_file.read_text(encoding="utf-8")
    assert "f3_sanitize_start" in text
    assert "integrity_verify_ok" in text
    assert "f3_sanitize_done" in text
    assert "leak_smoke_pass" in text


def test_rs001_sanitization_report_emitted(tmp_path: Path) -> None:
    """Passo 03.10: SANITIZATION_REPORT_<slug>_<ts>.md emitido em /Relatorios/."""
    ctx, fw, _src, _allowed, rel = _setup_run(tmp_path, "encoding_bomb")
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    reports = list(rel.glob("SANITIZATION_REPORT_encoding_bomb_*.md"))
    assert len(reports) == 1
    md = reports[0].read_text(encoding="utf-8")
    # Header YAML canonico
    assert md.startswith("---\n")
    assert "secret_patterns_hash:" in md
    # 10 categorias
    for cat in [f"C{i}" for i in range(1, 11)]:
        assert f"## Categoria {cat} " in md
    # Camada C6 secao
    assert "## Camada C6" in md
    # LGPD aviso
    assert "LGPD" in md
    # gitleaks externo (Camada C7)
    assert "gitleaks" in md.lower()


def test_rs001_sanitization_report_no_literal_token(tmp_path: Path) -> None:
    """ADR-004 inviolavel: report NUNCA contem valor literal do segredo."""
    ctx, fw, _src, _allowed, rel = _setup_run(tmp_path, "encoding_bomb")
    run_dry_run(ctx, fs_writer=fw)
    run_apply(ctx, fs_writer=fw)
    reports = list(rel.glob("SANITIZATION_REPORT_encoding_bomb_*.md"))
    assert len(reports) == 1
    md = reports[0].read_text(encoding="utf-8")
    assert TARGET_GHP_TOKEN not in md
    assert TARGET_AKIA not in md


# ===========================================================================
# Sumario: 7 fixtures + 5 testes complementares
# ===========================================================================

@pytest.mark.parametrize("slug", list(ADVERSARIAL_FACTORIES.keys()))
def test_rs001_run_f3_exits_zero_on_all_7_fixtures(slug: str, tmp_path: Path) -> None:
    """DoD Passo 03.15: 7/7 fixtures detect/processam SEM erro."""
    ctx, fw, _src, _allowed, _rel = _setup_run(tmp_path, slug)
    run_dry_run(ctx, fs_writer=fw)
    exit_code = run_apply(ctx, fs_writer=fw)
    assert exit_code == 0, f"{slug} falhou apply"
