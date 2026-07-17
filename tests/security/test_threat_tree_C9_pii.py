"""test_threat_tree_C9_pii.py — Threat Tree C9 (Operator PII leak) v1.1.0.

Cobre RS-NEW-031 (critical — ADR-029): nomes próprios + username SO + domínios
privados + regex custom do operador NUNCA devem vazar no destino sanitizado.

ATs cobertos (smoke isolado gate binário):
- AT-C9-01 — Nome próprio em README → redatado para [REDACTED-NAME]
- AT-C9-02 — Username de SO em path/comment → redatado para [REDACTED-USER]
- AT-C9-03 — Domínio privado em link/email → redatado para [REDACTED-DOMAIN]
- AT-C9-04 — Email custom (extra_redact_patterns) → redatado para [REDACTED-CUSTOM]
- AT-C9-05 — Smoke E2E: 0 matches RS-NEW-031 no destino após run_f3

DoD obrigatório: re-grep destino contra (names + usernames + domains + custom)
retorna 0 matches.
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f3_sanitizer import run_c9_pii_detector, run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ============================================================================
# AT-C9-01..04 — Unidade isolada (via run_c9_pii_detector)
# ============================================================================


def test_at_c9_01_name_in_readme_redacted() -> None:
    """Nome próprio em README → [REDACTED-NAME]; 0 matches literal no destino."""
    identity = OperatorIdentitySchema(
        names=["Noma Nomb Nomão"],
        usernames=["dummy_isolated_user"],
        domains=[],
    )
    text = "# README\n\nEscrito por Noma Nomb Nomão (autor)."
    sanitized, matches = run_c9_pii_detector(text, identity, rel_path="README.md")

    assert "Noma Nomb Nomão" not in sanitized, "leak de nome no destino"
    assert "[REDACTED-NAME]" in sanitized
    name_matches = [m for m in matches if m.category == "name"]
    assert len(name_matches) == 1
    assert name_matches[0].file_path == "README.md"


def test_at_c9_02_username_in_path_redacted() -> None:
    """Username em path (`c:\\Users\\usra\\...`) → [REDACTED-USER]."""
    identity = OperatorIdentitySchema(
        names=[],
        usernames=["usra"],
        domains=[],
    )
    text = 'CONFIG_PATH = "c:\\\\Users\\\\usra\\\\AppData\\\\Local"'
    sanitized, matches = run_c9_pii_detector(text, identity, rel_path="config.py")

    assert "usra" not in sanitized
    assert "[REDACTED-USER]" in sanitized
    assert any(m.category == "username" for m in matches)


def test_at_c9_03_domain_in_email_redacted() -> None:
    """Domínio privado em email → [REDACTED-DOMAIN]."""
    identity = OperatorIdentitySchema(
        names=[],
        usernames=["dummy_isolated_user"],
        domains=["empresaprivada.com"],
    )
    text = "Contato: suporte@empresaprivada.com ou comercial@empresaprivada.com"
    sanitized, matches = run_c9_pii_detector(text, identity, rel_path="CONTATO.md")

    assert "empresaprivada.com" not in sanitized
    domain_matches = [m for m in matches if m.category == "domain"]
    assert len(domain_matches) == 1
    assert domain_matches[0].count == 2


def test_at_c9_04_custom_pattern_redacted() -> None:
    """Pattern regex custom (extra_redact_patterns) → [REDACTED-CUSTOM]."""
    identity = OperatorIdentitySchema(
        names=[],
        usernames=["dummy_isolated_user"],
        domains=[],
        extra_redact_patterns=[r"PROJ-\d{6}"],
    )
    text = "Internal: PROJ-123456 (não publicar)"
    sanitized, matches = run_c9_pii_detector(text, identity, rel_path="internal.md")

    assert "PROJ-123456" not in sanitized
    assert "[REDACTED-CUSTOM]" in sanitized
    assert any(m.category == "custom" for m in matches)


# ============================================================================
# AT-C9-05 — Integração ponta-a-ponta com run_f3 + grep no destino
# ============================================================================


def test_at_c9_05_e2e_run_f3_with_c9_zero_leak(tmp_path: Path) -> None:
    """E2E gate RS-NEW-031: após run_f3 com identity, destino tem 0 matches literais.

    Cria source fake com 4 arquivos cobrindo as 4 categorias C9 ISOLADAMENTE
    (evita cascade C5 EMAIL_PESSOAL consumir domain). Roda run_f3 com identity
    explicit e grep o destino — NENHUM match literal pode existir.

    **Nota arquitetural**: domain `empresaprivada.com` em contexto de EMAIL é
    consumido por C5 (SECRET_MATRIX EMAIL_PESSOAL) ANTES de C9. Para validar
    C9 isolado, domínio aparece em URL não-email.
    """
    # 1. Source fake com PII — 4 arquivos, 1 categoria isolada cada
    source = tmp_path / "fake-source"
    source.mkdir()
    (source / "README.md").write_text(
        "# Projeto X\n\nAutor: Noma Nomb Nomão (contribuidor principal).",
        encoding="utf-8",
    )
    (source / "config.py").write_text(
        '# Config interno\n# Operator: usra — review pendente.',
        encoding="utf-8",
    )
    (source / "LINKS.md").write_text(
        "# Links\n\nDocumentação: https://empresaprivada.com/docs/api",
        encoding="utf-8",
    )
    (source / "internal_code.md").write_text(
        "# Projetos internos\n\nReferência: PROJ-987654 (NDA).",
        encoding="utf-8",
    )

    # 2. Destino + relatorios
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    dest = allowed / "GIT_fake-project"
    dest.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()

    # 3. Identity controlada (sem dummy_isolated_user para que auto-populate ative)
    identity = OperatorIdentitySchema(
        names=["Noma Nomb Nomão"],
        usernames=["usra"],
        domains=["empresaprivada.com"],
        extra_redact_patterns=[r"PROJ-\d{6}"],
    )

    # 4. FsWriter + AuditLogger
    fw = FsWriter(
        source_path=source,
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    audit = AuditLogger(
        audit_file=relatorios / "audit-log.jsonl",
        fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="1.1.0-alpha.1",
        sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64,
        slug="fake-project",
        source_path_redacted="src",
        dest_path_redacted="dst",
    )

    # 5. Run F3 com identity injetada
    result = run_f3(
        source_path=source,
        dest_path=dest,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
        identity=identity,
        rescan_dest=False,  # rescan_destination não tem regex pra C9 (separação clara)
    )

    # 6. DoD RS-NEW-031: 0 matches literais no destino
    leaks: list[tuple[str, str]] = []
    for dest_file in dest.rglob("*"):
        if not dest_file.is_file():
            continue
        content = dest_file.read_text(encoding="utf-8", errors="replace")
        for literal in (
            "Noma Nomb Nomão",
            "usra",
            "empresaprivada.com",
        ):
            if literal in content:
                leaks.append((dest_file.relative_to(dest).as_posix(), literal))
        # Pattern custom: re.search
        import re
        if re.search(r"PROJ-\d{6}", content):
            leaks.append((dest_file.relative_to(dest).as_posix(), "PROJ-NNNNNN"))

    assert leaks == [], f"RS-NEW-031 LEAK detectado no destino: {leaks}"

    # 7. F3Result reflete os matches via pii_matches
    assert len(result.pii_matches) >= 4, (
        f"Esperava ≥4 PIIMatches (1 por categoria); recebi {len(result.pii_matches)}"
    )
    categories_found = {m.category for m in result.pii_matches}
    assert categories_found == {"name", "username", "domain", "custom"}, (
        f"Esperava todas as 4 categorias; recebi {categories_found}"
    )
