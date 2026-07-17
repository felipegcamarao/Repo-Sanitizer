"""test_threat_tree_C10.py — Threat Tree C10 (Path leak adversarial) v1.1.0.

Cobre **RS-NEW-032** (crítico — ADR-030): paths absolutos Windows e Unix
NUNCA devem vazar no destino sanitizado.

ATs cobertos:
- AT-C10-01 — 5 paths Windows variantes (case + slash/backslash + drive letter)
- AT-C10-02 — 3 paths `/home/<user>/...` (Unix) + 2 paths `/Users/<user>/...` (macOS)
- AT-C10-03 — 1 path contendo username canônico (cascading C9→C10)
- AT-C10-04 — Smoke E2E: re-grep destino contra WINDOWS_PATH_RE + UNIX_PATH_RE = 0 matches

DoD obrigatório: re-grep destino contra os regex canônicos (`_path_sanitizer`
exports) retorna **0 matches** em todos os arquivos texto. Gate binário —
qualquer leak invalida o Bloco 02.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from repo_sanitizer.f3_sanitizer import run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._path_sanitizer import UNIX_PATH_RE, WINDOWS_PATH_RE
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "adversarial" / "path_leakage_fixture"


@pytest.fixture
def adversarial_run(tmp_path: Path) -> tuple[Path, Path]:
    """Copia a fixture adversarial para tmp_path/source, retorna (source, dest).

    Roda F3 com identity contendo `[NOME]` (username canônico do operador) e
    `OperatorIdentity` real. Retorna paths para asserts.
    """
    source = tmp_path / "source"
    shutil.copytree(FIXTURE_DIR, source)

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    dest = allowed / "GIT_adversarial-paths"
    dest.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()

    identity = OperatorIdentitySchema(
        names=[],
        usernames=["[NOME]"],  # username canônico
        domains=[],
    )
    fw = FsWriter(
        source_path=source,
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    audit = AuditLogger(
        audit_file=relatorios / "audit-log.jsonl",
        fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="1.1.0-alpha.2",
        sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64,
        slug="adversarial-paths",
        source_path_redacted="src",
        dest_path_redacted="dst",
    )

    run_f3(
        source_path=source,
        dest_path=dest,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
        identity=identity,
        rescan_dest=False,
    )
    return source, dest


# ============================================================================
# AT-C10-01..04 — Smoke + grep canônico
# ============================================================================


def test_rs_new_032_absolute_paths_redacted(adversarial_run: tuple[Path, Path]) -> None:
    """RS-NEW-032 (crítico) — re-grep destino retorna 0 matches absolutos.

    Fixture cobre 5 Windows + 3 /home/ + 2 /Users/ + 1 path com username
    canônico. Após run_f3 completo (C1..C10), NENHUM arquivo texto deve
    casar com WINDOWS_PATH_RE ou UNIX_PATH_RE.
    """
    _source, dest = adversarial_run

    leaks: list[tuple[str, str]] = []
    for dest_file in dest.rglob("*"):
        if not dest_file.is_file():
            continue
        if dest_file.suffix not in {".md", ".py", ".txt", ".yml", ".yaml", ".json", ".jsonl"}:
            continue
        try:
            content = dest_file.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            continue  # binário, fora do escopo C10
        rel = dest_file.relative_to(dest).as_posix()
        for m in WINDOWS_PATH_RE.finditer(content):
            leaks.append((rel, m.group(0)))
        for m in UNIX_PATH_RE.finditer(content):
            leaks.append((rel, m.group(0)))

    assert leaks == [], (
        f"RS-NEW-032 LEAK detectado no destino após F3 (C10): {leaks[:5]}"
    )


def test_at_c10_01_username_literal_not_leaked(
    adversarial_run: tuple[Path, Path],
) -> None:
    """AT-C10-01 — Username literal `[NOME]` NUNCA aparece no destino.

    Cascade C9 → C10: C9 redata `[NOME]` para `[REDACTED-USER]` em qualquer
    contexto (path ou texto livre); C10 redata os paths absolutos restantes.
    DoD combinado: zero `[NOME]` literal + zero path absoluto.
    """
    _source, dest = adversarial_run

    leaked_files: list[str] = []
    for dest_file in dest.rglob("*"):
        if not dest_file.is_file():
            continue
        try:
            content = dest_file.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        if "[NOME]" in content:
            leaked_files.append(dest_file.relative_to(dest).as_posix())

    assert leaked_files == [], (
        f"RS-NEW-031 + RS-NEW-032 LEAK — username `[NOME]` literal em: {leaked_files}"
    )


def test_at_c10_02_drive_letters_redacted(
    adversarial_run: tuple[Path, Path],
) -> None:
    """AT-C10-02 — Nenhuma drive letter Windows (`C:/`, `c:\\`, `D:`, `E:`) no destino.

    Política (b)/(c) sempre remove o prefixo `<drive>:[/\\]`. Mesmo paths em
    contextos exóticos (strings Python raw, diff headers) ficam limpos.
    """
    _source, dest = adversarial_run

    drives_found: list[tuple[str, str]] = []
    for dest_file in dest.rglob("*"):
        if not dest_file.is_file():
            continue
        try:
            content = dest_file.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        rel = dest_file.relative_to(dest).as_posix()
        # Procuramos drive letter SEGUIDA de separador (caracteriza path)
        import re as _re
        for m in _re.finditer(r"[A-Za-z]:[\\/]", content):
            drives_found.append((rel, m.group(0)))

    assert drives_found == [], (
        f"AT-C10-02 LEAK — drive letters não-redatadas: {drives_found[:5]}"
    )


def test_at_c10_03_unix_user_roots_redacted(
    adversarial_run: tuple[Path, Path],
) -> None:
    """AT-C10-03 — Nenhum `/home/<x>/` ou `/Users/<x>/` no destino.

    Política (b) para usernames em identity → `~/...`; política (c) para
    outros usernames → `<workspace>/...`. Em ambos os casos, o prefixo
    `/home/<x>` ou `/Users/<x>` é completamente substituído.
    """
    _source, dest = adversarial_run

    unix_paths_found: list[tuple[str, str]] = []
    for dest_file in dest.rglob("*"):
        if not dest_file.is_file():
            continue
        try:
            content = dest_file.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        rel = dest_file.relative_to(dest).as_posix()
        # Procuramos /home/<segmento> ou /Users/<segmento>
        import re as _re
        for m in _re.finditer(r"/(?:home|Users)/[^/\s]+", content):
            unix_paths_found.append((rel, m.group(0)))

    assert unix_paths_found == [], (
        f"AT-C10-03 LEAK — /home/ ou /Users/<x>/ não-redatado: {unix_paths_found[:5]}"
    )


# ============================================================================
# AT-C10-05 — anti-URL FP (MV-09 / RS-NEW-046 / ADR-037 / fecha C-V11-04)
# ============================================================================


@pytest.mark.parametrize(
    "url",
    [
        "https://exemplo.com/a:b",
        "http://x.com/c:d",
        "ftp://host/path:e",
    ],
)
def test_at_c10_05_url_scheme_nao_redatado(url: str) -> None:
    """AT-C10-05 — esquema de URL (`https://`) NÃO é tratado como path Windows.

    O lookbehind largura-fixa `(?<![A-Za-z])` impede casar a letra de drive
    ilusória (`s:` de http**s**://). A URL passa intacta pelo C10 — sem virar
    `<workspace>`. Regressão de C-V11-04 (URL FP em docs/README).
    """
    from repo_sanitizer.helpers._path_sanitizer import (
        WINDOWS_PATH_RE,
        sanitize_paths,
    )

    identity = OperatorIdentitySchema(names=[], usernames=["[NOME]"], domains=[])
    assert WINDOWS_PATH_RE.search(url) is None
    out, matches = sanitize_paths(url, Path("/nonexistent-src-root"), identity)
    assert out == url
    assert matches == []


def test_at_c10_05_path_windows_real_ainda_redatado() -> None:
    """AT-C10-05 (contraparte) — path Windows real ainda é redatado (anti-FN).

    O fix anti-URL NÃO pode regredir a cobertura: `C:\\Users\\[NOME]\\...`
    precedido por espaço/aspas/início-de-linha continua sendo redatado.
    """
    from repo_sanitizer.helpers._path_sanitizer import sanitize_paths

    identity = OperatorIdentitySchema(names=[], usernames=["[NOME]"], domains=[])
    text = "arquivo em C:/Users/[NOME]/proj/secret.json aqui"
    out, matches = sanitize_paths(text, Path("/nonexistent-src-root"), identity)
    assert "[NOME]" not in out
    assert "C:/Users" not in out
    assert len(matches) == 1
    assert matches[0].category == "user_path"
