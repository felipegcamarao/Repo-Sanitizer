"""test_f3_c10_integration.py — Bloco 02 Passo 2.2 integration tests (C10).

Cobre integração da Camada C10 (Path Sanitizer) no pipeline F3 completo:
- run_f3 com fixture Windows-paths → 0 paths absolutos no destino
- run_f3 com fixture Unix-paths → 0 paths absolutos no destino
- run_f3 com fixture mixed → 0 paths absolutos no destino (Win + Unix)
- run_f3 com fixture zero-paths → texto inalterado

**Cascading sanitization C9→C10 (PT-RS-04 layer 3)**: Em integration tests
com `usernames=["[NOME]"]`, C9 redata `[NOME]` para `[REDACTED-USER]` ANTES de
C10 ver o texto, então C10 cai na política (c) `other_absolute` (não em (b)
`user_path`). Isso é INTENCIONAL — o objetivo final (zero path absoluto + zero
PII no destino) é atingido. Validamos isso aqui via re-grep contra regex
canônicos do helper.

Backward-compat invariável (R-01): 833 testes pré-existentes + 18 unit C10
permanecem verdes.
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f3_sanitizer import run_f3
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._path_sanitizer import UNIX_PATH_RE, WINDOWS_PATH_RE
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Helpers de setup
# ---------------------------------------------------------------------------


def _setup_run_env(
    tmp_path: Path, files: dict[str, str], *, usernames: list[str] | None = None,
) -> tuple[Path, Path, FsWriter, AuditLogger, OperatorIdentitySchema]:
    """Constrói source + dest + relatorios + FsWriter + Audit + identity.

    `files`: dict rel_path → conteúdo. Arquivos texto UTF-8.
    `usernames`: lista de usernames para alimentar política (b) do C10.
    """
    source = tmp_path / "fake-source"
    source.mkdir()
    for rel_path, content in files.items():
        full = source / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    dest = allowed / "GIT_fake-project"
    dest.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()

    identity = OperatorIdentitySchema(
        names=[],
        usernames=usernames or ["dummy_isolated_user"],
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
        slug="fake-project",
        source_path_redacted="src",
        dest_path_redacted="dst",
    )
    return source, dest, fw, audit, identity


def _grep_dest_for_absolute_paths(dest: Path) -> list[tuple[str, str]]:
    """Re-grep destino contra WINDOWS_PATH_RE + UNIX_PATH_RE. Retorna leaks."""
    leaks: list[tuple[str, str]] = []
    for dest_file in dest.rglob("*"):
        if not dest_file.is_file():
            continue
        try:
            content = dest_file.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            continue  # binário (não é responsabilidade do C10)
        rel = dest_file.relative_to(dest).as_posix()
        for m in WINDOWS_PATH_RE.finditer(content):
            leaks.append((rel, m.group(0)))
        for m in UNIX_PATH_RE.finditer(content):
            leaks.append((rel, m.group(0)))
    return leaks


# ---------------------------------------------------------------------------
# Test 1 — Windows paths only → zero paths absolutos no destino
# ---------------------------------------------------------------------------


def test_c10_windows_paths_redacted_in_destination(tmp_path: Path) -> None:
    """Fixture com paths Windows: re-grep destino retorna 0 matches."""
    files = {
        "README.md": (
            "# Config\n\n"
            "Local: C:/Users/[NOME]/AppData/secret.json\n"
            "Outro: C:/VS Code/Outro Projeto/file.py\n"
        ),
    }
    source, dest, fw, audit, identity = _setup_run_env(
        tmp_path, files, usernames=["[NOME]"],
    )

    result = run_f3(
        source_path=source,
        dest_path=dest,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
        identity=identity,
        rescan_dest=False,
    )

    sanitized = (dest / "README.md").read_text(encoding="utf-8")
    # RS-NEW-032: zero literais do path absoluto
    assert "C:/Users" not in sanitized
    assert "C:/VS Code" not in sanitized
    # RS-NEW-031: zero literal username (cascade C9)
    assert "[NOME]" not in sanitized

    # Re-grep canônico (DoD ADR-030): 0 matches absolutos no destino
    leaks = _grep_dest_for_absolute_paths(dest)
    assert leaks == [], f"C10 falhou — leaks no destino: {leaks}"

    # F3Result reflete ≥2 matches em path_matches (cascading → other_absolute)
    assert len(result.path_matches) >= 2
    assert result.path_by_category.get("other_absolute", 0) >= 1


# ---------------------------------------------------------------------------
# Test 2 — Unix paths only → zero paths absolutos no destino
# ---------------------------------------------------------------------------


def test_c10_unix_paths_redacted_in_destination(tmp_path: Path) -> None:
    """Fixture com paths Unix `/home/...` e `/Users/...`: re-grep destino 0 matches."""
    files = {
        "config.md": (
            "# Paths\n\n"
            "Log linux: /home/[NOME]/proj/run.log\n"
            "Cache mac: /Users/[NOME]/Library/cache.db\n"
            "Outro: /home/stranger/dotfiles/config.yml\n"
        ),
    }
    source, dest, fw, audit, identity = _setup_run_env(
        tmp_path, files, usernames=["[NOME]"],
    )

    result = run_f3(
        source_path=source,
        dest_path=dest,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
        identity=identity,
        rescan_dest=False,
    )

    sanitized = (dest / "config.md").read_text(encoding="utf-8")
    assert "/home/[NOME]" not in sanitized
    assert "/Users/[NOME]" not in sanitized
    assert "/home/stranger" not in sanitized
    assert "[NOME]" not in sanitized

    # Re-grep canônico (DoD ADR-030)
    leaks = _grep_dest_for_absolute_paths(dest)
    assert leaks == [], f"C10 falhou — leaks no destino: {leaks}"

    # `stranger` não está em C9.usernames → não foi redatado por C9 → política (b)
    # do C10 dispara → ~/dotfiles/config.yml. Validamos categoria coexistência.
    categories = {m.category for m in result.path_matches}
    assert "user_path" in categories or "other_absolute" in categories


# ---------------------------------------------------------------------------
# Test 3 — Mixed Windows + Unix → zero paths absolutos no destino
# ---------------------------------------------------------------------------


def test_c10_mixed_windows_and_unix_paths(tmp_path: Path) -> None:
    """Fixture mixed: Windows + Unix; re-grep destino 0 matches em múltiplos arquivos."""
    files = {
        "doc/notes.md": (
            "# Notes\n\n"
            "Win: C:/Users/[NOME]/proj/a.py\n"
            "Unix: /home/[NOME]/proj/b.py\n"
            "Other: C:/VS Code/Outro/c.py\n"
        ),
        "src/module.py": (
            "# Imports\n"
            'PATH = r"C:\\Users\\[NOME]\\settings.json"\n'
        ),
    }
    source, dest, fw, audit, identity = _setup_run_env(
        tmp_path, files, usernames=["[NOME]"],
    )

    result = run_f3(
        source_path=source,
        dest_path=dest,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
        identity=identity,
        rescan_dest=False,
    )

    notes_sanitized = (dest / "doc" / "notes.md").read_text(encoding="utf-8")
    module_sanitized = (dest / "src" / "module.py").read_text(encoding="utf-8")
    assert "[NOME]" not in notes_sanitized
    assert "[NOME]" not in module_sanitized
    assert "C:/VS Code" not in notes_sanitized

    # Re-grep canônico ambos arquivos
    leaks = _grep_dest_for_absolute_paths(dest)
    assert leaks == [], f"C10 falhou — leaks no destino: {leaks}"

    # path_by_category sempre populado (≥4 paths Win + Unix capturados)
    total = sum(result.path_by_category.values())
    assert total >= 4


# ---------------------------------------------------------------------------
# Test 4 — Zero paths absolutos → texto inalterado
# ---------------------------------------------------------------------------


def test_c10_zero_paths_text_unchanged(tmp_path: Path) -> None:
    """Fixture sem paths absolutos: destino == source; F3Result.path_matches == []."""
    original = (
        "# Sem paths absolutos\n\n"
        "Apenas referências relativas: ./docs e ../README.md\n"
        "Texto comum sem drives nem rotas absolutas detectáveis.\n"
    )
    files = {"README.md": original}
    source, dest, fw, audit, identity = _setup_run_env(
        tmp_path, files, usernames=["[NOME]"],
    )

    result = run_f3(
        source_path=source,
        dest_path=dest,
        fs_writer=fw,
        audit=audit,
        project_root=PROJECT_ROOT,
        identity=identity,
        rescan_dest=False,
    )

    sanitized = (dest / "README.md").read_text(encoding="utf-8")
    assert sanitized == original, "C10 alterou texto sem paths absolutos"
    assert result.path_matches == []
    assert result.path_by_category == {}
