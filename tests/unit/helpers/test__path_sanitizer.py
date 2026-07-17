"""test__path_sanitizer.py — Camada C10 helper (ADR-030 + RS-NEW-032 + Bloco 02 / 2.1).

Cobre as 3 políticas canônicas (intra_source / user_path / other_absolute) +
edge cases (URLs file://, diff headers, backslash duplo-escape Python, mixed
text Windows + Unix). Meta de cobertura sobre `_path_sanitizer.py` ≥90%.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from repo_sanitizer.helpers._path_sanitizer import (
    UNIX_PATH_RE,
    WINDOWS_PATH_RE,
    PathMatch,
    classify_path,
    sanitize_paths,
)
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def source_root(tmp_path: Path) -> Path:
    """Source root canônico de cada teste — diretório temporário isolado."""
    root = tmp_path / "src-tree"
    root.mkdir()
    return root


@pytest.fixture
def identity_with_user() -> OperatorIdentitySchema:
    """Identity com username explícito — alimenta política (b) determinística."""
    return OperatorIdentitySchema(usernames=["[NOME]"], names=[], domains=[])


@pytest.fixture
def identity_empty() -> OperatorIdentitySchema:
    """Identity vazia (usernames inicializa via OS auto-detect — pode ou não popular).

    Para isolamento, usamos um nome que jamais será o login do CI.
    """
    return OperatorIdentitySchema(usernames=["__non_existent_user__"])


# ---------------------------------------------------------------------------
# Política (a) — intra_source → relativiza para ./
# ---------------------------------------------------------------------------


class TestPolicyIntraSource:
    """Paths DENTRO da source-tree são relativizados para ./<rel>."""

    def test_windows_intra_source_relativizado(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        # Constrói um path absoluto que aponta para dentro de source_root.
        target = source_root / "docs" / "README.md"
        text = f"Veja {target} para detalhes."
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert len(matches) == 1
        assert matches[0].category == "intra_source"
        assert matches[0].sanitized.startswith("./")
        assert "docs/README.md" in matches[0].sanitized
        # Texto destino contém substituição relativa
        assert "./docs/README.md" in out
        # E NÃO contém mais o path absoluto original (a substring drive-letter sumiu)
        drive = str(source_root)[:3]  # "C:\" ou "/tm" (Linux)
        if drive.startswith(("C:", "c:", "D:")):
            assert drive not in out

    def test_windows_intra_source_root_exato(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = f"root: {source_root}/"
        _out, matches = sanitize_paths(text, source_root, identity_with_user)
        # Aceitamos qualquer um dos dois (depende de capturar com ou sem trailing slash)
        assert len(matches) >= 1
        assert all(m.category == "intra_source" for m in matches)


# ---------------------------------------------------------------------------
# Política (b) — user_path → ~/
# ---------------------------------------------------------------------------


class TestPolicyUserPath:
    """Paths fora do source-tree contendo username conhecido viram ~/<suffix>."""

    def test_windows_user_path_tilde_redact(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = "Config em C:/Users/[NOME]/AppData/secret.json"
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert len(matches) == 1
        assert matches[0].category == "user_path"
        assert matches[0].sanitized == "~/AppData/secret.json"
        assert "~/AppData/secret.json" in out
        assert "[NOME]" not in out
        assert "C:/Users" not in out

    def test_unix_home_user_path_tilde_redact(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = "log em /home/[NOME]/projeto/run.log"
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert len(matches) == 1
        assert matches[0].category == "user_path"
        assert matches[0].sanitized == "~/projeto/run.log"
        assert "/home/[NOME]" not in out

    def test_unix_users_macos_user_path(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = "Cache em /Users/[NOME]/Library/cache.db"
        _out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert len(matches) == 1
        assert matches[0].category == "user_path"
        assert matches[0].sanitized == "~/Library/cache.db"


# ---------------------------------------------------------------------------
# Política (c) — other_absolute → <workspace>/
# ---------------------------------------------------------------------------


class TestPolicyOtherAbsolute:
    """Paths absolutos sem match em source nem em username viram <workspace>/."""

    def test_windows_other_absolute_via_vs_code_marker(
        self, source_root: Path, identity_empty: OperatorIdentitySchema
    ) -> None:
        text = "Source em C:/VS Code/Outro Projeto/file.py"
        out, matches = sanitize_paths(text, source_root, identity_empty)
        assert len(matches) == 1
        assert matches[0].category == "other_absolute"
        assert matches[0].sanitized == "<workspace>/Outro Projeto/file.py"
        assert "C:/VS Code" not in out
        assert "<workspace>/Outro Projeto/file.py" in out

    def test_unix_other_absolute_unknown_user(
        self, source_root: Path, identity_empty: OperatorIdentitySchema
    ) -> None:
        text = "Conf em /home/stranger/dotfiles/config.yml"
        out, matches = sanitize_paths(text, source_root, identity_empty)
        assert len(matches) == 1
        assert matches[0].category == "other_absolute"
        # Marker /home/ → suffix = "stranger/dotfiles/config.yml"
        assert matches[0].sanitized == "<workspace>/stranger/dotfiles/config.yml"
        assert "/home/stranger" not in out


# ---------------------------------------------------------------------------
# Mixed content + nenhum match (texto inalterado)
# ---------------------------------------------------------------------------


class TestMixedAndZeroMatch:
    """Textos sem paths absolutos passam inalterados; mixed Windows+Unix processado em ambas as regex."""

    def test_zero_match_text_unchanged(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = "Apenas texto. Inclui paths relativos como ./docs e ../README.md."
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert out == text
        assert matches == []

    def test_mixed_windows_and_unix_processed(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = (
            "win: C:/Users/[NOME]/proj/a.py | "
            "unix: /home/[NOME]/proj/b.py | "
            "other: C:/VS Code/Outro/c.py"
        )
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        cats = sorted(m.category for m in matches)
        assert cats == ["other_absolute", "user_path", "user_path"]
        assert "[NOME]" not in out
        assert "<workspace>/Outro/c.py" in out
        assert out.count("~/proj/") == 2


# ---------------------------------------------------------------------------
# Edge cases — diff headers, file:// URLs, backslash duplo-escape
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases listados no manifesto Passo 2.1.11."""

    def test_diff_header_path_redacted(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        text = "--- a/C:/Users/[NOME]/proj/file.py\n+++ b/C:/Users/[NOME]/proj/file.py"
        out, _matches = sanitize_paths(text, source_root, identity_with_user)
        assert "[NOME]" not in out
        # Mantém o prefixo `a/` e `b/` originais; só o path absoluto é redatado
        assert "--- a/~/proj/file.py" in out
        assert "+++ b/~/proj/file.py" in out

    def test_backslash_double_escape_python_string(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        # Texto-fonte com backslashes literais como apareceriam em código Python
        # escrito (`Path("C:\\\\Users\\\\[NOME]\\\\proj")`). No arquivo lido isso
        # vira `C:\\Users\\[NOME]\\proj` (2 backslashes literais por separador).
        text = r"caminho = r'C:\Users\[NOME]\proj\arquivo.txt'"
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert len(matches) == 1
        assert matches[0].category == "user_path"
        assert "[NOME]" not in out
        assert "~/proj/arquivo.txt" in out

    def test_python_path_string_intra_source(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        # Path() Python literal apontando para dentro do source
        target = source_root / "modulo.py"
        text = f'Path("{target}")'
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert len(matches) == 1
        assert matches[0].category == "intra_source"
        assert "./modulo.py" in out

    def test_idempotencia_segundo_run_sem_match_novo(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        # Idempotência: após sanitize, rodar de novo NÃO deve gerar novos matches.
        text = "C:/Users/[NOME]/log.txt e /home/[NOME]/run.log"
        first, _matches1 = sanitize_paths(text, source_root, identity_with_user)
        second, matches2 = sanitize_paths(first, source_root, identity_with_user)
        assert matches2 == []
        assert second == first


# ---------------------------------------------------------------------------
# Sanity checks dos regex compilados (uso indireto na C10 + threat tree)
# ---------------------------------------------------------------------------


class TestRegexExports:
    """`WINDOWS_PATH_RE` e `UNIX_PATH_RE` precisam ser usáveis pelo gate G2 (ADR-032)."""

    def test_windows_regex_captura_basico(self) -> None:
        assert WINDOWS_PATH_RE.search("Veja C:/Users/x/a.txt aqui")
        assert WINDOWS_PATH_RE.search(r"E:\projetos\bar")
        # Forma `C:` isolada (sem barra) NÃO captura — não é path
        assert WINDOWS_PATH_RE.search("apenas C: sem barra") is None


# ---------------------------------------------------------------------------
# A3 / MV-09 / RS-NEW-046 / ADR-037 — anti-esquema-URL (lookbehind largura-fixa)
# ---------------------------------------------------------------------------


class TestWindowsPathReAntiUrl:
    """`WINDOWS_PATH_RE` NÃO casa esquemas de URL (`https://x`) mas ainda casa
    paths Windows reais (`C:\\Users\\...`). Fecha C-V11-04 (URL FP)."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://exemplo.com/a:b",
            "http://x.com/c:d",
            "ftp://host/d:e",
            "HTTPS://EXEMPLO.COM/A:B",  # case-insensitive: s/S precede `:` → sem match
        ],
    )
    def test_url_schemes_nao_casam(self, url: str) -> None:
        # A letra de drive ilusória (`s:` de http**s**) é precedida por letra →
        # lookbehind `(?<![A-Za-z])` bloqueia o match.
        assert WINDOWS_PATH_RE.search(url) is None

    @pytest.mark.parametrize(
        "text",
        [
            r"C:\Users\[NOME]\proj\arquivo.txt",  # início de linha, backslash
            "Config em C:/Users/[NOME]/AppData/secret.json",  # após espaço
            '"D:/data/x/y"',  # após aspas
            "(E:/projetos/bar/baz)",  # após parêntese
            "--- a/C:/Users/[NOME]/proj/file.py",  # diff header (após `/`)
            "path=C:/win/sys/x.dll",  # após `=`
        ],
    )
    def test_paths_windows_reais_ainda_casam(self, text: str) -> None:
        # Paths reais são precedidos por espaço/aspas/`(`/`=`/`/`/início-de-linha
        # → lookbehind passa, match preservado (zero regressão de cobertura C10).
        assert WINDOWS_PATH_RE.search(text) is not None

    def test_url_em_doc_nao_e_redatada_no_pipeline(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        # Pipeline completo C10: URL em prosa permanece intacta (não vira <workspace>).
        text = "Veja a doc em https://exemplo.com/guide:start para detalhes."
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert out == text
        assert matches == []

    def test_path_real_apos_url_na_mesma_linha(
        self, source_root: Path, identity_with_user: OperatorIdentitySchema
    ) -> None:
        # URL preservada E path Windows real (após espaço) redatado na mesma linha.
        text = "ref https://ex.com/a:b e arquivo C:/Users/[NOME]/x.py local"
        out, matches = sanitize_paths(text, source_root, identity_with_user)
        assert "https://ex.com/a:b" in out  # URL intacta
        assert "[NOME]" not in out  # path real redatado (cascading)
        assert len(matches) == 1
        assert matches[0].category == "user_path"

    def test_lookbehind_largura_fixa_sem_redos(self) -> None:
        # Smoke de tempo: lookbehind largura-fixa não introduz catastrophic
        # backtracking. Input grande resolve rápido (<100ms típico).
        import time

        big = ("https://exemplo.com/a:b " * 5000) + "C:/Users/[NOME]/final.py"
        start = time.perf_counter()
        found = WINDOWS_PATH_RE.findall(big)
        elapsed = time.perf_counter() - start
        # Só o path real (1) casa; nenhuma das 5000 URLs.
        assert len(found) == 1
        assert elapsed < 1.0

    def test_unix_regex_captura_basico(self) -> None:
        assert UNIX_PATH_RE.search("path /home/joe/x")
        assert UNIX_PATH_RE.search("path /Users/joe/y")
        # /etc NÃO é capturado (canônico ADR-030: só /home e /Users)
        assert UNIX_PATH_RE.search("path /etc/passwd") is None


# ---------------------------------------------------------------------------
# classify_path direto (sem ir via regex sub) — cobre branches defensivas
# ---------------------------------------------------------------------------


class TestClassifyPathDirect:
    """`classify_path` é a API pública para o gate G2; testes diretos garantem retorno PathMatch."""

    def test_classify_returns_dataclass(self, source_root: Path) -> None:
        result = classify_path("C:/Users/[NOME]/x.py", source_root, ["[NOME]"])
        assert isinstance(result, PathMatch)
        assert result.category == "user_path"

    def test_classify_other_absolute_no_workspace_marker(self, source_root: Path) -> None:
        # Path totalmente opaco — não tem /VS Code/, /Users/, /home/ no caminho
        # após a raiz. Cai no fallback `<workspace>/`.
        result = classify_path("D:/foobar/x.py", source_root, [])
        assert result.category == "other_absolute"
        assert result.sanitized.startswith("<workspace>/")

    def test_classify_empty_usernames_skips_b(self, source_root: Path) -> None:
        # Sem usernames declarados, política (b) não dispara mesmo com username
        # presente no path — cai em (c).
        result = classify_path("C:/Users/[NOME]/x.py", source_root, [])
        assert result.category == "other_absolute"
