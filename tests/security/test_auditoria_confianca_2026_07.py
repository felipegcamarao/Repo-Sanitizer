"""test_auditoria_confianca_2026_07.py — regressões da Auditoria de Confiança Total.

Cada teste ancora um vazamento REAL encontrado no red team de 2026-07-12
(cobaia contaminada) ou uma correção estrutural aplicada na auditoria:

- AUD-01: F1 exclui históricos de sessão de IA (.claude/, .specstory/, safelog*.jsonl...).
- AUD-02: regex github_pat_ cobre variantes de comprimento (era estrito {22}_{59}).
- AUD-03: exceção LICENSE — nome do operador preservado APENAS em LICENSE (C9).
- AUD-04: G2 detecta PII em NOME DE ARQUIVO (filename leak nomao-helper.py).
- AUD-05: G2 tolera nome do operador no conteúdo de LICENSE, mas não em outros arquivos.
- AUD-06: reason do FSM não contém nome do operador (ia para .sanitizer-state.json).
- AUD-07: DEFAULT_FORBIDDEN_PATHS derivado do ambiente (sem username hardcoded).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from repo_sanitizer.f1_filter import classify_group_a
from repo_sanitizer.f3_sanitizer import LICENSE_BASENAMES, run_c9_pii_detector
from repo_sanitizer.f4_readme import _scan_pii_operador
from repo_sanitizer.helpers._fs_writer import DEFAULT_FORBIDDEN_PATHS
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema
from repo_sanitizer.secret_patterns import SECRET_MATRIX

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# AUD-01 — históricos de sessão de IA são Grupo A (excluídos no walk)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel_path", [
    ".claude/projects/sessao-2026-06-01.jsonl",
    ".claude/settings.json",
    "sub/dir/.claude/transcript.jsonl",
    ".specstory/history/2026-06-01-chat.md",
    ".cursor/rules.md",
    ".windsurf/config.json",
    ".aider.chat.history.md",
    ".aider/cache.json",
    ".history/src/app.py",
    "safelog.jsonl",
    "logs-agente/safelog-2026.jsonl",
    ".claude.json",
])
def test_aud01_sessoes_ia_sao_grupo_a(rel_path: str) -> None:
    is_a, motivo = classify_group_a(rel_path)
    assert is_a, f"{rel_path} deveria ser Grupo A (histórico de sessão IA); motivo={motivo!r}"


@pytest.mark.parametrize("rel_path", [
    # anti-falso-positivo: nomes de produto parecidos NÃO são excluídos
    "src/claude_client.py",
    "docs/history.md",
    "aiderman/module.py",
    "safelogic/core.py",
])
def test_aud01_anti_falso_positivo(rel_path: str) -> None:
    is_a, _ = classify_group_a(rel_path)
    assert not is_a, f"{rel_path} NÃO deveria ser excluído (falso positivo)"


# ---------------------------------------------------------------------------
# AUD-02 — github_pat_ robusto (red team: token 24_59 escapava do {22}_{59})
# ---------------------------------------------------------------------------

def _github_pat_rule():
    for rule in SECRET_MATRIX["C2"]:
        if rule.tipo == "API_KEY_github_pat":
            return rule
    raise AssertionError("regra API_KEY_github_pat ausente")


@pytest.mark.parametrize("token", [
    # formato oficial: 22 + _ + 59
    "github_pat_" + "A" * 22 + "_" + "b" * 59,
    # variante que VAZOU no red team round 1 (24 antes do underscore)
    "github_pat_Ficticio1234567890AbCdEf_" + "x" * 59,
    # variante compacta plausível
    "github_pat_" + "Z" * 40,
])
def test_aud02_github_pat_variantes_detectadas(token: str) -> None:
    rule = _github_pat_rule()
    assert rule.regex.search(token), f"github_pat_ não detectado: {token[:30]}..."


def test_aud02_github_pat_nao_casa_identificador() -> None:
    rule = _github_pat_rule()
    assert not rule.regex.search("my-github_pat_helper"), "ancoragem (?<![\\w-]) quebrada"


# ---------------------------------------------------------------------------
# AUD-03 — exceção LICENSE na C9 (nome preservado SÓ em LICENSE)
# ---------------------------------------------------------------------------

_IDENTITY = OperatorIdentitySchema(
    names=["Noma Nomão", "Nomao"],
    usernames=["usra"],
    domains=["acme.io"],
    extra_redact_patterns=[],
)

_MIT = "MIT License\n\nCopyright (c) 2026 Noma Nomão\n"


def test_aud03_license_preserva_nome_do_copyright() -> None:
    sanitized, matches = run_c9_pii_detector(
        _MIT, _IDENTITY, rel_path="LICENSE", skip_names=True,
    )
    assert "Noma Nomão" in sanitized, "exceção LICENSE deve preservar copyright holder"
    assert not [m for m in matches if m.category == "name"]


def test_aud03_license_ainda_redata_username_e_dominio() -> None:
    text = _MIT + "\nContato: usra em acme.io\n"
    sanitized, _ = run_c9_pii_detector(
        text, _IDENTITY, rel_path="LICENSE", skip_names=True,
    )
    assert "usra" not in sanitized, "username deve ser redatado mesmo em LICENSE"
    assert not re.search(r"\bacme\.ai\b", sanitized), "domínio deve ser redatado mesmo em LICENSE"


def test_aud03_fora_do_license_nome_e_redatado() -> None:
    sanitized, _ = run_c9_pii_detector(
        "Autor: Noma Nomão", _IDENTITY, rel_path="README.md",
    )
    assert "Noma Nomão" not in sanitized


def test_aud03_basenames_canonicos() -> None:
    assert {"license", "license.md", "license.txt", "licence"} == set(LICENSE_BASENAMES)


# ---------------------------------------------------------------------------
# AUD-04 / AUD-05 — G2: filename scan + exceção LICENSE no conteúdo
# ---------------------------------------------------------------------------

def test_aud04_g2_detecta_pii_em_filename(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "nomao-helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    samples = _scan_pii_operador(dest, [], ["nomao"])
    assert any("FILENAME" in s for s in samples), (
        "arquivo com nome do operador no FILENAME deve ser bloqueante (red team round 1)"
    )


def test_aud05_g2_tolera_nome_no_license_mas_nao_no_readme(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "LICENSE").write_text(_MIT, encoding="utf-8")
    (dest / "NOTAS.md").write_text("por Noma Nomão\n", encoding="utf-8")
    samples = _scan_pii_operador(dest, [], ["noma nomão", "noma"])
    assert not any(s.startswith("LICENSE:") and ":FILENAME:" not in s for s in samples), (
        f"LICENSE não deveria gerar amostra de conteúdo: {samples}"
    )
    assert any(s.startswith("NOTAS.md:") for s in samples), "NOTAS.md deveria ser flagrado"


def test_aud05_g2_username_bloqueia_ate_no_license(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "LICENSE").write_text(_MIT + "\nmantido por usra\n", encoding="utf-8")
    samples = _scan_pii_operador(dest, ["usra"], [])
    assert samples, "username em LICENSE deve continuar bloqueante"


# ---------------------------------------------------------------------------
# AUD-06 — nenhum reason/string de runtime com nome do operador chega ao destino
# ---------------------------------------------------------------------------

def test_aud06_fsm_reasons_sem_nome_do_operador() -> None:
    src = Path(__file__).resolve().parents[2] / "src" / "repo_sanitizer"
    ofensores: list[str] = []
    for py in src.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        # reasons de transition + prints vao para state file / stdout
        for m in re.finditer(r'reason\s*=\s*(?:f?)"([^"]*)"', text):
            if re.search(r"noma|usra|camar|acme", m.group(1), re.IGNORECASE):
                ofensores.append(f"{py.name}: {m.group(1)!r}")
    assert not ofensores, f"reason strings com PII do operador: {ofensores}"


# ---------------------------------------------------------------------------
# AUD-07 — FORBIDDEN_PATHS sem username hardcoded
# ---------------------------------------------------------------------------

def test_aud07_forbidden_paths_derivados_do_ambiente() -> None:
    home = Path.home()
    assert any(p == home / ".ssh" for p in DEFAULT_FORBIDDEN_PATHS), (
        ".ssh do usuário atual deve estar protegido"
    )
    assert any(p == home / "AppData" for p in DEFAULT_FORBIDDEN_PATHS)
    # nenhum path com username hardcoded que não seja o do ambiente atual
    for p in DEFAULT_FORBIDDEN_PATHS:
        s = str(p).lower()
        if "users" in s:
            assert str(home).lower() in s, f"path proibido hardcoded de outro usuário: {p}"
