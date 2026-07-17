r"""test_secret_patterns_v120_prefixes.py — A4 / MV-03 / RS-NEW-040.

Prefixos de chave MODERNOS adicionados em `secret_patterns.py::C2_RULES`
(GitHub fine-grained PAT, OpenAI sk-proj-, Stripe, GitLab, Slack app, AWS
temp/role). Smoke por regra:

- match em fixture sintetico (NUNCA segredo real),
- redacao end-to-end via `sanitize_text_content` → `<REDACTED-...>`,
- 0 literal vazado no texto sanitizado,
- ancoragem `(?<![\w-])` evita falso-positivo dentro de palavra.

Regras antigas (sk-/AKIA/ghp_/...) NÃO removidas — coberto por
`test_secret_patterns.py`. Aqui só os NOVOS tipos v1.2.0.
"""
from __future__ import annotations

import pytest

from repo_sanitizer.f3_sanitizer import sanitize_text_content
from repo_sanitizer.secret_patterns import SECRET_MATRIX

# ---------------------------------------------------------------------------
# Fixtures sintéticas (formato realista, valores arbitrários — não-segredos)
# ---------------------------------------------------------------------------

_GH_A = "A" * 22
_GH_B = "B" * 59

# (tipo_canonico, token_sintetico) — cada token casa exatamente sua regra nova.
NEW_PREFIX_TOKENS: list[tuple[str, str]] = [
    ("API_KEY_github_pat", "github_pat_" + _GH_A + "_" + _GH_B),
    ("API_KEY_openai_sk_proj", "sk-proj-T3BlbkAJ" + "x" * 24),
    ("API_KEY_stripe", "sk_live_" + "a" * 24),
    ("API_KEY_stripe", "rk_test_" + "b" * 24),
    ("API_KEY_stripe", "pk_live_" + "c" * 24),
    ("WEBHOOK_stripe", "whsec_" + "d" * 24),
    ("API_KEY_gitlab_pat", "glpat-" + "e" * 24),
    ("API_KEY_slack_app", "xapp-1-" + "f" * 24),
    ("API_KEY_slack_app", "xoxe-1-" + "g" * 24),
    ("API_KEY_aws_temp", "ASIA" + "Z" * 16),
    ("API_KEY_aws_temp", "AROA" + "Y" * 16),
]


def _rule_for(tipo: str):
    return next(r for r in SECRET_MATRIX["C2"] if r.tipo == tipo)


# ---------------------------------------------------------------------------
# 1. Cada regra existe na matriz C2 e tem ação canônica
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tipo", sorted({t for t, _ in NEW_PREFIX_TOKENS}))
def test_nova_regra_existe_e_redact_inline(tipo: str) -> None:
    rule = _rule_for(tipo)
    assert rule.category == "C2"
    assert rule.acao == "redact_inline"


# ---------------------------------------------------------------------------
# 2. Smoke por regra: match no fixture sintético
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tipo,token", NEW_PREFIX_TOKENS)
def test_regra_casa_fixture_sintetico(tipo: str, token: str) -> None:
    rule = _rule_for(tipo)
    assert rule.regex.search(f"valor = {token}") is not None


# ---------------------------------------------------------------------------
# 3. Redação end-to-end via sanitize_text_content + 0 literal vazado
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tipo,token", NEW_PREFIX_TOKENS)
def test_redacao_end_to_end_zero_literal(tipo: str, token: str) -> None:
    text = f"KEY={token}\noutra linha normal\n"
    result = sanitize_text_content(text, "utf-8")
    # Placeholder canônico presente
    assert f"<REDACTED-{tipo}>" in result.sanitized_text
    # ZERO literal: nenhum trecho do token sobrevive no texto sanitizado.
    assert token not in result.sanitized_text
    # O sufixo de alta-entropia também não vaza (substring de ≥16 chars).
    assert token[-16:] not in result.sanitized_text
    # Pelo menos 1 match do tipo esperado registrado.
    assert any(r.tipo == tipo for r, _ln, _enc in result.matches)


# ---------------------------------------------------------------------------
# 4. Anti-FP: ancoragem `(?<![\w-])` não casa dentro de palavra
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tipo,benigno",
    [
        ("API_KEY_openai_sk_proj", "task-project-id-referencia-interna"),
        ("WEBHOOK_stripe", "my_whsecret_internal_variable_name_xxxxxxxxxxxx"),
        ("API_KEY_gitlab_pat", "aglpat-" + "x" * 24),  # precedido por letra
        ("API_KEY_github_pat", "xgithub_pat_" + _GH_A + "_" + _GH_B),  # precedido por letra
        ("API_KEY_aws_temp", "XASIA" + "Z" * 16),  # precedido por maiúscula
    ],
)
def test_anti_fp_dentro_de_palavra(tipo: str, benigno: str) -> None:
    rule = _rule_for(tipo)
    assert rule.regex.search(benigno) is None


# ---------------------------------------------------------------------------
# 5. github_pat faixa paranoica {30,200} (Auditoria 2026-07)
# ---------------------------------------------------------------------------


def test_github_pat_faixa_paranoica() -> None:
    # Auditoria 2026-07: o formato estrito {22}_{59} deixou VAZAR um token
    # 24_59 no red team (round 1). Regra relaxada para [A-Za-z0-9_]{30,200}
    # (INV-5 Modo Paranoico): variantes proximas do formato oficial casam.
    rule = _rule_for("API_KEY_github_pat")
    assert rule.regex.search("github_pat_" + "A" * 21 + "_" + "B" * 59) is not None
    assert rule.regex.search("github_pat_" + "A" * 22 + "_" + "B" * 58) is not None
    # curto demais (< 30 chars apos o prefixo) → não casa (anti-FP).
    assert rule.regex.search("github_pat_" + "A" * 20) is None


# ---------------------------------------------------------------------------
# 6. Smoke de tempo (anti-ReDoS): token de 100k chars não trava
# ---------------------------------------------------------------------------


def test_smoke_tempo_token_gigante() -> None:
    import time

    big = "prefixo " + ("z" * 100_000) + " sufixo glpat-" + "k" * 24
    rule = _rule_for("API_KEY_gitlab_pat")
    start = time.perf_counter()
    m = rule.regex.search(big)
    elapsed = time.perf_counter() - start
    assert m is not None  # o glpat real ainda é encontrado
    assert elapsed < 1.0
