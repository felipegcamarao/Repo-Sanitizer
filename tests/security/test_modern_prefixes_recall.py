"""test_modern_prefixes_recall.py — A4 / MV-03 / RS-NEW-040 (adversarial).

Threat tree MV-03 (prefixos modernos): recall 100% sobre os 6+ formatos novos
de chave + controle anti-FP. Espelha o gate `assert_no_literal_secrets` (RS-005):
o achado NUNCA carrega o literal — só o `tipo` canônico.

ATs cobertos:
- AT-MV03-01 — recall: cada um dos 6+ formatos modernos é redatado (0 literal).
- AT-MV03-02 — multi-segredo numa única linha → todos redatados.
- AT-MV03-03 — anti-FP: identificadores benignos (`task-project-id`) intactos.
- AT-MV03-04 — zero-literal no SanitizationReportEntry (gate ADR-004 / RS-005).

Tokens são SINTÉTICOS (formato realista, valor arbitrário) — não há segredo real.
"""
from __future__ import annotations

import pytest

from repo_sanitizer.f3_sanitizer import sanitize_text_content
from repo_sanitizer.schemas.sanitization_report_entry import SanitizationReportEntry

_GH_A = "A" * 22
_GH_B = "B" * 59

# 6+ formatos modernos (cada um casa SUA regra dedicada nova v1.2.0).
ADVERSARIAL_TOKENS: dict[str, str] = {
    "github_pat": "github_pat_" + _GH_A + "_" + _GH_B,
    "openai_sk_proj": "sk-proj-T3BlbkAJ" + "Q3mZ" * 8,
    "stripe_sk_live": "sk_live_" + "Xk9" * 9,
    "stripe_whsec": "whsec_" + "Wh7" * 9,
    "gitlab_glpat": "glpat-" + "Gp5" * 9,
    "slack_xapp": "xapp-1-" + "Sl3" * 9,
    "aws_asia": "ASIA" + "QWERTYUIOP123456",
    "aws_aroa": "AROA" + "ZXCVBNMASDFGHJKL",
}


# ---------------------------------------------------------------------------
# AT-MV03-01 — recall 100% (cada formato redatado, 0 literal)
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("name,token", sorted(ADVERSARIAL_TOKENS.items()))
def test_at_mv03_01_recall_cada_formato(name: str, token: str) -> None:
    text = f"config:\n  chave: {token}\n"
    res = sanitize_text_content(text, "utf-8", timeout_seconds=5)
    assert token not in res.sanitized_text, f"LEAK: {name} literal sobreviveu"
    assert "<REDACTED-" in res.sanitized_text
    assert len(res.matches) >= 1


# ---------------------------------------------------------------------------
# AT-MV03-02 — multi-segredo numa linha (todos redatados)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_at_mv03_02_multi_segredo_uma_linha() -> None:
    tokens = list(ADVERSARIAL_TOKENS.values())
    line = "envs: " + " ".join(tokens)
    res = sanitize_text_content(line, "utf-8", timeout_seconds=5)
    for tok in tokens:
        assert tok not in res.sanitized_text, f"LEAK multi-segredo: {tok[:12]}..."


# ---------------------------------------------------------------------------
# AT-MV03-03 — anti-FP: identificadores benignos intactos
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "benigno",
    [
        "const taskProjectId = 'task-project-id-internal';",
        "variable my_whsecret_handler is fine",
        "documentation about glpat- prefix in general terms",
        "the word github_pat_ alone without a real token body",
    ],
)
def test_at_mv03_03_anti_fp_identificadores(benigno: str) -> None:
    res = sanitize_text_content(benigno, "utf-8", timeout_seconds=5)
    # Nenhum dos NOVOS tipos modernos dispara em texto benigno.
    novos = {
        "API_KEY_github_pat", "API_KEY_openai_sk_proj", "API_KEY_stripe",
        "WEBHOOK_stripe", "API_KEY_gitlab_pat", "API_KEY_slack_app",
        "API_KEY_aws_temp",
    }
    disparos = {r.tipo for r, _ln, _enc in res.matches} & novos
    assert disparos == set(), f"FP nos prefixos modernos: {disparos}"


# ---------------------------------------------------------------------------
# AT-MV03-04 — zero-literal no report (gate ADR-004 / RS-005)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_at_mv03_04_zero_literal_no_report() -> None:
    # Entry legítimo (só tipo canônico) PASSA no gate `assert_no_literal_secrets`.
    ok = SanitizationReportEntry(
        path_redacted="src/config.py",
        linha=12,
        categoria="C2",
        tipo="API_KEY_gitlab_pat",
        acao="redact_inline",
        encoding_detected="utf-8",
    )
    assert ok.tipo == "API_KEY_gitlab_pat"

    # Entry que tentasse embutir o literal de um segredo coberto pelo gate
    # (`sk-...` ∈ SECRET_REGEXES Sentinel) no campo path é REJEITADO (RS-005).
    # O gate `assert_no_literal_secrets` roda dentro de um model_validator, logo
    # o pydantic empacota `SecretLeakInArtifactError` num `ValidationError`.
    from pydantic import ValidationError

    from repo_sanitizer.schemas._secrets_gate import get_secret_regexes

    if not get_secret_regexes():
        pytest.skip("gate em modo no-op (bootstrap Sentinel ausente)")

    with pytest.raises(ValidationError, match="RS-005"):
        SanitizationReportEntry(
            path_redacted="cfg/sk-" + "A" * 24,  # literal sk-... proibido (gate)
            linha=12,
            categoria="C2",
            tipo="API_KEY_openai_sk_proj",
            acao="redact_inline",
            encoding_detected="utf-8",
        )
