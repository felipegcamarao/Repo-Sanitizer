"""test__pii_redactor_extra.py — Bloco 02 02.7 full impl smoke (ADR-028 + RS-018).

Cobertura adicional sobre full impl: 8+ fixtures cobrindo CPF/CNPJ/email/nome,
ordem de aplicacao (CNPJ antes CPF), summary/has_pii.
"""
from __future__ import annotations

from repo_sanitizer.helpers._pii_redactor import (
    REDACTED_TOKEN,
    has_pii,
    redact_path,
    summary,
)


def test_redact_email_dominio_com_pontos() -> None:
    s = "/users/john.doe@empresa.com.br/repo"
    out = redact_path(s)
    assert REDACTED_TOKEN in out
    assert "john.doe@empresa.com.br" not in out


def test_redact_cnpj_completo() -> None:
    s = "Cliente: 12.345.678/0001-90 pasta"
    out = redact_path(s)
    assert REDACTED_TOKEN in out
    assert "12.345.678/0001-90" not in out


def test_redact_cnpj_antes_de_cpf_no_evita_overlap() -> None:
    """CNPJ tem 14 digitos formatados (dois primeiros sao DV/sequencia que poderiam matchar CPF parcial).
    Garante que CNPJ inteiro foi consumido antes do CPF tentar."""
    s = "doc 12.345.678/0001-90 e cpf 123.456.789-00 ambos"
    out = redact_path(s)
    assert "12.345.678/0001-90" not in out
    assert "123.456.789-00" not in out
    # 2 redactions (CNPJ + CPF formatado)
    assert out.count(REDACTED_TOKEN) == 2


def test_redact_cpf_cru_em_path_segment() -> None:
    s = "/exports/12345678901/data.csv"
    out = redact_path(s)
    assert REDACTED_TOKEN in out
    assert "12345678901" not in out


def test_no_redact_numero_curto_que_nao_e_cpf() -> None:
    """10 digitos != CPF; 12 digitos != CPF; nao redact."""
    s = "/data/1234567890/file.csv"
    out = redact_path(s)
    assert "1234567890" in out  # nao matcha pattern CPF (precisa ser exatamente 11)


def test_no_redact_numero_dentro_de_sequencia_maior() -> None:
    """16 digitos (cartao de credito) NAO deve trigar CPF cru."""
    s = "/log/transacao-1234567890123456-ok.txt"
    out = redact_path(s)
    assert "1234567890123456" in out


def test_redact_nome_proprio_com_acento() -> None:
    s = "C:/users/José-António/repo"
    out = redact_path(s)
    assert REDACTED_TOKEN in out


def test_redact_nome_proprio_underscore() -> None:
    s = "/home/Noma_Rabia/projeto"
    out = redact_path(s)
    assert REDACTED_TOKEN in out


def test_no_redact_nome_unico() -> None:
    """Nome solo NAO ativa heuristica (precisa Nome+Sobrenome)."""
    s = "/home/Noma/repo"
    out = redact_path(s)
    assert "Noma" in out


def test_redact_multiplas_pii_no_mesmo_path() -> None:
    s = "/data/Noma-Rabia/john.doe@empresa.com/123.456.789-00.csv"
    out = redact_path(s)
    # 3 redactions: nome + email + CPF
    assert out.count(REDACTED_TOKEN) >= 3


def test_has_pii_true_para_email() -> None:
    assert has_pii("a@b.com") is True


def test_has_pii_true_para_cpf() -> None:
    assert has_pii("123.456.789-00") is True


def test_has_pii_false_para_path_seguro() -> None:
    assert has_pii("/projeto/src/main.py") is False


def test_has_pii_false_para_string_vazia() -> None:
    assert has_pii("") is False


def test_summary_contagem() -> None:
    s = "/data/Noma-Rabia/john.doe@empresa.com/123.456.789-00 + 12.345.678/0001-90"
    counts = summary(s)
    assert counts["cnpj"] == 1
    assert counts["cpf_formatado"] == 1
    assert counts["email"] == 1
    assert counts["nome_proprio"] >= 1


def test_summary_zero_pii_path_seguro() -> None:
    counts = summary("/projeto/src/main.py")
    assert all(v == 0 for v in counts.values())


def test_redact_path_string_vazia_safe() -> None:
    assert redact_path("") == ""


def test_redact_path_idempotente_apos_redact() -> None:
    """Aplicar redact 2x = mesmo resultado (token ja la)."""
    s = "a@b.com"
    out1 = redact_path(s)
    out2 = redact_path(out1)
    assert out1 == out2


def test_redact_path_email_em_segmento_url() -> None:
    """Edge case: email + path subsequente."""
    s = "https://api/users/admin@acme.io/profile.json"
    out = redact_path(s)
    assert "admin@acme.io" not in out
    assert "profile.json" in out  # parte segura preservada
