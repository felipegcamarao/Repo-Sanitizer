"""test__pii_redactor.py — PII redaction smoke (ADR-028)."""
from __future__ import annotations

from repo_sanitizer.helpers._pii_redactor import REDACTED_TOKEN, redact_path, redact_paths


def test_redact_cpf_formatado() -> None:
    s = "C:/projects/Noma-Rabia-123.456.789-01/file.py"
    out = redact_path(s)
    assert REDACTED_TOKEN in out
    assert "123.456.789-01" not in out


def test_redact_cpf_cru() -> None:
    s = "/data/12345678901/export.csv"
    out = redact_path(s)
    assert REDACTED_TOKEN in out


def test_redact_cnpj() -> None:
    s = "Cliente 12.345.678/0001-90 pasta"
    out = redact_path(s)
    assert REDACTED_TOKEN in out


def test_redact_email() -> None:
    s = "/users/noma@acme.io/repo"
    out = redact_path(s)
    assert REDACTED_TOKEN in out


def test_redact_nome_proprio() -> None:
    s = "C:/users/Noma_Rabia/projeto"
    out = redact_path(s)
    assert REDACTED_TOKEN in out


def test_no_redact_safe_path() -> None:
    s = "C:/VS Code/Git Hub - Noma/GIT_repo/README.md"
    out = redact_path(s)
    # "Git Hub - Noma" contem "Noma" mas nao trigga nome-proprio porque
    # so 1 palavra capitalized. "GIT_repo" sem PII. OK.
    # Mas "Noma" sozinho nao deve matchar. Verifica que paths canonicos passam.
    assert "GIT_repo" in out


def test_redact_paths_batch() -> None:
    inputs = [
        "a@b.com",
        "safe.txt",
        "123.456.789-00",
    ]
    out = redact_paths(inputs)
    assert REDACTED_TOKEN in out[0]
    assert out[1] == "safe.txt"
    assert REDACTED_TOKEN in out[2]
