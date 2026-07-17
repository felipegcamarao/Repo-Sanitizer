"""test_author_hardcoded.py — C1 / MV-05 / RS-NEW-035/041 / §5-8 (security).

- bypass: campo custom em `.sanitizer-allow`/manifest do source NAO altera o
  conjunto de campos redatados (lista HARDCODED — RS-NEW-035);
- modulo nao le config de autoria do filesystem do source;
- `augment_identity_from_env` deriva identidade SO do ambiente, sem subprocess git.
"""
from __future__ import annotations

import inspect
from pathlib import Path

from repo_sanitizer.helpers import _author_detector as ad
from repo_sanitizer.helpers._author_detector import redact_authorship
from repo_sanitizer.helpers._operator_identity_loader import augment_identity_from_env
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

# ---------------------------------------------------------------------------
# RS-NEW-035 — campos de autoria HARDCODED (anti-bypass por config-do-source)
# ---------------------------------------------------------------------------

def test_author_fields_hardcoded_not_read_from_source(tmp_path: Path) -> None:
    """`.sanitizer-allow` no source com campo custom NAO altera o que e redatado.

    A lista de manifests/campos e constante do modulo; nenhum arquivo de source
    pode estende-la ou desliga-la.
    """
    (tmp_path / ".sanitizer-allow").write_text(
        "skip_authors: true\n", encoding="utf-8",
    )
    text = (
        "[project]\n"
        'name = "pkg"\n'
        'authors = [{name = "Noma Nomao", email = "noma@acme.io"}]\n'
    )
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    # Config do source ignorada -> autoria ainda redatada.
    assert "noma@acme.io" not in out
    assert len(matches) >= 1


def test_module_does_not_read_source_config() -> None:
    """Grep de codigo: o modulo de autoria nao le allowlist de config do source.

    Os unicos `tomllib.loads`/`json.loads` operam sobre o TEXTO recebido (em
    memoria), nunca abrindo arquivos do filesystem (sem open/read_text/read_bytes).
    """
    source = inspect.getsource(ad)
    for forbidden in ("open(", ".read_text(", ".read_bytes(", "Path("):
        assert forbidden not in source, f"autoria nao deve fazer IO: {forbidden!r}"


def test_custom_manifest_field_not_redacted() -> None:
    """Campo NAO-canonico (`developer_secret`) num manifest custom -> nao redatado.

    So os campos de autoria HARDCODED disparam; arquivo nao-manifest e no-op.
    """
    text = 'developer_secret = "noma@acme.io"\n'
    out, matches = redact_authorship(text, "custom.toml", "custom.toml")
    assert out == text  # custom.toml nao esta em AUTHOR_MANIFESTS
    assert matches == []


# ---------------------------------------------------------------------------
# §5-8 — augment_identity_from_env (sem git, so ambiente)
# ---------------------------------------------------------------------------

def test_augment_from_env_email(monkeypatch) -> None:
    """EMAIL do ambiente -> pattern de redacao + username local."""
    monkeypatch.setenv("EMAIL", "noma.nomao@acme.io")
    base = OperatorIdentitySchema()
    aug = augment_identity_from_env(base)
    # email vira pattern de redacao (escapado).
    assert any("noma" in p for p in aug.extra_redact_patterns)
    # parte local vira username.
    assert "noma.nomao" in aug.usernames


def test_augment_from_env_git_author_name(monkeypatch) -> None:
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Noma Nomao")
    aug = augment_identity_from_env(OperatorIdentitySchema())
    assert "Noma Nomao" in aug.names


def test_augment_ignores_malformed_email(monkeypatch) -> None:
    """EMAIL malformado nao e adicionado (validacao defensiva)."""
    monkeypatch.setenv("EMAIL", "not-an-email")
    aug = augment_identity_from_env(OperatorIdentitySchema())
    assert not any("not-an-email" in p for p in aug.extra_redact_patterns)


def test_augment_no_subprocess_git() -> None:
    """Grep de codigo: augment nao usa subprocess (INV-8 / §5-8).

    Identidade derivada SO de env-vars (`EMAIL`/`GIT_AUTHOR_EMAIL`/...) e de
    `os`/`getpass`; NUNCA executa `git` via subprocess.
    """
    from repo_sanitizer.helpers import _operator_identity_loader as loader
    # `import subprocess` ausente do modulo -> impossivel invocar processo.
    assert "subprocess" not in loader.__dict__
    # Sintaxe de invocacao de processo ausente do codigo (ignora comentarios via
    # checagem de chamadas concretas).
    source = inspect.getsource(loader)
    for forbidden in ("subprocess.", "Popen(", "os.system(", "os.popen(", "check_output("):
        assert forbidden not in source, f"augment nao deve invocar processo: {forbidden!r}"


def test_augment_is_idempotent(monkeypatch) -> None:
    """Aplicar duas vezes nao duplica entradas (dedup)."""
    monkeypatch.setenv("EMAIL", "noma@acme.io")
    aug1 = augment_identity_from_env(OperatorIdentitySchema())
    aug2 = augment_identity_from_env(aug1)
    assert len(aug2.usernames) == len(set(aug2.usernames))
    assert len(aug2.extra_redact_patterns) == len(set(aug2.extra_redact_patterns))


def test_augment_never_raises_returns_schema() -> None:
    """augment sempre retorna um OperatorIdentitySchema (never-raise / ADR-013)."""
    out = augment_identity_from_env(OperatorIdentitySchema())
    assert isinstance(out, OperatorIdentitySchema)
