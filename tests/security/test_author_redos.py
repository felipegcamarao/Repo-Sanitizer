"""test_author_redos.py — ReDoS analysis dos regex de autoria (MV-05 / §5-4).

Adicionado pelo **#06-Security-Agent** (auditoria v1.2.0, evidence-first).

CONTEXTO (achado MÉDIO — defesa-em-camadas):
Os regex de bloco de autoria em `_author_detector.py`
(`_TOML_AUTHOR_BLOCK_RE`, `_JSON_AUTHOR_ARR_RE`, `_JSON_AUTHOR_OBJ_RE`) usam o
sub-padrão `(?:[^\\[\\]]|\\n)*?` / `[^{}]*?` com `\\n` SOBREPOSTO à classe negada.
Em entrada com colchete/chave de ABERTURA mas SEM o fechamento correspondente,
isso produz **catastrophic backtracking** (exponencial): empiricamente
n=20 entradas ~0.18 s, n=25 ~14 s (medido na auditoria #06).

POR QUE NÃO É EXPLORÁVEL NA PRÁTICA (mitigação existente):
`redact_authorship` só chama esses regex DEPOIS de `tomllib.loads`/`json.loads`
terem sucesso (`_has_author_data_*` == True). Um parse bem-sucedido GARANTE
colchetes/chaves balanceados -> o fechamento sempre existe -> o regex casa de
forma LINEAR. Quando o parse FALHA (manifest malformado / colchete não-fechado),
o código vai para o `_redact_textual_fallback`, que usa APENAS
`_NAME_ANGLE_EMAIL_RE`/`_EMAIL_RE` (ambos lineares, com caps) — os regex de bloco
NÃO rodam sobre entrada desbalanceada.

ESTE TESTE prova a mitigação (a entrada adversarial NÃO chega aos regex perigosos
via `redact_authorship`) e serve de gate de regressão: se um refactor futuro
expuser os regex de bloco a entrada desbalanceada (ou remover o gate de parse),
estes asserts de tempo falham.

HOTFIX SEC-01 (#04-Executor, v1.2.0): a recomendação foi APLICADA — os sub-padrões
ambíguos `(?:[^\\[\\]]|\\n)*?` em `_TOML_AUTHOR_BLOCK_RE` e `_JSON_AUTHOR_ARR_RE`
foram trocados por `[^\\[\\]]*?` (a classe negada já casa `\\n`; o alternante `|\\n`
era redundante e a causa do backtracking). Agora TANTO o caminho de produção QUANTO
o caminho ADVERSARIAL (regex bruto sobre input desbalanceado) são LINEARES.
Os testes `test_*_raw_regex_*_adversarial_is_linear` abaixo fixam esse hardening:
medem o regex CRU diretamente sobre array não-fechado e exigem tempo linear/limitado
(antes do fix: n=25 ~31 s TOML / ~100 s JSON, catastrophic backtracking).
"""
from __future__ import annotations

import json
import time

from repo_sanitizer.helpers._author_detector import (
    _JSON_AUTHOR_ARR_RE,
    _TOML_AUTHOR_BLOCK_RE,
    redact_authorship,
)

# Orçamento de tempo generoso (a forma linear roda em ~ms; o backtracking levaria
# segundos/minutos). 2.0 s é folgado o suficiente para não dar flake sob carga.
_TIME_BUDGET_S = 2.0


def _elapsed(fn) -> float:
    t0 = time.perf_counter()
    fn()
    return time.perf_counter() - t0


def test_valid_large_package_json_authors_is_linear() -> None:
    """package.json VÁLIDO com array grande de contributors -> redação LINEAR.

    Parse OK => colchetes balanceados => sem catastrophic backtracking.
    """
    contributors = [{"name": "a", "email": "a@b.co"} for _ in range(400)]
    text = json.dumps({"name": "pkg", "version": "1.0.0",
                       "contributors": contributors}, indent=2)
    dt = _elapsed(lambda: redact_authorship(text, "package.json", "package.json"))
    assert dt < _TIME_BUDGET_S, f"ReDoS suspeito em package.json válido: {dt:.2f}s"
    # E redigiu de fato (não no-op):
    out, matches = redact_authorship(text, "package.json", "package.json")
    assert "a@b.co" not in out
    assert len(matches) >= 1


def test_valid_large_pyproject_authors_is_linear() -> None:
    """pyproject.toml VÁLIDO com array grande de authors -> redação LINEAR."""
    authors = ",\n".join(
        ['  {name = "a", email = "a@b.co"}' for _ in range(400)]
    )
    text = (
        '[project]\nname = "pkg"\nversion = "1.0.0"\n'
        f"authors = [\n{authors}\n]\n"
    )
    dt = _elapsed(lambda: redact_authorship(text, "pyproject.toml", "pyproject.toml"))
    assert dt < _TIME_BUDGET_S, f"ReDoS suspeito em pyproject válido: {dt:.2f}s"


def test_malformed_unclosed_toml_array_uses_safe_fallback() -> None:
    """TOML MALFORMADO (array não-fechado) -> fallback textual LINEAR (não trava).

    Este é exatamente o input que causaria catastrophic backtracking se chegasse
    ao `_TOML_AUTHOR_BLOCK_RE`. A mitigação (gate de parse) desvia para o fallback.
    """
    text = 'authors = [' + ('"a@b.co"\n' * 2000)  # nunca fecha o array
    dt = _elapsed(lambda: redact_authorship(text, "pyproject.toml", "pyproject.toml"))
    assert dt < _TIME_BUDGET_S, f"manifest malformado travou (ReDoS): {dt:.2f}s"
    # O fallback ainda redige emails (nunca skip silencioso / §5-7):
    out, matches = redact_authorship(text, "pyproject.toml", "pyproject.toml")
    assert "a@b.co" not in out
    assert len(matches) >= 1


def test_malformed_unclosed_json_array_uses_safe_fallback() -> None:
    """package.json MALFORMADO (array não-fechado) -> fallback textual LINEAR."""
    text = '{"contributors": [' + ('{"name":"a","email":"a@b.co"},\n' * 2000)
    dt = _elapsed(lambda: redact_authorship(text, "package.json", "package.json"))
    assert dt < _TIME_BUDGET_S, f"json malformado travou (ReDoS): {dt:.2f}s"
    out, _matches = redact_authorship(text, "package.json", "package.json")
    assert "a@b.co" not in out


def test_bracket_in_string_value_does_not_trigger_backtracking() -> None:
    """Colchete LITERAL em valor de string não dispara backtracking (falha rápido)."""
    contributors = [{"name": "[", "email": "a@b.co"} for _ in range(200)]
    text = json.dumps({"contributors": contributors}, indent=2)
    dt = _elapsed(lambda: redact_authorship(text, "package.json", "package.json"))
    assert dt < _TIME_BUDGET_S, f"bracket-in-value travou: {dt:.2f}s"


# ---------------------------------------------------------------------------
# HOTFIX SEC-01 — gate de regressão do REGEX CRU (caminho adversarial).
#
# Antes do hotfix, alimentar os regex de bloco com um array de ABERTURA SEM
# fechamento causava catastrophic backtracking exponencial (n=25 ~31 s TOML /
# ~100 s JSON, medido). Estes testes batem no regex DIRETAMENTE (sem o gate de
# parse de `redact_authorship`) e exigem tempo LINEAR/limitado — provam que o
# sub-padrão ambíguo foi eliminado. Se alguém reintroduzir `(?:[^\[\]]|\n)*?`,
# estes asserts de tempo voltam a estourar e falham.
# ---------------------------------------------------------------------------

#: Orçamento apertado: a forma linear roda em << 1 ms mesmo com 5000 entradas;
#: o backtracking antigo levava dezenas de segundos. 1.0 s é folga ampla.
_RAW_TIME_BUDGET_S = 1.0


def test_raw_regex_toml_unbalanced_adversarial_is_linear() -> None:
    """Regex CRU TOML sobre array NÃO-FECHADO -> linear (sem catastrophic bt)."""
    # n bem acima do ponto onde o regex antigo já travava (n=25 ~31 s).
    text = "authors = [" + ('"a@b.co"\n' * 5000)  # nunca fecha
    dt = _elapsed(lambda: _TOML_AUTHOR_BLOCK_RE.search(text))
    assert dt < _RAW_TIME_BUDGET_S, (
        f"ReDoS reaberto em _TOML_AUTHOR_BLOCK_RE (input desbalanceado): {dt:.3f}s"
    )
    # Sem fechamento => sem match (semântica correta, falha rápido).
    assert _TOML_AUTHOR_BLOCK_RE.search(text) is None


def test_raw_regex_json_unbalanced_adversarial_is_linear() -> None:
    """Regex CRU JSON sobre array NÃO-FECHADO -> linear (sem catastrophic bt)."""
    text = '"authors": [' + ('{"name":"a","email":"a@b.co"}\n' * 5000)  # nunca fecha
    dt = _elapsed(lambda: _JSON_AUTHOR_ARR_RE.search(text))
    assert dt < _RAW_TIME_BUDGET_S, (
        f"ReDoS reaberto em _JSON_AUTHOR_ARR_RE (input desbalanceado): {dt:.3f}s"
    )
    assert _JSON_AUTHOR_ARR_RE.search(text) is None


def test_raw_regex_still_matches_balanced_multiline_block() -> None:
    """Semântica preservada: o regex novo ainda casa o BLOCO multi-linha inteiro.

    `[^\\[\\]]*?` casa newline (classe negada já incluía `\\n`), então arrays
    multi-linha balanceados continuam sendo capturados por completo — o hotfix
    não muda captura/grupos.
    """
    toml = (
        'authors = [\n'
        '  {name = "a", email = "a@b.co"},\n'
        '  {name = "b", email = "b@c.co"}\n'
        ']\n'
    )
    m = _TOML_AUTHOR_BLOCK_RE.search(toml)
    assert m is not None
    assert m.group("key") == "authors"
    assert m.group("val").startswith("[") and m.group("val").rstrip().endswith("]")
    assert "\n" in m.group("val")  # casou através de múltiplas linhas

    js = (
        '"contributors": [\n'
        '  {"name":"a","email":"a@b.co"},\n'
        '  {"name":"b"}\n'
        ']'
    )
    mj = _JSON_AUTHOR_ARR_RE.search(js)
    assert mj is not None
    assert mj.group("key") == "contributors"
    assert mj.group("val").startswith("[") and mj.group("val").rstrip().endswith("]")
    assert "\n" in mj.group("val")
