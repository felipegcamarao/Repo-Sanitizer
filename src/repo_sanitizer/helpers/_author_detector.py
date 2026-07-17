"""_author_detector.py — Detector ESTRUTURAL de autoria em manifests.

v1.2.0 / MV-05 / RS-NEW-041 (+035, +045) / ADR-038 / mitigacoes §5-7/8.

Redata SOMENTE campos de **autoria** (nome+email) em manifests de pacote, com
placeholders que PRESERVAM a estrutura do manifest (Gate G2 valida o build):
- `<REDACTED-AUTHOR-NAME>` / `<REDACTED-AUTHOR-EMAIL>`.

Manifests cobertos (HARDCODED — RS-NEW-035, anti-bypass por config-do-source):
- `pyproject.toml`: `[project] authors=[{name=, email=}]` + `maintainers`;
  `[tool.poetry] authors=["Nome <email>"]` + `maintainers`.
- `package.json`: `author` (string ou objeto), `contributors`, `maintainers`.
- `Cargo.toml`: `[package] authors=["Nome <email>"]`.
- `composer.json`: `authors=[{name, email}]`.
- `AUTHORS` / `CONTRIBUTORS` (arquivo de texto, 1 autor/linha).
- `CITATION.cff`: `authors: - family-names/given-names/email`.

NUNCA toca `name` do pacote, `dependencies`, `license`, `version`, `description`
(MV05-B / §5-7) — redatar isso quebraria o build.

Parsing DEFENSIVO (§5-7 / MV05-D): tenta `tomllib`/`json` por manifest; se
malformado -> **fallback regex textual** de email/`Nome <email>` (NUNCA skip
silencioso, NUNCA crash).

INV: este modulo e read-only sobre o texto JA em memoria (copy-then-redact-in-dest,
RS-NEW-045); nunca le config de autoria do source para decidir o que redatar — a
lista de campos/manifests e CONSTANTE deste modulo.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Placeholders canonicos (preservam a ESTRUTURA do manifest -> G2 / §5-7).
# ---------------------------------------------------------------------------

REDACTED_AUTHOR_NAME = "<REDACTED-AUTHOR-NAME>"
REDACTED_AUTHOR_EMAIL = "<REDACTED-AUTHOR-EMAIL>"

# ---------------------------------------------------------------------------
# Manifests HARDCODED (basename lowercase) onde autoria e redatada.
# ---------------------------------------------------------------------------

AUTHOR_MANIFESTS: frozenset[str] = frozenset({
    "pyproject.toml", "package.json", "cargo.toml", "composer.json",
    "authors", "contributors", "authors.md", "contributors.md",
    "authors.txt", "contributors.txt", "citation.cff",
})

#: Chaves de campo de autoria (nunca `name`/`dependencies`/`license`).
_AUTHOR_KEYS: frozenset[str] = frozenset({
    "authors", "author", "maintainers", "maintainer", "contributors",
})

# ---------------------------------------------------------------------------
# Regex de fallback / textual (HARDCODED).
# ---------------------------------------------------------------------------

#: Email RFC-ish (ancorado, cap defensivo anti-ReDoS).
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}(?![\w-])"
)

#: `Nome Sobrenome <email>` (formato Cargo/poetry/git). Captura nome e email.
_NAME_ANGLE_EMAIL_RE = re.compile(
    r"(?P<name>[^\"'<>\n,]{1,120}?)\s*<\s*"
    r"(?P<email>[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})\s*>"
)


@dataclass(frozen=True)
class AuthorMatch:
    """Achado de autoria — ZERO-LITERAL (so metadados; nunca o valor).

    `field` = chave de autoria (`authors`/`author`/...); `kind` = `name`|`email`.
    """

    rel_path: str
    field: str
    kind: str  # "name" | "email"


def _redact_name_angle_email(text: str, field: str, rel_path: str,
                             matches: list[AuthorMatch]) -> str:
    """Redata todos os `Nome <email>` no texto (placeholder preserva estrutura)."""
    def _repl(m: re.Match[str]) -> str:
        matches.append(AuthorMatch(rel_path=rel_path, field=field, kind="name"))
        matches.append(AuthorMatch(rel_path=rel_path, field=field, kind="email"))
        return f"{REDACTED_AUTHOR_NAME} <{REDACTED_AUTHOR_EMAIL}>"
    return _NAME_ANGLE_EMAIL_RE.sub(_repl, text)


def _redact_emails(text: str, field: str, rel_path: str,
                   matches: list[AuthorMatch]) -> str:
    """Redata emails soltos (sem `<>`) no texto."""
    def _repl(m: re.Match[str]) -> str:
        matches.append(AuthorMatch(rel_path=rel_path, field=field, kind="email"))
        return REDACTED_AUTHOR_EMAIL
    return _EMAIL_RE.sub(_repl, text)


# ---------------------------------------------------------------------------
# Localizacao estrutural dos blocos de autoria (parsing-aware mas redacao textual).
# ---------------------------------------------------------------------------
# Estrategia: usar o parser (tomllib/json) APENAS para CONFIRMAR que ha campo de
# autoria com valor (anti-FP em manifest sem autoria). A redacao em si e textual
# sobre o BLOCO do campo (preserva formatacao/comentarios; nunca toca `name`/dep).


def _has_author_data_toml(text: str) -> bool:
    """True sse o TOML tem algum campo de autoria nao-vazio (parse defensivo)."""
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return False
    # PEP 621: [project] authors/maintainers
    project = data.get("project")
    if isinstance(project, dict):
        for k in ("authors", "maintainers"):
            if project.get(k):
                return True
    # Poetry: [tool.poetry] authors/maintainers
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            for k in ("authors", "maintainers"):
                if poetry.get(k):
                    return True
    # Cargo: [package] authors
    package = data.get("package")
    return bool(isinstance(package, dict) and package.get("authors"))


def _has_author_data_json(text: str) -> bool:
    """True sse o JSON tem algum campo de autoria nao-vazio (parse defensivo)."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return any(data.get(k) for k in _AUTHOR_KEYS)


# Regex que isolam o BLOCO de um campo de autoria (array/objeto) para redacao
# cirurgica — nunca toca outros campos. Ancorados na chave de autoria.

# TOML array `authors = [ ... ]` / `maintainers = [ ... ]` (single ou multi-linha).
# SEC-01 (hotfix): sub-padrao NAO-ambiguo `[^\[\]]*?`. A classe negada `[^\[\]]`
# JA casa `\n`, entao o antigo alternante `(?:[^\[\]]|\n)*?` era REDUNDANTE e
# criava catastrophic backtracking (ReDoS) em input desbalanceado. Mesma semantica
# (casa qualquer char exceto colchetes, incluindo newline), agora LINEAR.
_TOML_AUTHOR_BLOCK_RE = re.compile(
    r"(?im)^[ \t]*(?P<key>authors|maintainers)[ \t]*=[ \t]*"
    r"(?P<val>\[[^\[\]]*?\])"
)

# JSON `"author": <obj|string>` e `"contributors"|"maintainers": [ ... ]`.
_JSON_AUTHOR_OBJ_RE = re.compile(
    r"(?s)\"(?P<key>author|maintainer)\"[ \t]*:[ \t]*\{(?P<val>[^{}]*?)\}"
)
_JSON_AUTHOR_STR_RE = re.compile(
    r"\"(?P<key>author|maintainer)\"[ \t]*:[ \t]*\"(?P<val>[^\"]*)\""
)
# SEC-01 (hotfix): idem `_TOML_AUTHOR_BLOCK_RE` — `[^\[\]]*?` linear (sem o
# alternante `|\n` redundante que causava catastrophic backtracking).
_JSON_AUTHOR_ARR_RE = re.compile(
    r"(?s)\"(?P<key>authors|contributors|maintainers)\"[ \t]*:[ \t]*"
    r"(?P<val>\[[^\[\]]*?\])"
)

# JSON pares `"name": "..."` / `"email": "..."` DENTRO de um bloco de autoria.
_JSON_INNER_NAME_RE = re.compile(r"\"name\"[ \t]*:[ \t]*\"(?P<v>[^\"]*)\"")
_JSON_INNER_EMAIL_RE = re.compile(r"\"(email|url)\"[ \t]*:[ \t]*\"(?P<v>[^\"]*)\"")


def _redact_toml(text: str, rel_path: str, matches: list[AuthorMatch]) -> str:
    """Redata blocos de autoria TOML (`authors`/`maintainers`)."""
    def _block_repl(m: re.Match[str]) -> str:
        key = m.group("key")
        val = m.group("val")
        # Dentro do array: `"Nome <email>"` (Cargo/poetry) ou `{name=, email=}`.
        new_val = _redact_name_angle_email(val, key, rel_path, matches)
        # Emails soltos remanescentes (ex.: PEP 621 `{name="x", email="y@z"}`).
        new_val = _redact_emails(new_val, key, rel_path, matches)
        # Nomes em `name = "..."` dentro do array de tabelas inline (PEP 621).
        def _name_repl(nm: re.Match[str]) -> str:
            matches.append(AuthorMatch(rel_path=rel_path, field=key, kind="name"))
            return f'name = "{REDACTED_AUTHOR_NAME}"'
        new_val = re.sub(r'name[ \t]*=[ \t]*"[^"]*"', _name_repl, new_val)
        return f"{key} = {new_val}"
    return _TOML_AUTHOR_BLOCK_RE.sub(_block_repl, text)


def _redact_json_block(val: str, key: str, rel_path: str,
                       matches: list[AuthorMatch]) -> str:
    """Redata `name`/`email`/`url` dentro de um bloco de autoria JSON."""
    def _name_repl(nm: re.Match[str]) -> str:
        matches.append(AuthorMatch(rel_path=rel_path, field=key, kind="name"))
        return f'"name": "{REDACTED_AUTHOR_NAME}"'

    def _email_repl(em: re.Match[str]) -> str:
        matches.append(AuthorMatch(rel_path=rel_path, field=key, kind="email"))
        return f'"{em.group(1)}": "{REDACTED_AUTHOR_EMAIL}"'

    out = _JSON_INNER_NAME_RE.sub(_name_repl, val)
    out = _JSON_INNER_EMAIL_RE.sub(_email_repl, out)
    # Emails soltos dentro de strings tipo "Nome <email>".
    out = _redact_name_angle_email(out, key, rel_path, matches)
    out = _redact_emails(out, key, rel_path, matches)
    return out


def _redact_json(text: str, rel_path: str, matches: list[AuthorMatch]) -> str:
    """Redata blocos de autoria JSON (`author`/`contributors`/`maintainers`)."""
    def _obj_repl(m: re.Match[str]) -> str:
        key = m.group("key")
        new_val = _redact_json_block(m.group("val"), key, rel_path, matches)
        return f'"{key}": {{{new_val}}}'

    def _str_repl(m: re.Match[str]) -> str:
        key = m.group("key")
        raw = m.group("val")
        # author string: "Nome <email> (url)" -> redata nome+email se houver.
        if "<" in raw and "@" in raw:
            new_raw = _redact_name_angle_email(raw, key, rel_path, matches)
        elif "@" in raw:
            new_raw = _redact_emails(raw, key, rel_path, matches)
        else:
            # autor sem email: redata o nome inteiro.
            matches.append(AuthorMatch(rel_path=rel_path, field=key, kind="name"))
            new_raw = REDACTED_AUTHOR_NAME
        return f'"{key}": "{new_raw}"'

    def _arr_repl(m: re.Match[str]) -> str:
        key = m.group("key")
        new_val = _redact_json_block(m.group("val"), key, rel_path, matches)
        return f'"{key}": {new_val}'

    out = _JSON_AUTHOR_OBJ_RE.sub(_obj_repl, text)
    out = _JSON_AUTHOR_ARR_RE.sub(_arr_repl, out)
    out = _JSON_AUTHOR_STR_RE.sub(_str_repl, out)
    return out


def _redact_plain_authors(text: str, rel_path: str,
                          matches: list[AuthorMatch]) -> str:
    """Redata arquivo AUTHORS/CONTRIBUTORS (1 autor/linha: `Nome <email>`)."""
    out = _redact_name_angle_email(text, "authors", rel_path, matches)
    out = _redact_emails(out, "authors", rel_path, matches)
    return out


def _redact_textual_fallback(text: str, rel_path: str,
                             matches: list[AuthorMatch]) -> str:
    """Fallback textual quando o parser falha (manifest malformado / §5-7 MV05-D).

    NUNCA skip silencioso: aplica redacao de `Nome <email>` + emails soltos.
    """
    out = _redact_name_angle_email(text, "author", rel_path, matches)
    out = _redact_emails(out, "author", rel_path, matches)
    return out


def redact_authorship(
    text: str,
    basename: str,
    rel_path: str,
) -> tuple[str, list[AuthorMatch]]:
    """Redata campos de AUTORIA em manifests (estrutural + fallback defensivo).

    Args:
        text: conteudo do manifest (texto JA em memoria; read-only sobre source).
        basename: nome do arquivo (decide o manifest; HARDCODED).
        rel_path: path relativo POSIX (preenche AuthorMatch.rel_path).

    Returns:
        Tuple (texto_redatado, matches). `matches` vazia se nada redatado.
        ZERO-LITERAL: matches nunca contem o valor; placeholders preservam a
        estrutura do manifest (Gate G2 valida o build).

    Garantias (§5-7 / RS-NEW-041):
        - So redata em manifests da lista HARDCODED (AUTHOR_MANIFESTS).
        - So toca campos de autoria; NUNCA `name`/`dependencies`/`license`.
        - Parser falha -> fallback regex textual (nunca crash, nunca skip silente).
    """
    low = basename.lower()
    if low not in AUTHOR_MANIFESTS:
        return (text, [])

    matches: list[AuthorMatch] = []

    if low == "pyproject.toml" or low == "cargo.toml":
        if _has_author_data_toml(text):
            out = _redact_toml(text, rel_path, matches)
        else:
            # TOML malformado OU sem autoria estruturada -> fallback textual
            # apenas se o parse FALHOU (malformado); se parse OK e sem autoria,
            # nao redata nada (anti-FP).
            try:
                tomllib.loads(text)
                out = text  # parse OK, sem autoria -> no-op
            except (tomllib.TOMLDecodeError, ValueError):
                out = _redact_textual_fallback(text, rel_path, matches)
        return (out, matches)

    if low in ("package.json", "composer.json"):
        if _has_author_data_json(text):
            out = _redact_json(text, rel_path, matches)
        else:
            try:
                json.loads(text)
                out = text  # parse OK, sem autoria -> no-op
            except (json.JSONDecodeError, ValueError):
                out = _redact_textual_fallback(text, rel_path, matches)
        return (out, matches)

    if low == "citation.cff":
        # CFF e YAML; sem parser dedicado -> redacao textual de email/nome-angle.
        out = _redact_name_angle_email(text, "authors", rel_path, matches)
        out = _redact_emails(out, "authors", rel_path, matches)
        return (out, matches)

    # AUTHORS / CONTRIBUTORS (+ variantes .md/.txt)
    out = _redact_plain_authors(text, rel_path, matches)
    return (out, matches)


def is_author_manifest(basename: str) -> bool:
    """True sse `basename` e um manifest onde autoria estrutural se aplica."""
    return basename.lower() in AUTHOR_MANIFESTS


__all__ = [
    "AUTHOR_MANIFESTS",
    "REDACTED_AUTHOR_EMAIL",
    "REDACTED_AUTHOR_NAME",
    "AuthorMatch",
    "is_author_manifest",
    "redact_authorship",
]
