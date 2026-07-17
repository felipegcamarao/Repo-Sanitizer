"""_path_sanitizer.py — Camada C10 do F3 (ADR-030 + RS-NEW-032).

Detector determinístico de paths absolutos em arquivos texto, com 3 políticas
canônicas de sanitização:

- (a) `intra_source` — path resolve dentro da `source_root` → relativiza para
  `./<rel>` via `Path.relative_to` (preserva semântica para clones).
- (b) `user_path` — path contém um username declarado em
  `OperatorIdentity.usernames` (case-sensitive) → redata o prefixo até (e
  incluindo) o segmento do username por `~/`.
- (c) `other_absolute` — qualquer outro absoluto (Windows ou Unix) → redata
  para `<workspace>/` + suffix após `/VS Code/`, `/Users/` ou `/home/`.

Ordem de tentativa por match: (a) → (b) → (c). A primeira política aplicável
vence. NUNCA chama LLM (INV-9). NUNCA toca binários (caller deve filtrar via
`_binary_detector` — política do Bloco 02 passo 2.2). NUNCA raise.

Regex pré-compilados (cache global do módulo):

- WINDOWS_PATH_RE — `[A-Za-z]:[\\\\/](segments...)`
- UNIX_PATH_RE    — `(/(?:home|Users)/<user>(/segment)*)`

Edge cases endereçados explicitamente:
- Paths em strings Python (`Path("c:/...")`)
- Paths em URLs file:// (`file:///c:/...`)
- Paths em diff headers (`--- a/c:/...` ou `+++ b/c:/...`)
- Backslash duplo-escape de strings Python (`c:\\\\Users\\\\<user>`)

Cobertura ≥90% gate Bloco 02 (Passo 2.1).

**Interação cascading com Camada C9** (PT-RS-04 layer 3 — INTENCIONAL):
A ordem canônica do F3 é C9 (PII) → C10 (Paths) → C7 (rescan). Quando o texto
chega ao C10, qualquer username em `OperatorIdentity.usernames` JÁ foi
redatado por C9 para `[REDACTED-USER]`. Logo, paths como
`C:/Users/[NOME]/...` chegam ao C10 como `C:/Users/[REDACTED-USER]/...` —
a política (b) `user_path` NÃO dispara (segmento `[NOME]` literal não existe
mais no texto). Cai na política (c) `other_absolute` →
`<workspace>/[REDACTED-USER]/...`. **O objetivo final (zero path absoluto +
zero PII no destino) ainda é atingido** — apenas a atribuição final de
categoria muda. Comportamento INTENCIONAL análogo ao documentado em
`run_c9_pii_detector` ("Cascading sanitization"). Política (b) C10 dispara
quando o username NÃO está em `OperatorIdentity` (e.g., username de outro
operador em paths copy-pasted) — ainda valioso defensivamente.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Literal

from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

PathCategory = Literal["intra_source", "user_path", "other_absolute"]

# ---------------------------------------------------------------------------
# Regex canônicos (ADR-030)
# ---------------------------------------------------------------------------
# Windows absoluto: letra de drive + separador + ao menos um segmento.
# Aceita backslash literal ou forward slash. Para texto vindo de strings Python
# (`"c:\\\\Users\\\\..."`) a sequência `\\\\` aparece como `\\` no texto-fonte
# já lido — i.e., dois backslashes literais entre segmentos. O charset
# `[\\/]+` cobre ambos os casos (`/`, `\`, `\\`, `/\\`...).
#
# Anti-esquema-URL (MV-09 / RS-NEW-046 / ADR-037 / fecha C-V11-04): o negative
# lookbehind `(?<![A-Za-z])` de LARGURA FIXA impede casar a letra de drive
# quando precedida por outra letra. Em `https://x`, o `s:` (de `httpS`) deixa de
# casar `[A-Za-z]:` → URLs (`https://`/`http://`/`ftp://`/`file://`) não viram
# `<workspace>`. Largura fixa (sem quantificador) ⇒ zero catastrophic
# backtracking. Paths Windows reais são tipicamente precedidos por espaço,
# aspas, `(`, `=`, `/`, `\`, início-de-linha → continuam casando.
WINDOWS_PATH_RE = re.compile(
    r"(?<![A-Za-z])[A-Za-z]:[\\/]+(?:[^\\/<>:\"|?*\n\r\t]+[\\/]+)+(?:[^\\/<>:\"|?*\n\r\t]+)?",
)

# Unix absoluto: somente raízes contendo username (/home/<user>/... ou
# /Users/<user>/...). Não casamos `/etc`, `/var`, `/usr`, etc., porque eles
# raramente carregam PII e o risco de falso-positivo (relativizar `/etc/...`
# acidentalmente) é maior que o benefício.
UNIX_PATH_RE = re.compile(
    r"/(?:home|Users)/[^/\s<>\"|?*]+(?:/[^/\s<>\"|?*]+)*",
)

# Marcadores de "workspace root" para política (c) — extrai o suffix MAIS curto
# após uma destas barras. Mantém legível o destino sem expor o prefixo do
# operador. Ordem importa (specific-first):
_WORKSPACE_MARKERS = ("/VS Code/", "/Users/", "/home/")


# ---------------------------------------------------------------------------
# Estruturas de dados
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PathMatch:
    """Um match individual de path absoluto detectado e classificado.

    Atributos:
        category: política aplicada (a/b/c).
        original: substring exata como aparece no texto-fonte (NÃO redacted aqui;
            consumer-side decide se loga ou não — em F3 sempre passa por
            `redact_path` antes de qualquer audit/report).
        sanitized: substring de substituição já no formato canônico
            (`./...`, `~/...`, ou `<workspace>/...`).
    """

    category: PathCategory
    original: str
    sanitized: str


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------


def _normalize_separators(raw: str) -> str:
    """Normaliza backslash múltiplo → single slash para análise via PurePath.

    `c:\\\\Users\\\\[NOME]` (8 chars como aparece numa string Python duplo-escapada
    no source) → `c:/Users/[NOME]`. NÃO altera o texto-fonte, apenas a forma
    interna usada para `relative_to` e detecção de username.
    """
    # Colapsa runs de `\` ou `/` para um único `/`
    return re.sub(r"[\\/]+", "/", raw)


def _try_relativize(match: str, source_root: Path) -> str | None:
    """Tenta relativizar `match` para `./<rel>` sob `source_root`.

    Returns:
        String relativa POSIX começando com `./` se sucesso; None em qualquer
        falha (path fora da source-tree, malformado, ou normalização absurda).

    NUNCA raise — todas as exceções de Path são capturadas.
    """
    normalized = _normalize_separators(match)
    candidate: PurePath
    root_pure: PurePath
    if re.match(r"^[A-Za-z]:/", normalized):
        candidate = PureWindowsPath(normalized)
        root_pure = PureWindowsPath(_normalize_separators(str(source_root)))
    else:
        candidate = PurePosixPath(normalized)
        root_pure = PurePosixPath(_normalize_separators(str(source_root)))
    try:
        rel = candidate.relative_to(root_pure)
    except (ValueError, OSError):
        return None
    rel_posix = rel.as_posix()
    # `relative_to` da raiz exata retorna `.` — devolvemos `./` para preservar
    # idempotência da semântica (e zero ambiguidade vs match vazio).
    if rel_posix in ("", "."):
        return "./"
    return f"./{rel_posix}"


def _try_user_redact(match: str, usernames: list[str]) -> str | None:
    """Tenta redatar prefixo até (e incluindo) o segmento do username por `~/`.

    Args:
        match: substring path absoluta exata (mantém separadores originais).
        usernames: lista de usernames case-sensitive (de `OperatorIdentity`).

    Returns:
        String redatada `~/<suffix>` se algum username foi encontrado como
        segmento; None caso contrário.
    """
    if not usernames:
        return None
    # Normalizamos só para localizar segmentos; a fatia volta ao texto original.
    normalized = _normalize_separators(match)
    segments = normalized.split("/")
    for user in usernames:
        if not user:
            continue
        # Busca exata por segmento (case-sensitive — usernames de SO são).
        try:
            idx = segments.index(user)
        except ValueError:
            continue
        # Tudo APÓS o segmento do username vai para o suffix.
        suffix_parts = segments[idx + 1 :]
        suffix = "/".join(suffix_parts)
        if suffix:
            return f"~/{suffix}"
        return "~/"
    return None


def _redact_other_absolute(match: str) -> str:
    """Política (c): redação canônica para `<workspace>/<suffix>`.

    Extrai o suffix mais curto após `/VS Code/`, `/Users/` ou `/home/` (na
    ordem). Se nenhum marcador presente, retorna `<workspace>/` sem suffix
    (path completamente opaco — raro mas defensivo).
    """
    normalized = _normalize_separators(match)
    for marker in _WORKSPACE_MARKERS:
        idx = normalized.find(marker)
        if idx >= 0:
            suffix = normalized[idx + len(marker) :]
            if suffix:
                return f"<workspace>/{suffix}"
            return "<workspace>/"
    return "<workspace>/"


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------


def classify_path(match: str, source_root: Path, usernames: list[str]) -> PathMatch:
    """Classifica e calcula a substituição canônica para `match`.

    Ordem de tentativa: (a) intra_source → (b) user_path → (c) other_absolute.
    A primeira política aplicável vence. NUNCA raise.

    Args:
        match: substring exata como capturada por `WINDOWS_PATH_RE` ou
            `UNIX_PATH_RE`.
        source_root: raiz do source-tree (`ctx.source_path` em F3) — usado
            para `Path.relative_to` na política (a).
        usernames: `OperatorIdentity.usernames` (case-sensitive) — alimenta
            política (b).

    Returns:
        `PathMatch` com a categoria e a string sanitizada.
    """
    rel = _try_relativize(match, source_root)
    if rel is not None:
        return PathMatch(category="intra_source", original=match, sanitized=rel)

    user_redacted = _try_user_redact(match, usernames)
    if user_redacted is not None:
        return PathMatch(category="user_path", original=match, sanitized=user_redacted)

    return PathMatch(
        category="other_absolute",
        original=match,
        sanitized=_redact_other_absolute(match),
    )


def sanitize_paths(
    text: str,
    source_root: Path,
    identity: OperatorIdentitySchema,
) -> tuple[str, list[PathMatch]]:
    """Aplica Camada C10 sobre `text` (arquivo texto).

    Itera WINDOWS_PATH_RE depois UNIX_PATH_RE; cada match passa por
    `classify_path` + substituição via `re.sub` callback. Idempotente:
    substituições produzem strings (`./`, `~/`, `<workspace>/`) que NÃO casam
    de novo nas regex (a regex Windows exige `:` na 2ª posição; a Unix exige
    prefixo `/home/` ou `/Users/` — ambos faltam nas substituições).

    Multi-pass loop (ADR-030 fix Bloco 05 v1.1.0): repete o pipeline até
    ponto-fixo (`sanitized == prev`) ou cap MAX_PASSES. Resolve o caso em que
    o greedy match consome `c` no início de um path subsequente (e.g.,
    `c:/.../para c:/...`), deixando `:/...` residual após a 1ª substituição
    — a 2ª passada reformula o residual com o `c` final do replacement.

    Args:
        text: conteúdo do arquivo (tipicamente pós-C9 PII Detector).
        source_root: `ctx.source_path` (raiz do source-tree).
        identity: `OperatorIdentitySchema` já carregada (reusa a do C9).

    Returns:
        Tuple `(sanitized_text, matches)`. `matches` em ordem de aparição
        (Windows primeiro, Unix depois). Para entradas com 1 path único, o
        multi-pass é no-op (converge em 1 iteração).
    """
    matches: list[PathMatch] = []
    usernames = list(identity.usernames)

    def _windows_repl(m: re.Match[str]) -> str:
        pm = classify_path(m.group(0), source_root, usernames)
        matches.append(pm)
        return pm.sanitized

    def _unix_repl(m: re.Match[str]) -> str:
        pm = classify_path(m.group(0), source_root, usernames)
        matches.append(pm)
        return pm.sanitized

    max_passes = 8  # safety cap; convergência típica em 1-2 iter.
    sanitized = text
    for _ in range(max_passes):
        prev = sanitized
        sanitized = WINDOWS_PATH_RE.sub(_windows_repl, sanitized)
        sanitized = UNIX_PATH_RE.sub(_unix_repl, sanitized)
        if sanitized == prev:
            break

    return sanitized, matches


__all__ = [
    "UNIX_PATH_RE",
    "WINDOWS_PATH_RE",
    "PathCategory",
    "PathMatch",
    "classify_path",
    "sanitize_paths",
]
