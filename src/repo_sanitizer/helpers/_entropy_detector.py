"""_entropy_detector.py — Camada ADITIVA de deteccao por entropia de Shannon.

v1.2.0 / MV-04 / RS-NEW-035/036/037/047 / ADR-034 / mitigacoes §5-1/2/3/4/11.

Rede de seguranca para chaves/segredos de **alta entropia SEM prefixo conhecido**
que a matriz regex canonica (`secret_patterns.py`) nao pega. E a **ULTIMA** camada
de texto do F3, **ADITIVA** (INV-10): nunca substitui uma regra dedicada, so cobre
o gap residual.

Tensao central do ciclo (FN x FP):
- **FN** (objetivo "100%"): token base64/hex custom de alta entropia escapa -> vaza.
- **FP** (Gate G2 / RS-NEW-036): redatar um git-SHA40/UUID/SRI-hash de lockfile
  QUEBRA `package-lock.json`/`uv.lock` -> replica nao-funcional.

Resolucao (HARDCODED — RS-NEW-035, anti-bypass T-02):
1. Opera SO em **tokens isolados** (`[A-Za-z0-9+/=_-]{24,512}`, delimitados por
   boundary) — nunca em prosa inteira.
2. Threshold: base64-like len>=24 & Shannon **>4.5 bits/char**; hex-like
   (`[0-9a-f]{32,}`) **>3.0 bits/char** (hex tem alfabeto de 16 simbolos ->
   entropia maxima ~4.0, por isso threshold menor).
3. **ALLOWLIST DURA HARDCODED** (`ENTROPY_ALLOWLIST_RE`): git-SHA40, git-SHA256,
   UUID v1-v5, SRI (`sha256-`/`sha384-`/`sha512-`), e trechos ja `<REDACTED-*>`.
4. **NUNCA** aplica em lockfiles (`*.lock`, `*.sum`, `package-lock.json`,
   `yarn.lock`, `uv.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`, ...) nem em
   linhas com `integrity:`/`hash:` de lockfile.
5. Pula trechos ja redatados; binarios sao tratados antes (Bloco B) — entropia
   so vê texto.
6. **Zero-literal** (RS-NEW-047): `EntropyMatch` NUNCA armazena os bytes do token,
   so `rel_path`/`line`/`entropy`/`length`.

Placeholder canonico: `<REDACTED-HIGH-ENTROPY>`.

INV: allowlist/threshold/lockfile-list sao CONSTANTES deste modulo; jamais lidos
de arquivo do repo-fonte (RS-NEW-035 / mitigacao §5-1).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constantes HARDCODED (RS-NEW-035 / §5-1). NUNCA lidas do repo-fonte.
# ---------------------------------------------------------------------------

#: Comprimento minimo de token para considerar entropia (§5-2).
MIN_LEN = 24
#: Cap superior de comprimento de token (anti-OOM/ReDoS — MV04-D / §5-4).
MAX_LEN = 512
#: Threshold de entropia base64-like (bits/char). >4.5 = alta entropia.
ENTROPY_THRESHOLD = 4.5
#: Threshold de entropia hex-like (bits/char). Hex tem alfabeto 16 -> max ~4.0.
HEX_THRESHOLD = 3.0

#: Placeholder canonico (zero-literal — NUNCA contem o token).
ENTROPY_PLACEHOLDER = "<REDACTED-HIGH-ENTROPY>"

#: Tokenizador: sequencias base64/base64url-like isoladas por boundary.
#: `(?<![A-Za-z0-9+/=_-])` + `(?![A-Za-z0-9+/=_-])` garantem token ISOLADO
#: (§5-2). Cap `{24,512}` evita catastrophic backtracking / OOM (§5-4).
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{24,512}(?![A-Za-z0-9+/=_-])")

#: Token "hex puro" (alfabeto reduzido) — usa HEX_THRESHOLD.
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# ---------------------------------------------------------------------------
# ALLOWLIST DURA HARDCODED (RS-NEW-036 / §5-2). Anti-FP que quebra build (T-01).
# ---------------------------------------------------------------------------

ENTROPY_ALLOWLIST_RE: tuple[re.Pattern[str], ...] = (
    # git SHA-1 (40 hex) — commit/tree/blob ids. Quebraria lockfiles/submodules.
    re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE),
    # git SHA-256 (64 hex) — novo formato de object-id do git.
    re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE),
    # UUID v1-v5 (8-4-4-4-12) — ids legitimos onipresentes.
    re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    ),
    # SRI hash (Subresource Integrity): sha256-/sha384-/sha512- + base64.
    # `integrity:` de package-lock/yarn.lock. Redatar quebra a verificacao.
    re.compile(r"^sha(256|384|512)-[A-Za-z0-9+/=]+$"),
    # Ja redatado por camada anterior (regex/C9/C10/autoria) — NUNCA re-disparar.
    re.compile(r"^<REDACTED-", re.IGNORECASE),
    re.compile(r"^\[REDACTED-", re.IGNORECASE),
)

# ---------------------------------------------------------------------------
# Lockfiles — entropia NUNCA aplicada (RS-NEW-036 / §5-2). Hashes legitimos.
# ---------------------------------------------------------------------------

#: Basenames (lowercase) de lockfiles cujo conteudo e majoritariamente hash.
LOCKFILE_BASENAMES: frozenset[str] = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "uv.lock", "poetry.lock", "pdm.lock", "cargo.lock", "go.sum",
    "composer.lock", "gemfile.lock", "packages.lock.json", "flake.lock",
    "bun.lockb",
})

#: Sufixos (lowercase) de arquivos majoritariamente hash/checksum.
LOCKFILE_SUFFIXES: tuple[str, ...] = (".lock", ".sum")

#: Marcadores de linha que indicam campo de hash de lockfile -> skip da linha.
_INTEGRITY_LINE_RE = re.compile(r"\b(integrity|resolved|checksum|hash)\b\s*[:=]", re.IGNORECASE)


@dataclass(frozen=True)
class EntropyMatch:
    """Achado de entropia — ZERO-LITERAL (RS-NEW-047 / §5-11).

    NUNCA armazena os bytes do token; so metadados auditaveis.
    """

    rel_path: str
    line: int
    entropy: float
    length: int


def shannon_entropy(s: str) -> float:
    """Entropia de Shannon (bits/char) de uma string (Python puro, stdlib).

    H = -sum(p_i * log2(p_i)) sobre a distribuicao de simbolos.
    String vazia -> 0.0 (sem divisao por zero).
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for freq in counts.values():
        p = freq / length
        entropy -= p * math.log2(p)
    return entropy


def is_lockfile(basename: str) -> bool:
    """True sse `basename` e um lockfile/checksum onde entropia NAO se aplica."""
    low = basename.lower()
    if low in LOCKFILE_BASENAMES:
        return True
    return low.endswith(LOCKFILE_SUFFIXES)


def _is_allowlisted(token: str) -> bool:
    """True sse o token casa a allowlist dura (git-SHA/UUID/SRI/ja-redatado)."""
    return any(rx.match(token) for rx in ENTROPY_ALLOWLIST_RE)


def _token_is_high_entropy(token: str) -> tuple[bool, float]:
    """Decide se um token isolado e de alta entropia. Retorna (decisao, entropia).

    - len < MIN_LEN -> nunca (False).
    - hex puro -> threshold HEX_THRESHOLD (alfabeto 16, max ~4.0).
    - base64-like -> threshold ENTROPY_THRESHOLD.
    """
    length = len(token)
    if length < MIN_LEN:
        return (False, 0.0)
    entropy = shannon_entropy(token)
    if _HEX_RE.match(token):
        return (entropy > HEX_THRESHOLD, entropy)
    return (entropy > ENTROPY_THRESHOLD, entropy)


def redact_high_entropy(
    text: str,
    rel_path: str,
    basename: str,
    *,
    enabled: bool,
) -> tuple[str, list[EntropyMatch]]:
    """Camada ADITIVA de entropia — ULTIMA transformacao de texto do F3.

    Redata tokens isolados de alta entropia para `<REDACTED-HIGH-ENTROPY>`,
    respeitando a allowlist dura HARDCODED e pulando lockfiles/linhas integrity.

    Args:
        text: texto JA sanitizado pelas camadas anteriores (regex/C9/C10/autoria).
        rel_path: path relativo POSIX no destino (preenche EntropyMatch.rel_path).
        basename: nome do arquivo (decide skip de lockfile).
        enabled: flag `--entropy`. Quando False -> NO-OP (texto inalterado).

    Returns:
        Tuple (texto_redatado, matches). `matches` vazia se nada redatado.
        ZERO-LITERAL: matches nunca contem os bytes do token (RS-NEW-047).

    Defesas (RS-NEW-035/036/037 / §5-1/2/3):
        - `not enabled` -> no-op (C3 / flag).
        - lockfile -> no-op (hashes legitimos quebrariam build).
        - linha com `integrity:`/`resolved:` -> linha pulada.
        - token na allowlist (git-SHA/UUID/SRI/ja-redatado) -> preservado.
        - so token isolado, len>=24, entropia acima do threshold.
    """
    if not enabled:
        return (text, [])
    if is_lockfile(basename):
        return (text, [])

    matches: list[EntropyMatch] = []

    # Pre-computa offsets de linha para mapear posicao -> numero de linha barato.
    # (1 passada; evita `text[:pos].count("\n")` O(n^2) em arquivos grandes.)
    line_starts: list[int] = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def _line_of(pos: int) -> int:
        # busca binaria do indice de linha (1-based).
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    # Linhas com marcador integrity/resolved/checksum sao puladas (range de chars).
    # Computado lazy: so se houver tokens candidatos.
    def _line_is_integrity(pos: int) -> bool:
        ln = _line_of(pos)
        start = line_starts[ln - 1]
        end = line_starts[ln] if ln < len(line_starts) else len(text)
        return bool(_INTEGRITY_LINE_RE.search(text[start:end]))

    # Itera tokens via re.finditer. TOKEN_RE tem cap {24,512} -> sem ReDoS;
    # nao precisa de safe_finditer (sem backtracking catastrofico no alfabeto fixo).
    # Construimos o texto de saida por fatias (evita custo de sub repetido).
    out_parts: list[str] = []
    last_end = 0
    for m in TOKEN_RE.finditer(text):
        token = m.group(0)
        # 1) allowlist dura (git-SHA/UUID/SRI/ja-redatado) -> preserva.
        if _is_allowlisted(token):
            continue
        # 2) entropia abaixo do threshold / muito curto -> preserva.
        decision, entropy = _token_is_high_entropy(token)
        if not decision:
            continue
        # 3) linha de hash de lockfile (integrity:/resolved:) -> preserva.
        if _line_is_integrity(m.start()):
            continue
        # Redacao: substitui o token pelo placeholder canonico.
        out_parts.append(text[last_end:m.start()])
        out_parts.append(ENTROPY_PLACEHOLDER)
        last_end = m.end()
        matches.append(EntropyMatch(
            rel_path=rel_path,
            line=_line_of(m.start()),
            entropy=round(entropy, 3),
            length=len(token),
        ))

    if not matches:
        return (text, [])
    out_parts.append(text[last_end:])
    return ("".join(out_parts), matches)


__all__ = [
    "ENTROPY_ALLOWLIST_RE",
    "ENTROPY_PLACEHOLDER",
    "ENTROPY_THRESHOLD",
    "HEX_THRESHOLD",
    "LOCKFILE_BASENAMES",
    "LOCKFILE_SUFFIXES",
    "MAX_LEN",
    "MIN_LEN",
    "TOKEN_RE",
    "EntropyMatch",
    "is_lockfile",
    "redact_high_entropy",
    "shannon_entropy",
]
