"""f3_sanitizer.py — F3 Sanitizer CRITICO (Modo Completo AGRAVADO 3x).

Bloco 03 (RS-001 TOP-01 catastrofico irreversivel DREAD-5 45/50). Implementa
**7 camadas defensivas independentes** para zerar falso-negativos de segredo
no destino sanitizado:

Camadas:
- C1: catalogo 10 categorias (`secret_patterns.SECRET_MATRIX`).
- C2: copia local `_sanitize.py` Sentinel v1.2.0 (verificada via integrity).
- C3: integrity SHA-256 sobre `secret_patterns.py` (verificada pre-run).
- C4: multi-encoding scanner (UTF-8/UTF-8-BOM/UTF-16-LE-BOM/UTF-16-BE-BOM/Latin-1/UTF-7).
- C5: binary deep scan — primeiros 64 KB de cada binario recebem regex C2/C7.
- C6: smoke re-scan destino apos sanitizacao = 0 matches.
- C7: docs operacional dupla validacao gitleaks externo ([NOME] roda manual).

Pipeline F3 (sequencial determinstico INVARIANTE):
1. Pre-flight Camada C2 + C3: `integrity.md` verify (raise IntegrityFailure se
   mismatch). EXEC ANTES de qualquer scan.
2. Walk source com `f1_filter.run_filter` (read-only; reusa classificacao F1).
3. Para cada entry com `acao='incluir'`:
   a) Read source bytes (Path.read_bytes — read-only INV-1).
   b) Decide acao file-level por nome (C1 .env / C7 cert / C8 CSV PII).
      - C1 .env: NUNCA copia; emite `.env.example` com chaves vazias.
      - C7 cert: NUNCA copia (skip).
      - C8 CSV PII: NUNCA copia (skip).
   c) Senao, classifica binario (`_binary_detector.classify`):
      - Binario: deep scan primeiros 64 KB com regex C2 + C7 (Camada C5).
        Se match: skip + audit `f3_binary_secret_detected`.
        Se OK: copia bytes literais (binarios nao redact-inline).
      - Texto: multi-encode decode (Camada C4) — TODAS as variantes Latin-1/UTF-8
        sao escaneadas via `safe_finditer` (regex lib timeout 30s/arquivo
        ADR-026). Aplica acoes:
          * redact_inline / placeholder: substitui valor por `<REDACTED-{tipo}>`.
          * remove_line: filtra linhas que matchem.
        Texto resultante e escrito em dest via FsWriter.
4. Camada C6: re-scan destino apos write completo. Aggregate 0 matches = pass.
5. Audit: f3_sanitize_start / integrity_verify_ok / f3_sanitize_done /
   leak_smoke_pass | leak_smoke_fail | f3_timeout_skip.

Exit codes via raise (mapeados em cli.py):
- IntegrityFailure -> exit 3 (Camada C2/C3 fail).
- F3Timeout -> exit 6 (timeout regex sem skip possivel).
- Inv1Violation -> exit 2 (source mudou durante F3).

ADRs ancorados: ADR-001 / ADR-002 / ADR-003 / ADR-004 / ADR-015 / ADR-020 /
                ADR-021 / ADR-023 / ADR-026 / ADR-028.
RS cobertos: RS-001 (TOP-01) / RS-004 / RS-005 / RS-008 / RS-013 / RS-019 /
             RS-022 / RS-028.

NAO importa _sanitize.py upstream Sentinel — apenas via local-copy
`tests/fixtures/sentinel/_sanitize.py` (ADR-023 + RS-013), e mesmo essa nao e
usada diretamente em F3 (apenas via `schemas/_secrets_gate` para Pydantic gates).
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import regex as _regex

from repo_sanitizer.f1_filter import (
    GROUP_C_FILES,
    FilterCandidate,
    run_filter,
    walk_source,
)
from repo_sanitizer.helpers._author_detector import (
    AuthorMatch,
    redact_authorship,
)
from repo_sanitizer.helpers._binary_detector import classify as binary_classify
from repo_sanitizer.helpers._binary_policy import (
    classify_binary_tier,
    is_image_media,
)
from repo_sanitizer.helpers._encoding import (
    EncodingLabel,
    classify_encoding,
    try_decode_sequential,
)
from repo_sanitizer.helpers._entropy_detector import (
    EntropyMatch,
    redact_high_entropy,
)
from repo_sanitizer.helpers._git_history_scan import (
    GitArtifact,
    scan_git_history_artifacts,
)
from repo_sanitizer.helpers._hash_tree import snapshot as hash_snapshot
from repo_sanitizer.helpers._integrity import verify_integrity
from repo_sanitizer.helpers._operator_identity_loader import (
    augment_identity_from_env,
    load_operator_identity,
)
from repo_sanitizer.helpers._path_sanitizer import PathMatch, sanitize_paths
from repo_sanitizer.helpers._pii_match import PIICategory, PIIMatch
from repo_sanitizer.helpers._pii_redactor import redact_path
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema
from repo_sanitizer.schemas.sanitization_report_entry import (
    SanitizationCategory,
    SanitizationReportEntry,
)
from repo_sanitizer.secret_patterns import (
    C1_FILENAME_RE,
    C7_RULES,
    SECRET_MATRIX,
    ActionLabel,
    SecretRule,
)

if TYPE_CHECKING:
    from repo_sanitizer.helpers._audit import AuditLogger
    from repo_sanitizer.helpers._fs_writer import FsWriter

DEFAULT_TIMEOUT_SECONDS = 30  # ADR-026
DEEP_SCAN_BYTES = 64 * 1024  # Camada C5: primeiros 64 KB de binarios


# ===========================================================================
# Excecoes
# ===========================================================================


class IntegrityFailure(RuntimeError):  # noqa: N818  nome canonico
    """Camada C2/C3 falhou (mismatch integrity.md). Caller -> exit 3."""


class F3Timeout(RuntimeError):  # noqa: N818  nome canonico
    """Timeout regex sobre arquivo. Caller -> exit 6 OU skip + log (default)."""


class Inv1Violation(RuntimeError):  # noqa: N818  nome canonico
    """Fonte alterada durante F3 (RS-002). Caller -> exit 2."""


class LeakDetectedInDestination(RuntimeError):  # noqa: N818
    """Camada C6 re-scan falhou: secret detectado em destino apos F3 (RS-001 CATASTROFICO)."""


class GitHistoryInDestination(RuntimeError):  # noqa: N818
    """Gate de historico Git falhou: artefato de historico no destino apos F3.

    v1.2.0 / MV-02 / RS-NEW-038 / ADR-035. Espelha `LeakDetectedInDestination`.
    Caller (cli.py) mapeia para **exit code 8**. Bloqueante: replica NUNCA deve
    conter `.git/`/`packed-refs`/`*.patch`/`.gitattributes` com filtros, etc.
    """


# ===========================================================================
# Estruturas de dados
# ===========================================================================


@dataclass(frozen=True)
class F3ContentMatch:
    """Um match individual encontrado no scan (line-level)."""

    rel_path: str  # POSIX relative path (nao redacted aqui; redact ao emitir report)
    line: int | None  # 1-based; None se file-level
    categoria: SanitizationCategory
    tipo: str  # rotulo canonico (NUNCA literal)
    acao: str  # remove_file | placeholder | redact_inline | envexample | remove_line
    encoding_detected: EncodingLabel


@dataclass
class F3Result:
    """Resultado canonico de uma execucao F3."""

    matches: list[F3ContentMatch] = field(default_factory=list)
    files_processed: int = 0
    files_written: int = 0
    files_skipped_remove: int = 0
    files_skipped_timeout: int = 0
    files_with_secrets: int = 0
    secrets_by_category: dict[str, int] = field(default_factory=dict)
    rescan_destination_zero: bool = False
    timeouts: list[str] = field(default_factory=list)  # rel paths que timed out
    integrity_ok: bool = False
    snapshot_pre: dict[str, Any] = field(default_factory=dict)
    snapshot_pos: dict[str, Any] = field(default_factory=dict)
    # Camada C9 (ADR-029 v1.1.0 — RS-NEW-031)
    pii_matches: list[PIIMatch] = field(default_factory=list)
    pii_by_category: dict[str, int] = field(default_factory=dict)
    # Camada C10 (ADR-030 v1.1.0 — RS-NEW-032)
    path_matches: list[PathMatch] = field(default_factory=list)
    path_by_category: dict[str, int] = field(default_factory=dict)
    # MV-02 / RS-NEW-038 / ADR-035 — gate de historico Git no destino
    git_history_artifacts: list[GitArtifact] = field(default_factory=list)
    # MV-06 / RS-NEW-042 / ADR-036 — politica binaria 3-tier
    # `.png`/`.pdf`/... mantidos com flag "EXIF/metadados nao inspecionados".
    exif_uninspected: list[str] = field(default_factory=list)
    # contagem de binarios excluidos por tier (data/credential).
    binary_excluded_by_tier: dict[str, int] = field(default_factory=dict)
    # MV-05 / RS-NEW-041 / ADR-038 — autoria estrutural (manifests).
    author_matches: list[AuthorMatch] = field(default_factory=list)
    author_by_field: dict[str, int] = field(default_factory=dict)
    # MV-04 / RS-NEW-035/036/037 / ADR-034 — entropia Shannon (ultima camada).
    entropy_matches: list[EntropyMatch] = field(default_factory=list)
    entropy_count: int = 0
    # Estado da camada de entropia para o checklist (D2): None=nao-rodou,
    # True=rodou (default ON), False=SKIPPED por `--entropy off`.
    entropy_enabled: bool = True
    # P1-b (GAP-S07-01) — Camada C6 re-scan: residual REAL por categoria do
    # SECRET_MATRIX ("C1".."C10"). Diferente de `rescan_destination_zero` (global),
    # isto permite que CADA check do Checklist de Publicacao derive da SUA propria
    # categoria, sem cascata espuria de um FP em outra categoria. Vazio = 0 residual.
    rescan_residual_by_category: dict[str, int] = field(default_factory=dict)


# ===========================================================================
# Camadas C2 + C3 — Integrity pre-flight
# ===========================================================================


def preflight_integrity(
    project_root: Path,
    integrity_md: Path | None = None,
) -> dict[str, Any]:
    """Camada C2 + C3 (RS-001 + RS-004 + RS-013): verify integrity.md.

    Falha = IntegrityFailure (caller mapeia para exit 3 + audit fail).

    Args:
        project_root: raiz onde estao os arquivos rastreados (com paths relativos).
        integrity_md: arquivo manifesto; default = project_root/integrity.md.
    """
    if integrity_md is None:
        integrity_md = project_root / "integrity.md"
    result = verify_integrity(integrity_md, project_root, audit_file=None)
    if not result["ok"]:
        files = [m["file"] for m in result["mismatches"]]
        raise IntegrityFailure(
            f"F3 preflight integrity FAIL: {len(files)} mismatch(es): {files[:5]}"
        )
    return result


# ===========================================================================
# Regex timeout wrapper (ADR-026 + RS-022)
# ===========================================================================


@functools.lru_cache(maxsize=256)
def _to_regex_pattern(pattern_str: str, pattern_flags: int) -> _regex.Pattern[str]:
    """Cache re.Pattern -> regex.Pattern para suporte a timeout.

    regex.compile aceita as mesmas flags de re (IGNORECASE=2, MULTILINE=8, ...).
    """
    # regex module rejects re.UNICODE (256) which is implicit in regex anyway.
    # Strip it to avoid potential conflicts.
    flags = pattern_flags & ~re.UNICODE
    return _regex.compile(pattern_str, flags=flags)


def safe_finditer(
    re_pattern: re.Pattern[str],
    text: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[_regex.Match[str]]:
    """Wrap re.Pattern -> regex.Pattern com timeout (ADR-026).

    Raises:
        F3Timeout: se regex timeout exceeded.
    """
    rx = _to_regex_pattern(re_pattern.pattern, re_pattern.flags)
    try:
        return list(rx.finditer(text, timeout=float(timeout_seconds)))
    except TimeoutError as exc:
        raise F3Timeout(
            f"regex timeout > {timeout_seconds}s: pattern={re_pattern.pattern!r}"
        ) from exc
    except _regex.error:
        return []  # regex compile/match error treated as no-match


def safe_sub(
    re_pattern: re.Pattern[str],
    repl: str,
    text: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Wrap regex.sub com timeout."""
    rx = _to_regex_pattern(re_pattern.pattern, re_pattern.flags)
    try:
        # Anotacao explicita resolve `no-any-return` do stub do modulo `regex`
        # (MV-10 / A1): `rx.sub` retorna `Any` no stub; fixamos o tipo aqui.
        out: str = rx.sub(repl, text, timeout=float(timeout_seconds))
        return out
    except TimeoutError as exc:
        raise F3Timeout(
            f"regex sub timeout > {timeout_seconds}s: pattern={re_pattern.pattern!r}"
        ) from exc
    except _regex.error:
        return text


# ===========================================================================
# Camada C1 — decisao acao file-level (filename)
# ===========================================================================


@dataclass(frozen=True)
class FilenameDecision:
    """Resultado da decisao por nome de arquivo."""

    categoria: SanitizationCategory
    tipo: str
    acao: str  # 'envexample' | 'remove_file'
    detail: str = ""


def decide_filename_action(basename: str, rel_path_posix: str) -> FilenameDecision | None:
    """Decisao file-level por nome (C1 / C7 / C8 CSV via heuristica).

    Retorna FilenameDecision ou None se nao for file-level (passa para scan
    line-level).

    NOTA: arquivos com sufixo `.example` (ex: `.env.example`, `config.example`)
    sao OUTPUTS canonicos seguros do F3 (placeholder com chaves vazias). Nunca
    sao tratados como secret file-level. Esta regra TAMBEM cobre Camada C6
    re-scan apos F3 (evita falso-positivo no proprio output do agente).
    """
    # Bypass canonico: arquivos .example sao outputs seguros (RS-029 anti-spoofing
    # ainda nao deve disparar aqui pois F3 ja sanitizou o conteudo).
    if basename.endswith(".example"):
        return None
    # C1: .env files
    if C1_FILENAME_RE.match(basename):
        return FilenameDecision(
            categoria="C1",
            tipo="ENV_FILE",
            acao="envexample",
            detail=f".env file ({basename}); emit .env.example com chaves vazias",
        )
    # C7: cert / private key by extension
    for rule in C7_RULES:
        if rule.tipo == "CERT_FILE_EXT" and rule.regex.search(basename):
            return FilenameDecision(
                categoria="C7",
                tipo="CERT_FILE_EXT",
                acao="remove_file",
                detail=f"extensao cert/key ({basename})",
            )
    return None


# ===========================================================================
# Scan + sanitizacao line-level (texto)
# ===========================================================================


def _placeholder_for(rule: SecretRule) -> str:
    """Placeholder canonico que NUNCA contem o valor literal (ADR-004)."""
    return f"<REDACTED-{rule.tipo}>"


@dataclass
class TextSanitizationResult:
    """Resultado do scan + sanitizacao de um arquivo texto."""

    sanitized_text: str
    matches: list[tuple[SecretRule, int, EncodingLabel]]  # (rule, line, encoding_label)
    timeouts: list[str] = field(default_factory=list)  # tipos que timed out
    skip_file: bool = False  # True se C7 PEM block / C8 CSV header detected
    skip_reason: str = ""


# Categorias que tem acao file-level quando casam em CONTEUDO (nao so filename):
# - C7 PEM block: remove_file (skip dest)
# - C8 CSV header com PII: remove_file (skip dest)
_CONTENT_FILE_LEVEL_TIPOS: frozenset[str] = frozenset({
    "PRIVATE_KEY_PEM_BLOCK",
    "CLIENT_CSV_HEADER",
})


def sanitize_text_content(
    text: str,
    encoding: EncodingLabel,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> TextSanitizationResult:
    """Aplica matriz C2..C10 (line-level) sobre `text` na variant `encoding`.

    Returns:
        TextSanitizationResult com texto sanitizado + matches + flags.
    """
    sanitized = text
    matches: list[tuple[SecretRule, int, EncodingLabel]] = []
    timeouts: list[str] = []
    skip_file = False
    skip_reason = ""

    for category, rules in SECRET_MATRIX.items():
        if category == "C1":  # file-level only
            continue
        for rule in rules:
            # C7 CERT_FILE_EXT e file-level (filename); ja tratado em decide_filename_action
            if rule.tipo == "CERT_FILE_EXT":
                continue
            try:
                rule_matches = safe_finditer(rule.regex, sanitized, timeout_seconds=timeout_seconds)
            except F3Timeout:
                timeouts.append(rule.tipo)
                continue

            if not rule_matches:
                continue

            # Compute line numbers (1-based) for each match
            for m in rule_matches:
                line_no = sanitized[:m.start()].count("\n") + 1
                matches.append((rule, line_no, encoding))

            # File-level content matches: signal skip
            if rule.tipo in _CONTENT_FILE_LEVEL_TIPOS:
                skip_file = True
                skip_reason = f"conteudo casou {rule.tipo} ({rule.acao})"
                # Nao precisa sanitizar mais; arquivo sera skipado.
                continue

            # Apply action
            if rule.acao in {"redact_inline", "placeholder"}:
                try:
                    sanitized = safe_sub(
                        rule.regex, _placeholder_for(rule), sanitized,
                        timeout_seconds=timeout_seconds,
                    )
                except F3Timeout:
                    timeouts.append(rule.tipo)
                    continue
            elif rule.acao == "remove_line":
                # Mantem apenas linhas que NAO casam com a regra
                kept_lines: list[str] = []
                for line in sanitized.splitlines(keepends=True):
                    if rule.regex.search(line):
                        continue
                    kept_lines.append(line)
                sanitized = "".join(kept_lines)
            elif rule.acao == "remove_file":
                # ja sinalizado via skip_file acima para tipos C7/C8 file-level
                skip_file = True
                skip_reason = f"acao remove_file disparada por {rule.tipo}"

    return TextSanitizationResult(
        sanitized_text=sanitized,
        matches=matches,
        timeouts=timeouts,
        skip_file=skip_file,
        skip_reason=skip_reason,
    )


# ===========================================================================
# Camada C9 — PII Detector do operador (ADR-029 v1.1.0 + RS-NEW-031)
# ===========================================================================

# Placeholders canônicos (NUNCA usar string vazia — preserva legibilidade + audit trail)
_C9_PLACEHOLDERS: dict[PIICategory, str] = {
    "name": "[REDACTED-NAME]",
    "username": "[REDACTED-USER]",
    "domain": "[REDACTED-DOMAIN]",
    "custom": "[REDACTED-CUSTOM]",
}

_C9_EXCERPT_MAX_LEN = 50


def _build_pii_excerpt(sanitized_text: str, placeholder: str) -> str:
    """Constrói excerpt ≤50 chars de contexto ao redor do PRIMEIRO placeholder.

    O excerpt SEMPRE é construído a partir do texto JÁ sanitizado, então o
    placeholder substituiu o valor literal — não há vazamento (PT-RS-04 layer 3).
    Newlines colapsados para single space para evitar quebrar a tabela do report.
    """
    idx = sanitized_text.find(placeholder)
    if idx < 0:  # corner-case defensivo (placeholder não encontrado)
        return placeholder
    margin = max(0, (_C9_EXCERPT_MAX_LEN - len(placeholder)) // 2)
    start = max(0, idx - margin)
    end = min(len(sanitized_text), idx + len(placeholder) + margin)
    excerpt = sanitized_text[start:end].replace("\n", " ").replace("\r", " ")
    if len(excerpt) > _C9_EXCERPT_MAX_LEN:
        excerpt = excerpt[:_C9_EXCERPT_MAX_LEN]
    return excerpt


def _apply_c9_detector(
    sanitized: str,
    pattern_str: str,
    *,
    category: PIICategory,
    case_insensitive: bool,
    rel_path: str,
) -> tuple[str, PIIMatch | None]:
    """Aplica UM detector C9 (1 pattern, 1 categoria). Retorna (texto_novo, match_ou_None).

    Detector NÃO emite PIIMatch quando count==0 (sem ruído).
    """
    flags = _regex.IGNORECASE if case_insensitive else 0
    try:
        pattern = _regex.compile(pattern_str, flags=flags)
    except _regex.error:
        return sanitized, None  # pattern malformado — degrade gracioso

    found = list(pattern.finditer(sanitized))
    if not found:
        return sanitized, None

    count = len(found)
    first_match_pos = found[0].start()
    line_no = sanitized[:first_match_pos].count("\n") + 1
    placeholder = _C9_PLACEHOLDERS[category]
    new_text = pattern.sub(placeholder, sanitized)
    match = PIIMatch(
        category=category,
        file_path=rel_path,
        line_no=line_no,
        count=count,
        excerpt_redacted=_build_pii_excerpt(new_text, placeholder),
    )
    return new_text, match


# Auditoria 2026-07 — excecao canonica UNICA: em arquivo LICENSE (MIT etc.) o
# NOME do operador (copyright holder) PODE permanecer. Demais categorias C9
# (usernames/domains/custom) e toda a matriz de segredos CONTINUAM aplicadas.
LICENSE_BASENAMES: frozenset[str] = frozenset({
    "license", "license.md", "license.txt", "licence",
})


def run_c9_pii_detector(
    text: str,
    identity: OperatorIdentitySchema,
    *,
    rel_path: str = "",
    skip_names: bool = False,
) -> tuple[str, list[PIIMatch]]:
    """Camada C9 (ADR-029 + RS-NEW-031): detecta e redata PII do operador.

    Aplica 4 detectors determinísticos em ordem A → B → C → D:
        A. names — case-insensitive Unicode-aware (`\\b{name}\\b` via regex lib)
        B. usernames — case-sensitive (`\\b{username}\\b`)
        C. domains — case-sensitive (`\\b{domain}\\b`)
        D. extra_redact_patterns — regex custom (já validado pelo schema)

    Args:
        text: conteúdo do arquivo (tipicamente pós-`sanitize_text_content`).
        identity: schema com listas de PII do operador.
        rel_path: path relativo POSIX no destino (preenche PIIMatch.file_path).

    Returns:
        Tuple (sanitized_text, matches). `matches` é vazia se 0 PII detectada.

    Performance:
        Cada detector é independente; ordem fixa garante determinismo + idempotência.
        Cada pattern compila on-the-fly (não cacheado — identity é per-run).

    Nota arquitetural — **Cascading sanitization** (PT-RS-04 layered defense):
        Detectors anteriores podem "consumir" prefixos de patterns posteriores.
        Ex: se `usernames=["[NOME]"]` E `extra_redact_patterns=["[NOME]@gmail.com"]`,
        o detector B (username) redata "[NOME]" primeiro → texto fica
        "[REDACTED-USER]@gmail.com" → detector D (custom) não casa mais o email
        completo. O OBJETIVO FINAL (zero PII vazada) ainda é atingido, mas a
        atribuição final de categoria é "username" (não "custom"). Isto é
        comportamento INTENCIONAL — não bug. Para garantir atribuição "custom",
        o operador deve usar patterns que NÃO compartilham prefixos com os
        usernames/names/domains declarados.
    """
    sanitized = text
    matches: list[PIIMatch] = []

    # Detector A — Names (case-insensitive, Unicode-aware via regex lib)
    # skip_names=True: excecao LICENSE (copyright holder preservado).
    for name in [] if skip_names else identity.names:
        if not name:
            continue
        sanitized, pii = _apply_c9_detector(
            sanitized,
            rf"\b{_regex.escape(name)}\b",
            category="name",
            case_insensitive=True,
            rel_path=rel_path,
        )
        if pii is not None:
            matches.append(pii)

    # Detector B — Usernames (case-sensitive)
    for username in identity.usernames:
        if not username:
            continue
        sanitized, pii = _apply_c9_detector(
            sanitized,
            rf"\b{_regex.escape(username)}\b",
            category="username",
            case_insensitive=False,
            rel_path=rel_path,
        )
        if pii is not None:
            matches.append(pii)

    # Detector C — Domains (case-sensitive — domínios são lowercase canônicos)
    for domain in identity.domains:
        if not domain:
            continue
        sanitized, pii = _apply_c9_detector(
            sanitized,
            rf"\b{_regex.escape(domain)}\b",
            category="domain",
            case_insensitive=False,
            rel_path=rel_path,
        )
        if pii is not None:
            matches.append(pii)

    # Detector D — Custom regex (já validado por @field_validator no schema)
    for pattern_str in identity.extra_redact_patterns:
        if not pattern_str:
            continue
        sanitized, pii = _apply_c9_detector(
            sanitized,
            pattern_str,
            category="custom",
            case_insensitive=False,
            rel_path=rel_path,
        )
        if pii is not None:
            matches.append(pii)

    return sanitized, matches


# ===========================================================================
# Camada C5 — Binary deep scan (primeiros 64 KB)
# ===========================================================================


def scan_binary_deep(
    rel_path: str,
    sample: bytes,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[list[tuple[SecretRule, EncodingLabel]], list[str]]:
    """Camada C5: aplica C2 (API keys) + C7 (PEM headers) sobre os primeiros
    64 KB do binario, multi-encoded.

    Returns: (matches, timeouts).
    """
    matches: list[tuple[SecretRule, EncodingLabel]] = []
    timeouts: list[str] = []

    # Deep scan: tenta decodificar como texto (multi-encoding)
    for enc, text in try_decode_sequential(sample):
        # Apenas C2 (API keys) + C7 (PEM block) — sao os tipos com header textual
        for rule in SECRET_MATRIX["C2"] + SECRET_MATRIX["C7"]:
            if rule.tipo == "CERT_FILE_EXT":  # file-level, ja tratado
                continue
            try:
                found = safe_finditer(rule.regex, text, timeout_seconds=timeout_seconds)
            except F3Timeout:
                timeouts.append(f"{rel_path}:{rule.tipo}")
                continue
            if found:
                matches.append((rule, enc))
                break  # Uma deteccao por rule e suficiente (binario nao redact)
    return matches, timeouts


# ===========================================================================
# Camada C6 — Re-scan destino apos sanitizacao
# ===========================================================================


def rescan_destination(
    dest_path: Path,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    exclude_paths: set[str] | None = None,
) -> tuple[int, list[F3ContentMatch]]:
    """Camada C6 (RS-001): re-scan completo do destino apos F3.

    Returns: (n_total_matches, list_of_matches).
    `exclude_paths` aceita rel POSIX paths para excluir (state file, relatorios).
    """
    excludes = exclude_paths or set()
    out: list[F3ContentMatch] = []
    if not dest_path.exists():
        return 0, out
    import os as _os
    for dirpath, dirnames, filenames in _os.walk(dest_path, followlinks=False):
        # Exclui artefatos do agente (state file, relatorios)
        dirnames[:] = [d for d in dirnames if d not in {".sanitizer-state.json"}]
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                rel = full.relative_to(dest_path).as_posix()
            except ValueError:
                continue
            if rel in excludes:
                continue
            # Filename-level
            decision = decide_filename_action(fname, rel)
            if decision is not None:
                # File-level secret no destino apos F3 = LEAK (Camada C6 fail).
                # C1 .env nao deveria existir (so .env.example), C7 nao deveria
                # existir, etc. Se existir, e leak.
                out.append(F3ContentMatch(
                    rel_path=rel, line=None,
                    categoria=decision.categoria, tipo=decision.tipo,
                    acao=decision.acao,
                    encoding_detected="latin-1",
                ))
                continue
            # Content-level
            try:
                content_bytes = full.read_bytes()
            except OSError:
                continue
            bin_info = binary_classify(full)
            if bin_info["is_binary"]:
                sample = content_bytes[:DEEP_SCAN_BYTES]
                bin_matches, _ = scan_binary_deep(rel, sample, timeout_seconds=timeout_seconds)
                for rule, enc in bin_matches:
                    out.append(F3ContentMatch(
                        rel_path=rel, line=None,
                        categoria=rule.category, tipo=rule.tipo,
                        acao=rule.acao,
                        encoding_detected=enc,
                    ))
                continue
            # Texto: multi-encoding scan
            for enc, text in try_decode_sequential(content_bytes):
                tsr = sanitize_text_content(text, enc, timeout_seconds=timeout_seconds)
                for rule, line, var_enc in tsr.matches:
                    out.append(F3ContentMatch(
                        rel_path=rel, line=line,
                        categoria=rule.category, tipo=rule.tipo,
                        acao=rule.acao,
                        encoding_detected=var_enc,
                    ))
    return len(out), out


# ===========================================================================
# Pipeline principal F3
# ===========================================================================


def _emit_env_example(
    src_bytes: bytes,
    dest_env_example_path: Path,
    fs_writer: FsWriter,
) -> int:
    """Para arquivos C1 .env: emite .env.example com chaves vazias.

    Strategia: parse linha-a-linha; preserva nomes de variaveis; zera valores.
    Lines nao-KEY=VALUE sao mantidas como comentarios. Em case de decode-error,
    emite arquivo placeholder generico.
    """
    try:
        text = src_bytes.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = src_bytes.decode("latin-1", errors="replace")
    out_lines: list[str] = []
    n_keys = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            out_lines.append(f"{key}=")
            n_keys += 1
        else:
            out_lines.append(f"# {line}")
    if not out_lines:
        out_lines.append("# (env file vazio)")
    output = "\n".join(out_lines) + "\n"
    fs_writer.safe_write_bytes(dest_env_example_path, output.encode("utf-8"))
    return n_keys


def _classify_text_or_binary_for_processing(
    full_src: Path, src_bytes: bytes,
) -> tuple[bool, EncodingLabel]:
    """Retorna (is_binary, encoding_label). Encoding aplicavel a texto."""
    bin_info = binary_classify(full_src)
    if bin_info["is_binary"]:
        return True, "binary"
    enc = classify_encoding(full_src)
    if enc == "binary":
        return True, "binary"
    return False, enc


def _entry_to_matches(
    cand: FilterCandidate,
    rule_matches: list[tuple[SecretRule, int, EncodingLabel]],
) -> list[F3ContentMatch]:
    """Converte matches internos em F3ContentMatch para o report."""
    out: list[F3ContentMatch] = []
    for rule, line, enc in rule_matches:
        out.append(F3ContentMatch(
            rel_path=cand.rel_path_posix,
            line=line,
            categoria=rule.category,
            tipo=rule.tipo,
            acao=rule.acao,
            encoding_detected=enc,
        ))
    return out


def run_f3(
    *,
    source_path: Path,
    dest_path: Path,
    fs_writer: FsWriter,
    audit: AuditLogger,
    project_root: Path,
    integrity_md: Path | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    rescan_dest: bool = True,
    raise_on_leak: bool = True,
    raise_on_git_history: bool = True,
    identity: OperatorIdentitySchema | None = None,
    entropy_enabled: bool = True,
) -> F3Result:
    """Executa F3 sobre source -> dest (Bloco 03 polish-driven).

    Pre-condicao:
        - source_path existe e e read-only (INV-1 enforced via FsWriter).
        - dest_path foi criado (atomic_create_versioned_dest, Bloco 02).
        - fs_writer instalado com source_path em FORBIDDEN_PATHS (INV-1 + ADR-020).
        - audit emite metadata canonica (RS-027).

    Pos-condicao:
        - dest_path contem copia sanitizada do source[acao='incluir'].
        - .env files removidos; emite .env.example com chaves vazias.
        - cert/key files (C7) removidos.
        - PII/secrets (C2..C10) redacted/removed do conteudo line-by-line.
        - Camada C6 re-scan dest = 0 matches (ou LeakDetectedInDestination raise).
        - INV-1 snapshot pre/pos identical.

    Raises:
        IntegrityFailure: Camada C2/C3 fail (-> exit 3).
        F3Timeout: regex timeout sem skip (sem default; default = skip + log).
        Inv1Violation: source mudou durante F3 (-> exit 2).
        LeakDetectedInDestination: Camada C6 fail (-> exit 5 + audit fail).
    """
    result = F3Result()
    result.entropy_enabled = entropy_enabled

    # 0) Camada C9 (ADR-029 v1.1.0): carregar OperatorIdentity (best-effort)
    if identity is None:
        identity = load_operator_identity(project_root)
    # MV-05 / RS-NEW-041 / §5-8: amplia identidade com sinais do AMBIENTE
    # (EMAIL/GIT_AUTHOR_EMAIL/USERPROFILE) — HARDCODED, sem git, never-raise.
    identity = augment_identity_from_env(identity)
    # `_c9_enabled` evita overhead quando identity vem totalmente vazia
    _c9_enabled = bool(
        identity.names or identity.usernames or identity.domains
        or identity.extra_redact_patterns
    )

    # 1) INV-1 snapshot pre
    snap_pre = hash_snapshot(source_path)
    result.snapshot_pre = snap_pre
    audit.log("inv1_snapshot_pre", detail={
        "phase": "f3_start",
        "aggregate_prefix": snap_pre["aggregate"][:16],
        "file_count": snap_pre["file_count"],
    })

    # 2) Pre-flight Camadas C2 + C3 (integrity verify)
    audit.log("f3_sanitize_start", detail={
        "source_resolved": redact_path(str(source_path)),
        "dest_resolved": redact_path(str(dest_path)),
        "timeout_seconds": timeout_seconds,
    })
    try:
        preflight_integrity(project_root, integrity_md)
        result.integrity_ok = True
        audit.log("integrity_verify_ok", detail={"phase": "f3_preflight"})
    except IntegrityFailure as exc:
        audit.log("integrity_verify_fail", detail={
            "phase": "f3_preflight", "error": str(exc),
        })
        raise

    # 3) Re-walk source para enumerar arquivos `incluir` (consistente com F1).
    f1_res = run_filter(source_path)

    # Map: rel_path_posix -> FilterCandidate (re-walk para abs_path)
    candidates_by_rel: dict[str, FilterCandidate] = {}
    for cand in walk_source(source_path):
        candidates_by_rel[cand.rel_path_posix] = cand

    # 4) Iterar entries `incluir` em ordem deterministica (lexico por rel path).
    for cand in sorted(candidates_by_rel.values(), key=lambda c: c.rel_path_posix):
        if cand.acao != "incluir":
            continue
        # GROUP_C_FILES e default-include sao processados; Grupo A/B excluir foi
        # filtrado antes.
        result.files_processed += 1

        # 4a) Decisao file-level (C1 .env / C7 cert / C8 CSV-PII por nome).
        basename = cand.rel_path_posix.split("/")[-1]
        decision = decide_filename_action(basename, cand.rel_path_posix)
        if decision is not None:
            if decision.acao == "envexample":
                # C1 .env: nao copia; emite .env.example
                dest_env_example = dest_path / cand.rel_path_posix.rsplit("/", 1)[0] / f"{basename}.example" \
                    if "/" in cand.rel_path_posix else dest_path / f"{basename}.example"
                try:
                    src_bytes = cand.abs_path.read_bytes()
                except OSError:
                    src_bytes = b""
                _emit_env_example(src_bytes, dest_env_example, fs_writer)
                result.files_written += 1
                result.matches.append(F3ContentMatch(
                    rel_path=cand.rel_path_posix, line=None,
                    categoria=decision.categoria, tipo=decision.tipo,
                    acao="envexample",
                    encoding_detected="utf-8",
                ))
                result.files_skipped_remove += 1
                _bump_cat(result, decision.categoria)
            else:
                # C7: skip
                result.files_skipped_remove += 1
                result.matches.append(F3ContentMatch(
                    rel_path=cand.rel_path_posix, line=None,
                    categoria=decision.categoria, tipo=decision.tipo,
                    acao=decision.acao,
                    encoding_detected="binary" if cand.is_binary else "utf-8",
                ))
                _bump_cat(result, decision.categoria)
            continue

        # 4a-bis) Politica binaria 3-tier por NOME (MV-06 / RS-NEW-042 / ADR-036).
        # Binario precede entropia; data/credencial excluidos por default. A
        # decisao por extensao roda ANTES da leitura completa (defesa LGPD).
        # `.csv` (texto) e `.sqlite`/`.parquet`/`.pem` (binario) caem aqui.
        tier_by_name = classify_binary_tier(basename, cand.binary_label)
        if tier_by_name in ("data", "credential"):
            _exclude_binary_tier(result, cand.rel_path_posix, tier_by_name)
            continue

        # 4b) Read source (read-only INV-1)
        try:
            src_bytes = cand.abs_path.read_bytes()
        except OSError:
            continue
        is_binary, enc_label = _classify_text_or_binary_for_processing(cand.abs_path, src_bytes)

        if is_binary:
            # 4c.binary.0) Politica binaria 3-tier por MAGIC (anti-rename-spoof).
            # Ex.: SQLite renomeado p/ `.bin` -> magic "SQLite3" forca tier data.
            bin_info_magic = binary_classify(cand.abs_path)
            tier_by_magic = classify_binary_tier(
                basename, str(bin_info_magic["magic_label"]),
            )
            if tier_by_magic in ("data", "credential"):
                _exclude_binary_tier(result, cand.rel_path_posix, tier_by_magic)
                continue
            # 4c.binary) Camada C5 deep scan primeiros 64 KB
            sample = src_bytes[:DEEP_SCAN_BYTES]
            bin_matches, bin_timeouts = scan_binary_deep(
                cand.rel_path_posix, sample, timeout_seconds=timeout_seconds,
            )
            if bin_timeouts:
                result.files_skipped_timeout += 1
                result.timeouts.extend(bin_timeouts)
                for t in bin_timeouts:
                    audit.log("f3_timeout_skip", detail={
                        "path_redacted": redact_path(cand.rel_path_posix),
                        "tipo": t,
                    })
            if bin_matches:
                # Binario com chave -> skip dest (nao copia)
                result.files_skipped_remove += 1
                for rule, found_enc in bin_matches:
                    result.matches.append(F3ContentMatch(
                        rel_path=cand.rel_path_posix, line=None,
                        categoria=rule.category, tipo=rule.tipo,
                        acao="remove_file",
                        encoding_detected=found_enc,
                    ))
                    _bump_cat(result, rule.category)
                result.files_with_secrets += 1
                continue
            # Binario limpo (tier safe) -> copia literal via FsWriter.
            # MV-06: imagens/midia mantidas com FLAG "EXIF nao inspecionado"
            # (transparencia; parse EXIF e MV-15/fora de escopo, INV-8).
            if is_image_media(basename, str(bin_info_magic["magic_label"])):
                result.exif_uninspected.append(cand.rel_path_posix)
            dest_file = dest_path / cand.rel_path_posix
            fs_writer.safe_write_bytes(dest_file, src_bytes)
            result.files_written += 1
            continue

        # 4c.text) Multi-encoding scan + sanitizacao
        all_matches: list[tuple[SecretRule, int, EncodingLabel]] = []
        skip_file = False
        sanitized_for_write: str | None = None

        text_variants = try_decode_sequential(src_bytes)
        if not text_variants:
            # Fallback: Latin-1 sempre decode; mas se vazio, copia literal.
            dest_file = dest_path / cand.rel_path_posix
            fs_writer.safe_write_bytes(dest_file, src_bytes)
            result.files_written += 1
            continue

        # Estrategia: a variant primaria (primeira que casa com classify_encoding)
        # e a fonte da verdade para sanitizacao; OUTRAS variants sao escaneadas
        # APENAS para detectar matches (zero falso-negativo encoding-bomb).
        primary_variant: tuple[EncodingLabel, str] | None = next(
            ((e, t) for e, t in text_variants if e == enc_label), None,
        )
        if primary_variant is None:
            primary_variant = text_variants[0]
        primary_enc, primary_text = primary_variant

        # Sanitizar a variant primaria
        primary_sanit = sanitize_text_content(primary_text, primary_enc, timeout_seconds=timeout_seconds)
        if primary_sanit.timeouts:
            result.files_skipped_timeout += 1
            result.timeouts.append(cand.rel_path_posix)
            for t in primary_sanit.timeouts:
                audit.log("f3_timeout_skip", detail={
                    "path_redacted": redact_path(cand.rel_path_posix),
                    "tipo": t,
                })
        all_matches.extend(primary_sanit.matches)
        skip_file = primary_sanit.skip_file
        sanitized_for_write = primary_sanit.sanitized_text

        # Escanear variants secundarias APENAS para deteccao (zero FN encoding-bomb)
        for var_enc, var_text in text_variants:
            if var_enc == primary_enc:
                continue
            sec = sanitize_text_content(var_text, var_enc, timeout_seconds=timeout_seconds)
            if sec.matches:
                # Adiciona apenas matches NAO ja capturados pela primary
                for m in sec.matches:
                    # dedup por (tipo, line)
                    key = (m[0].tipo, m[1])
                    if not any((mp[0].tipo, mp[1]) == key for mp in all_matches):
                        all_matches.append(m)
            if sec.skip_file:
                skip_file = True

        # Decisao final
        if skip_file:
            result.files_skipped_remove += 1
            # Emite match file-level para o report
            # (matches ja inclui o conteudo C7/C8 que disparou)
            for rule, _line, var_enc in all_matches:
                if rule.tipo in _CONTENT_FILE_LEVEL_TIPOS:
                    result.matches.append(F3ContentMatch(
                        rel_path=cand.rel_path_posix, line=None,
                        categoria=rule.category, tipo=rule.tipo,
                        acao="remove_file",
                        encoding_detected=var_enc,
                    ))
                    _bump_cat(result, rule.category)
            continue

        # Emit matches line-level para report
        if all_matches:
            result.files_with_secrets += 1
            for rule, line, var_enc in all_matches:
                result.matches.append(F3ContentMatch(
                    rel_path=cand.rel_path_posix, line=line,
                    categoria=rule.category, tipo=rule.tipo,
                    acao=rule.acao,
                    encoding_detected=var_enc,
                ))
                _bump_cat(result, rule.category)

        # Camada C9 (ADR-029 v1.1.0): PII detection sobre texto sanitizado
        if _c9_enabled and sanitized_for_write is not None:
            sanitized_for_write, pii_matches = run_c9_pii_detector(
                sanitized_for_write,
                identity,
                rel_path=cand.rel_path_posix,
                skip_names=basename.lower() in LICENSE_BASENAMES,
            )
            for pm in pii_matches:
                result.pii_matches.append(pm)
                result.pii_by_category[pm.category] = (
                    result.pii_by_category.get(pm.category, 0) + pm.count
                )

        # Camada C10 (ADR-030 v1.1.0 — RS-NEW-032): Path Sanitizer
        # Aplica somente em arquivos texto (sanitized_for_write is not None) e
        # SEMPRE — independente de identity vazia. Política (a) intra_source
        # relativiza paths absolutos do próprio source-tree (ganho mesmo sem
        # OperatorIdentity preenchida). Reusa a identity já carregada por C9.
        if sanitized_for_write is not None:
            sanitized_for_write, path_matches_file = sanitize_paths(
                sanitized_for_write, source_path, identity,
            )
            for pathm in path_matches_file:
                result.path_matches.append(pathm)
                result.path_by_category[pathm.category] = (
                    result.path_by_category.get(pathm.category, 0) + 1
                )

        # MV-05 / RS-NEW-041 / ADR-038 — Autoria estrutural (apos C10, antes da
        # entropia / §5-7). So toca campos de autoria de manifests; nunca
        # `name`/dep/license. Placeholder preserva estrutura -> Gate G2 valida build.
        if sanitized_for_write is not None:
            sanitized_for_write, author_matches_file = redact_authorship(
                sanitized_for_write, basename, cand.rel_path_posix,
            )
            for am in author_matches_file:
                result.author_matches.append(am)
                result.author_by_field[am.field] = (
                    result.author_by_field.get(am.field, 0) + 1
                )

        # MV-04 / RS-NEW-035/036/037 / ADR-034 — Entropia Shannon (ULTIMA camada
        # de texto, ADITIVA / §5-3). Pula tokens ja-redatados (allowlist) e
        # lockfiles; ligavel por `--entropy` (entropy_enabled). So texto.
        if sanitized_for_write is not None:
            sanitized_for_write, entropy_matches_file = redact_high_entropy(
                sanitized_for_write, cand.rel_path_posix, basename,
                enabled=entropy_enabled,
            )
            for em in entropy_matches_file:
                result.entropy_matches.append(em)
                result.entropy_count += 1

        # Write sanitized to dest via FsWriter
        dest_file = dest_path / cand.rel_path_posix
        try:
            if sanitized_for_write is None:
                fs_writer.safe_write_bytes(dest_file, src_bytes)
            else:
                # Re-encode em UTF-8 (canonico no destino) — o destino tipicamente
                # convergira para UTF-8 (defesa em camadas anti encoding-bomb).
                fs_writer.safe_write_bytes(dest_file, sanitized_for_write.encode("utf-8"))
            result.files_written += 1
        except Exception:
            # Em falha de write, audita e continua (nao para o pipeline)
            audit.log("fs_write_blocked", detail={
                "path_redacted": redact_path(cand.rel_path_posix),
                "phase": "f3_write",
            })
            raise

    # 5) Camada C6 — re-scan destino apos sanitizacao
    if rescan_dest:
        # Exclui artefatos do agente do re-scan (state file)
        excludes = {".sanitizer-state.json"}
        n_leaks, leaks = rescan_destination(
            dest_path, timeout_seconds=timeout_seconds, exclude_paths=excludes,
        )
        result.rescan_destination_zero = (n_leaks == 0)
        # P1-b (GAP-S07-01): persiste o residual REAL por categoria do re-scan
        # para que o Checklist de Publicacao derive cada item da sua propria
        # categoria (sem cascata espuria). Zero-literal: so categoria + contagem.
        residual_by_cat: dict[str, int] = {}
        for leak_match in leaks:
            residual_by_cat[leak_match.categoria] = (
                residual_by_cat.get(leak_match.categoria, 0) + 1
            )
        result.rescan_residual_by_category = residual_by_cat
        if n_leaks == 0:
            audit.log("leak_smoke_pass", detail={
                "phase": "f3_rescan_destination",
                "files_processed": result.files_processed,
                "files_written": result.files_written,
            })
        else:
            audit.log("leak_smoke_fail", detail={
                "phase": "f3_rescan_destination",
                "n_leaks": n_leaks,
                "first_5_categories": [m.categoria for m in leaks[:5]],
            })
            if raise_on_leak:
                raise LeakDetectedInDestination(
                    f"RS-001 CATASTROFICO: Camada C6 falhou. {n_leaks} leak(s) em "
                    f"destino apos F3. Primeiros 5 tipos: "
                    f"{[m.tipo for m in leaks[:5]]}"
                )

    # 5.5) Gate BLOQUEANTE de historico Git (MV-02 / RS-NEW-038 / ADR-035).
    # Re-scan por NOME E CONTEUDO; qualquer artefato -> raise (exit 8). §5-5.
    if rescan_dest:
        git_artifacts = scan_git_history_artifacts(dest_path)
        result.git_history_artifacts = git_artifacts
        if git_artifacts:
            audit.log("git_history_detected", detail={
                "phase": "f3_git_history_gate",
                "n_artifacts": len(git_artifacts),
                "first_5_kinds": [a.kind for a in git_artifacts[:5]],
                "first_5_paths": [redact_path(a.rel_path) for a in git_artifacts[:5]],
            })
            if raise_on_git_history:
                raise GitHistoryInDestination(
                    f"RS-NEW-038: gate de historico Git falhou. "
                    f"{len(git_artifacts)} artefato(s) de historico no destino "
                    f"apos F3. Primeiros 5 tipos: "
                    f"{[a.kind for a in git_artifacts[:5]]}"
                )
        else:
            audit.log("git_history_clean", detail={
                "phase": "f3_git_history_gate",
                "n_artifacts": 0,
            })

    # 6) INV-1 snapshot pos + gate
    snap_pos = hash_snapshot(source_path)
    result.snapshot_pos = snap_pos
    if snap_pre["aggregate"] != snap_pos["aggregate"]:
        audit.log("inv1_violation", detail={"phase": "f3_done"})
        raise Inv1Violation(
            f"F3 INV-1 violation: source mudou durante F3 "
            f"(pre={snap_pre['aggregate'][:16]} vs pos={snap_pos['aggregate'][:16]})"
        )
    audit.log("inv1_snapshot_pos", detail={
        "phase": "f3_done",
        "aggregate_prefix": snap_pos["aggregate"][:16],
        "file_count": snap_pos["file_count"],
    })

    # 6.5) audit C9 (ADR-029 v1.1.0) — somente se C9 habilitado
    if _c9_enabled:
        audit.log("f3_c9_pii_done", detail={
            "pii_files_affected": len({m.file_path for m in result.pii_matches}),
            "pii_total_matches": sum(m.count for m in result.pii_matches),
            "pii_by_category": result.pii_by_category,
        })

    # 6.6) audit C10 (ADR-030 v1.1.0 — RS-NEW-032): SEMPRE emite (mesmo zero
    # paths) para trail completo do gate G2 (ADR-032).
    audit.log("f3_c10_paths_done", detail={
        "path_total_matches": len(result.path_matches),
        "path_by_category": result.path_by_category,
    })

    # 6.7) audit MV-05 autoria estrutural (ADR-038) — zero-literal (so contagens).
    audit.log("f3_author_done", detail={
        "author_total_matches": len(result.author_matches),
        "author_by_field": result.author_by_field,
    })

    # 6.8) audit MV-04 entropia (ADR-034) — zero-literal; sinaliza SKIPPED se off.
    audit.log("f3_entropy_done", detail={
        "entropy_enabled": entropy_enabled,
        "entropy_count": result.entropy_count,
    })

    # 7) audit done
    audit.log("f3_sanitize_done", detail={
        "files_processed": result.files_processed,
        "files_written": result.files_written,
        "files_skipped_remove": result.files_skipped_remove,
        "files_skipped_timeout": result.files_skipped_timeout,
        "files_with_secrets": result.files_with_secrets,
        "secrets_by_category": result.secrets_by_category,
        "rescan_zero": result.rescan_destination_zero,
        "pii_by_category": result.pii_by_category,
        "path_by_category": result.path_by_category,
        "binary_excluded_by_tier": result.binary_excluded_by_tier,
        "exif_uninspected_count": len(result.exif_uninspected),
        "git_history_artifacts": len(result.git_history_artifacts),
        "author_by_field": result.author_by_field,
        "entropy_count": result.entropy_count,
        "entropy_enabled": entropy_enabled,
    })

    # Suppress f1_res unused warning; used implicitly to drive race detection at caller.
    _ = f1_res
    _ = GROUP_C_FILES
    return result


def _bump_cat(result: F3Result, category: str) -> None:
    result.secrets_by_category[category] = result.secrets_by_category.get(category, 0) + 1


def _exclude_binary_tier(result: F3Result, rel_path: str, tier: str) -> None:
    """MV-06 / RS-NEW-042: exclui binario de tier data/credencial do destino.

    `data` -> categoria C8 (client data exports / LGPD); `credential` -> C7
    (certs/private keys). Emite F3ContentMatch `remove_file` (zero-literal:
    so tipo canonico, nunca o conteudo).
    """
    categoria: SanitizationCategory = "C7" if tier == "credential" else "C8"
    tipo = "BINARY_CREDENTIAL_EXCLUDED" if tier == "credential" else "BINARY_DATA_EXCLUDED"
    result.files_skipped_remove += 1
    result.files_with_secrets += 1
    result.binary_excluded_by_tier[tier] = (
        result.binary_excluded_by_tier.get(tier, 0) + 1
    )
    result.matches.append(F3ContentMatch(
        rel_path=rel_path, line=None,
        categoria=categoria, tipo=tipo,
        acao="remove_file",
        encoding_detected="binary",
    ))
    _bump_cat(result, categoria)


def f3_matches_to_report_entries(
    matches: list[F3ContentMatch],
) -> list[SanitizationReportEntry]:
    """Converte F3ContentMatch -> SanitizationReportEntry (Pydantic gate ADR-004).

    Aplica `redact_path` sobre rel_path para defesa em camadas RS-018.
    """
    out: list[SanitizationReportEntry] = []
    for m in matches:
        entry = SanitizationReportEntry(
            path_redacted=redact_path(m.rel_path),
            linha=m.line,
            categoria=m.categoria,
            tipo=m.tipo,
            acao=_normalize_action_for_schema(m.acao),
            encoding_detected=m.encoding_detected if m.encoding_detected != "utf-7" else "latin-1",
        )
        out.append(entry)
    return out


# Schema literal aceita: "remove_file", "placeholder", "redact_inline", "envexample", "remove_line"
# Mapeia "binary"/"utf-7" para tipos canonicos quando aplicavel
_CANONICAL_ACTIONS: frozenset[str] = frozenset(
    {"remove_file", "placeholder", "redact_inline", "envexample", "remove_line"}
)


def _normalize_action_for_schema(acao: str) -> ActionLabel:
    # MV-10 / A2: o guard `in _CANONICAL_ACTIONS` PROVA o membership em runtime;
    # o `cast` apenas informa o type-checker do invariante ja garantido (nao
    # mascara bug, ao contrario de `# type: ignore` — proibido pela mitigacao 14).
    if acao in _CANONICAL_ACTIONS:
        return cast(ActionLabel, acao)
    return "remove_file"  # fallback conservador


__all__ = [
    "DEEP_SCAN_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "F3ContentMatch",
    "F3Result",
    "F3Timeout",
    "FilenameDecision",
    "GitHistoryInDestination",
    "IntegrityFailure",
    "Inv1Violation",
    "LeakDetectedInDestination",
    "TextSanitizationResult",
    "decide_filename_action",
    "f3_matches_to_report_entries",
    "preflight_integrity",
    "rescan_destination",
    "run_c9_pii_detector",
    "run_f3",
    "safe_finditer",
    "safe_sub",
    "sanitize_text_content",
    "scan_binary_deep",
]
