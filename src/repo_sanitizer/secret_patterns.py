"""secret_patterns.py — Extensao local das 10 categorias canonicas F3 (ADR-001 + ADR-002 + ADR-015 + INV-5 Modo Paranoico + INV-10).

Bloco 01: matriz canonica 10 categorias com regex base. Bloco 03 expande
cada categoria com smoke test isolado + acao por categoria (ADR-002 matriz fixa).

Categorias canonicas (escopo §5 F3 + brainstorm.json):
    C1  .env files (`.env`, `.env.local`, `.env.production`, etc)
    C2  API keys hardcoded (sk-, AIza, ghp_, xoxb-, AKIA, tvly-, etc)
    C3  JWT/OAuth tokens (eyJ... 3 partes base64)
    C4  Database URLs com credenciais (`postgres://user:pass@host`, etc)
    C5  PII textual BR (CPF, CNPJ, email, telefone) — LGPD INV-12
    C6  Secrets em config (`"api_key": "..."`, `password = "..."`)
    C7  Cert / private keys (-----BEGIN ... PRIVATE KEY-----)
    C8  Client data exports (CSV / db dumps com header sensitive)
    C9  URLs internas (.internal, .corp, db.acme.internal)
    C10 Comments TODO/FIXME marcando key (`# TODO: remover key antes do commit`)

INVARIANTE (RS-001 TOP-01 catastrofico): matriz e canonica + integrity SHA-256
locked. Bloco 01 grava hash via record_secret_patterns_integrity(). Em Bloco 03
F3 verifica pre-run + mismatch = exit 3.

IMPORT: este modulo NAO importa _sanitize.py upstream — apenas a copia local
via tests/fixtures/sentinel/_sanitize.py (ADR-023 + RS-013).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern
from typing import Literal

# Re-export das 5 regexes herdadas da copia local Sentinel (camada base).
# [NOME] pode importar do local-copy via importlib em runtime (Bloco 03 F3).
SENTINEL_INHERITED_REGEXES_SOURCE: list[str] = [
    r"tvly-[A-Za-z0-9]+",
    r"AKIA[A-Z0-9]+",
    r"ghp_[A-Za-z0-9]+",
    r"sk-[A-Za-z0-9]{16,}",
    r"(?i)(api[_-]?key|password|secret)\s*[:=]\s*[^\s\"]+",
]


CategoryLabel = Literal[
    "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10",
]


ActionLabel = Literal[
    "remove_file",
    "placeholder",
    "redact_inline",
    "envexample",
    "remove_line",
]


@dataclass(frozen=True)
class SecretRule:
    """Uma regra de deteccao + acao canonica."""
    category: CategoryLabel
    tipo: str          # rotulo canonico (nunca valor literal)
    regex: Pattern[str]
    acao: ActionLabel
    description: str = ""


# ============== CATEGORIA C1 — .env files ==============
# Acao file-level: remove_file (toda .env nunca passa) + emite envexample.
C1_FILENAME_RE = re.compile(
    r"^(\.env(\.[A-Za-z0-9_-]+)?|.*\.env|env)$",
)

C1_RULES: list[SecretRule] = [
    SecretRule(
        category="C1",
        tipo="ENV_FILE",
        regex=C1_FILENAME_RE,  # aplicado a basename
        acao="remove_file",
        description="Arquivos .env / .env.* / *.env",
    ),
]


# ============== CATEGORIA C2 — API keys hardcoded ==============
# Acao: redact_inline (substitui valor por <REDACTED-API-KEY> + envexample).
C2_RULES: list[SecretRule] = [
    SecretRule("C2", "API_KEY_openai_sk", re.compile(r"sk-[A-Za-z0-9]{16,}"), "redact_inline",
               "OpenAI sk-... (16+ chars)"),
    SecretRule("C2", "API_KEY_google_AIza", re.compile(r"AIza[A-Za-z0-9_-]{20,}"), "redact_inline",
               "Google API AIza...(20+ chars)"),
    SecretRule("C2", "API_KEY_github_ghp", re.compile(r"ghp_[A-Za-z0-9]{20,}"), "redact_inline",
               "GitHub PAT ghp_..."),
    SecretRule("C2", "API_KEY_github_gho", re.compile(r"gh[opsur]_[A-Za-z0-9]{20,}"), "redact_inline",
               "GitHub gho_/ghs_/ghu_/ghr_/ghp_ tokens"),
    SecretRule("C2", "API_KEY_slack_xoxb", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "redact_inline",
               "Slack xoxb-, xoxa-, xoxp-, xoxr-, xoxs-"),
    SecretRule("C2", "API_KEY_aws_AKIA", re.compile(r"AKIA[A-Z0-9]{16}"), "redact_inline",
               "AWS Access Key ID"),
    SecretRule("C2", "API_KEY_tavily_tvly", re.compile(r"tvly-[A-Za-z0-9]{20,}"), "redact_inline",
               "Tavily API tvly-..."),
    SecretRule("C2", "API_KEY_anthropic_sk_ant", re.compile(r"sk-ant-[A-Za-z0-9-]{20,}"), "redact_inline",
               "Anthropic sk-ant-..."),
    # ----- v1.2.0 / A4 / MV-03 / RS-NEW-040: prefixos modernos ANCORADOS -----
    # Ancoragem `(?<![\w-])` (largura-fixa, anti-ReDoS) evita casar substring
    # dentro de palavra/identificador (ex.: `task-project-id` não casa
    # `sk-proj-`). Cap superior `{n,200}` limita o token (anti-OOM). `tipo`
    # canonico, NUNCA literal. Processadas via safe_finditer/safe_sub
    # (timeout 30s ADR-026) em sanitize_text_content. NÃO remove regras antigas.
    # Auditoria 2026-07: red team provou que o formato estrito {22}_{59} deixa
    # escapar tokens com contagem ligeiramente diferente (FN real na cobaia).
    # INV-5 Modo Paranoico: faixa larga {30,200} com charset [A-Za-z0-9_].
    SecretRule("C2", "API_KEY_github_pat",
               re.compile(r"(?<![\w-])github_pat_[A-Za-z0-9_]{30,200}"),
               "redact_inline", "GitHub fine-grained PAT github_pat_<30..200>"),
    SecretRule("C2", "API_KEY_openai_sk_proj",
               re.compile(r"(?<![\w-])sk-proj-[A-Za-z0-9_-]{20,200}"),
               "redact_inline", "OpenAI project key sk-proj-... (marcador T3BlbkAJ)"),
    SecretRule("C2", "API_KEY_stripe",
               re.compile(r"(?<![\w-])(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,200}"),
               "redact_inline", "Stripe (sk|rk|pk)_(live|test)_..."),
    SecretRule("C2", "WEBHOOK_stripe",
               re.compile(r"(?<![\w-])whsec_[A-Za-z0-9]{20,200}"),
               "redact_inline", "Stripe webhook signing secret whsec_..."),
    SecretRule("C2", "API_KEY_gitlab_pat",
               re.compile(r"(?<![\w-])glpat-[A-Za-z0-9_-]{20,200}"),
               "redact_inline", "GitLab personal access token glpat-..."),
    SecretRule("C2", "API_KEY_slack_app",
               re.compile(r"(?<![\w-])(?:xapp|xoxe)-[A-Za-z0-9-]{10,200}"),
               "redact_inline", "Slack app-level / config token xapp-/xoxe-..."),
    # AWS: a regra `API_KEY_aws_AKIA` (acima) JA cobre AKIA permanente. Aqui
    # adicionamos as variantes TEMPORARIAS/ROLE (ASIA/AROA) SEM remover a antiga
    # (restricao do #04: "NAO remova regras existentes"). Sem duplicacao de AKIA.
    SecretRule("C2", "API_KEY_aws_temp",
               re.compile(r"(?<![A-Z0-9])(?:ASIA|AROA)[A-Z0-9]{16}"),
               "redact_inline", "AWS temp/role access key (ASIA temporario / AROA role)"),
]


# ============== CATEGORIA C3 — JWT/OAuth tokens ==============
C3_RULES: list[SecretRule] = [
    SecretRule("C3", "JWT_TOKEN", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
               "redact_inline", "JWT (header.payload.sig base64url)"),
    SecretRule("C3", "OAUTH_BEARER", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"),
               "redact_inline", "Authorization Bearer <token>"),
]


# ============== CATEGORIA C4 — Database URLs ==============
C4_RULES: list[SecretRule] = [
    SecretRule("C4", "DATABASE_URL_postgres", re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+"),
               "redact_inline", "postgres://user:pass@host"),
    SecretRule("C4", "DATABASE_URL_mysql", re.compile(r"mysql://[^:\s]+:[^@\s]+@[^/\s]+"),
               "redact_inline", "mysql://user:pass@host"),
    SecretRule("C4", "DATABASE_URL_mongodb", re.compile(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+"),
               "redact_inline", "mongodb://user:pass@host"),
    SecretRule("C4", "DATABASE_URL_redis", re.compile(r"redis://[^:\s]*:[^@\s]+@[^/\s]+"),
               "redact_inline", "redis://[user]:pass@host"),
]


# ============== CATEGORIA C5 — PII textual BR (LGPD INV-12) ==============
C5_RULES: list[SecretRule] = [
    SecretRule("C5", "CPF_FORMATADO", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
               "redact_inline", "CPF NNN.NNN.NNN-NN"),
    SecretRule("C5", "CPF_CRU", re.compile(r"(?<!\d)\d{11}(?!\d)"),
               "redact_inline", "CPF 11 digitos (heuristica)"),
    SecretRule("C5", "CNPJ", re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),
               "redact_inline", "CNPJ NN.NNN.NNN/NNNN-NN"),
    SecretRule("C5", "EMAIL_PESSOAL", re.compile(r"[A-Za-z0-9._%+-]+@(?!example\.com|test\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
               "redact_inline", "email (excl. example.com / test.com)"),
    SecretRule("C5", "TELEFONE_BR", re.compile(r"\+?55\s*\(?\d{2}\)?\s*9?\s*\d{4}-?\d{4}"),
               "redact_inline", "+55 11 9NNNN-NNNN"),
]


# ============== CATEGORIA C6 — Secrets em config (.json/.yml) ==============
C6_RULES: list[SecretRule] = [
    # P1-c (GAP-S07-02): separadores HORIZONTAIS apenas (`[ \t]*` em vez de `\s*`)
    # para NAO cruzar `\n`. Sem isto, `STRIPE_SECRET=\nNEXT_VAR=x` casava o valor
    # da PROXIMA linha -> `.env.example` de chaves vazias disparava o gate exit-7
    # e bloqueava uma replica LIMPA. O valor casado tem >=1 char nao-trivial NA
    # MESMA linha: `[^\s\"'#]` exige um char visivel imediatamente apos o
    # separador, entao chave vazia (so newline) NAO casa. Inline real ainda casa.
    SecretRule("C6", "CONFIG_KEY_GENERIC",
               re.compile(r"(?i)(api[_-]?key|password|secret|token|auth)[ \t]*[:=][ \t]*[\"']?[^\s\"'#]+[\"']?"),
               "redact_inline", "API_KEY=valor / api_key: valor / password=valor"),
]


# ============== CATEGORIA C7 — Cert / private keys ==============
C7_RULES: list[SecretRule] = [
    SecretRule("C7", "PRIVATE_KEY_PEM_BLOCK",
               re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"),
               "remove_file", "PEM private key header"),
    SecretRule("C7", "CERT_FILE_EXT",
               re.compile(r"\.(pem|key|p12|pfx|crt|pkcs12)$", re.IGNORECASE),
               "remove_file", "cert/key file extension"),
]


# ============== CATEGORIA C8 — Client data exports ==============
C8_RULES: list[SecretRule] = [
    SecretRule("C8", "CLIENT_CSV_HEADER",
               re.compile(r"(?i)(cpf|nome[_-]completo|telefone|email|endereco)[,;\t]"),
               "remove_file", "CSV header com PII columns"),
]


# ============== CATEGORIA C9 — URLs internas ==============
C9_RULES: list[SecretRule] = [
    SecretRule("C9", "INTERNAL_HOSTNAME",
               re.compile(r"\b[a-z0-9-]+\.(?:internal|corp|local|acme)\.(?:com|net|io|br)?\b"),
               "redact_inline", "*.internal / *.corp / *.local / acme.* hostnames"),
    SecretRule("C9", "PRIVATE_IPV4",
               re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}\b"),
               "redact_inline", "RFC 1918 private IPv4"),
]


# ============== CATEGORIA C10 — TODO/FIXME marker ==============
C10_RULES: list[SecretRule] = [
    SecretRule("C10", "TODO_REMOVE_KEY_MARKER",
               re.compile(r"(?i)(#|//|/\*|<!--)\s*(TODO|FIXME|XXX|HACK)[^\n]*?(remove|tirar|deletar)[^\n]*?(key|chave|password|secret|token)"),
               "remove_line", "Comment marker TODO/FIXME re: secret"),
]


# Matriz canonica consolidada (ADR-002 matriz fixa MVP).
SECRET_MATRIX: dict[CategoryLabel, list[SecretRule]] = {
    "C1": C1_RULES,
    "C2": C2_RULES,
    "C3": C3_RULES,
    "C4": C4_RULES,
    "C5": C5_RULES,
    "C6": C6_RULES,
    "C7": C7_RULES,
    "C8": C8_RULES,
    "C9": C9_RULES,
    "C10": C10_RULES,
}


def all_rules() -> list[SecretRule]:
    """Flatten da matriz (uso em Bloco 03 F3 scanner)."""
    out: list[SecretRule] = []
    for rules in SECRET_MATRIX.values():
        out.extend(rules)
    return out


def category_count() -> dict[CategoryLabel, int]:
    """Retorna {categoria: n_rules}."""
    return {c: len(rs) for c, rs in SECRET_MATRIX.items()}


__all__ = [
    "C1_FILENAME_RE",
    "SECRET_MATRIX",
    "SENTINEL_INHERITED_REGEXES_SOURCE",
    "ActionLabel",
    "CategoryLabel",
    "SecretRule",
    "all_rules",
    "category_count",
]
