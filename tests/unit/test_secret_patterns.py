"""test_secret_patterns.py — matriz canonica 10 categorias (ADR-001 + ADR-002).

Bloco 03 Passo 03.1 (Camada C1 RS-001): smoke por cat ativando cada uma das 10
categorias com fixture canonica positiva + 1 fixture negativa por cat (FP-control).
"""
from __future__ import annotations

from repo_sanitizer.secret_patterns import (
    C1_FILENAME_RE,
    SECRET_MATRIX,
    all_rules,
    category_count,
)

# ===========================================================================
# Estrutura da matriz canonica (smoke base; vinha do Bloco 01)
# ===========================================================================

def test_matrix_has_10_categories() -> None:
    assert set(SECRET_MATRIX.keys()) == {f"C{i}" for i in range(1, 11)}


def test_each_category_has_at_least_one_rule() -> None:
    for cat, rules in SECRET_MATRIX.items():
        assert len(rules) >= 1, f"Categoria {cat} sem regras"


def test_all_rules_have_canonical_action() -> None:
    valid_actions = {"remove_file", "placeholder", "redact_inline", "envexample", "remove_line"}
    for r in all_rules():
        assert r.acao in valid_actions


def test_category_count_returns_dict() -> None:
    cnt = category_count()
    assert sum(cnt.values()) == len(all_rules())


# ===========================================================================
# Smokes por CATEGORIA (Bloco 03 Passo 03.1 — 1 positivo + 1 negativo cada)
# ===========================================================================

# ----------------- C1 .env files (file-level) -----------------

def test_c1_matches_env_filename() -> None:
    assert C1_FILENAME_RE.match(".env") is not None
    assert C1_FILENAME_RE.match(".env.local") is not None
    assert C1_FILENAME_RE.match(".env.production") is not None
    assert C1_FILENAME_RE.match("env") is not None
    assert C1_FILENAME_RE.match("config.env") is not None


def test_c1_no_match_on_unrelated_filenames() -> None:
    # Falso-positivo control
    assert C1_FILENAME_RE.match("environment.md") is None
    assert C1_FILENAME_RE.match("README.md") is None
    assert C1_FILENAME_RE.match("envoy-config.yml") is None


# ----------------- C2 API keys hardcoded -----------------

def test_c2_detects_openai_sk() -> None:
    rule = next(r for r in SECRET_MATRIX["C2"] if r.tipo == "API_KEY_openai_sk")
    assert rule.regex.search("API_KEY=sk-abc1234567890def1234567890") is not None


def test_c2_detects_ghp_token() -> None:
    rule = next(r for r in SECRET_MATRIX["C2"] if r.tipo == "API_KEY_github_ghp")
    assert rule.regex.search("token: ghp_abc123def456ghi789jklmnop") is not None


def test_c2_detects_aws_akia() -> None:
    rule = next(r for r in SECRET_MATRIX["C2"] if r.tipo == "API_KEY_aws_AKIA")
    assert rule.regex.search("aws_id=AKIAIOSFODNN7EXAMPLE") is not None


def test_c2_no_match_on_random_text() -> None:
    rule_ghp = next(r for r in SECRET_MATRIX["C2"] if r.tipo == "API_KEY_github_ghp")
    assert rule_ghp.regex.search("hello world sem token aqui") is None


# ----------------- C3 JWT/OAuth tokens -----------------

def test_c3_detects_jwt_token() -> None:
    rule = next(r for r in SECRET_MATRIX["C3"] if r.tipo == "JWT_TOKEN")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
    assert rule.regex.search(f"Authorization: {jwt}") is not None


def test_c3_detects_oauth_bearer() -> None:
    rule = next(r for r in SECRET_MATRIX["C3"] if r.tipo == "OAUTH_BEARER")
    assert rule.regex.search("Authorization: Bearer abc123def456ghi789jklmnop") is not None


def test_c3_no_match_on_bare_word() -> None:
    rule = next(r for r in SECRET_MATRIX["C3"] if r.tipo == "JWT_TOKEN")
    assert rule.regex.search("eyJ not.complete") is None


# ----------------- C4 Database URLs -----------------

def test_c4_detects_postgres_url() -> None:
    rule = next(r for r in SECRET_MATRIX["C4"] if r.tipo == "DATABASE_URL_postgres")
    assert rule.regex.search("postgres://user:pass@host:5432/db") is not None


def test_c4_detects_mongodb_url() -> None:
    rule = next(r for r in SECRET_MATRIX["C4"] if r.tipo == "DATABASE_URL_mongodb")
    assert rule.regex.search("mongodb://admin:secret@cluster0.mongodb.net/dbname") is not None


def test_c4_no_match_on_plain_url() -> None:
    rule = next(r for r in SECRET_MATRIX["C4"] if r.tipo == "DATABASE_URL_postgres")
    assert rule.regex.search("postgres://host:5432/db") is None  # sem user:pass


# ----------------- C5 PII textual BR (LGPD INV-12) -----------------

def test_c5_detects_cpf_formatado() -> None:
    rule = next(r for r in SECRET_MATRIX["C5"] if r.tipo == "CPF_FORMATADO")
    assert rule.regex.search("CPF: 123.456.789-00 cliente X") is not None


def test_c5_detects_cnpj() -> None:
    rule = next(r for r in SECRET_MATRIX["C5"] if r.tipo == "CNPJ")
    assert rule.regex.search("CNPJ: 12.345.678/0001-90") is not None


def test_c5_detects_email_pessoal() -> None:
    rule = next(r for r in SECRET_MATRIX["C5"] if r.tipo == "EMAIL_PESSOAL")
    assert rule.regex.search("contato: john.doe@empresa.com") is not None


def test_c5_no_match_on_example_email() -> None:
    rule = next(r for r in SECRET_MATRIX["C5"] if r.tipo == "EMAIL_PESSOAL")
    # exclui example.com/test.com per regex
    assert rule.regex.search("contato: user@example.com") is None


# ----------------- C6 Secrets em config -----------------

def test_c6_detects_config_key() -> None:
    rule = next(r for r in SECRET_MATRIX["C6"] if r.tipo == "CONFIG_KEY_GENERIC")
    # YAML / .properties / .env: chave sem aspas + valor (com ou sem aspas)
    assert rule.regex.search('api_key: my-secret-value-123') is not None
    assert rule.regex.search("API_KEY=value123") is not None
    assert rule.regex.search('auth_token: "deadbeef-xyz"') is not None


def test_c6_detects_password_assignment() -> None:
    rule = next(r for r in SECRET_MATRIX["C6"] if r.tipo == "CONFIG_KEY_GENERIC")
    assert rule.regex.search("password = supersecreto123") is not None


def test_c6_no_match_on_label_only() -> None:
    rule = next(r for r in SECRET_MATRIX["C6"] if r.tipo == "CONFIG_KEY_GENERIC")
    assert rule.regex.search("password is required") is None  # sem `:` ou `=`


# ----------------- C6 P1-c (GAP-S07-02): nao cruzar newline -----------------

def test_c6_no_fp_on_empty_env_example_multiline() -> None:
    """P1-c: `.env.example` de chaves VAZIAS multi-linha NAO dispara C6.

    ANTES: `\\s*` apos `[:=]` cruzava `\\n` e capturava a variavel da linha
    seguinte -> FP que bloqueava (exit-7) uma replica limpa. AGORA: separador
    horizontal `[ \\t]*` nao cruza newline; chave vazia (so `\\n`) nao casa.
    """
    rule = next(r for r in SECRET_MATRIX["C6"] if r.tipo == "CONFIG_KEY_GENERIC")
    env_example = (
        "STRIPE_WEBHOOK_SECRET=\n"
        "NEXT_PUBLIC_API_KEY=\n"
        "DATABASE_PASSWORD=\n"
        "AUTH_TOKEN=\n"
    )
    assert rule.regex.findall(env_example) == []


def test_c6_no_fp_on_empty_key_then_value_next_line() -> None:
    """P1-c: chave vazia seguida de outra com valor NAO casa cruzando o newline."""
    rule = next(r for r in SECRET_MATRIX["C6"] if r.tipo == "CONFIG_KEY_GENERIC")
    # TOKEN vazio (so espacos horizontais + newline); OTHER nao e chave-gatilho.
    assert rule.regex.findall("TOKEN=   \nOTHER_VAR=realvalue123") == []


def test_c6_still_detects_inline_secret() -> None:
    """P1-c: segredo inline REAL na MESMA linha AINDA dispara C6 (sem afrouxar)."""
    rule = next(r for r in SECRET_MATRIX["C6"] if r.tipo == "CONFIG_KEY_GENERIC")
    assert rule.regex.search('api_key = "sk-abcdef1234567890XYZ"') is not None
    assert rule.regex.search("password=hunter2supersecret") is not None
    assert rule.regex.search("secret: deadbeef-cafe-1234") is not None


# ----------------- C7 Cert / private keys -----------------

def test_c7_detects_pem_header() -> None:
    rule = next(r for r in SECRET_MATRIX["C7"] if r.tipo == "PRIVATE_KEY_PEM_BLOCK")
    assert rule.regex.search("-----BEGIN RSA PRIVATE KEY-----") is not None


def test_c7_detects_cert_file_ext() -> None:
    rule = next(r for r in SECRET_MATRIX["C7"] if r.tipo == "CERT_FILE_EXT")
    assert rule.regex.search("server.pem") is not None
    assert rule.regex.search("client.key") is not None
    assert rule.regex.search("cert.p12") is not None


def test_c7_no_match_on_readme() -> None:
    rule = next(r for r in SECRET_MATRIX["C7"] if r.tipo == "PRIVATE_KEY_PEM_BLOCK")
    assert rule.regex.search("README.md") is None


# ----------------- C8 Client data exports -----------------

def test_c8_detects_csv_header_with_cpf() -> None:
    rule = next(r for r in SECRET_MATRIX["C8"] if r.tipo == "CLIENT_CSV_HEADER")
    assert rule.regex.search("nome,cpf,email\n[NOME],123,a@b.com") is not None


def test_c8_detects_csv_nome_completo() -> None:
    rule = next(r for r in SECRET_MATRIX["C8"] if r.tipo == "CLIENT_CSV_HEADER")
    assert rule.regex.search("id;nome_completo;data\n") is not None


def test_c8_no_match_on_unrelated_csv() -> None:
    rule = next(r for r in SECRET_MATRIX["C8"] if r.tipo == "CLIENT_CSV_HEADER")
    # CSV de metricas sem PII -> sem match
    assert rule.regex.search("metric,value,unit\nrps,100,req/s") is None


# ----------------- C9 URLs internas / hostnames -----------------

def test_c9_detects_internal_hostname() -> None:
    rule = next(r for r in SECRET_MATRIX["C9"] if r.tipo == "INTERNAL_HOSTNAME")
    assert rule.regex.search("db.acme.internal:5432") is not None


def test_c9_detects_private_ipv4() -> None:
    rule = next(r for r in SECRET_MATRIX["C9"] if r.tipo == "PRIVATE_IPV4")
    assert rule.regex.search("conectando em 10.0.0.5") is not None
    assert rule.regex.search("conectando em 192.168.1.100") is not None


def test_c9_no_match_on_public_ip() -> None:
    rule = next(r for r in SECRET_MATRIX["C9"] if r.tipo == "PRIVATE_IPV4")
    assert rule.regex.search("conectando em 8.8.8.8") is None


# ----------------- C10 TODO/FIXME marker -----------------

def test_c10_detects_todo_remove_key() -> None:
    rule = next(r for r in SECRET_MATRIX["C10"] if r.tipo == "TODO_REMOVE_KEY_MARKER")
    assert rule.regex.search("# TODO: remover api_key antes do commit") is not None


def test_c10_detects_fixme_comment() -> None:
    rule = next(r for r in SECRET_MATRIX["C10"] if r.tipo == "TODO_REMOVE_KEY_MARKER")
    assert rule.regex.search("// FIXME: tirar essa password hardcoded") is not None


def test_c10_no_match_on_generic_todo() -> None:
    rule = next(r for r in SECRET_MATRIX["C10"] if r.tipo == "TODO_REMOVE_KEY_MARKER")
    assert rule.regex.search("# TODO: revisar logica") is None
