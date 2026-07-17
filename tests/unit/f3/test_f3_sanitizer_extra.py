"""test_f3_sanitizer_extra.py — cobertura adicional Bloco 03 (DoD >= 90%).

Cobre branches especificos nao acionados pelos integration tests:
- _emit_env_example com variantes (vazio, comment-only, sem '=', com BOM Latin-1)
- _classify_text_or_binary_for_processing com classify_encoding='binary'
- f3_matches_to_report_entries normalization (utf-7 -> latin-1; acao nao-canonica)
- _normalize_action_for_schema fallback
- run_f3 com fixture .env real (envexample emit)
- run_f3 com fixture .pem real (remove_file)
- run_f3 com raise_on_leak=False (warning, nao raise)
- rescan_destination com texto contendo CPF
- scan_binary_deep timeout (catastrophic regex injection -> nao acontece em
  matriz real; teste do safe wrapper ja cobre o caminho)
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f3_sanitizer import (
    F3ContentMatch,
    _classify_text_or_binary_for_processing,
    _emit_env_example,
    _normalize_action_for_schema,
    f3_matches_to_report_entries,
    rescan_destination,
    run_f3,
    sanitize_text_content,
)
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[3]


# ===========================================================================
# _emit_env_example branches
# ===========================================================================

def _make_fw(tmp_path: Path, source_path: Path) -> FsWriter:
    return FsWriter(
        source_path=source_path,
        allowed_roots=[tmp_path],
        override_forbidden=[source_path],
    )


def test_emit_env_example_with_kv_pairs(tmp_path: Path) -> None:
    src = tmp_path / "src.env"
    src.write_bytes(b"")
    fw = _make_fw(tmp_path, src)
    dest = tmp_path / "out" / ".env.example"
    content = b"API_KEY=secret_value\nDB_URL=postgres://user:pass@h\n# comment\n\n"
    n = _emit_env_example(content, dest, fw)
    assert n == 2
    text = dest.read_text(encoding="utf-8")
    assert "API_KEY=" in text
    assert "DB_URL=" in text
    assert "secret_value" not in text  # valor zerado
    assert "# comment" in text


def test_emit_env_example_empty_input(tmp_path: Path) -> None:
    src = tmp_path / "src.env"
    src.write_bytes(b"")
    fw = _make_fw(tmp_path, src)
    dest = tmp_path / "out2" / ".env.example"
    n = _emit_env_example(b"", dest, fw)
    assert n == 0
    text = dest.read_text(encoding="utf-8")
    assert "env file vazio" in text


def test_emit_env_example_line_without_equals_becomes_comment(tmp_path: Path) -> None:
    src = tmp_path / "src.env"
    src.write_bytes(b"")
    fw = _make_fw(tmp_path, src)
    dest = tmp_path / "out3" / ".env.example"
    content = b"# header\nORPHAN_LINE_NO_EQUALS\nKEY=val\n"
    n = _emit_env_example(content, dest, fw)
    assert n == 1
    text = dest.read_text(encoding="utf-8")
    assert "# ORPHAN_LINE_NO_EQUALS" in text


def test_emit_env_example_latin1_fallback(tmp_path: Path) -> None:
    src = tmp_path / "src.env"
    src.write_bytes(b"")
    fw = _make_fw(tmp_path, src)
    dest = tmp_path / "out4" / ".env.example"
    # bytes que nao sao UTF-8 mas Latin-1 sempre decode
    content = b"KEY=valor\xff\nOTHER=ok\n"
    n = _emit_env_example(content, dest, fw)
    assert n == 2


# ===========================================================================
# _classify_text_or_binary_for_processing
# ===========================================================================

def test_classify_text_or_binary_returns_binary_for_pdf(tmp_path: Path) -> None:
    f = tmp_path / "a.pdf"
    f.write_bytes(b"%PDF-1.4\nfoo\nbar\n")
    is_bin, _enc = _classify_text_or_binary_for_processing(f, b"%PDF-1.4")
    assert is_bin is True


def test_classify_text_or_binary_returns_text_utf8(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_text("hello world\n", encoding="utf-8")
    is_bin, enc = _classify_text_or_binary_for_processing(f, b"hello world\n")
    assert is_bin is False
    assert enc == "utf-8"


def test_classify_text_or_binary_null_byte_treated_as_binary(tmp_path: Path) -> None:
    f = tmp_path / "a.dat"
    f.write_bytes(b"asdf\x00asdf")
    is_bin, _enc = _classify_text_or_binary_for_processing(f, b"asdf\x00asdf")
    assert is_bin is True


# ===========================================================================
# f3_matches_to_report_entries normalization
# ===========================================================================

def test_f3_matches_to_report_entries_normalizes_utf7_to_latin1() -> None:
    matches = [F3ContentMatch(
        rel_path="data.txt", line=5, categoria="C2",
        tipo="API_KEY_github_ghp", acao="redact_inline",
        encoding_detected="utf-7",
    )]
    entries = f3_matches_to_report_entries(matches)
    assert len(entries) == 1
    assert entries[0].encoding_detected == "latin-1"


def test_normalize_action_for_schema_canonical() -> None:
    assert _normalize_action_for_schema("remove_file") == "remove_file"
    assert _normalize_action_for_schema("redact_inline") == "redact_inline"


def test_normalize_action_for_schema_fallback() -> None:
    """Acao nao-canonica deve cair em 'remove_file' (fallback conservador)."""
    assert _normalize_action_for_schema("ridiculous_unknown_action") == "remove_file"


# ===========================================================================
# Pipeline run_f3 com fixture .env -> envexample
# ===========================================================================

def _setup_run_f3(tmp_path: Path, slug: str = "demo"):
    src = tmp_path / "src"
    src.mkdir()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    relatorios = allowed / "Relatorios"
    relatorios.mkdir()
    dest = allowed / f"GIT_{slug}-v1"
    dest.mkdir()
    fw = FsWriter(source_path=src, allowed_roots=[allowed], override_forbidden=[])
    audit = AuditLogger(
        audit_file=relatorios / "audit-log.jsonl", fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="0.3.0a1", sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64, slug=slug,
        source_path_redacted="src", dest_path_redacted="dst",
    )
    return src, dest, fw, audit


def test_run_f3_emits_env_example_when_env_file_present(tmp_path: Path) -> None:
    src, dest, fw, audit = _setup_run_f3(tmp_path)
    (src / ".env").write_text("API_KEY=ghp_real_secret_should_not_propagate_to_dest_at_all\n",
                              encoding="utf-8")
    (src / "README.md").write_text("# demo\n", encoding="utf-8")

    result = run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    # .env nao copiado, mas .env.example sim
    assert not (dest / ".env").exists()
    env_example = dest / ".env.example"
    assert env_example.exists()
    text = env_example.read_text(encoding="utf-8")
    assert "API_KEY=" in text
    assert "ghp_real_secret_should_not_propagate_to_dest_at_all" not in text
    # match C1 reportado
    assert any(m.categoria == "C1" for m in result.matches)


def test_run_f3_skips_pem_cert_file(tmp_path: Path) -> None:
    src, dest, fw, audit = _setup_run_f3(tmp_path)
    (src / "server.pem").write_text("# fake cert\n", encoding="utf-8")
    (src / "README.md").write_text("# demo\n", encoding="utf-8")

    result = run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    # cert NAO copiado
    assert not (dest / "server.pem").exists()
    # README copiado
    assert (dest / "README.md").exists()
    # match C7 reportado
    assert any(m.categoria == "C7" for m in result.matches)


def test_run_f3_with_raise_on_leak_false_doesnt_raise(tmp_path: Path) -> None:
    """raise_on_leak=False: Camada C6 falha registrada em result, sem raise."""
    src, dest, fw, audit = _setup_run_f3(tmp_path)
    (src / "README.md").write_text("# normal\n", encoding="utf-8")
    # Salt: pre-poluir destino com .env (simulacao leak pre-existente para test).
    # Note: F3 walking source nao colide com poluicao do destino, mas Camada C6
    # re-scan detect.
    (dest / ".env").write_text("KEY=val\n", encoding="utf-8")

    result = run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
        raise_on_leak=False,
    )
    # Resultado registra que rescan falhou (mas nao raise)
    assert result.rescan_destination_zero is False


def test_run_f3_text_file_with_ghp_token_redacted(tmp_path: Path) -> None:
    src, dest, fw, audit = _setup_run_f3(tmp_path)
    (src / "config.py").write_text(
        '# config\nKEY = "ghp_abcdef123456789012345"\n',
        encoding="utf-8",
    )
    (src / "README.md").write_text("# demo\n", encoding="utf-8")

    result = run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    # config.py copiado mas sanitizado
    out = (dest / "config.py").read_text(encoding="utf-8")
    assert "ghp_abcdef123456789012345" not in out
    assert "<REDACTED" in out
    # Match line-level reportado
    assert any(m.categoria in {"C2", "C6"} for m in result.matches)


def test_run_f3_with_binary_clean_copies_literal(tmp_path: Path) -> None:
    src, dest, fw, audit = _setup_run_f3(tmp_path)
    # Binario PNG limpo (so magic bytes + bytes inocuos)
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + b"clean-data"
    (src / "logo.png").write_bytes(png_bytes)
    (src / "README.md").write_text("# demo\n", encoding="utf-8")

    run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    # Binario limpo COPIADO literalmente
    assert (dest / "logo.png").exists()
    assert (dest / "logo.png").read_bytes() == png_bytes


def test_run_f3_idempotent_re_run_finds_zero_in_destination(tmp_path: Path) -> None:
    """Idempotencia: re-rodar F3 sobre o mesmo source no MESMO destino (versao
    diferente) produz dest equivalente. Aqui simplificamos para 2 destinos
    distintos e checamos que ambos sao consistentes."""
    src, dest, fw, audit = _setup_run_f3(tmp_path, slug="idempotent")
    (src / "README.md").write_text("# demo\n", encoding="utf-8")

    result_a = run_f3(
        source_path=src, dest_path=dest,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    files_a = sorted([p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()])

    # Segundo dest
    dest2 = dest.parent / "GIT_idempotent-v2"
    dest2.mkdir()
    result_b = run_f3(
        source_path=src, dest_path=dest2,
        fs_writer=fw, audit=audit,
        project_root=PROJECT_ROOT,
    )
    files_b = sorted([p.relative_to(dest2).as_posix() for p in dest2.rglob("*") if p.is_file()])

    assert files_a == files_b
    assert result_a.files_processed == result_b.files_processed


# ===========================================================================
# rescan_destination cobre cenarios adicionais
# ===========================================================================

def test_rescan_destination_detects_cpf_in_csv(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "data.txt").write_text("Cliente CPF: 123.456.789-00 ativo\n", encoding="utf-8")
    n, matches = rescan_destination(dest)
    assert n >= 1
    assert any(m.categoria == "C5" for m in matches)


def test_rescan_destination_binary_with_aws_key(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "leaked.bin").write_bytes(
        b"\x00" * 100 + b"AKIAIOSFODNN7EXAMPLE" + b"\x00" * 100,
    )
    n, _matches = rescan_destination(dest)
    assert n >= 1


def test_sanitize_text_content_returns_no_skip_for_clean_text() -> None:
    text = "print('hello')\n# nothing sensitive\n"
    r = sanitize_text_content(text, "utf-8")
    assert r.sanitized_text == text
    assert r.matches == []
    assert r.skip_file is False
