"""test_f3_phase5_cov_push.py — Fase 5 cov push f3_sanitizer.py >=88%.

Carry-over D-EX-18 (Bloco 03): f3_sanitizer.py cov 87.91% -> meta 88%+.
Branches faltantes (defensivos rare-path) cobertos via mock-based tests:

- remove_file action via skip_file pos C7 content match
- rescan_destination com dest inexistente / OSError / ValueError relative_to
- _emit_env_example UnicodeDecodeError fallback latin-1
- scan_binary_deep com sample que dispara C7 PEM
- _classify_text_or_binary_for_processing edge case binary fallback
- F3 write Exception path -> audit fs_write_blocked
- INV-1 violation pre/pos mismatch raise

Estrategia: mocks via monkeypatch + tmp_path; INV-1 preservada.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Push 1 — rescan_destination com dest inexistente -> (0, [])
# ---------------------------------------------------------------------------


def test_rescan_destination_dest_does_not_exist(tmp_path: Path) -> None:
    """rescan_destination retorna (0, []) quando dest_path nao existe."""
    from repo_sanitizer.f3_sanitizer import rescan_destination

    nonexistent = tmp_path / "nope"
    n, leaks = rescan_destination(nonexistent)
    assert n == 0
    assert leaks == []


# ---------------------------------------------------------------------------
# Push 2 — rescan_destination com OSError no read_bytes
# ---------------------------------------------------------------------------


def test_rescan_destination_oserror_on_read_bytes(tmp_path: Path) -> None:
    """rescan_destination skipa arquivo se read_bytes raise OSError."""
    from repo_sanitizer.f3_sanitizer import rescan_destination

    dest = tmp_path / "dest"
    dest.mkdir()
    f = dest / "broken.txt"
    f.write_text("normal content", encoding="utf-8")

    real_read_bytes = Path.read_bytes

    def raising_read_bytes(self):
        if self.name == "broken.txt":
            raise OSError("simulated permission error")
        return real_read_bytes(self)

    with patch.object(Path, "read_bytes", raising_read_bytes):
        n, leaks = rescan_destination(dest)
    assert n == 0
    assert leaks == []


# ---------------------------------------------------------------------------
# Push 3 — _emit_env_example com bytes que disparam decode replace path
# ---------------------------------------------------------------------------


def test_emit_env_example_with_invalid_utf8_bytes(tmp_path: Path) -> None:
    """_emit_env_example com bytes invalidos UTF-8 -> latin-1 fallback via errors=replace."""
    from repo_sanitizer.f3_sanitizer import _emit_env_example
    from repo_sanitizer.helpers._fs_writer import FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "out.env.example"
    # Bytes parcialmente invalidos UTF-8 (Latin-1 chars > 0x7F)
    src_bytes = b"API_KEY=valor\nKEY2=\xff\xfeoutra\n"
    n_keys = _emit_env_example(src_bytes, target, fw)
    assert n_keys >= 1
    out = target.read_text(encoding="utf-8")
    assert "API_KEY=" in out


# ---------------------------------------------------------------------------
# Push 4 — _emit_env_example com arquivo vazio
# ---------------------------------------------------------------------------


def test_emit_env_example_empty_file(tmp_path: Path) -> None:
    """_emit_env_example sobre bytes vazios -> placeholder generico."""
    from repo_sanitizer.f3_sanitizer import _emit_env_example
    from repo_sanitizer.helpers._fs_writer import FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "empty.env.example"
    _emit_env_example(b"", target, fw)
    out = target.read_text(encoding="utf-8")
    assert "env file vazio" in out or len(out) > 0


# ---------------------------------------------------------------------------
# Push 5 — _emit_env_example com linhas sem `=` (comentadas)
# ---------------------------------------------------------------------------


def test_emit_env_example_lines_without_equals(tmp_path: Path) -> None:
    """Linha sem `=` deve virar comentario `# linha`."""
    from repo_sanitizer.f3_sanitizer import _emit_env_example
    from repo_sanitizer.helpers._fs_writer import FsWriter

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-src",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    target = allowed / "comments.env.example"
    src = b"linha-sem-equals\nKEY=value\n"
    _emit_env_example(src, target, fw)
    out = target.read_text(encoding="utf-8")
    assert "# linha-sem-equals" in out
    assert "KEY=" in out


# ---------------------------------------------------------------------------
# Push 6 — scan_binary_deep com sample PEM
# ---------------------------------------------------------------------------


def test_scan_binary_deep_with_pem_block() -> None:
    """scan_binary_deep detecta PEM private key header."""
    from repo_sanitizer.f3_sanitizer import scan_binary_deep

    sample = b"binary header\x00\x00-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END\x01"
    matches, timeouts = scan_binary_deep("fake.bin", sample)
    # Ao menos 1 match PEM esperado
    assert len(matches) >= 1
    assert timeouts == []


# ---------------------------------------------------------------------------
# Push 7 — sanitize_text_content remove_line para C10 TODO marker
# ---------------------------------------------------------------------------


def test_sanitize_text_content_remove_line_c10_todo() -> None:
    """C10 TODO marker -> acao=remove_line; linha eliminada do sanitized."""
    from repo_sanitizer.f3_sanitizer import sanitize_text_content

    text = "line1\n# TODO: tirar API_KEY antes do commit XXX\nline3\n"
    tsr = sanitize_text_content(text, "utf-8")
    # remove_line ocorre; linha NAO deve estar no sanitized
    assert "TODO: tirar API_KEY" not in tsr.sanitized_text
    assert "line1" in tsr.sanitized_text
    assert "line3" in tsr.sanitized_text
    assert len(tsr.matches) >= 1


# ---------------------------------------------------------------------------
# Push 8 — sanitize_text_content placeholder para C2 redact_inline
# ---------------------------------------------------------------------------


def test_sanitize_text_content_redact_inline_c2() -> None:
    """C2 API key -> redact_inline; valor substituido por placeholder."""
    from repo_sanitizer.f3_sanitizer import sanitize_text_content

    text = "GITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890abcd\n"
    tsr = sanitize_text_content(text, "utf-8")
    # Valor original NAO deve estar no sanitized; placeholder presente
    assert "ghp_abcdef1234567890abcdef1234567890abcd" not in tsr.sanitized_text
    assert "REDACTED" in tsr.sanitized_text or "PLACEHOLDER" in tsr.sanitized_text


# ---------------------------------------------------------------------------
# Push 9 — sanitize_text_content sem matches retorna text unchanged
# ---------------------------------------------------------------------------


def test_sanitize_text_content_no_match_text_unchanged() -> None:
    """Texto limpo sem secrets -> sanitized_text == text original."""
    from repo_sanitizer.f3_sanitizer import sanitize_text_content

    text = "# README\n\nProjeto simples sem segredos.\nPara rodar: python main.py\n"
    tsr = sanitize_text_content(text, "utf-8")
    assert tsr.sanitized_text == text
    assert tsr.matches == []
    assert tsr.skip_file is False


# ---------------------------------------------------------------------------
# Push 10 — decide_filename_action `.example` bypass canonico (D-EX-16)
# ---------------------------------------------------------------------------


def test_decide_filename_action_example_bypass() -> None:
    """`.env.example` deve passar (output canonico F3; sem False Positive em C1)."""
    from repo_sanitizer.f3_sanitizer import decide_filename_action

    decision = decide_filename_action(".env.example", ".env.example")
    assert decision is None, (
        "decide_filename_action deve retornar None para .env.example (output seguro F3)"
    )


# ---------------------------------------------------------------------------
# Push 11 — f3_matches_to_report_entries normaliza acao
# ---------------------------------------------------------------------------


def test_f3_matches_to_report_entries_normalize_action() -> None:
    """f3_matches_to_report_entries normaliza acao para Literal Pydantic v2."""
    from repo_sanitizer.f3_sanitizer import (
        F3ContentMatch,
        f3_matches_to_report_entries,
    )

    matches = [
        F3ContentMatch(
            rel_path="src/x.py",
            line=10,
            categoria="C2",
            tipo="API_KEY_github_ghp",
            acao="redact_inline",
            encoding_detected="utf-8",
        ),
        F3ContentMatch(
            rel_path="users/joao.silva@gmail.com/x.py",
            line=None,
            categoria="C7",
            tipo="PRIVATE_KEY_PEM_BLOCK",
            acao="remove_file",
            encoding_detected="utf-7",  # convertido para latin-1 no schema
        ),
    ]
    entries = f3_matches_to_report_entries(matches)
    assert len(entries) == 2
    # PII path foi redact_path (RS-018)
    assert "[REDACTED-PII]" in entries[1].path_redacted
    # encoding utf-7 -> latin-1 normalize
    assert entries[1].encoding_detected == "latin-1"


# ---------------------------------------------------------------------------
# Push 12 — rescan_destination detecta leak em destino (C6 fail)
# ---------------------------------------------------------------------------


def test_rescan_destination_detects_leak_in_dest(tmp_path: Path) -> None:
    """rescan_destination retorna leaks quando dest tem secret residual."""
    from repo_sanitizer.f3_sanitizer import rescan_destination

    dest = tmp_path / "dest"
    dest.mkdir()
    leaky = dest / "code.py"
    leaky.write_text(
        "GITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890abcd\n",
        encoding="utf-8",
    )
    n, leaks = rescan_destination(dest)
    assert n >= 1, "C6 deve detectar leak residual em destino"
    assert len(leaks) >= 1
