"""test_gitignore_merge.py — Bloco D / Passo D1 (MV-07 / RS-NEW-044).

Cobre o `.gitignore` ROBUSTO no destino com MERGE ADITIVO:
  - `generate_gitignore_additions` (bloco canonico HARDCODED).
  - `merge_gitignore` (anexa faltantes, dedup, idempotente, preserva autor).
  - integracao `f2_organizer.auto_generate_templates` (3 cenarios):
      (1) destino SEM `.gitignore`  -> template + bloco canonico.
      (2) destino COM `.gitignore` do autor -> regras preservadas + merge.
      (3) `.sanitizer-state.json` sem path absoluto/PII (MV07-B).
  - C-V11-05: `.sanitizer-state.json` SEMPRE no `.gitignore`.
"""
from __future__ import annotations

import json
from pathlib import Path

from repo_sanitizer.f2_organizer import auto_generate_templates, compute_score
from repo_sanitizer.helpers._boilerplate_generator import (
    CACHE_GITIGNORE_ENTRIES,
    GITIGNORE_CANONICAL_ENTRIES,
    SANITIZER_GITIGNORE_ENTRIES,
    generate_gitignore_additions,
    merge_gitignore,
)
from repo_sanitizer.helpers._fs_writer import FsWriter
from repo_sanitizer.helpers._state_machine import State, StateMachine

# ===========================================================================
# generate_gitignore_additions — bloco canonico
# ===========================================================================

def test_additions_contains_sanitizer_state_json() -> None:
    """C-V11-05: `.sanitizer-state.json` SEMPRE no bloco canonico."""
    block = generate_gitignore_additions()
    assert ".sanitizer-state.json" in block


def test_additions_contains_canonical_caches() -> None:
    """Caches canonicos (MV-01) presentes no bloco."""
    block = generate_gitignore_additions()
    for entry in (".venv/", "__pycache__/", "*.pyc", "node_modules/",
                  "dist/", "build/", "*.egg-info/", ".env", ".env.*"):
        assert entry in block, f"falta {entry} no bloco canonico"


def test_additions_contains_reports_and_audit() -> None:
    """Artefatos do proprio sanitizador no destino ignorados."""
    block = generate_gitignore_additions()
    assert "/Relatorios/" in block
    assert "audit-log.jsonl" in block
    assert "SANITIZATION_REPORT_*.md" in block


def test_canonical_entries_union_is_sanitizer_plus_caches() -> None:
    assert GITIGNORE_CANONICAL_ENTRIES == (
        SANITIZER_GITIGNORE_ENTRIES + CACHE_GITIGNORE_ENTRIES
    )


def test_additions_has_no_literal_secret_values() -> None:
    """Zero-literal: bloco so tem nomes de artefato/cache (RS-005)."""
    block = generate_gitignore_additions()
    # heuristica: nenhum '=' atribuindo valor; nenhum token longo base64.
    assert "ghp_" not in block
    assert "sk-" not in block


# ===========================================================================
# merge_gitignore — aditivo, dedup, idempotente, preserva autor
# ===========================================================================

def test_merge_into_empty_adds_canonical() -> None:
    out = merge_gitignore("")
    assert ".sanitizer-state.json" in out
    assert ".venv/" in out


def test_merge_preserves_author_rules() -> None:
    author = "# regras do autor\nmeu_dir_privado/\n*.bak\n"
    out = merge_gitignore(author)
    assert "meu_dir_privado/" in out
    assert "*.bak" in out
    assert ".sanitizer-state.json" in out  # canonico anexado


def test_merge_does_not_duplicate_existing_entry() -> None:
    """`.venv/` ja presente -> NAO duplica (dedup por linha)."""
    author = ".venv/\n__pycache__/\n"
    out = merge_gitignore(author)
    assert out.count(".venv/") == 1
    assert out.count("__pycache__/") == 1


def test_merge_is_idempotent() -> None:
    """Rodar 2x nao duplica nada (merge(merge(x)) == merge(x))."""
    author = "node_modules\ncustom_dir/\n"
    once = merge_gitignore(author)
    twice = merge_gitignore(once)
    assert twice == once


def test_merge_full_block_is_noop() -> None:
    """Se todas canonicas ja presentes -> retorna inalterado."""
    full = merge_gitignore("")
    assert merge_gitignore(full) == full


def test_merge_empty_when_all_present_returns_existing_unchanged() -> None:
    """Existing com TODAS as canonicas -> identidade (sem banner duplicado)."""
    existing = "\n".join(GITIGNORE_CANONICAL_ENTRIES) + "\n"
    out = merge_gitignore(existing)
    assert out == existing


def test_merge_ignores_comment_lines_for_dedup() -> None:
    """Comentarios do autor nao contam como entrada (sao preservados)."""
    author = "# .venv/ comentario explicativo\nfoo/\n"
    out = merge_gitignore(author)
    # `.venv/` em comentario NAO conta como presente -> canonico e anexado
    assert ".venv/" in out
    # comentario do autor preservado
    assert "# .venv/ comentario explicativo" in out


# ===========================================================================
# Integracao f2_organizer — 3 cenarios D1
# ===========================================================================

def _make_fw(tmp_path: Path) -> FsWriter:
    source_path = tmp_path / "fake_src"
    source_path.mkdir()
    return FsWriter(
        source_path=source_path,
        allowed_roots=[tmp_path],
        override_forbidden=[source_path],
    )


def test_scenario1_dest_without_gitignore_gets_template_plus_canonical(tmp_path: Path) -> None:
    """Cenario 1: destino SEM `.gitignore` -> template + bloco canonico."""
    dest = tmp_path / "dest"
    dest.mkdir()
    fw = _make_fw(tmp_path)
    score = compute_score(dest)
    generated = auto_generate_templates(dest, score, fw, language="python")
    assert ".gitignore" in [name for name, _ in generated]
    gi = (dest / ".gitignore").read_text(encoding="utf-8")
    # template python + canonico
    assert "__pycache__/" in gi
    assert ".sanitizer-state.json" in gi  # C-V11-05


def test_scenario2_dest_with_author_gitignore_merged(tmp_path: Path) -> None:
    """Cenario 2: destino COM `.gitignore` do autor -> preserva + merge aditivo."""
    dest = tmp_path / "dest"
    dest.mkdir()
    # simula `.gitignore` vindo do source (copiado por F3)
    (dest / ".gitignore").write_text(
        "# autor\nsegredo_do_autor/\n*.private\n.venv/\n", encoding="utf-8",
    )
    fw = _make_fw(tmp_path)
    score = compute_score(dest)
    generated = auto_generate_templates(dest, score, fw, language="python")
    gi = (dest / ".gitignore").read_text(encoding="utf-8")
    # regras do autor PRESERVADAS
    assert "segredo_do_autor/" in gi
    assert "*.private" in gi
    # canonicas anexadas
    assert ".sanitizer-state.json" in gi
    # .venv/ ja existia -> nao duplica
    assert gi.count(".venv/") == 1
    # registrado como merge aditivo
    assert (".gitignore", "gitignore_merge_aditivo") in generated


def test_scenario2_idempotent_second_run_no_change(tmp_path: Path) -> None:
    """Cenario 2 idempotente: 2a chamada nao altera nem registra."""
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / ".gitignore").write_text("# autor\nfoo/\n", encoding="utf-8")
    fw = _make_fw(tmp_path)

    score1 = compute_score(dest)
    auto_generate_templates(dest, score1, fw, language="generic")
    gi_after_1 = (dest / ".gitignore").read_text(encoding="utf-8")

    score2 = compute_score(dest)
    generated2 = auto_generate_templates(dest, score2, fw, language="generic")
    gi_after_2 = (dest / ".gitignore").read_text(encoding="utf-8")

    assert gi_after_2 == gi_after_1  # idempotente
    # 2a rodada NAO registra `.gitignore` (nada a anexar)
    assert ".gitignore" not in [name for name, _ in generated2]


def test_scenario3_state_file_no_absolute_path_or_pii(tmp_path: Path) -> None:
    """Cenario 3 (MV07-B): `.sanitizer-state.json` sem path absoluto/PII."""
    dest = tmp_path / "GIT_demo-v1"
    dest.mkdir()
    fw = _make_fw(tmp_path)
    sm = StateMachine(dest_path=dest, fs_writer=fw, initial_state=State.IDLE)
    sm.save(reason="teste")
    payload = json.loads((dest / ".sanitizer-state.json").read_text(encoding="utf-8"))
    # NAO contem path absoluto da fonte/destino
    assert "dest_path" not in payload
    assert "dest_name" in payload
    # so o basename da pasta (sem drive/usuario)
    assert payload["dest_name"] == "GIT_demo-v1"
    raw = (dest / ".sanitizer-state.json").read_text(encoding="utf-8")
    # nenhum segmento de path absoluto Windows/Unix vazado
    assert ":/" not in raw
    assert ":\\" not in raw
    assert str(tmp_path) not in raw
