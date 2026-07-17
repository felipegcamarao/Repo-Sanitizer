"""test_f2_organizer.py — Bloco 04 (Modo Padrao AgenteIA).

Cobre detect_language + compute_score + auto_generate_templates +
decide_move + resolve_license_path + apply_safe_moves + run_f2.
"""
from __future__ import annotations

from pathlib import Path

from repo_sanitizer.f2_organizer import (
    GITIGNORE_LANGUAGE_TO_TEMPLATE,
    LANGUAGE_MARKERS,
    MONOREPO_MARKERS,
    SCORE_ITEMS_CANONICAL,
    TEMPLATE_FILE_MAP,
    apply_safe_moves,
    auto_generate_templates,
    compute_score,
    decide_move,
    detect_language,
    resolve_license_path,
    run_f2,
)
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[3]


# ===========================================================================
# detect_language
# ===========================================================================

def test_detect_language_python(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    d = detect_language(tmp_path)
    assert d.primary == "python"
    assert d.is_monorepo is False


def test_detect_language_node(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    d = detect_language(tmp_path)
    assert d.primary == "node"


def test_detect_language_monorepo(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{}\n', encoding="utf-8")
    (tmp_path / "pnpm-workspace.yaml").write_text("packages:\n", encoding="utf-8")
    d = detect_language(tmp_path)
    assert d.is_monorepo is True


def test_detect_language_monorepo_via_packages_dir(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{}\n', encoding="utf-8")
    (tmp_path / "packages").mkdir()
    d = detect_language(tmp_path)
    assert d.is_monorepo is True


def test_detect_language_rust(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    d = detect_language(tmp_path)
    assert d.primary == "rust"


def test_detect_language_generic_fallback(tmp_path: Path) -> None:
    # Sem marker -> generic
    (tmp_path / "README.md").write_text("# x\n", encoding="utf-8")
    d = detect_language(tmp_path)
    assert d.primary == "generic"


def test_detect_language_csharp_via_csproj(tmp_path: Path) -> None:
    (tmp_path / "MyApp.csproj").write_text("<Project/>", encoding="utf-8")
    d = detect_language(tmp_path)
    assert d.primary == "csharp"


def test_detect_language_dest_missing_returns_generic(tmp_path: Path) -> None:
    d = detect_language(tmp_path / "no_such")
    assert d.primary == "generic"


# ===========================================================================
# compute_score
# ===========================================================================

def test_compute_score_empty_dest_returns_zero(tmp_path: Path) -> None:
    dest = tmp_path / "empty"
    dest.mkdir()
    s = compute_score(dest)
    assert s.total == 0
    assert s.max == 10


def test_compute_score_full_passes_threshold(tmp_path: Path) -> None:
    dest = tmp_path / "full"
    dest.mkdir()
    # 10 itens preenchidos
    (dest / "README.md").write_text("# x\n", encoding="utf-8")
    (dest / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (dest / "CONTRIBUTING.md").write_text("ok\n", encoding="utf-8")
    (dest / "CODE_OF_CONDUCT.md").write_text("ok\n", encoding="utf-8")
    (dest / "SECURITY.md").write_text("ok\n", encoding="utf-8")
    (dest / ".gitignore").write_text("node_modules\n", encoding="utf-8")
    (dest / "CHANGELOG.md").write_text("# 1.0\n", encoding="utf-8")
    (dest / ".github" / "workflows").mkdir(parents=True)
    (dest / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    src = dest / "src"
    src.mkdir()
    (src / "main.py").write_text("\n", encoding="utf-8")
    tests = dest / "tests"
    tests.mkdir()
    (tests / "test_x.py").write_text("\n", encoding="utf-8")

    s = compute_score(dest)
    assert s.total == 10
    assert s.is_passing(8)


def test_compute_score_empty_license_not_counted(tmp_path: Path) -> None:
    """AT-10 forca-bruta vazio: arquivos 0 bytes NAO contam."""
    dest = tmp_path / "empty_license"
    dest.mkdir()
    (dest / "LICENSE").write_text("", encoding="utf-8")  # 0 bytes
    (dest / "README.md").write_text("# x\n", encoding="utf-8")
    s = compute_score(dest)
    items_by_name = {i.name: i for i in s.items}
    assert items_by_name["LICENSE"].present is False  # vazio nao conta
    assert items_by_name["README"].present is True


def test_compute_score_github_workflows_requires_yml(tmp_path: Path) -> None:
    dest = tmp_path / "gh"
    dest.mkdir()
    # .github existe mas SEM workflows yml -> nao conta
    gh = dest / ".github"
    gh.mkdir()
    s = compute_score(dest)
    items_by_name = {i.name: i for i in s.items}
    assert items_by_name[".github/workflows"].present is False

    # Adiciona yml -> conta
    (gh / "workflows").mkdir()
    (gh / "workflows" / "ci.yml").write_text("name: x\n", encoding="utf-8")
    s2 = compute_score(dest)
    items_by_name2 = {i.name: i for i in s2.items}
    assert items_by_name2[".github/workflows"].present is True


def test_compute_score_alternative_src_dir(tmp_path: Path) -> None:
    """src/ ou lib/ ou app/ contam como item src."""
    dest = tmp_path / "lib_dir"
    dest.mkdir()
    lib = dest / "lib"
    lib.mkdir()
    (lib / "x.py").write_text("", encoding="utf-8")
    s = compute_score(dest)
    items_by_name = {i.name: i for i in s.items}
    assert items_by_name["src/"].present is True


# ===========================================================================
# auto_generate_templates
# ===========================================================================

def _make_fw(tmp_path: Path, source_path: Path | None = None) -> FsWriter:
    if source_path is None:
        source_path = tmp_path / "fake_src"
        source_path.mkdir()
    return FsWriter(
        source_path=source_path,
        allowed_roots=[tmp_path],
        override_forbidden=[source_path],
    )


def test_auto_generate_templates_creates_3_pt_br(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    fw = _make_fw(tmp_path)

    pre_score = compute_score(dest)
    generated = auto_generate_templates(dest, pre_score, fw, language="python")
    files_generated = [name for name, _ in generated]
    assert "CONTRIBUTING.md" in files_generated
    assert "CODE_OF_CONDUCT.md" in files_generated
    assert "SECURITY.md" in files_generated
    assert ".gitignore" in files_generated

    # CONTRIBUTING.md tem conteudo em PT-BR
    c = (dest / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "Como Contribuir" in c

    # CODE_OF_CONDUCT tem Contributor Covenant 2.1
    coc = (dest / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    assert "Contributor Covenant" in coc

    # P1-a (GAP-S07-03): SECURITY.md gerado no destino usa placeholder neutro,
    # NUNCA o email real do operador (que vazaria PII na replica publicavel).
    sec = (dest / "SECURITY.md").read_text(encoding="utf-8")
    assert "<EMAIL-DO-MANTENEDOR>" in sec
    assert "tecnologia@acme.io" not in sec


def test_auto_generate_templates_doesnt_overwrite_existing(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "CONTRIBUTING.md").write_text("# existente\n", encoding="utf-8")
    fw = _make_fw(tmp_path)

    pre_score = compute_score(dest)
    generated = auto_generate_templates(dest, pre_score, fw, language="generic")
    files_generated = [name for name, _ in generated]
    # CONTRIBUTING ja existe -> nao deve regenerar
    assert "CONTRIBUTING.md" not in files_generated
    # Conteudo preservado
    assert (dest / "CONTRIBUTING.md").read_text(encoding="utf-8") == "# existente\n"


def test_auto_generate_gitignore_language_specific(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    fw = _make_fw(tmp_path)

    pre_score = compute_score(dest)
    auto_generate_templates(dest, pre_score, fw, language="node")
    gi = (dest / ".gitignore").read_text(encoding="utf-8")
    # node.gitignore contem node_modules
    assert "node_modules" in gi


# ===========================================================================
# decide_move
# ===========================================================================

def test_decide_move_md_in_root_suggests_docs() -> None:
    d = decide_move("guide.md", "# Guide\n")
    assert d is not None
    assert d.action == "suggested"
    assert d.dest_rel == "docs/guide.md"


def test_decide_move_readme_protected() -> None:
    """README.md NUNCA deve ser movido."""
    assert decide_move("README.md", "# r\n") is None


def test_decide_move_license_protected() -> None:
    assert decide_move("LICENSE.md", "MIT\n") is None


def test_decide_move_test_py_absolute_import_moved() -> None:
    content = "import os\nfrom mypkg.main import main\n\ndef test_x():\n    main()\n"
    d = decide_move("test_main.py", content)
    assert d is not None
    assert d.action == "moved"
    assert d.dest_rel == "tests/test_main.py"


def test_decide_move_test_py_relative_import_suggested() -> None:
    content = "from .main import main\n\ndef test_x():\n    main()\n"
    d = decide_move("test_main.py", content)
    assert d is not None
    assert d.action == "suggested"


def test_decide_move_unknown_file_returns_none() -> None:
    assert decide_move("random.txt", "content\n") is None


def test_decide_move_spec_ts_treated_as_test() -> None:
    d = decide_move("foo.spec.ts", "describe('x', () => {})\n")
    assert d is not None
    assert d.dest_rel == "tests/foo.spec.ts"


# ===========================================================================
# resolve_license_path
# ===========================================================================

def test_resolve_license_root_already_present(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "LICENSE").write_text("MIT\n", encoding="utf-8")
    fw = _make_fw(tmp_path)
    moved = resolve_license_path(dest, fw)
    assert moved is None  # ja esta no root


def test_resolve_license_in_docs_moves_to_root(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    docs = dest / "docs"
    docs.mkdir()
    (docs / "LICENSE.md").write_text("MIT\n", encoding="utf-8")
    fw = _make_fw(tmp_path)
    moved = resolve_license_path(dest, fw)
    assert moved == "LICENSE.md"
    assert (dest / "LICENSE.md").exists()
    assert not (docs / "LICENSE.md").exists()


def test_resolve_license_missing_returns_none(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    fw = _make_fw(tmp_path)
    assert resolve_license_path(dest, fw) is None


# ===========================================================================
# apply_safe_moves
# ===========================================================================

def test_apply_safe_moves_moves_test_with_absolute_imports(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "test_x.py").write_text("import os\nfrom mypkg import x\n", encoding="utf-8")
    (dest / "README.md").write_text("# x\n", encoding="utf-8")
    fw = _make_fw(tmp_path)
    decisions = apply_safe_moves(dest, fw)
    moved = [d for d in decisions if d.action == "moved"]
    assert len(moved) == 1
    assert (dest / "tests" / "test_x.py").exists()
    assert not (dest / "test_x.py").exists()


def test_apply_safe_moves_only_suggests_relative_imports(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "test_x.py").write_text("from .main import x\n", encoding="utf-8")
    fw = _make_fw(tmp_path)
    decisions = apply_safe_moves(dest, fw)
    suggested = [d for d in decisions if d.action == "suggested"]
    moved = [d for d in decisions if d.action == "moved"]
    assert len(suggested) >= 1
    assert len(moved) == 0
    assert (dest / "test_x.py").exists()  # nao foi movido


# ===========================================================================
# run_f2 pipeline
# ===========================================================================

def _new_audit(tmp_path: Path, fw: FsWriter) -> AuditLogger:
    relatorios = tmp_path / "Relatorios"
    relatorios.mkdir(exist_ok=True)
    return AuditLogger(
        audit_file=relatorios / "audit-log.jsonl", fs_writer=fw,
        run_id="00000000-0000-0000-0000-000000000000",
        agent_version="0.4.0a1", sentinel_sanitize_version="v1.2.0",
        secret_patterns_hash="a" * 64, slug="demo",
        source_path_redacted="src", dest_path_redacted="dst",
    )


def test_run_f2_python_repo_generates_templates_and_score(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    (dest / "README.md").write_text("# demo\n", encoding="utf-8")
    (dest / "LICENSE").write_text("MIT\n", encoding="utf-8")
    src = dest / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "main.py").write_text("def main():\n    pass\n", encoding="utf-8")
    tests = dest / "tests"
    tests.mkdir()
    (tests / "test_main.py").write_text("def test():\n    pass\n", encoding="utf-8")

    fw = _make_fw(tmp_path)
    audit = _new_audit(tmp_path, fw)

    result = run_f2(dest_path=dest, fs_writer=fw, audit=audit)

    assert result.detection is not None
    assert result.detection.primary == "python"
    # 4 templates auto-gerados (CONTRIBUTING + CODE_OF_CONDUCT + SECURITY + .gitignore)
    template_names = [t[0] for t in result.templates_generated]
    assert "CONTRIBUTING.md" in template_names
    assert ".gitignore" in template_names

    # Score >= 8 apos auto-gera
    assert result.score is not None
    assert result.score.is_passing(8), (
        f"Score apos run_f2: {result.score.total}/{result.score.max}"
    )


def test_run_f2_audit_log_has_canonical_actions(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "README.md").write_text("# x\n", encoding="utf-8")
    fw = _make_fw(tmp_path)
    audit = _new_audit(tmp_path, fw)
    run_f2(dest_path=dest, fs_writer=fw, audit=audit)
    audit_text = audit.audit_file.read_text(encoding="utf-8")
    assert "f2_organize_start" in audit_text
    assert "f2_organize_done" in audit_text
    assert "f2_template_generated" in audit_text


# ===========================================================================
# Constantes / sanity
# ===========================================================================

def test_score_items_canonical_has_10() -> None:
    assert len(SCORE_ITEMS_CANONICAL) == 10


def test_language_markers_covers_8_ecosystems() -> None:
    assert set(LANGUAGE_MARKERS.keys()) >= {
        "python", "node", "rust", "go", "java", "csharp", "php", "ruby",
    }


def test_monorepo_markers_canonical() -> None:
    assert "pnpm-workspace.yaml" in MONOREPO_MARKERS
    assert "lerna.json" in MONOREPO_MARKERS


def test_gitignore_language_map_has_9_entries() -> None:
    assert len(GITIGNORE_LANGUAGE_TO_TEMPLATE) == 9


def test_template_file_map_3_pt_br() -> None:
    assert TEMPLATE_FILE_MAP["CONTRIBUTING.md"] == "contributing_pt_br.md"
    assert TEMPLATE_FILE_MAP["CODE_OF_CONDUCT.md"] == "code_of_conduct_pt_br.md"
    assert TEMPLATE_FILE_MAP["SECURITY.md"] == "security_pt_br.md"


def test_project_root_exists() -> None:
    """Sanity: PROJECT_ROOT path correto."""
    assert PROJECT_ROOT.exists()
    assert (PROJECT_ROOT / "pyproject.toml").exists()
