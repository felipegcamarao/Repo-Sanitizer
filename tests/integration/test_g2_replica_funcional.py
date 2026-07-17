"""test_g2_replica_funcional.py — Gate G2 (ADR-032 + ADR-033) Bloco 04.

5 cenarios integration cobrindo RS-NEW-034:
    1. Fixture limpa sem pyproject/LICENSE -> auto-gen + outcome done_with_warnings
    2. Fixture com path absoluto residual    -> outcome done_with_failure (exit 7)
    3. Fixture com PII operador residual     -> outcome done_with_failure (exit 7)
    4. Fixture totalmente limpa              -> outcome done (legacy)
    5. Fixture mixed (auto-gen + paths)      -> outcome done_with_failure
       (paths bloqueia mesmo com auto-gen)

Helpers consumidos:
    - run_g2_replica_funcional (helper isolado; nao chama F4 finalize)
    - FsWriter canonico
    - AuditLogger canonico
"""
from __future__ import annotations

import json
from pathlib import Path

from repo_sanitizer.f4_readme import G2Result, run_g2_replica_funcional
from repo_sanitizer.helpers._audit import AuditLogger
from repo_sanitizer.helpers._fs_writer import FsWriter

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _make_fixtures(tmp_path: Path) -> tuple[Path, FsWriter, AuditLogger]:
    """Cria estrutura mínima destino + FsWriter + AuditLogger fakes para G2."""
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir()
    rel = allowed / "Relatorios"
    rel.mkdir()
    dest = allowed / "GIT_g2_fixture"
    dest.mkdir()
    fw = FsWriter(
        source_path=tmp_path / "fake-source",
        allowed_roots=[allowed],
        override_forbidden=[],
    )
    audit = AuditLogger(
        audit_file=rel / "audit-log.jsonl",
        fs_writer=fw,
        run_id="01234567-89ab-cdef-0123-456789abcdef",
        agent_version="1.1.0-rc.1",
        sentinel_sanitize_version="v1.3.0",
        secret_patterns_hash="0" * 64,
        slug="g2_fixture",
        source_path_redacted="<source>",
        dest_path_redacted="<dest>",
    )
    return dest, fw, audit


def _seed_python_repo_clean(dest: Path, with_pyproject: bool = True, with_license: bool = True) -> None:
    """Popular dest com Python repo limpo (zero paths, zero PII).

    Sempre cria `requirements.txt` para garantir language detection = python
    independente de pyproject.toml estar presente (ADR-032 Python detection
    via LANGUAGE_MARKERS aceita pyproject/setup.py/setup.cfg/requirements).
    """
    (dest / "README.md").write_text("# clean\n\nfoo\n", encoding="utf-8")
    (dest / "requirements.txt").write_text("# minimal\n", encoding="utf-8")
    src = dest / "src" / "clean"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "main.py").write_text("def hi():\n    return 1\n", encoding="utf-8")
    if with_pyproject:
        (dest / "pyproject.toml").write_text(
            '[project]\nname = "clean"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
    if with_license:
        (dest / "LICENSE").write_text("MIT License\n\nCopyright 2026\n", encoding="utf-8")


# -------------------- Cenario 1: auto-gen --------------------


def test_g2_clean_fixture_without_boilerplate_autogen_warnings(tmp_path: Path) -> None:
    """Fixture limpa sem pyproject/LICENSE -> auto-gen + outcome done_with_warnings."""
    dest, fw, audit = _make_fixtures(tmp_path)
    _seed_python_repo_clean(dest, with_pyproject=False, with_license=False)

    result: G2Result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="clean-fixture",
        license_override="MIT",
    )

    assert result.outcome == "done_with_warnings"
    assert result.check_a_boilerplate is True
    assert result.check_b_license is True
    assert result.check_c_paths_zero is True
    assert result.check_d_pii_zero is True
    assert len(result.auto_generated_files) == 2
    # pyproject + LICENSE foram criados
    assert (dest / "pyproject.toml").exists()
    assert (dest / "LICENSE").exists()
    # Banner ADR-033 presente
    assert "INFERRED BOILERPLATE" in (dest / "pyproject.toml").read_text(encoding="utf-8")
    assert "INFERRED LICENSE" in (dest / "LICENSE").read_text(encoding="utf-8")
    assert result.language_detected == "python"


# -------------------- Cenario 2: paths bloqueia --------------------


def test_g2_fixture_with_absolute_paths_blocking_failure(tmp_path: Path) -> None:
    """Fixture com path absoluto residual -> outcome done_with_failure."""
    dest, fw, audit = _make_fixtures(tmp_path)
    _seed_python_repo_clean(dest)
    # Inject path absoluto Windows residual em arquivo de codigo
    (dest / "src" / "clean" / "config.py").write_text(
        "BASE = 'C:/Users/[NOME]/AppData/Local/myapp'\n",
        encoding="utf-8",
    )

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="paths-fixture",
    )

    assert result.outcome == "done_with_failure"
    assert result.check_c_paths_zero is False
    assert len(result.paths_found) >= 1
    assert any("config.py" in s for s in result.paths_found)
    assert len(result.blocking_failures) >= 1
    assert any("Paths absolutos" in b for b in result.blocking_failures)


# -------------------- Cenario 3: PII bloqueia --------------------


def test_g2_fixture_with_pii_operator_blocking_failure(tmp_path: Path) -> None:
    """Fixture com PII operador residual -> outcome done_with_failure."""
    dest, fw, audit = _make_fixtures(tmp_path)
    _seed_python_repo_clean(dest)
    # Inject PII operador (acme.io = domain default em operator_identity)
    # Em arquivo USER-CODE (nao skipped pelo _G2_PII_SKIP_FILES)
    (dest / "src" / "clean" / "contact.py").write_text(
        "EMAIL = 'test@acme.io'\n",
        encoding="utf-8",
    )

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="pii-fixture",
    )

    assert result.outcome == "done_with_failure"
    assert result.check_d_pii_zero is False
    assert len(result.pii_found) >= 1
    assert any("contact.py" in s for s in result.pii_found)
    assert any("PII operador" in b for b in result.blocking_failures)


# -------------------- Cenario 4: tudo OK = done --------------------


def test_g2_clean_fixture_all_passing_outcome_done(tmp_path: Path) -> None:
    """Fixture totalmente limpa com pyproject + LICENSE -> outcome done."""
    dest, fw, audit = _make_fixtures(tmp_path)
    _seed_python_repo_clean(dest, with_pyproject=True, with_license=True)

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="all-clean",
    )

    assert result.outcome == "done"
    assert result.check_a_boilerplate is True
    assert result.check_b_license is True
    assert result.check_c_paths_zero is True
    assert result.check_d_pii_zero is True
    assert result.auto_generated_files == []
    assert result.blocking_failures == []


# -------------------- Cenario 5: mixed -> paths ainda bloqueia --------------------


def test_g2_mixed_autogen_plus_paths_still_failure(tmp_path: Path) -> None:
    """Fixture sem boilerplate + COM paths -> done_with_failure (paths prevalece)."""
    dest, fw, audit = _make_fixtures(tmp_path)
    _seed_python_repo_clean(dest, with_pyproject=False, with_license=False)
    (dest / "src" / "clean" / "leaky.py").write_text(
        "PATH = 'C:/Users/[NOME]/secrets'\n",
        encoding="utf-8",
    )

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="mixed-fixture",
    )

    # paths_found NAO zero -> failure prevalece sobre auto-gen warnings
    assert result.outcome == "done_with_failure"
    assert result.check_c_paths_zero is False
    # Auto-gen aconteceu (boilerplate ausente)
    assert len(result.auto_generated_files) == 2  # pyproject + LICENSE
    assert (dest / "pyproject.toml").exists()
    assert (dest / "LICENSE").exists()


# -------------------- Bonus polish-driven --------------------


def test_g2_license_override_apache_2_0(tmp_path: Path) -> None:
    """--license=APACHE-2.0 deve gerar LICENSE Apache (nao MIT default)."""
    dest, fw, audit = _make_fixtures(tmp_path)
    _seed_python_repo_clean(dest, with_pyproject=True, with_license=False)

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="apache-fixture",
        license_override="APACHE-2.0",
    )

    assert result.outcome == "done_with_warnings"
    license_content = (dest / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_content
    assert "Version 2.0" in license_content


def test_g2_generic_language_no_boilerplate_required(tmp_path: Path) -> None:
    """Language generic (sem markers) -> check_a passa trivialmente sem auto-gen."""
    dest, fw, audit = _make_fixtures(tmp_path)
    # Sem pyproject/package.json/Cargo/go.mod -> generic
    (dest / "README.md").write_text("# generic\n", encoding="utf-8")
    (dest / "data.txt").write_text("hello\n", encoding="utf-8")
    (dest / "LICENSE").write_text("MIT\n", encoding="utf-8")

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="generic-fixture",
    )

    assert result.language_detected == "generic"
    assert result.check_a_boilerplate is True  # trivial pass
    # Nenhum pyproject foi criado
    assert not (dest / "pyproject.toml").exists()
    assert result.outcome == "done"


def test_g2_node_repo_auto_gens_package_json(tmp_path: Path) -> None:
    """Repo Node sem package.json -> auto-gen package.json."""
    dest, fw, audit = _make_fixtures(tmp_path)
    (dest / "README.md").write_text("# node app\n", encoding="utf-8")
    src = dest / "src"
    src.mkdir()
    (src / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
    # Hint para detect_language: vamos forcar criando indicador node
    # Usamos jsconfig.json ou similar — porem detect_language so reconhece package.json
    # Vamos criar package.json placeholder vazio para depois APAGA-LO

    # Truque: detect_language so detecta com package.json presente.
    # Para testar auto-gen, precisamos do destino que apos F2 detect=node mas package.json ausente.
    # Como detect_language so detecta com marker -> testa cenario:
    # Crio package.json mas zero-bytes -> trigger auto-gen.
    (dest / "package.json").write_text("", encoding="utf-8")
    (dest / "LICENSE").write_text("MIT\n", encoding="utf-8")

    result = run_g2_replica_funcional(
        dest_path=dest,
        project_root=PROJECT_ROOT,
        fs_writer=fw,
        audit=audit,
        project_slug="node-fixture",
    )

    assert result.language_detected == "node"
    # package.json existia mas era 0 bytes -> auto-gen
    assert len(result.auto_generated_files) == 1
    pkg_content = (dest / "package.json").read_text(encoding="utf-8")
    payload = json.loads(pkg_content)
    assert payload["name"] == "node-fixture"
    assert payload["version"] == "0.0.0"
