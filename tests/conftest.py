"""conftest.py — pytest fixtures globais para repo-sanitizer-agent.

Pipeline A+ v4.1.x; isolacao por tmp_path; INV-1 read-only fonte.
"""
from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SENTINEL_FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "sentinel"


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Path absoluto da raiz do agente."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def sentinel_fixtures_dir() -> Path:
    """Path para tests/fixtures/sentinel/ (local-copies protegidas)."""
    return SENTINEL_FIXTURES_DIR


@pytest.fixture
def isolated_run_id() -> str:
    """Run ID determinstico para testes (NAO usar em runtime)."""
    return "00000000-0000-0000-0000-000000000000"


@pytest.fixture
def fake_source_path(tmp_path: Path) -> Path:
    """Fonte fake isolada em tmp_path. INV-1 enforcement aplicavel."""
    src = tmp_path / "fake-source-repo"
    src.mkdir()
    (src / "README.md").write_text("# fake source\n", encoding="utf-8")
    return src


@pytest.fixture
def fake_allowed_root(tmp_path: Path) -> Path:
    """ALLOWED_ROOT fake isolado para testes do _fs_writer."""
    root = tmp_path / "fake-git-hub-[NOME]"
    root.mkdir()
    return root


@pytest.fixture
def fake_forbidden_paths(tmp_path: Path) -> list[Path]:
    """Lista de paths proibidos fake para testes _fs_writer."""
    paths = [
        tmp_path / "fake-ssh",
        tmp_path / "fake-appdata",
        tmp_path / "fake-env-file.env",
    ]
    for p in paths[:2]:
        p.mkdir()
    paths[2].write_text("FAKE=fake\n", encoding="utf-8")
    return paths
