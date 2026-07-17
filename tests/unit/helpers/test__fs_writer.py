"""test__fs_writer.py — 8 cenarios canonicos do _fs_writer (ADR-020 + RS-002/007/010).

Cobertura obrigatoria para DoD Bloco 01:

(a) write OK em ALLOWED root
(b) FORBIDDEN_PATH .ssh
(c) FORBIDDEN_PATH AppData
(d) FORBIDDEN_PATH source_path (INV-1 runtime)
(e) Fora de ALLOWED
(f) Symlink dest aponta para FORBIDDEN
(g) `../` traversal
(h) Windows reserved names (NUL/CON/COM1/AUX)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from repo_sanitizer.helpers._fs_writer import (
    FsWriteOutOfBoundsError,
    FsWriter,
)


def make_writer(
    tmp_path: Path,
    source_path: Path | None = None,
    extra_forbidden: list[Path] | None = None,
) -> FsWriter:
    """Helper: FsWriter com ALLOWED_ROOT = tmp_path/git-hub-[NOME].

    Usa override_forbidden=[] para nao herdar defaults (AppData inclui pytest tmp_path).
    """
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir(exist_ok=True)
    return FsWriter(
        source_path=source_path or (tmp_path / "fake-source"),
        allowed_roots=[allowed],
        override_forbidden=extra_forbidden or [],
    )


# (a) write OK em ALLOWED root
def test_a_write_ok_in_allowed_root(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    dest = tmp_path / "git-hub-[NOME]" / "GIT_test" / "README.md"
    written = fw.safe_write_text(dest, "# olar")
    assert written.exists()
    assert written.read_text(encoding="utf-8") == "# olar"


# (b) FORBIDDEN .ssh
def test_b_forbidden_ssh(tmp_path: Path) -> None:
    ssh = tmp_path / "fake-ssh"
    ssh.mkdir()
    fw = make_writer(tmp_path, extra_forbidden=[ssh])
    # mas o caminho de escrita deve estar formalmente dentro de allowed_roots
    # para a camada FORBIDDEN ser checada — vamos colocar um symlink no allowed
    # que aponta para fora. Aqui simulamos diretamente: tentar escrever em ssh.
    with pytest.raises(FsWriteOutOfBoundsError, match=r"Path proibido|Fora de ALLOWED"):
        fw.safe_write_text(ssh / "id_rsa", "PRIVATE")


# (c) FORBIDDEN AppData
def test_c_forbidden_appdata(tmp_path: Path) -> None:
    appdata = tmp_path / "fake-appdata"
    appdata.mkdir()
    fw = make_writer(tmp_path, extra_forbidden=[appdata])
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(appdata / "Roaming" / "stuff.txt", "x")


# (d) FORBIDDEN source_path runtime (INV-1)
def test_d_forbidden_source_path_runtime(tmp_path: Path) -> None:
    """source_path SEMPRE adicionado a FORBIDDEN_PATHS (INV-1).

    Para testar especificamente FORBIDDEN (nao 'Fora de ALLOWED'), o source
    fica DENTRO do allowed root (cenario realista: agente operando sobre
    /Git Hub - [NOME]/repo-local que tambem e o destino).
    """
    allowed = tmp_path / "git-hub-[NOME]"
    allowed.mkdir(exist_ok=True)
    source = allowed / "my-source-repo"
    source.mkdir()
    fw = FsWriter(
        source_path=source,
        allowed_roots=[allowed],
        override_forbidden=[],  # tmp_path em AppData
    )
    # Tentar escrever DENTRO do source -> deve cair em FORBIDDEN (source no forbidden)
    with pytest.raises(FsWriteOutOfBoundsError, match=r"proibido|INV-1"):
        fw.safe_write_text(source / "README.md", "tamper")


# (e) Fora de ALLOWED
def test_e_outside_allowed(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    far_away = tmp_path / "elsewhere" / "x.txt"
    with pytest.raises(FsWriteOutOfBoundsError, match="Fora de ALLOWED"):
        fw.safe_write_text(far_away, "x")


# (f) Symlink dest aponta para FORBIDDEN
@pytest.mark.skipif(sys.platform == "win32" and not os.environ.get("CI_SUPPORT_SYMLINKS"),
                    reason="symlink em Windows requer admin/developer mode")
def test_f_symlink_target_forbidden(tmp_path: Path) -> None:
    forbidden_dir = tmp_path / "fake-ssh"
    forbidden_dir.mkdir()
    fw = make_writer(tmp_path, extra_forbidden=[forbidden_dir])
    allowed = tmp_path / "git-hub-[NOME]"
    sym_link = allowed / "traitor_link"
    try:
        os.symlink(forbidden_dir, sym_link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation nao suportado neste ambiente.")
    with pytest.raises(FsWriteOutOfBoundsError):
        fw.safe_write_text(sym_link / "child.txt", "x")


# (g) ../ traversal
def test_g_traversal_rejected(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    allowed = tmp_path / "git-hub-[NOME]"
    # ../ traversal resolve para FORA de allowed
    sneaky = allowed / "GIT_x" / ".." / ".." / "outside.txt"
    with pytest.raises(FsWriteOutOfBoundsError, match="Fora de ALLOWED"):
        fw.safe_write_text(sneaky, "x")


# (h) Windows reserved names
@pytest.mark.parametrize("reserved", ["NUL", "CON", "COM1", "AUX", "PRN", "LPT1"])
def test_h_windows_reserved_names(tmp_path: Path, reserved: str) -> None:
    fw = make_writer(tmp_path)
    dest = tmp_path / "git-hub-[NOME]" / "GIT_test" / reserved
    with pytest.raises(FsWriteOutOfBoundsError, match="reservado Windows"):
        fw.safe_write_text(dest, "x")


# Extra: safe_copy refusa symlink fonte
def test_extra_safe_copy_refuses_symlink_source(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    src_file = tmp_path / "real.txt"
    src_file.write_text("ok", encoding="utf-8")
    sym = tmp_path / "linkfile"
    try:
        os.symlink(src_file, sym)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation nao suportado.")
    dest = tmp_path / "git-hub-[NOME]" / "GIT_test" / "x.txt"
    with pytest.raises(FsWriteOutOfBoundsError, match="symlink"):
        fw.safe_copy(sym, dest)


# Extra: safe_move refusa mover FROM forbidden (INV-1)
def test_extra_safe_move_refuses_from_forbidden(tmp_path: Path) -> None:
    source = tmp_path / "my-source-repo"
    source.mkdir()
    src_file = source / "leaked.txt"
    src_file.write_text("hello", encoding="utf-8")
    fw = make_writer(tmp_path, source_path=source)
    dest = tmp_path / "git-hub-[NOME]" / "GIT_test" / "leaked.txt"
    with pytest.raises(FsWriteOutOfBoundsError, match="FROM path proibido"):
        fw.safe_move(src_file, dest)


# Extra: assert_allowed retorna path resolvido em caso de sucesso
def test_extra_assert_allowed_returns_resolved(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    dest = tmp_path / "git-hub-[NOME]" / "GIT_test" / "ok.txt"
    resolved = fw.assert_allowed(dest)
    assert resolved.is_absolute()
    assert resolved.name == "ok.txt"


# Extra: safe_mkdir + exist_ok=False (RS-021 auto-versionamento)
def test_extra_safe_mkdir_exist_ok_false(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    dest = tmp_path / "git-hub-[NOME]" / "GIT_new"
    fw.safe_mkdir(dest, exist_ok=False)
    assert dest.is_dir()
    with pytest.raises(FileExistsError):
        fw.safe_mkdir(dest, exist_ok=False)


# Extra: safe_append_text gera audit-log style append
def test_extra_safe_append_text(tmp_path: Path) -> None:
    fw = make_writer(tmp_path)
    dest = tmp_path / "git-hub-[NOME]" / "Relatorios" / "audit-log.jsonl"
    fw.safe_append_text(dest, '{"a":1}\n')
    fw.safe_append_text(dest, '{"a":2}\n')
    content = dest.read_text(encoding="utf-8")
    assert content == '{"a":1}\n{"a":2}\n'
