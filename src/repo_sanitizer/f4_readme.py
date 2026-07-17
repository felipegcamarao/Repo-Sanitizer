"""f4_readme.py — README via Claude Code chat agente (F4; Bloco 05 Modo Completo).

Pipeline F4 (Bloco 05):
1. `collect_kit(dest_path)` coleta evidencia structurada: linguagem + arvore +
   docstrings + CLI args + README_fonte_original_read_only + license_status +
   tem_changelog + features_extraidas.
2. `apply_full_filter(kit)` aplica 12 INJ-XX (RS-003 camada C1) + isolation tag
   `<project_context>` (RS-003 camada C2) sobre o kit JSON.
3. `write_kit_json(kit_filtered, fs_writer, /Relatorios/.tmp/)` grava o kit em
   diretorio .tmp (ADR-027 cleanup automatico em finalize).
4. `emit_generate_readme_instruction(slug)` printa stdout: instrucao explicita
   para [NOME] invocar `/generate-readme [slug]` via Claude Code chat (INV-9).
5. FSM transition: APPLYING -> AWAITING_README (Bloco 04 ja faz) -> caller
   recebe README do destino + invoca `run_finalize`.
6. `run_finalize(dest_path, readme_path)` valida markdownlint + link-check via
   subprocess (degrade gracioso ADR-013); cleanup `.tmp/`; FSM finalize_done -> DONE.

ADRs ancorados: ADR-012 (kit JSON) + ADR-013 (degrade gracioso) +
ADR-014 (12 INJ-XX) + ADR-017 (cap 1 LLM/run) + ADR-018 (sem auto-detect) +
ADR-022 (injection_patterns local copy) + ADR-027 (.tmp cleanup).

RS cobertos:
- RS-003 (anti-injection 4 camadas) via _injection_filter
- RS-012 (injection_patterns integrity heritage Bloco 01)
- RS-014 (kit cleanup pos-finalize)
- RS-015 (markdownlint degrade gracioso)
- RS-017 (cap LLM 1/run)
- RS-023 (degrade stub PT-BR nao-vazio quando runtime ausente)
- RS-025 (runtime guard heritage helpers/_runtime_guard.py)
"""
from __future__ import annotations

import ast
import contextlib
import datetime as _dt
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from repo_sanitizer import __version__
from repo_sanitizer.helpers._binary_detector import is_binary
from repo_sanitizer.helpers._boilerplate_generator import (
    ALLOWED_LICENSES,
    LicenseId,
    generate_cargo_toml,
    generate_go_mod,
    generate_license,
    generate_package_json,
    generate_pyproject,
)
from repo_sanitizer.helpers._injection_filter import (
    InjectionMatch,
    apply_full_filter,
)
from repo_sanitizer.helpers._operator_identity_loader import load_operator_identity
from repo_sanitizer.helpers._path_sanitizer import (
    UNIX_PATH_RE,
    WINDOWS_PATH_RE,
)
from repo_sanitizer.helpers._pii_redactor import redact_path
from repo_sanitizer.helpers._runtime_guard import detect_runtime, runtime_marker
from repo_sanitizer.schemas.operator_identity_schema import OperatorIdentitySchema

if TYPE_CHECKING:
    from repo_sanitizer.helpers._audit import AuditLogger
    from repo_sanitizer.helpers._fs_writer import FsWriter


# ===========================================================================
# Constantes canonicas
# ===========================================================================

TMP_DIR_NAME = ".tmp"
KIT_JSON_PREFIX = "README_INPUT_"
KIT_JSON_SUFFIX = ".json"

DEGRADE_STUB_PT_BR = """# {slug}

> ⚠️ **README skipped — LLM runtime unavailable.** Este arquivo e um stub gerado
> pelo `repo-sanitizer-agent` (ADR-013 degrade gracioso) quando o runtime
> canonico Claude Code chat NAO foi detectado durante `/sanitize-finalize`.
>
> Para gerar um README completo, execute:
>
> 1. Abra o VS Code chat agente com `Ctrl+Alt+C` (Claude Code).
> 2. Rode `/generate-readme {slug}` apontando para o kit em
>    `Relatorios/.tmp/README_INPUT_{slug}_*.json`.
> 3. Salve o README gerado em `{slug_dest}/README.md` e re-execute
>    `/sanitize-finalize {slug}`.

## Sobre este projeto

(secao a ser preenchida pelo runtime canonico Claude Code chat.)

## Setup

(secao a ser preenchida.)

## Licenca

Consulte `LICENSE` no root deste repositorio.

---

_Stub gerado em {ts} via repo-sanitizer-agent v{agent_version}._
"""


# ===========================================================================
# Estruturas de dados
# ===========================================================================


@dataclass
class F4Kit:
    """Kit JSON canonico passado para Claude Code chat (apos isolation)."""

    slug: str
    run_id: str
    agent_version: str
    language: str
    is_monorepo: bool
    tree_outline: list[str] = field(default_factory=list)
    docstrings: list[dict[str, str]] = field(default_factory=list)  # {file, name, doc}
    cli_args: list[dict[str, str]] = field(default_factory=list)
    license_status: str = "unknown"
    has_changelog: bool = False
    readme_source: str | None = None  # conteudo READ-ONLY do README do fonte (se existe)
    features: list[str] = field(default_factory=list)
    runtime_detected: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "run_id": self.run_id,
            "agent_version": self.agent_version,
            "language": self.language,
            "is_monorepo": self.is_monorepo,
            "tree_outline": self.tree_outline,
            "docstrings": self.docstrings,
            "cli_args": self.cli_args,
            "license_status": self.license_status,
            "has_changelog": self.has_changelog,
            "readme_source": self.readme_source,
            "features": self.features,
            "runtime_detected": self.runtime_detected,
        }


@dataclass
class F4FinalizeResult:
    """Resultado da fase finalize."""

    readme_path: Path | None = None
    readme_bytes: int = 0
    markdownlint_status: str = "NOT_AVAILABLE"  # NOT_AVAILABLE | PASS | FAIL
    link_check_status: str = "NOT_AVAILABLE"
    tmp_cleaned: bool = False
    degrade_stub_used: bool = False
    audit_messages: list[str] = field(default_factory=list)


# ===========================================================================
# Excecoes canonicas
# ===========================================================================


class F4MissingReadme(RuntimeError):  # noqa: N818
    """README.md ausente no destino durante /sanitize-finalize."""


class F4CapLlmExceeded(RuntimeError):  # noqa: N818
    """Cap 1 invocacao LLM por run excedida (ADR-017 + RS-017)."""


# ===========================================================================
# Coleta do kit (Passo 05.1)
# ===========================================================================


_TREE_OUTLINE_MAX_ENTRIES = 60
_DOCSTRING_FILE_LIMIT = 20
_DOCSTRING_TEXT_LIMIT = 240
_README_SOURCE_LIMIT_BYTES = 4 * 1024  # 4 KB
_FEATURES_LIMIT = 16


def _build_tree_outline(dest_path: Path) -> list[str]:
    """Tree-style outline ate 2 niveis + cap 60 entries."""
    outline: list[str] = []
    if not dest_path.exists():
        return outline
    for entry in sorted(dest_path.iterdir(), key=lambda p: (p.is_file(), p.name)):
        if entry.name in {".sanitizer-state.json", TMP_DIR_NAME}:
            continue
        outline.append(("dir: " if entry.is_dir() else "file: ") + entry.name)
        if entry.is_dir() and entry.name not in {".git", "node_modules", "__pycache__"}:
            for sub in sorted(entry.iterdir(), key=lambda p: (p.is_file(), p.name)):
                outline.append(
                    f"  {'dir: ' if sub.is_dir() else 'file: '}{entry.name}/{sub.name}",
                )
                if len(outline) >= _TREE_OUTLINE_MAX_ENTRIES:
                    return outline
        if len(outline) >= _TREE_OUTLINE_MAX_ENTRIES:
            return outline
    return outline


def _extract_python_docstrings(dest_path: Path) -> list[dict[str, str]]:
    """Walk .py files e extrai module/class/function docstrings (cap)."""
    found: list[dict[str, str]] = []
    if not dest_path.exists():
        return found
    file_count = 0
    for py_file in dest_path.rglob("*.py"):
        if any(part in {".git", "__pycache__", "node_modules"} for part in py_file.parts):
            continue
        if file_count >= _DOCSTRING_FILE_LIMIT:
            break
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        try:
            rel = py_file.relative_to(dest_path).as_posix()
        except ValueError:
            rel = py_file.name
        # Module docstring
        mod_doc = ast.get_docstring(tree)
        if mod_doc:
            found.append({
                "file": rel, "name": "<module>",
                "doc": mod_doc[:_DOCSTRING_TEXT_LIMIT],
            })
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node)
                if doc:
                    found.append({
                        "file": rel, "name": node.name,
                        "doc": doc[:_DOCSTRING_TEXT_LIMIT],
                    })
        file_count += 1
    return found


def _extract_cli_args(dest_path: Path) -> list[dict[str, str]]:
    """Heuristica: argparse `--flag` em arquivos *.py com 'argparse'."""
    args: list[dict[str, str]] = []
    if not dest_path.exists():
        return args
    seen = set()
    import re
    flag_re = re.compile(r'add_argument\(\s*[\'"](?P<flag>--?[\w-]+)[\'"][^)]*?'
                         r'(help=[\'"](?P<help>[^\'"]+)[\'"])?', re.DOTALL)
    for py_file in dest_path.rglob("*.py"):
        if any(part in {".git", "__pycache__", "node_modules"} for part in py_file.parts):
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "argparse" not in content:
            continue
        for m in flag_re.finditer(content):
            flag = m.group("flag")
            if flag in seen:
                continue
            seen.add(flag)
            args.append({"flag": flag, "help": (m.group("help") or "").strip()})
            if len(args) >= 30:
                return args
    return args


def _detect_license_status(dest_path: Path) -> str:
    """unknown | present | absent. License presente => sample primeira linha."""
    if not dest_path.exists():
        return "unknown"
    for cand in ("LICENSE", "LICENSE.md", "LICENSE.txt", "License", "License.md"):
        p = dest_path / cand
        if p.is_file() and p.stat().st_size > 0:
            with contextlib.suppress(OSError, UnicodeDecodeError):
                first_line = p.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
                if first_line:
                    return f"present ({first_line[0].strip()[:60]})"
            return "present"
    return "absent"


def _detect_changelog(dest_path: Path) -> bool:
    if not dest_path.exists():
        return False
    for cand in ("CHANGELOG.md", "CHANGELOG", "CHANGES.md", "Changelog.md"):
        if (dest_path / cand).is_file():
            return True
    return False


def _read_readme_source(source_path: Path) -> str | None:
    """Le README do FONTE (read-only INV-1; cap 4 KB)."""
    if not source_path.exists():
        return None
    for cand in ("README.md", "README", "README.rst", "README.txt", "Readme.md"):
        p = source_path / cand
        if p.is_file():
            with contextlib.suppress(OSError, UnicodeDecodeError):
                content = p.read_bytes()[:_README_SOURCE_LIMIT_BYTES]
                return content.decode("utf-8", errors="replace")
    return None


def _detect_language_simple(dest_path: Path, is_monorepo_hint: bool = False) -> tuple[str, bool]:
    """Reusa detect_language do f2_organizer (heritage Bloco 04)."""
    from repo_sanitizer.f2_organizer import detect_language
    d = detect_language(dest_path)
    return d.primary, d.is_monorepo or is_monorepo_hint


def _extract_features(docstrings: list[dict[str, str]]) -> list[str]:
    """Heuristica: primeiras N docstrings -> feature bullets curtos."""
    out: list[str] = []
    for d in docstrings:
        if d.get("name") == "<module>":
            continue
        text = d.get("doc", "")
        if not text:
            continue
        first_sentence = text.split(".")[0].strip()
        if not first_sentence:
            continue
        out.append(f"{d['file']}::{d['name']} — {first_sentence[:120]}")
        if len(out) >= _FEATURES_LIMIT:
            return out
    return out


def collect_kit(
    *,
    source_path: Path,
    dest_path: Path,
    slug: str,
    run_id: str,
) -> F4Kit:
    """Coleta kit JSON canonico para Claude Code chat (Passo 05.1)."""
    docstrings = _extract_python_docstrings(dest_path)
    language, is_monorepo = _detect_language_simple(dest_path)
    return F4Kit(
        slug=slug,
        run_id=run_id,
        agent_version=__version__,
        language=language,
        is_monorepo=is_monorepo,
        tree_outline=_build_tree_outline(dest_path),
        docstrings=docstrings,
        cli_args=_extract_cli_args(dest_path),
        license_status=_detect_license_status(dest_path),
        has_changelog=_detect_changelog(dest_path),
        readme_source=_read_readme_source(source_path),
        features=_extract_features(docstrings),
        runtime_detected=detect_runtime(),
    )


# ===========================================================================
# Filter injection + isolation tag (Passo 05.2)
# ===========================================================================


def filter_and_isolate_kit(
    kit: F4Kit,
) -> tuple[dict[str, Any], list[InjectionMatch]]:
    """Aplica RS-003 camadas C1 + C2 sobre o kit (heritage Bloco 01 helper)."""
    raw = kit.to_dict()
    filtered, matches = apply_full_filter(raw)
    return filtered, matches


# ===========================================================================
# Write kit JSON em /Relatorios/.tmp/ (Passo 05.3)
# ===========================================================================


def kit_filename(slug: str, run_id: str) -> str:
    ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{KIT_JSON_PREFIX}{slug}_{ts}_{run_id[:8]}{KIT_JSON_SUFFIX}"


def write_kit_json(
    kit_filtered: dict[str, Any],
    *,
    slug: str,
    run_id: str,
    fs_writer: FsWriter,
    relatorios_path: Path,
) -> Path:
    """Grava kit em `/Relatorios/.tmp/README_INPUT_<slug>_<ts>_<run_id8>.json`.

    Defesa ADR-027: gravacao em `.tmp/` para cleanup automatico em finalize.
    """
    tmp_dir = relatorios_path / TMP_DIR_NAME
    fname = kit_filename(slug, run_id)
    target = tmp_dir / fname
    content = json.dumps(kit_filtered, ensure_ascii=False, indent=2) + "\n"
    return fs_writer.safe_write_text(target, content)


# ===========================================================================
# Stdout instruction (Passo 05.4)
# ===========================================================================


def emit_generate_readme_instruction(
    *,
    slug: str,
    kit_path: Path,
    matches: list[InjectionMatch],
) -> str:
    """Retorna a instrucao a ser impressa em stdout para [NOME] (Passo 05.4)."""
    runtime = runtime_marker()
    lines = [
        "=" * 70,
        f"[F4 README] Kit JSON pronto para Claude Code chat: {kit_path}",
        f"[F4 README] Runtime detectado: {runtime}",
        f"[F4 README] Injections sanitizadas pelo filter: {len(matches)} match(es)",
        "",
        "PROXIMOS PASSOS (manual via Claude Code chat agente):",
        "  1. Abra Claude Code chat no VS Code (Ctrl+Alt+C).",
        f"  2. Rode: /generate-readme {slug}",
        f"     (aponte para o kit em: {kit_path})",
        "  3. Cole o README.md gerado em: <dest>/README.md",
        f"  4. Execute: /sanitize-finalize {slug}",
        "",
        "(Cap LLM = 1 invocacao por run, ADR-017. Re-runs nao re-emitem o kit.)",
        "=" * 70,
    ]
    return "\n".join(lines)


# ===========================================================================
# Cap LLM 1/run (Passo 05.8)
# ===========================================================================


def cap_llm_kit_emitted(state_dir: Path) -> bool:
    """Retorna True se ja existe sinal de kit emitido (ADR-017 cap 1/run)."""
    flag = state_dir / ".f4_kit_emitted"
    return flag.exists()


def mark_kit_emitted(state_dir: Path, fs_writer: FsWriter) -> None:
    """Marca que o kit ja foi emitido para este destino."""
    flag = state_dir / ".f4_kit_emitted"
    fs_writer.safe_write_text(flag, _dt.datetime.now(_dt.UTC).isoformat() + "\n")


# ===========================================================================
# Degrade gracioso stub PT-BR (Passo 05.7 + RS-023)
# ===========================================================================


def write_degrade_stub_readme(
    *,
    dest_path: Path,
    slug: str,
    fs_writer: FsWriter,
) -> Path:
    """Gera README stub PT-BR nao-vazio quando runtime Claude Code indisponivel."""
    ts = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    content = DEGRADE_STUB_PT_BR.format(
        slug=slug,
        slug_dest=dest_path.name,
        ts=ts,
        agent_version=__version__,
    )
    target = dest_path / "README.md"
    return fs_writer.safe_write_text(target, content)


# ===========================================================================
# Markdownlint + link-check (Passos 05.5 + 05.6) — degrade gracioso ADR-013
# ===========================================================================


def _which(cmd: str) -> str | None:
    """shutil.which wrapper — None se ausente."""
    return shutil.which(cmd)


def run_markdownlint(readme_path: Path, *, timeout_seconds: int = 30) -> str:
    """Roda `markdownlint-cli` se disponivel. Retorna PASS | FAIL | NOT_AVAILABLE."""
    bin_path = _which("markdownlint")
    if bin_path is None:
        return "NOT_AVAILABLE"
    try:
        result = subprocess.run(
            [bin_path, str(readme_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "FAIL"
    return "PASS" if result.returncode == 0 else "FAIL"


def run_link_check(readme_path: Path, *, timeout_seconds: int = 60) -> str:
    """Roda `markdown-link-check` se disponivel. PASS | FAIL | NOT_AVAILABLE."""
    bin_path = _which("markdown-link-check")
    if bin_path is None:
        return "NOT_AVAILABLE"
    try:
        result = subprocess.run(
            [bin_path, str(readme_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "FAIL"
    return "PASS" if result.returncode == 0 else "FAIL"


# ===========================================================================
# Cleanup .tmp/ (Passo 05.9 + ADR-027 + RS-014)
# ===========================================================================


def cleanup_tmp_kits(relatorios_path: Path, slug: str) -> int:
    """Remove `README_INPUT_<slug>_*.json` de `/Relatorios/.tmp/`."""
    tmp_dir = relatorios_path / TMP_DIR_NAME
    if not tmp_dir.exists():
        return 0
    n = 0
    for p in tmp_dir.glob(f"{KIT_JSON_PREFIX}{slug}_*{KIT_JSON_SUFFIX}"):
        with contextlib.suppress(OSError):
            p.unlink()
            n += 1
    return n


# ===========================================================================
# Pipeline principal F4 — run_generate_readme + run_finalize
# ===========================================================================


def run_f4_emit_kit(
    *,
    source_path: Path,
    dest_path: Path,
    slug: str,
    run_id: str,
    fs_writer: FsWriter,
    audit: AuditLogger,
    relatorios_path: Path,
) -> tuple[Path, F4Kit, list[InjectionMatch]]:
    """Bloco 05 Passos 05.1 + 05.2 + 05.3 + 05.4 + 05.8.

    Cap LLM 1/run enforced via flag file `.f4_kit_emitted` no destino (ADR-017).

    Returns: (kit_path, kit, injection_matches).
    Raises: F4CapLlmExceeded se cap 1/run violado.
    """
    # Cap LLM (Passo 05.8 + ADR-017 + RS-017)
    if cap_llm_kit_emitted(dest_path):
        audit.log("f4_kit_emitted", detail={
            "cap_violated": True,
            "phase": "cap_check",
        })
        raise F4CapLlmExceeded(
            f"Cap LLM 1/run violado para {slug}: kit ja emitido. "
            "Re-runs requerem novo destino versionado (use sanitize-apply de novo)."
        )

    # 1) Coleta kit
    kit = collect_kit(source_path=source_path, dest_path=dest_path,
                      slug=slug, run_id=run_id)

    # 2) Filter injection + isolation tag
    filtered, matches = filter_and_isolate_kit(kit)

    # 3) Audit injections detectadas
    if matches:
        audit.log("injection_redacted", detail={
            "count": len(matches),
            "pattern_ids": list({m.pattern_id for m in matches})[:12],
        })

    # 4) Write kit em /Relatorios/.tmp/
    kit_path = write_kit_json(
        filtered, slug=slug, run_id=run_id,
        fs_writer=fs_writer, relatorios_path=relatorios_path,
    )

    # 5) Marca cap LLM
    mark_kit_emitted(dest_path, fs_writer)

    # 6) Audit kit emitted
    audit.log("f4_kit_emitted", detail={
        "kit_path_redacted": redact_path(str(kit_path)),
        "language": kit.language,
        "is_monorepo": kit.is_monorepo,
        "tree_entries": len(kit.tree_outline),
        "docstrings": len(kit.docstrings),
        "cli_args": len(kit.cli_args),
        "features": len(kit.features),
        "license_status": kit.license_status,
        "has_changelog": kit.has_changelog,
        "readme_source_present": kit.readme_source is not None,
        "runtime_detected": kit.runtime_detected,
        "injections_filtered": len(matches),
    })

    return kit_path, kit, matches


def run_f4_finalize(
    *,
    dest_path: Path,
    slug: str,
    run_id: str,
    fs_writer: FsWriter,
    audit: AuditLogger,
    relatorios_path: Path,
    raise_on_missing_readme: bool = False,
) -> F4FinalizeResult:
    """Bloco 05 Passos 05.5 + 05.6 + 05.7 + 05.9.

    Pipeline:
    1. Verifica README.md no destino. Se ausente E runtime != claude_code,
       gera degrade stub PT-BR + warning (RS-023).
    2. Roda `markdownlint-cli` subprocess (degrade NOT_AVAILABLE; RS-015).
    3. Roda `markdown-link-check` subprocess (degrade NOT_AVAILABLE).
    4. Cleanup `.tmp/README_INPUT_<slug>_*.json` (ADR-027 + RS-014).
    5. Audit `f4_finalize_done`.

    Returns: F4FinalizeResult com status detalhado.
    """
    result = F4FinalizeResult()
    readme = dest_path / "README.md"

    if not readme.exists():
        if raise_on_missing_readme:
            raise F4MissingReadme(
                f"README.md ausente em {dest_path}. Execute /generate-readme {slug}."
            )
        # Degrade gracioso (RS-023 + ADR-013): emite stub PT-BR
        readme = write_degrade_stub_readme(
            dest_path=dest_path, slug=slug, fs_writer=fs_writer,
        )
        result.degrade_stub_used = True
        result.audit_messages.append("README.md ausente; stub PT-BR emitido")

    result.readme_path = readme
    result.readme_bytes = readme.stat().st_size

    # markdownlint
    result.markdownlint_status = run_markdownlint(readme)
    result.audit_messages.append(f"markdownlint={result.markdownlint_status}")

    # link-check
    result.link_check_status = run_link_check(readme)
    result.audit_messages.append(f"link_check={result.link_check_status}")

    # Cleanup .tmp/
    n_cleaned = cleanup_tmp_kits(relatorios_path, slug)
    result.tmp_cleaned = n_cleaned > 0
    result.audit_messages.append(f"tmp_files_cleaned={n_cleaned}")

    audit.log("f4_finalize_done", detail={
        "readme_path_redacted": redact_path(str(readme)),
        "readme_bytes": result.readme_bytes,
        "markdownlint": result.markdownlint_status,
        "link_check": result.link_check_status,
        "tmp_files_cleaned": n_cleaned,
        "degrade_stub_used": result.degrade_stub_used,
    })

    return result


# ===========================================================================
# Helpers para tests
# ===========================================================================


def list_kit_jsons(relatorios_path: Path, slug: str) -> list[Path]:
    """Lista kit JSONs em `.tmp/` (uso em tests + cleanup verification)."""
    tmp = relatorios_path / TMP_DIR_NAME
    if not tmp.exists():
        return []
    return sorted(tmp.glob(f"{KIT_JSON_PREFIX}{slug}_*{KIT_JSON_SUFFIX}"))


def reset_kit_cap_flag(dest_path: Path) -> bool:
    """Remove o flag `.f4_kit_emitted` (uso APENAS em tests)."""
    flag = dest_path / ".f4_kit_emitted"
    if flag.exists():
        with contextlib.suppress(OSError):
            flag.unlink()
            return True
    return False


# ===========================================================================
# Gate G2 — Replica Funcional Verified (Bloco 04 ADR-032 + ADR-033)
# ===========================================================================


@dataclass
class G2Result:
    """Resultado do Gate G2 (Bloco 04 ADR-032).

    Atributos:
        check_a_boilerplate: True se boilerplate presente OU auto-gerado.
        check_b_license: True se LICENSE presente OU auto-gerado.
        check_c_paths_zero: True se zero paths absolutos detectados.
        check_d_pii_zero: True se zero PII operador detectado.
        outcome: "done" | "done_with_warnings" | "done_with_failure".
        auto_generated_files: lista de paths auto-gerados (banner ADR-033).
        blocking_failures: lista de descrições PT-BR de falhas bloqueantes
            (apenas (c) e (d); (a) e (b) auto-gen são warnings).
        language_detected: language primary detectada (reuso f2_organizer).
        paths_found: lista de paths absolutos encontrados (cap 20 amostras).
        pii_found: lista de PII matches encontrados (cap 20 amostras).
    """

    check_a_boilerplate: bool = False
    check_b_license: bool = False
    check_c_paths_zero: bool = False
    check_d_pii_zero: bool = False
    outcome: str = "done"  # "done" | "done_with_warnings" | "done_with_failure"
    auto_generated_files: list[Path] = field(default_factory=list)
    blocking_failures: list[str] = field(default_factory=list)
    language_detected: str = "generic"
    paths_found: list[str] = field(default_factory=list)
    pii_found: list[str] = field(default_factory=list)


# Mapa language -> (filename, generator)
_BOILERPLATE_MAP: dict[str, tuple[str, Any]] = {
    "python": ("pyproject.toml", generate_pyproject),
    "node": ("package.json", generate_package_json),
    "rust": ("Cargo.toml", generate_cargo_toml),
    "go": ("go.mod", generate_go_mod),
}

_LICENSE_CANDIDATE_NAMES: tuple[str, ...] = (
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "License",
    "License.md",
)

# Diretorios a pular no walk do destino (consistente com C9/C10 patterns)
_G2_WALK_SKIP_DIRS: frozenset[str] = frozenset({
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tmp",
    TMP_DIR_NAME,
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
})

# Cap de amostras de matches (evita audit-log gigante)
_G2_SAMPLES_CAP = 20

# Cap de bytes por arquivo (defensivo; arquivos >2MB sao texto incomum)
_G2_FILE_READ_CAP_BYTES = 2 * 1024 * 1024

# Polish-driven (Bloco 04): arquivos AGENT-GENERATED que contem contato
# operador OU metadata de redaction intencional. Skip APENAS do G2.d (PII).
# G2.c (paths absolutos) continua scaneando estes — paths jamais sao
# intencionais em nenhum arquivo, mesmo agent-generated.
#
# Justificativa:
#   - CODE_OF_CONDUCT/CONTRIBUTING/SECURITY: F2 injeta intencionalmente o
#     email canonico (tecnologia@acme.io) como contato publico. Excluir do
#     scan de PII evita falso-positivo bloqueante; G2.d nao deve barrar
#     contato publico que F2 propositadamente coloca no destino.
#   - *_AUDIT.md: relatorios de auditoria do agente DENTRO do destino
#     (C9_AUDIT, C10_AUDIT) documentam exatamente os patterns redatados.
#     Por design contem as strings que foram removidas.
_G2_PII_SKIP_FILES: frozenset[str] = frozenset({
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "C9_AUDIT.md",
    "C10_AUDIT.md",
    ".sanitizer-state.json",
})

# Skip para G2.c (paths absolutos):
#   - Audit reports: documentam paths sanitizados (evidence).
#   - .sanitizer-state.json: FSM agent state COM dest_path real (necessario
#     para tracking; nao publicavel — gitignored convencionalmente).
#   - F2 templates: contem URLs `https://...` que disparam falso-positivo
#     em WINDOWS_PATH_RE (`s:` matches `[A-Za-z]:`). Pre-existing regex
#     limitation; fix em ADR-034 pos-v1.1.0 (out of scope Bloco 04).
_G2_PATHS_SKIP_FILES: frozenset[str] = frozenset({
    "C9_AUDIT.md",
    "C10_AUDIT.md",
    ".sanitizer-state.json",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    # LICENSE: textos canonicos APACHE-2.0 contem `http://www.apache.org/licenses/...`
    # que dispara falso-positivo em WINDOWS_PATH_RE (`p:` matches `[A-Za-z]:`).
    # LICENSE files do upstream tambem podem conter URLs (creditos, FAQ).
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
})


def _walk_text_files(dest_path: Path) -> Iterator[tuple[Path, str]]:
    """Yields (path, text_content) para arquivos texto-only no destino.

    Reuso de _binary_detector (consistente C9/C10).
    Skip de dirs canonicos (_G2_WALK_SKIP_DIRS).
    Cap defensivo de bytes por arquivo.
    """
    for root, dirs, filenames in os.walk(dest_path):
        # In-place mutation para skip de subdirs (os.walk pattern)
        dirs[:] = [d for d in dirs if d not in _G2_WALK_SKIP_DIRS]
        for fname in filenames:
            fpath = Path(root) / fname
            try:
                if fpath.stat().st_size > _G2_FILE_READ_CAP_BYTES:
                    continue
                if is_binary(fpath):
                    continue
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            yield fpath, content


def _build_identity_patterns(identity: OperatorIdentitySchema) -> list[str]:
    """Constroi lista de patterns literais (case-insensitive) para re-grep G2.d.

    Inclui:
      - identity.names (literal strings, case-insensitive)
      - identity.usernames (literal strings, case-insensitive)
      - identity.domains (literal strings, case-insensitive)

    Filtra strings vazias e patterns triviais (<3 chars; evitar false-positives
    massivos em palavras curtas como "ab").
    """
    raw = list(identity.names) + list(identity.usernames) + list(identity.domains)
    return [p.strip() for p in raw if p and len(p.strip()) >= 3]


def _scan_paths_absolutos(dest_path: Path) -> list[str]:
    """Re-grep G2.c: walk destino e coleta matches de WINDOWS_PATH_RE + UNIX_PATH_RE.

    Returns lista de amostras (cap _G2_SAMPLES_CAP) no formato
    "rel_path:line_num:match" para audit/report consumption.

    Skip de _G2_PATHS_SKIP_FILES (audit reports do agente).
    """
    samples: list[str] = []
    for fpath, content in _walk_text_files(dest_path):
        if fpath.name in _G2_PATHS_SKIP_FILES:
            continue
        try:
            rel = fpath.relative_to(dest_path).as_posix()
        except ValueError:
            rel = fpath.name
        for lineno, line in enumerate(content.splitlines(), start=1):
            for regex in (WINDOWS_PATH_RE, UNIX_PATH_RE):
                m = regex.search(line)
                if m:
                    samples.append(f"{rel}:{lineno}:{m.group(0)[:120]}")
                    if len(samples) >= _G2_SAMPLES_CAP:
                        return samples
                    break  # uma amostra por linha (suficiente para [NOME] ver evidencia)
    return samples


# Auditoria 2026-07 — basenames de LICENSE onde o NOME do operador (copyright
# holder) e a UNICA PII tolerada (excecao canonica; espelha f3_sanitizer.LICENSE_BASENAMES).
_G2_LICENSE_BASENAMES: frozenset[str] = frozenset({
    "license", "license.md", "license.txt", "licence",
})


def _scan_pii_operador(
    dest_path: Path,
    patterns: list[str],
    name_patterns: list[str] | None = None,
) -> list[str]:
    """Re-grep G2.d: walk destino case-insensitive procurando identity patterns.

    Args:
        patterns: literal strings (case-insensitive) SEM names quando
            `name_patterns` for passado separado (split da auditoria 2026-07).
        name_patterns: patterns de NOMES do operador — aplicados a todos os
            arquivos EXCETO LICENSE (excecao canonica: copyright holder).

    Returns lista de amostras (cap _G2_SAMPLES_CAP) "rel:line:pattern_hit".

    Skip de _G2_PII_SKIP_FILES: arquivos agent-generated com PII intencional
    (CODE_OF_CONDUCT/CONTRIBUTING/SECURITY templates F2 + *_AUDIT.md reports).

    Auditoria 2026-07: alem do CONTEUDO, o PATH RELATIVO de cada arquivo tambem
    e escaneado — red team provou que `[NOME]-helper.py` (nome pessoal no
    FILENAME) atravessava todas as camadas.
    """
    names = name_patterns or []
    if not patterns and not names:
        return []
    samples: list[str] = []
    lower_patterns = [p.lower() for p in patterns]
    lower_names = [p.lower() for p in names]
    for fpath, content in _walk_text_files(dest_path):
        try:
            rel = fpath.relative_to(dest_path).as_posix()
        except ValueError:
            rel = fpath.name
        # (1) FILENAME/path scan — sempre, inclusive para skip-files
        rel_lower = rel.lower()
        for p in lower_patterns + lower_names:
            if p in rel_lower:
                samples.append(f"{rel}:0:FILENAME:{p}")
                if len(samples) >= _G2_SAMPLES_CAP:
                    return samples
                break
        # (2) CONTENT scan
        if fpath.name in _G2_PII_SKIP_FILES:
            continue
        is_license = fpath.name.lower() in _G2_LICENSE_BASENAMES
        content_patterns = lower_patterns if is_license else lower_patterns + lower_names
        for lineno, line in enumerate(content.splitlines(), start=1):
            line_lower = line.lower()
            for p in content_patterns:
                if p in line_lower:
                    samples.append(f"{rel}:{lineno}:{p}")
                    if len(samples) >= _G2_SAMPLES_CAP:
                        return samples
                    break
    return samples


def _detect_language_for_g2(dest_path: Path) -> str:
    """Detecta language primary reuso de f2_organizer.detect_language.

    Import local para evitar ciclo (f4_readme nao importa f2_organizer
    em outras paths; isolar para G2 only).
    """
    from repo_sanitizer.f2_organizer import detect_language
    return detect_language(dest_path).primary


def run_g2_replica_funcional(
    *,
    dest_path: Path,
    project_root: Path,
    fs_writer: FsWriter,
    audit: AuditLogger,
    project_slug: str = "",
    license_override: LicenseId = "MIT",
) -> G2Result:
    """Bloco 04 ADR-032: Gate G2 (Replica Funcional Verified) - 4 checks.

    Executa apos run_f4_finalize (markdownlint + cleanup .tmp/) e ANTES da
    FSM transition. Resultado guia transicao:
        - (c)/(d) FAIL -> raise G2BlockingFailure (caller mapeia exit 7)
        - (a)/(b) auto-gen -> outcome "done_with_warnings"
        - todos OK -> outcome "done"

    Args:
        dest_path: pasta destino (sanitizado, ja com README).
        project_root: raiz do repo-sanitizer (para load_operator_identity).
        fs_writer: FsWriter canonico (escrita atomica de boilerplate/LICENSE).
        audit: AuditLogger canonico (emite f4_g2_done).
        project_slug: slug canonico do projeto-fonte (Bloco 03 extract_project_slug).
            Usado como `name=` em pyproject/package.json/Cargo. Fallback 'project'.
        license_override: ID da licenca para auto-gen (default MIT, --license CLI).

    Returns:
        G2Result com checks + outcome + auto_generated_files + blocking_failures.

    Never raises G2BlockingFailure aqui — caller (orchestrator.run_finalize)
    decide se levanta ou nao para FSM transition.
    """
    # Validate license_override (defensivo; CLI ja restringe via argparse choices)
    if license_override not in ALLOWED_LICENSES:
        license_override = "MIT"

    result = G2Result(language_detected=_detect_language_for_g2(dest_path))

    # ---------------- Check (a): Boilerplate ----------------
    boilerplate_entry = _BOILERPLATE_MAP.get(result.language_detected)
    if boilerplate_entry is None:
        # Generic language: nao ha boilerplate canonico; check (a) passa trivialmente
        result.check_a_boilerplate = True
    else:
        filename, generator = boilerplate_entry
        target = dest_path / filename
        if target.exists() and target.stat().st_size > 0:
            result.check_a_boilerplate = True
        else:
            # Auto-gen (ADR-033)
            slug_for_pkg = project_slug or dest_path.name
            content = generator(slug_for_pkg)
            fs_writer.safe_write_text(target, content)
            result.check_a_boilerplate = True
            result.auto_generated_files.append(target)

    # ---------------- Check (b): LICENSE ----------------
    license_present = any(
        (dest_path / cand).is_file() and (dest_path / cand).stat().st_size > 0
        for cand in _LICENSE_CANDIDATE_NAMES
    )
    if license_present:
        result.check_b_license = True
    else:
        target = dest_path / "LICENSE"
        year = _dt.datetime.now(_dt.UTC).year
        content = generate_license(license_override, year=year)
        fs_writer.safe_write_text(target, content)
        result.check_b_license = True
        result.auto_generated_files.append(target)

    # ---------------- Check (c): Zero paths absolutos ----------------
    result.paths_found = _scan_paths_absolutos(dest_path)
    result.check_c_paths_zero = len(result.paths_found) == 0
    if not result.check_c_paths_zero:
        result.blocking_failures.append(
            f"Paths absolutos detectados no destino: {len(result.paths_found)} "
            f"amostra(s) (cap {_G2_SAMPLES_CAP}). Camada C10 (Bloco 02) deveria "
            f"ter sanitizado em F3."
        )

    # ---------------- Check (d): Zero PII operador ----------------
    identity = load_operator_identity(project_root)
    # Auditoria 2026-07: split names vs demais — names sao tolerados APENAS no
    # conteudo de LICENSE (copyright holder); usernames/domains em lugar nenhum.
    _min = 3
    name_patterns = [p.strip() for p in identity.names if p and len(p.strip()) >= _min]
    other_patterns = [
        p.strip()
        for p in list(identity.usernames) + list(identity.domains)
        if p and len(p.strip()) >= _min
    ]
    result.pii_found = _scan_pii_operador(dest_path, other_patterns, name_patterns)
    result.check_d_pii_zero = len(result.pii_found) == 0
    if not result.check_d_pii_zero:
        result.blocking_failures.append(
            f"PII operador detectado no destino: {len(result.pii_found)} "
            f"amostra(s) (cap {_G2_SAMPLES_CAP}). Camada C9 (Bloco 01) deveria "
            f"ter redatado em F3."
        )

    # ---------------- Outcome decision ----------------
    if not result.check_c_paths_zero or not result.check_d_pii_zero:
        result.outcome = "done_with_failure"
    elif result.auto_generated_files:
        result.outcome = "done_with_warnings"
    else:
        result.outcome = "done"

    # Audit (ADR-032)
    audit.log("f4_g2_done", detail={
        "check_a_boilerplate": result.check_a_boilerplate,
        "check_b_license": result.check_b_license,
        "check_c_paths_zero": result.check_c_paths_zero,
        "check_d_pii_zero": result.check_d_pii_zero,
        "outcome": result.outcome,
        "auto_generated_files": [
            redact_path(p.as_posix()) for p in result.auto_generated_files
        ],
        "language_detected": result.language_detected,
        "license_override": license_override,
        "paths_found_count": len(result.paths_found),
        "pii_found_count": len(result.pii_found),
        # Amostras (cap _G2_SAMPLES_CAP) — paths SAO sensitive, mas amostras
        # ja sao matches dentro do destino e devem aparecer no audit-log
        # para [NOME] ler durante inspecao pos-failure.
        "paths_found_samples": result.paths_found[:5],
        "pii_found_samples": result.pii_found[:5],
    })

    return result


__all__ = [
    "DEGRADE_STUB_PT_BR",
    "KIT_JSON_PREFIX",
    "KIT_JSON_SUFFIX",
    "TMP_DIR_NAME",
    "F4CapLlmExceeded",
    "F4FinalizeResult",
    "F4Kit",
    "F4MissingReadme",
    "G2Result",
    "cap_llm_kit_emitted",
    "cleanup_tmp_kits",
    "collect_kit",
    "emit_generate_readme_instruction",
    "filter_and_isolate_kit",
    "kit_filename",
    "list_kit_jsons",
    "mark_kit_emitted",
    "reset_kit_cap_flag",
    "run_f4_emit_kit",
    "run_f4_finalize",
    "run_g2_replica_funcional",
    "run_link_check",
    "run_markdownlint",
    "write_degrade_stub_readme",
    "write_kit_json",
]


# Suppress unused-import warnings de symbols externos so usados via TYPE_CHECKING
_ = os
