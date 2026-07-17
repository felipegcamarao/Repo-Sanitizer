"""f2_organizer.py — Organizacao Visual por Melhores Praticas de Mercado (F2).

Bloco 04 (Modo Padrao AgenteIA). Reorganiza fisicamente a arvore de arquivos do
destino sanitizado para estrutura canonica GitHub Community Standards + score
10 itens binario. Atua APENAS no destino (INV-1).

Pipeline F2 (sequencial determinstico):
1. Detect linguagem + monorepo via heuristica (pyproject.toml / package.json /
   Cargo.toml / go.mod / pom.xml / Gemfile / composer.json / *.csproj).
2. Auto-gerar templates ausentes (CONTRIBUTING + CODE_OF_CONDUCT + SECURITY)
   via `importlib.resources` (ADR-010).
3. Auto-gerar `.gitignore` por linguagem se ausente (ADR-011 — 9 templates locais).
4. Movimentacao segura .md docs -> docs/; tests com imports absolutos -> tests/.
   Imports relativos = sugestao apenas (RS-020).
5. Conflito local: LICENSE em path nao-canonico -> move para root do destino.
6. Score 10 itens binario:
   1) README.md (existe + > 0 bytes)
   2) LICENSE (existe + > 0 bytes)
   3) CONTRIBUTING.md
   4) CODE_OF_CONDUCT.md
   5) SECURITY.md
   6) .gitignore
   7) CHANGELOG.md
   8) .github/workflows/
   9) src/ (ou equivalente como `lib/`, `app/`)
   10) tests/ (ou `test/`, `spec/`)
7. Apenda secao "Organizacao F2" no SANITIZATION_REPORT existente.
8. Audit log: f2_organize_start + f2_template_generated + f2_file_moved +
   f2_organize_done.

ADRs: ADR-010 (templates PT-BR) + ADR-011 (.gitignore local) + ADR-020 (FsWriter SSOT).
RS cobertos: RS-020 (F2 dry-run audit) + RS-024 (templates versionados) +
RS-030 (SECURITY contact tecnologia@acme.io).
"""
from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from repo_sanitizer.helpers._boilerplate_generator import merge_gitignore
from repo_sanitizer.helpers._pii_redactor import redact_path

if TYPE_CHECKING:
    from repo_sanitizer.helpers._audit import AuditLogger
    from repo_sanitizer.helpers._fs_writer import FsWriter


# ===========================================================================
# Deteccao de linguagem
# ===========================================================================

LANGUAGE_MARKERS: dict[str, list[str]] = {
    "python": ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"],
    "node": ["package.json"],
    "rust": ["Cargo.toml"],
    "go": ["go.mod"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "csharp": [".csproj", ".sln"],
    "php": ["composer.json"],
    "ruby": ["Gemfile"],
}


MONOREPO_MARKERS: list[str] = [
    "pnpm-workspace.yaml",
    "lerna.json",
    "nx.json",
    "turbo.json",
    "rush.json",
]


@dataclass(frozen=True)
class LanguageDetection:
    primary: str  # uma das keys de LANGUAGE_MARKERS ou "generic"
    is_monorepo: bool
    markers_found: tuple[str, ...]


def detect_language(dest_path: Path) -> LanguageDetection:
    """Heuristica: scan root do destino procurando markers canonicos.

    Em caso de empate (multiplos markers), retorna o PRIMEIRO da ordem canonica
    de LANGUAGE_MARKERS.
    """
    if not dest_path.exists():
        return LanguageDetection("generic", False, ())

    found: list[str] = []
    is_monorepo = False

    # Listar arquivos no root + dirs imediatos
    root_files: set[str] = set()
    for entry in dest_path.iterdir():
        if entry.is_file():
            root_files.add(entry.name)
        elif entry.is_dir() and entry.name in {"packages", "apps", "libs"}:
            # monorepo: muitos package.json em packages/
            is_monorepo = True

    # Monorepo markers explicitos
    for marker in MONOREPO_MARKERS:
        if marker in root_files:
            is_monorepo = True
            found.append(marker)

    # Detectar linguagem (primeira ordem canonica)
    primary = "generic"
    for lang, markers in LANGUAGE_MARKERS.items():
        for marker in markers:
            if marker in root_files:
                if primary == "generic":
                    primary = lang
                found.append(marker)
                break
        if primary != "generic" and primary == lang:
            # Continuar para detectar outros markers (ex: monorepo node)
            continue

    # Heuristica adicional para .csproj/.sln (case-insensitive suffix)
    if primary == "generic":
        for fname in root_files:
            lower = fname.lower()
            if lower.endswith((".csproj", ".sln")):
                primary = "csharp"
                found.append(fname)
                break

    return LanguageDetection(primary=primary, is_monorepo=is_monorepo, markers_found=tuple(found))


# ===========================================================================
# Score 10 itens GitHub Community Standards
# ===========================================================================

@dataclass
class ScoreItem:
    name: str  # canonical item name
    present: bool
    path_rel: str = ""  # relative path no destino se present
    size_bytes: int = 0
    note: str = ""


@dataclass
class F2Score:
    items: list[ScoreItem] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(1 for i in self.items if i.present)

    @property
    def max(self) -> int:
        return len(self.items)

    def is_passing(self, threshold: int = 8) -> bool:
        return self.total >= threshold


# Os 10 itens canonicos + heuristica de match
SCORE_ITEMS_CANONICAL: list[tuple[str, list[str], bool]] = [
    # (item_name, candidate_basenames_case_insensitive, is_directory)
    ("README", ["readme", "readme.md", "readme.rst", "readme.txt"], False),
    ("LICENSE", ["license", "license.md", "license.txt", "licence"], False),
    ("CONTRIBUTING", ["contributing", "contributing.md"], False),
    ("CODE_OF_CONDUCT", ["code_of_conduct", "code_of_conduct.md"], False),
    ("SECURITY", ["security", "security.md"], False),
    (".gitignore", [".gitignore"], False),
    ("CHANGELOG", ["changelog", "changelog.md", "changes.md"], False),
    (".github/workflows", [".github"], True),  # dir; checa subdir workflows
    ("src/", ["src", "lib", "app"], True),
    ("tests/", ["tests", "test", "spec", "__tests__"], True),
]


def compute_score(dest_path: Path, min_size_bytes: int = 1) -> F2Score:
    """Calcula score 10 itens binario. Item conta apenas se presente E nao-vazio
    (mitigacao AT-10 forca-bruta vazio)."""
    score = F2Score()
    if not dest_path.exists():
        for name, _, _ in SCORE_ITEMS_CANONICAL:
            score.items.append(ScoreItem(name=name, present=False, note="dest nao existe"))
        return score

    root_entries = {e.name.lower(): e for e in dest_path.iterdir()}

    for name, candidates, is_dir in SCORE_ITEMS_CANONICAL:
        matched: Path | None = None
        for cand in candidates:
            entry = root_entries.get(cand.lower())
            if entry is None:
                continue
            if is_dir and entry.is_dir():
                # Caso especial .github: precisa ter subdir workflows com pelo menos 1 .yml
                if name == ".github/workflows":
                    wf = entry / "workflows"
                    if wf.is_dir() and any(wf.glob("*.y*ml")):
                        matched = wf
                        break
                else:
                    # Verifica se dir nao-vazio
                    if any(entry.iterdir()):
                        matched = entry
                        break
            elif not is_dir and entry.is_file():
                size = entry.stat().st_size
                if size >= min_size_bytes:
                    matched = entry
                    break
        if matched is not None:
            try:
                rel = matched.relative_to(dest_path).as_posix()
            except ValueError:
                rel = matched.name
            size = matched.stat().st_size if matched.is_file() else 0
            score.items.append(ScoreItem(
                name=name, present=True, path_rel=rel, size_bytes=size,
            ))
        else:
            score.items.append(ScoreItem(name=name, present=False))

    return score


# ===========================================================================
# Auto-geracao de templates
# ===========================================================================

TEMPLATE_FILE_MAP: dict[str, str] = {
    "CONTRIBUTING.md": "contributing_pt_br.md",
    "CODE_OF_CONDUCT.md": "code_of_conduct_pt_br.md",
    "SECURITY.md": "security_pt_br.md",
}


GITIGNORE_LANGUAGE_TO_TEMPLATE: dict[str, str] = {
    "python": "python.gitignore",
    "node": "node.gitignore",
    "rust": "rust.gitignore",
    "go": "go.gitignore",
    "java": "java.gitignore",
    "csharp": "csharp.gitignore",
    "php": "php.gitignore",
    "ruby": "ruby.gitignore",
    "generic": "generic.gitignore",
}


def _load_template(template_basename: str, subdir: str = "") -> str:
    """Carrega template via importlib.resources (ADR-010 + ADR-011)."""
    pkg = "repo_sanitizer.templates"
    if subdir:
        pkg = f"{pkg}.{subdir}"
    return files(pkg).joinpath(template_basename).read_text(encoding="utf-8")


def auto_generate_templates(
    dest_path: Path,
    score: F2Score,
    fs_writer: FsWriter,
    *,
    language: str = "generic",
) -> list[tuple[str, str]]:
    """Auto-gera CONTRIBUTING / CODE_OF_CONDUCT / SECURITY / .gitignore quando ausentes.

    LICENSE + CHANGELOG: NUNCA inventa — apenas sinaliza no relatorio.

    Returns: list[(filename, action)] entries gerados (para audit_log).
    """
    generated: list[tuple[str, str]] = []
    item_by_name = {i.name: i for i in score.items}

    # 3 templates PT-BR
    template_to_score = {
        "CONTRIBUTING.md": "CONTRIBUTING",
        "CODE_OF_CONDUCT.md": "CODE_OF_CONDUCT",
        "SECURITY.md": "SECURITY",
    }
    for filename, score_name in template_to_score.items():
        item = item_by_name.get(score_name)
        if item is None or item.present:
            continue
        content = _load_template(TEMPLATE_FILE_MAP[filename])
        fs_writer.safe_write_text(dest_path / filename, content)
        generated.append((filename, "template_pt_br"))

    # .gitignore — MERGE ADITIVO ROBUSTO (v1.2.0 / MV-07 / RS-NEW-044).
    # Antes (v1.1.x): so escrevia se AUSENTE. Agora SEMPRE garante que o
    # `.gitignore` do destino contenha as entradas canonicas (incl.
    # `.sanitizer-state.json` — fecha C-V11-05), SEM destruir as regras do autor
    # (mitigacao §5-10 / MV07-C).
    gi_path = dest_path / ".gitignore"
    gi_item = item_by_name.get(".gitignore")
    if gi_item is not None and not gi_item.present:
        # Destino NAO tem `.gitignore`: template-da-linguagem + bloco canonico.
        template_name = GITIGNORE_LANGUAGE_TO_TEMPLATE.get(language, "generic.gitignore")
        template = _load_template(template_name, subdir="gitignore")
        content = merge_gitignore(template)
        fs_writer.safe_write_text(gi_path, content)
        generated.append((".gitignore", f"gitignore_{language}"))
    else:
        # Destino JA tem `.gitignore` (veio do source via F3): MERGE aditivo.
        # Le o existente, anexa so o que falta (dedup), nunca overwrite cego.
        try:
            existing = gi_path.read_text(encoding="utf-8") if gi_path.exists() else ""
        except OSError:
            existing = ""
        merged = merge_gitignore(existing)
        if merged != existing:
            fs_writer.safe_write_text(gi_path, merged)
            generated.append((".gitignore", "gitignore_merge_aditivo"))
        # Se merged == existing (idempotente: todas canonicas ja presentes) ->
        # NAO escreve nem registra (evita ruido + escrita desnecessaria).

    return generated


# ===========================================================================
# Movimentacao segura (ADR-020 + RS-020 + AT-07)
# ===========================================================================

# Heuristica: arquivo de teste com import absoluto pode ser movido com seguranca
# para tests/. Imports relativos -> sugestao apenas.
_IMPORT_ABSOLUTE_PY = re.compile(r"^from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+|^import\s+[A-Za-z_]", re.MULTILINE)
_IMPORT_RELATIVE_PY = re.compile(r"^from\s+\.+", re.MULTILINE)


@dataclass(frozen=True)
class MoveDecision:
    src_rel: str
    dest_rel: str
    action: str  # "moved" | "suggested" | "skipped"
    reason: str


def decide_move(
    src_rel_posix: str,
    src_content: str | None,
) -> MoveDecision | None:
    """Decide se um arquivo deve ser movido (heuristica segura).

    Returns:
        MoveDecision se o arquivo deve ser tocado (move OU sugestao).
        None se nao se aplica.
    """
    basename = src_rel_posix.split("/")[-1].lower()

    # CASO 1: arquivo .md na raiz que parece doc -> sugere docs/
    if "/" not in src_rel_posix and basename.endswith(".md"):
        # Excecoes: README/LICENSE/CONTRIBUTING/CODE_OF_CONDUCT/SECURITY/CHANGELOG ficam no root
        protected = {"readme.md", "license.md", "contributing.md", "code_of_conduct.md",
                     "security.md", "changelog.md", "changes.md"}
        if basename not in protected:
            return MoveDecision(
                src_rel=src_rel_posix,
                dest_rel=f"docs/{src_rel_posix}",
                action="suggested",
                reason=".md no root -> sugerir docs/ (revisar manualmente)",
            )

    # CASO 2: test_*.py / *_test.py / spec.ts no root -> tests/ se imports absolutos
    is_test_file = (
        (basename.startswith("test_") or basename.endswith(("_test.py", ".spec.ts", ".spec.js")))
        and "/" not in src_rel_posix
    )
    if is_test_file and src_content is not None:
        if _IMPORT_RELATIVE_PY.search(src_content):
            return MoveDecision(
                src_rel=src_rel_posix,
                dest_rel=f"tests/{src_rel_posix}",
                action="suggested",
                reason="test no root com imports relativos -> sugestao (move quebraria)",
            )
        if _IMPORT_ABSOLUTE_PY.search(src_content) or basename.endswith((".spec.ts", ".spec.js")):
            return MoveDecision(
                src_rel=src_rel_posix,
                dest_rel=f"tests/{src_rel_posix}",
                action="moved",
                reason="test no root com imports absolutos -> move seguro p/ tests/",
            )
    return None


def apply_safe_moves(
    dest_path: Path,
    fs_writer: FsWriter,
) -> list[MoveDecision]:
    """Aplica movimentacoes seguras + emite sugestoes.

    Decisao apenas em arquivos no root do destino. Subdirs sao deixados intactos
    (movimentacao recursiva e fora do escopo F2 MVP)."""
    decisions: list[MoveDecision] = []
    if not dest_path.exists():
        return decisions

    for entry in list(dest_path.iterdir()):
        if not entry.is_file():
            continue
        rel = entry.name
        try:
            content = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = None
        decision = decide_move(rel, content)
        if decision is None:
            continue
        decisions.append(decision)

        # Apenas executa o move quando action == "moved"
        if decision.action == "moved":
            dest_target = dest_path / decision.dest_rel
            # Em falha de move, registra mas nao bloqueia pipeline
            with contextlib.suppress(Exception):
                fs_writer.safe_move(entry, dest_target)
    return decisions


# ===========================================================================
# Conflito LICENSE (move para root)
# ===========================================================================

def resolve_license_path(
    dest_path: Path,
    fs_writer: FsWriter,
) -> str | None:
    """Se LICENSE esta em docs/ ou path nao-canonico, move para root do destino.

    Returns: rel_path da movimentacao ou None.
    """
    if not dest_path.exists():
        return None
    license_root = any((dest_path / n).exists() for n in ("LICENSE", "LICENSE.md", "LICENSE.txt"))
    if license_root:
        return None
    # Procura LICENSE em subdirs (apenas 1 nivel para evitar walk caro)
    for sub in dest_path.iterdir():
        if not sub.is_dir():
            continue
        for cand in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
            f = sub / cand
            if f.is_file():
                target = dest_path / cand
                try:
                    fs_writer.safe_move(f, target)
                    return cand
                except Exception:
                    return None
    return None


# ===========================================================================
# Pipeline F2 principal
# ===========================================================================

@dataclass
class F2Result:
    detection: LanguageDetection | None = None
    score: F2Score | None = None
    templates_generated: list[tuple[str, str]] = field(default_factory=list)
    moves: list[MoveDecision] = field(default_factory=list)
    license_moved: str | None = None


def run_f2(
    *,
    dest_path: Path,
    fs_writer: FsWriter,
    audit: AuditLogger,
) -> F2Result:
    """Executa F2 sobre o destino sanitizado (pos-F3).

    Pipeline:
    1. detect_language(dest)
    2. compute_score(dest) [pre-template]
    3. auto_generate_templates(dest, score) [3 PT-BR + .gitignore]
    4. resolve_license_path(dest)
    5. apply_safe_moves(dest)
    6. compute_score(dest) [pos-template + moves]
    """
    audit.log("f2_organize_start", detail={"dest_redacted": redact_path(str(dest_path))})

    result = F2Result()

    # 1) Deteccao
    result.detection = detect_language(dest_path)
    audit.log("f2_organize_start", detail={
        "phase": "language_detected",
        "primary": result.detection.primary,
        "is_monorepo": result.detection.is_monorepo,
        "markers": list(result.detection.markers_found)[:10],
    })

    # 2) Score pre
    pre_score = compute_score(dest_path)

    # 3) Auto-gerar templates
    result.templates_generated = auto_generate_templates(
        dest_path, pre_score, fs_writer,
        language=result.detection.primary,
    )
    for filename, source in result.templates_generated:
        audit.log("f2_template_generated", detail={
            "filename": filename, "template_source": source,
        })

    # 4) Resolver LICENSE em path nao-canonico (mover para root)
    result.license_moved = resolve_license_path(dest_path, fs_writer)
    if result.license_moved:
        audit.log("f2_file_moved", detail={
            "filename": result.license_moved, "reason": "LICENSE para root",
        })

    # 5) Movimentacoes seguras
    result.moves = apply_safe_moves(dest_path, fs_writer)
    for mv in result.moves:
        if mv.action == "moved":
            audit.log("f2_file_moved", detail={
                "src_redacted": redact_path(mv.src_rel),
                "dest_redacted": redact_path(mv.dest_rel),
                "reason": mv.reason,
            })

    # 6) Score pos
    result.score = compute_score(dest_path)

    audit.log("f2_organize_done", detail={
        "score_total": result.score.total,
        "score_max": result.score.max,
        "is_passing": result.score.is_passing(),
        "templates_generated_count": len(result.templates_generated),
        "moves_count": sum(1 for m in result.moves if m.action == "moved"),
        "suggestions_count": sum(1 for m in result.moves if m.action == "suggested"),
        "license_moved": result.license_moved,
        "monorepo": result.detection.is_monorepo,
        "language": result.detection.primary,
    })
    return result


__all__ = [
    "GITIGNORE_LANGUAGE_TO_TEMPLATE",
    "LANGUAGE_MARKERS",
    "MONOREPO_MARKERS",
    "SCORE_ITEMS_CANONICAL",
    "TEMPLATE_FILE_MAP",
    "F2Result",
    "F2Score",
    "LanguageDetection",
    "MoveDecision",
    "ScoreItem",
    "apply_safe_moves",
    "auto_generate_templates",
    "compute_score",
    "decide_move",
    "detect_language",
    "resolve_license_path",
    "run_f2",
]
