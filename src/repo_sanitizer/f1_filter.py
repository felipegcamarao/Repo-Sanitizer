"""f1_filter.py — Filtro de Pertinencia (F1) — Bloco 02.

Classifica arquivos em Grupos A/B/C, walk read-only sobre o repo-fonte (INV-1
reforcado 2x). Output: lista de FilterDiffEntry pronta para emitir como
FILTER_DIFF.md (via reports/filter_diff_writer.py).

Pipeline F1 (sequencial determinstico):
1. Walk fonte com `os.walk(followlinks=False)` — INV-1 read-only.
2. Para cada arquivo:
   a) Se symlink/junction/hardlink (`_symlink_guard.is_unsafe_link`) -> EXCLUI
      como `acao='symlink_excluded'` + sinaliza em FILTER_DIFF secao dedicada.
   b) Classifica em GRUPO A (lixo deterministico) -> `acao='excluir'`.
   c) Senao classifica em GRUPO C (whitelist canonica por nome) -> `acao='incluir'`.
   d) Senao classifica em GRUPO B (heuristica ambiguo) -> `acao='excluir'` +
      sinaliza para review.
   e) Default -> `acao='incluir'` (caiu fora dos 3 grupos).
3. Calcula `is_binary` via `_binary_detector.classify`.
4. Aplica `_pii_redactor.redact_path` em path (defesa para FILTER_DIFF).
5. Emite snapshot SHA-256 fonte (pre-walk) para INV-1 gate (RS-002).

ADRs:
- ADR-005 (dry-run obrigatorio)
- ADR-006 (pipeline F1->F3->F2->F4 INVARIANTE; F1 nao chama F3/F2/F4)
- ADR-007 (sem override Grupo B no MVP — heuristica final)
- ADR-008 (auto-versionamento destino — delegado para reports/sanitize layer)
- ADR-009 (binary magic-bytes via _binary_detector)
- ADR-019 (symlink NEVER follow via _symlink_guard)
- ADR-025 (hash-tree fonte via _hash_tree)
- ADR-028 (PII redaction paths via _pii_redactor)

RS cobertos:
- RS-006 (symlink exclude)
- RS-016 (race fonte — gate em filter_diff_writer pre-apply)
- RS-018 (PII paths)
- RS-020 (F1 dry-run)
- RS-021 (auto-versionamento — delegado)
- RS-029 (Grupo C anomalo — F3 escaneia conteudo no pipeline)

API publica:
    GROUP_A_PATTERNS: lista de (regex, motivo) -> 10 categorias
    GROUP_C_FILES: set[str] -> whitelist canonica por nome
    GROUP_C_DIRS: set[str] -> dirs whitelist
    GROUP_B_HEURISTICS: lista de (regex, motivo) -> heuristica ambiguo
    GROUP_B_REVIEW_THRESHOLD: int (default 10)
    classify_path(rel_path_posix: str) -> tuple[group, motivo, action]
    walk_source(source: Path) -> Iterator[FilterCandidate]
    run_filter(source, run_id, ...) -> FilterResult
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repo_sanitizer.helpers._binary_detector import classify as binary_classify
from repo_sanitizer.helpers._cross_project_classifier import (
    CrossProjectClassification,
    classify_cross_project,
    extract_project_slug,
)
from repo_sanitizer.helpers._hash_tree import snapshot as hash_snapshot
from repo_sanitizer.helpers._pii_redactor import redact_path
from repo_sanitizer.helpers._symlink_guard import classify_link, is_unsafe_link
from repo_sanitizer.schemas.filter_diff_entry import (
    ActionLabel as EntryActionLabel,
)
from repo_sanitizer.schemas.filter_diff_entry import (
    FilterDiffEntry,
)
from repo_sanitizer.schemas.filter_diff_entry import (
    GroupLabel as EntryGroupLabel,
)

# ===========================================================================
# Grupo A — Lixo deterministico (10 categorias canonicas; ADR-006 / WBS 02.1)
# ===========================================================================
# Ordem importa: patterns mais especificos antes de mais genericos.
# Match contra path POSIX relativo (forward slashes).
GROUP_A_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # 1. .git/  (historico Git — fora do escopo)
    (re.compile(r"(^|/)\.git(/|$)"), "diretorio .git/ (historico Git fora do escopo)"),
    # 2. __pycache__/  (cache Python)
    (re.compile(r"(^|/)__pycache__(/|$)"), "cache Python __pycache__/"),
    # 3. node_modules/  (deps JS)
    (re.compile(r"(^|/)node_modules(/|$)"), "node_modules/ (gerenciado por npm/pnpm)"),
    # 4. .vscode/  (config IDE — exceto whitelist em GROUP_C)
    (re.compile(r"(^|/)\.vscode(/|$)"), "config IDE .vscode/ (preferencias pessoais)"),
    # 5. .idea/  (config JetBrains)
    (re.compile(r"(^|/)\.idea(/|$)"), "config IDE .idea/ (JetBrains)"),
    # 6. *.log  (logs runtime)
    (re.compile(r"\.log$"), "log runtime (.log)"),
    # 7. *.tmp / *.temp  (temporarios)
    (re.compile(r"\.(tmp|temp)$"), "arquivo temporario (.tmp/.temp)"),
    # 8. dist/  (build output JS/Python)
    (re.compile(r"(^|/)dist(/|$)"), "build output dist/"),
    # 9. build/  (build output generic)
    (re.compile(r"(^|/)build(/|$)"), "build output build/"),
    # 10. *.pyc  (Python bytecode)
    (re.compile(r"\.pyc$"), "Python bytecode (.pyc)"),
    # Bonus categorias adicionais comuns (consistente com GitHub Community):
    (re.compile(r"(^|/)\.pytest_cache(/|$)"), "cache pytest"),
    (re.compile(r"(^|/)\.mypy_cache(/|$)"), "cache mypy"),
    (re.compile(r"(^|/)\.ruff_cache(/|$)"), "cache ruff"),
    (re.compile(r"(^|/)\.tox(/|$)"), "ambiente tox"),
    (re.compile(r"(^|/)htmlcov(/|$)"), "cobertura HTML"),
    (re.compile(r"(^|/)\.coverage(/|$)"), "arquivo de cobertura"),
    (re.compile(r"(^|/)\.coverage(\.[\w.-]+)?$"), "arquivo de cobertura (.coverage[.host.pid])"),
    (re.compile(r"(^|/)\.next(/|$)"), "build Next.js"),
    (re.compile(r"(^|/)target(/|$)"), "build Rust/Java target/"),
    (re.compile(r"(^|/)\.gradle(/|$)"), "cache Gradle"),
    (re.compile(r"(^|/)Thumbs\.db$"), "Thumbs.db Windows"),
    (re.compile(r"(^|/)\.DS_Store$"), ".DS_Store macOS"),
    (re.compile(r"\.swp$"), "swap vim (.swp)"),
    (re.compile(r"\.bak$"), "backup (.bak)"),
    (re.compile(r"\.orig$"), "merge conflict orig (.orig)"),
    # =====================================================================
    # v1.2.0 / MV-01 / RS-NEW-039 — Lista canonica EXAUSTIVA de caches/lixo
    # de execucao (Grupo A). Cada entry ancorada `(^|/)nome(/|$)` para dir e
    # `\.ext$` para extensao (NUNCA casa pasta de produto legitima — fixture de
    # falso-positivo prova `src/build_tools/`, `data/dist_metrics/`,
    # `app/target_groups/` MANTIDOS). Mitigacao §5-6 (#02 threat model).
    # ATENCAO `env`: ancorado `(^|/)(\.venv|venv|env)(/|$)` exige separador →
    # NAO engole `.env` (basename, segredo C1) — MV01-C resolvido.
    # =====================================================================
    # Ambientes virtuais Python (dir; exige separador → nao casa `.env` file)
    (re.compile(r"(^|/)(\.venv|venv|env)(/|$)"),
     "ambiente virtual Python (.venv/venv/env)"),
    # Bytecode/objetos compilados (extensao — seguros, nunca pasta de produto)
    (re.compile(r"\.pyo$"), "Python bytecode otimizado (.pyo)"),
    (re.compile(r"\.pdb$"), "debug symbols (.pdb)"),
    (re.compile(r"\.class$"), "Java bytecode (.class)"),
    (re.compile(r"\.(o|obj)$"), "objeto compilado (.o/.obj)"),
    # egg-info (build metadata Python; ancorado por dir/basename)
    (re.compile(r"(^|/)[^/]+\.egg-info(/|$)"), "metadata egg-info Python"),
    # Caches de ferramentas de teste/lint/type/coverage
    (re.compile(r"(^|/)\.ruff_cache(/|$)"), "cache ruff"),
    (re.compile(r"(^|/)\.nox(/|$)"), "ambiente nox"),
    (re.compile(r"(^|/)\.hypothesis(/|$)"), "cache hypothesis"),
    (re.compile(r"(^|/)\.nyc_output(/|$)"), "cobertura nyc (.nyc_output)"),
    (re.compile(r"(^|/)\.eslintcache$"), "cache eslint (.eslintcache)"),
    (re.compile(r"(^|/)\.stylelintcache$"), "cache stylelint (.stylelintcache)"),
    (re.compile(r"(^|/)coverage\.xml$"), "relatorio de cobertura (coverage.xml)"),
    (re.compile(r"\.tsbuildinfo$"), "cache incremental TypeScript (.tsbuildinfo)"),
    # Caches de ferramentas de build/bundlers JS
    (re.compile(r"(^|/)\.cache(/|$)"), "cache generico (.cache)"),
    (re.compile(r"(^|/)\.parcel-cache(/|$)"), "cache Parcel"),
    (re.compile(r"(^|/)\.turbo(/|$)"), "cache Turborepo (.turbo)"),
    (re.compile(r"(^|/)\.svelte-kit(/|$)"), "build SvelteKit (.svelte-kit)"),
    (re.compile(r"(^|/)\.terraform(/|$)"), "cache Terraform (.terraform)"),
    (re.compile(r"(^|/)__pypackages__(/|$)"), "PEP 582 __pypackages__/"),
    # Notebooks / outros
    (re.compile(r"(^|/)\.ipynb_checkpoints(/|$)"), "checkpoints Jupyter"),
    # =====================================================================
    # Auditoria 2026-07 — historicos de sessao de agentes de IA (Grupo A).
    # Red team provou que `.claude/` e `.specstory/` com transcripts eram
    # COPIADOS para o destino (apenas com redacao regex do conteudo).
    # Transcripts de sessao carregam contexto interno inteiro: exclusao total.
    # =====================================================================
    (re.compile(r"(^|/)\.claude(/|$)"), "historico de sessao IA (.claude/)"),
    (re.compile(r"(^|/)\.specstory(/|$)"), "historico de sessao IA (.specstory/)"),
    (re.compile(r"(^|/)\.cursor(/|$)"), "config/historico IDE IA (.cursor/)"),
    (re.compile(r"(^|/)\.windsurf(/|$)"), "config/historico IDE IA (.windsurf/)"),
    (re.compile(r"(^|/)\.aider[^/]*(/|$)"), "historico de sessao IA (.aider*)"),
    (re.compile(r"(^|/)\.history(/|$)"), "VS Code Local History (.history/)"),
    (re.compile(r"(^|/)safelog[^/]*\.jsonl$"), "safelog de sessao IA (safelog*.jsonl)"),
    (re.compile(r"(^|/)\.claude\.json$"), "estado de sessao IA (.claude.json)"),
]


# ===========================================================================
# Gate de historico Git — walk-side (v1.2.0 / MV-02 / RS-NEW-038; mitig. §5-5)
# ===========================================================================
# Artefatos de historico Git que vivem FORA de `.git/` (a pasta `.git/` ja e
# coberta em GROUP_A_PATTERNS). Estes sao Grupo A (excluir) sob INV-5:
# `*.patch`/`*.diff` legitimos (ex.: patches de doc) tambem caem aqui —
# trade-off DOCUMENTADO e aceito (modo paranoico zero-FN > zero-FP). O gate
# BLOQUEANTE no destino (B3) usa este conjunto + deteccao por conteudo.
GIT_HISTORY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(^|/)packed-refs$"), "git packed-refs (historico)"),
    (re.compile(r"(^|/)ORIG_HEAD$"), "git ORIG_HEAD (historico)"),
    (re.compile(r"(^|/)FETCH_HEAD$"), "git FETCH_HEAD (historico)"),
    (re.compile(r"(^|/)\.gitmodules$"), "git .gitmodules (submodule)"),
    (re.compile(r"\.(orig|rej)$"), "artefato de merge/patch (.orig/.rej)"),
    (re.compile(r"\.(patch|diff)$"),
     "patch/diff de historico (.patch/.diff) — INV-5"),
    (re.compile(r"\.bundle$"), "git bundle (.bundle)"),
]


# ===========================================================================
# Grupo C — Whitelist canonica por NOME (sem inspecao de conteudo; ADR-007)
# ===========================================================================
# Match exato case-insensitive sobre basename.
# Whitelist do GitHub Community Standards + comuns ecossistemas (Python/Node/Rust/etc.)
# AT-01 spoofing aceito: F3 escaneia conteudo no pipeline (compensa).
GROUP_C_FILES: frozenset[str] = frozenset({
    # GitHub Community Standards
    "license", "license.md", "license.txt", "licence",
    "readme", "readme.md", "readme.rst", "readme.txt",
    "contributing", "contributing.md",
    "code_of_conduct", "code_of_conduct.md",
    "security", "security.md",
    "support", "support.md",
    "issue_template", "issue_template.md",
    "pull_request_template", "pull_request_template.md",
    "changelog", "changelog.md", "changes.md",
    "authors", "authors.md", "contributors", "contributors.md",
    "notice", "notice.md", "notice.txt",
    # Configs essenciais
    ".gitignore", ".gitattributes", ".editorconfig", ".gitkeep",
    # Python ecosystem
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "requirements-dev.txt", "poetry.lock", "pdm.lock", "uv.lock",
    "manifest.in", "tox.ini", "pytest.ini", "ruff.toml", "mypy.ini",
    # Node ecosystem
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ".npmrc", ".nvmrc", "tsconfig.json", "jsconfig.json",
    ".eslintrc", ".eslintrc.json", ".eslintrc.yml", ".prettierrc",
    "vite.config.ts", "vite.config.js", "next.config.js", "next.config.mjs",
    # Rust
    "cargo.toml", "cargo.lock", "rust-toolchain.toml", "rustfmt.toml",
    # Go
    "go.mod", "go.sum",
    # Java/Kotlin
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    # PHP
    "composer.json", "composer.lock",
    # Ruby
    "gemfile", "gemfile.lock", ".ruby-version",
    # C#
    ".csproj", ".sln",
    # CI/CD
    ".dockerignore", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "makefile", "justfile",
})


# Whitelist de DIRETORIOS (basename match case-insensitive). Conteudo desses
# dirs NAO e auto-incluido — apenas o dir nao e classificado como Grupo A.
GROUP_C_DIRS: frozenset[str] = frozenset({
    ".github", ".gitlab", "src", "lib", "tests", "test", "docs", "doc",
    "examples", "example", "scripts", "schemas", "schema",
})


# Arquivos canonicos dentro de .vscode/ que NAO sao classificados como Grupo A:
GROUP_C_VSCODE_WHITELIST: frozenset[str] = frozenset({
    "extensions.json", "settings.example.json", "launch.example.json",
})


# ===========================================================================
# Grupo B — Heuristica de ambiguidade (ADR-007: sem override no MVP)
# ===========================================================================
# Match em qualquer parte do path POSIX (case-insensitive). Quando match, marca
# como `acao='excluir'` + `grupo='B'` + `grupo_reason_detail` para review.
GROUP_B_HEURISTICS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(draft|drafts)\b", re.IGNORECASE), "marker 'draft' no path/nome"),
    (re.compile(r"\b(rascunho|rascunhos)\b", re.IGNORECASE), "marker 'rascunho' no path/nome"),
    (re.compile(r"\b(teste-local|test-local)\b", re.IGNORECASE), "marker 'teste-local'"),
    (re.compile(r"\b(notas[-_]noma|notas[-_]pessoais)\b", re.IGNORECASE),
     "marker 'notas-noma' / 'notas-pessoais'"),
    (re.compile(r"\b(todo[-_]pessoal|todo[-_]personal)\b", re.IGNORECASE),
     "marker 'todo-pessoal'"),
    (re.compile(r"\b(privado|private[-_]notes)\b", re.IGNORECASE),
     "marker 'privado'/'private-notes'"),
    (re.compile(r"\bscratch\b", re.IGNORECASE), "marker 'scratch'"),
    (re.compile(r"\bsandbox[-_]?\w*\b", re.IGNORECASE), "marker 'sandbox*'"),
    (re.compile(r"_old\b|\.old$", re.IGNORECASE), "marker '_old' / '.old'"),
    (re.compile(r"_obsolet[oae]\b", re.IGNORECASE), "marker '_obsoleto/-a/-e'"),
    (re.compile(r"\bcopy\b|\bcopia\b", re.IGNORECASE),
     "marker 'copy'/'copia'"),
]

# Threshold para sinalizar `>N arquivos requer revisao` no FILTER_DIFF.
GROUP_B_REVIEW_THRESHOLD: int = 10


# ===========================================================================
# Classificacao
# ===========================================================================

GroupLabel = str  # 'A' | 'B' | 'C' | 'default-include'


def _is_inside_dir(rel_path_posix: str, dir_name: str) -> bool:
    """True sse `rel_path_posix` esta dentro de algum segmento exato `dir_name`."""
    parts = rel_path_posix.split("/")
    return dir_name in parts


def classify_group_a(rel_path_posix: str) -> tuple[bool, str]:
    """Retorna (matched, motivo). Verifica .vscode whitelist antes."""
    # Excecao .vscode whitelist (ADR-007)
    parts = rel_path_posix.split("/")
    if ".vscode" in parts:
        # Se for arquivo dentro de .vscode/, checa whitelist
        basename = parts[-1].lower()
        if basename in GROUP_C_VSCODE_WHITELIST:
            return False, ""  # Nao e Grupo A — sera Grupo C
    for pattern, motivo in GROUP_A_PATTERNS:
        if pattern.search(rel_path_posix):
            return True, motivo
    # v1.2.0 / MV-02 / RS-NEW-038 — artefatos de historico Git fora de `.git/`
    for pattern, motivo in GIT_HISTORY_PATTERNS:
        if pattern.search(rel_path_posix):
            return True, motivo
    return False, ""


def classify_group_c(rel_path_posix: str) -> tuple[bool, str]:
    """Whitelist por NOME (case-insensitive)."""
    parts = rel_path_posix.split("/")
    basename_lower = parts[-1].lower()
    if basename_lower in GROUP_C_FILES:
        return True, f"whitelist canonica: {parts[-1]}"
    # .vscode whitelist
    if ".vscode" in parts and basename_lower in GROUP_C_VSCODE_WHITELIST:
        return True, f"whitelist .vscode/: {parts[-1]}"
    return False, ""


def classify_group_b(rel_path_posix: str) -> tuple[bool, str]:
    """Heuristica ambiguo. Aceita FP per INV-14 (excluir por default em ambiguidade)."""
    for pattern, motivo in GROUP_B_HEURISTICS:
        if pattern.search(rel_path_posix):
            return True, motivo
    return False, ""


def classify_path(rel_path_posix: str) -> tuple[GroupLabel, str, str]:
    """Classifica path relativo POSIX em (grupo, motivo, acao_canonica).

    Ordem (ADR-006 + ADR-007):
    1. Grupo A (lixo deterministico) -> excluir
    2. Grupo C (whitelist) -> incluir
    3. Grupo B (heuristica ambiguo) -> excluir (sinaliza review)
    4. Default -> incluir (caiu fora dos 3)

    Retorna:
        (grupo, motivo, acao_canonica)
        grupo: 'A' | 'B' | 'C' | 'default-include'
        acao_canonica: 'incluir' | 'excluir'
    """
    # 1) Grupo A — lixo deterministico
    matched, motivo = classify_group_a(rel_path_posix)
    if matched:
        return "A", motivo, "excluir"

    # 2) Grupo C — whitelist canonica
    matched, motivo = classify_group_c(rel_path_posix)
    if matched:
        return "C", motivo, "incluir"

    # 3) Grupo B — heuristica ambiguo
    matched, motivo = classify_group_b(rel_path_posix)
    if matched:
        return "B", motivo, "excluir"

    # 4) Default-include
    return "default-include", "fora dos 3 grupos canonicos (default include)", "incluir"


# ===========================================================================
# Walk + classificacao
# ===========================================================================

@dataclass
class FilterCandidate:
    """Resultado intermediario de um arquivo classificado por F1."""
    rel_path_posix: str
    abs_path: Path
    grupo: GroupLabel
    motivo: str
    acao: str  # 'incluir' | 'excluir' | 'symlink_excluded'
    is_binary: bool = False
    binary_label: str = ""
    size_bytes: int = 0
    grupo_reason_detail: str | None = None
    link_info: dict[str, Any] | None = None


def walk_source(source: Path) -> Iterator[FilterCandidate]:
    """Walk recursivo read-only do fonte (INV-1).

    `os.walk(followlinks=False)` + sub-dirs unsafe (junction/symlink) sao
    excluidos do walk (consistente com `_hash_tree.compute_tree_hashes`).

    Para cada arquivo encontrado, yield FilterCandidate ainda nao classificado
    em Grupo A/B/C — caller chama `classify_candidate(c)` para preencher.
    """
    source = Path(source).resolve()
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        # Defesa: exclui sub-dirs que sao symlink/junction (RS-006)
        for d in list(dirnames):
            full_d = Path(dirpath) / d
            if is_unsafe_link(full_d):
                # Sinaliza o dir-link como FilterCandidate symlink_excluded
                rel = full_d.relative_to(source).as_posix()
                yield FilterCandidate(
                    rel_path_posix=rel + "/",
                    abs_path=full_d,
                    grupo="A",
                    motivo="link suspeito (symlink/junction) — RS-006",
                    acao="symlink_excluded",
                    link_info=classify_link(full_d),
                )
                dirnames.remove(d)

        for fname in filenames:
            full = Path(dirpath) / fname
            rel = full.relative_to(source).as_posix()

            # 1) Symlink/junction/hardlink check
            if is_unsafe_link(full):
                yield FilterCandidate(
                    rel_path_posix=rel,
                    abs_path=full,
                    grupo="A",
                    motivo="link suspeito (symlink/junction/hardlink) — RS-006",
                    acao="symlink_excluded",
                    link_info=classify_link(full),
                    size_bytes=_safe_size(full),
                )
                continue

            # 2) Classificacao A/B/C
            grupo, motivo, acao = classify_path(rel)
            bin_info = binary_classify(full)
            cand = FilterCandidate(
                rel_path_posix=rel,
                abs_path=full,
                grupo=grupo,
                motivo=motivo,
                acao=acao,
                is_binary=bool(bin_info["is_binary"]),
                binary_label=str(bin_info["magic_label"]),
                size_bytes=_safe_size(full),
                grupo_reason_detail=motivo if grupo == "B" else None,
            )
            yield cand


def _safe_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


# ===========================================================================
# Pipeline run_filter (orquestracao F1 completa)
# ===========================================================================

@dataclass
class FilterResult:
    """Resultado canonico de uma execucao F1 dry-run.

    Caller (orchestrator) usa `entries` para emitir FILTER_DIFF.md, `snapshot`
    para gravar/comparar com run apply (RS-016 race detection), e os
    contadores para log/decisao.

    Bloco 03 (ADR-031 + RS-NEW-033) adiciona 3 campos:
    - `cross_project_classifications`: lista canonica de classificacoes F1.5
      (1 entry por arquivo de Grupo C antes da promocao).
    - `f1_5_counts`: dict com promocoes contadas
      (`cross_project_to_B`, `ambiguous_to_B`, `cache_to_A`, `intra_project_kept_C`).
    - `project_slug`: slug canonico resolvido para o source-tree.
    Todos com default — backwards-compat 100% para callers v1.0.x.
    """
    entries: list[FilterDiffEntry] = field(default_factory=list)
    symlink_excluded: list[FilterDiffEntry] = field(default_factory=list)
    snapshot_pre: dict[str, Any] = field(default_factory=dict)
    counts_by_group: dict[str, int] = field(default_factory=dict)
    counts_by_acao: dict[str, int] = field(default_factory=dict)
    grupo_b_excedeu_threshold: bool = False
    review_threshold: int = GROUP_B_REVIEW_THRESHOLD
    # Bloco 03 — F1.5 outputs
    cross_project_classifications: list[CrossProjectClassification] = field(
        default_factory=list,
    )
    f1_5_counts: dict[str, int] = field(default_factory=dict)
    project_slug: str = ""

    def included_paths(self) -> list[str]:
        return [e.path_redacted for e in self.entries if e.acao == "incluir"]

    def excluded_paths(self) -> list[str]:
        return [e.path_redacted for e in self.entries if e.acao == "excluir"]


def _candidate_to_entry(cand: FilterCandidate) -> FilterDiffEntry:
    """Converte FilterCandidate -> FilterDiffEntry (Pydantic validate)."""
    grupo: str = cand.grupo if cand.grupo in {"A", "B", "C"} else "C"
    acao: str = cand.acao
    if cand.acao == "symlink_excluded":
        # Schema aceita literal 'symlink_excluded'
        acao_final: str = "symlink_excluded"
    else:
        acao_final = "excluir" if acao == "excluir" else "incluir"

    # Para 'default-include' marcamos como Grupo C (whitelist por exclusao);
    # motivo deixa claro o caso edge.
    if cand.grupo == "default-include":
        grupo = "C"

    return FilterDiffEntry(
        path_redacted=redact_path(cand.rel_path_posix),
        grupo=grupo,  # type: ignore[arg-type]
        motivo=cand.motivo,
        acao=acao_final,  # type: ignore[arg-type]
        is_binary=cand.is_binary,
        size_bytes=cand.size_bytes,
        grupo_reason_detail=cand.grupo_reason_detail,
    )


def _resolve_context_md(source: Path) -> Path | None:
    """Auto-discovery do ``context-*.md`` na raiz do source-tree.

    Retorna o primeiro arquivo que casa ``context-*.md`` (ordem lexicografica)
    OU ``None`` se nenhum encontrado. NUNCA raise — usa `glob` read-only.
    """
    try:
        candidates = sorted(source.glob("context-*.md"))
    except OSError:
        return None
    return candidates[0] if candidates else None


def _apply_f1_5_promotion(
    entry: FilterDiffEntry,
    classification: CrossProjectClassification,
) -> FilterDiffEntry:
    """Rebuild de uma FilterDiffEntry com a promocao F1.5 aplicada.

    Pydantic v2 ``frozen=True`` no schema impede mutacao; usamos rebuild
    explicito mantendo path/size/binary e injetando novo grupo + motivo
    derivado da `evidence`. Evidence-string e capada em 200 chars
    (defesa contra paths longos em multipla classificacao).
    """
    target_grupo: EntryGroupLabel = classification.promoted_to
    target_acao: EntryActionLabel = "excluir"  # toda promocao F1.5 fora de C exclui
    evidence_str = "; ".join(classification.evidence)[:200]
    motivo = f"F1.5 {classification.category}: {evidence_str}"
    return FilterDiffEntry(
        path_redacted=entry.path_redacted,
        grupo=target_grupo,
        motivo=motivo,
        acao=target_acao,
        is_binary=entry.is_binary,
        size_bytes=entry.size_bytes,
        grupo_reason_detail=evidence_str,
    )


def run_filter(
    source: Path,
    *,
    context_md_path: Path | None = None,
) -> FilterResult:
    """Executa F1 dry-run sobre `source`. Read-only INV-1 enforce via walk.

    Bloco 03 (ADR-031 + RS-NEW-033) adiciona sub-fase F1.5 imediatamente apos
    a classificacao A/B/C inicial: cada entry de Grupo C eh re-classificada
    via `classify_cross_project`; entries cross-project/ambiguous/cache sao
    promovidas para B (review) ou A (exclude) com `motivo` derivado da
    `evidence` literal do classifier.

    Args:
        source: raiz do source-tree (read-only enforce).
        context_md_path: caminho opcional para o ``context-[slug].md``. Se
            None, auto-discovery via ``source.glob("context-*.md")``.
            Sem context.md → modo defensivo (todos planos/relatorios para B).

    Retorna FilterResult com:
    - entries: FilterDiffEntry list pos-F1.5 (validado Pydantic)
    - symlink_excluded: subset com `acao='symlink_excluded'`
    - snapshot_pre: hash-tree pre-walk (gate INV-1 / RS-002)
    - counts_by_group / counts_by_acao: contagens FINAIS (pos-F1.5)
    - grupo_b_excedeu_threshold: True sse Grupo B count > GROUP_B_REVIEW_THRESHOLD
    - cross_project_classifications: lista de classificacoes F1.5 emitidas
    - f1_5_counts: dict com promocoes contadas (cross_project_to_B etc.)
    - project_slug: slug canonico resolvido (`extract_project_slug`)
    """
    source = Path(source).resolve()
    if not source.exists():
        raise FileNotFoundError(f"f1_filter: source nao existe: {source}")

    # Snapshot pre (RS-002 gate)
    snap = hash_snapshot(source)

    # F1.5 setup — auto-discovery context.md + slug resolution
    if context_md_path is None:
        context_md_path = _resolve_context_md(source)
    project_slug = extract_project_slug(source, context_md_path)

    entries: list[FilterDiffEntry] = []
    symlink_entries: list[FilterDiffEntry] = []
    cross_classifications: list[CrossProjectClassification] = []
    counts_group: dict[str, int] = {"A": 0, "B": 0, "C": 0}
    counts_acao: dict[str, int] = {"incluir": 0, "excluir": 0, "symlink_excluded": 0}
    f1_5_counts: dict[str, int] = {
        "cross_project_to_B": 0,
        "ambiguous_to_B": 0,
        "cache_to_A": 0,
        "intra_project_kept_C": 0,
    }

    for cand in walk_source(source):
        entry = _candidate_to_entry(cand)

        # F1.5 — re-classifica entries de Grupo C `incluir` (default-include)
        if entry.grupo == "C" and entry.acao == "incluir":
            classification = classify_cross_project(
                cand.rel_path_posix, project_slug,
            )
            cross_classifications.append(classification)
            if classification.category == "intra_project":
                f1_5_counts["intra_project_kept_C"] += 1
            else:
                entry = _apply_f1_5_promotion(entry, classification)
                if classification.category == "cross_project":
                    f1_5_counts["cross_project_to_B"] += 1
                elif classification.category == "ambiguous":
                    f1_5_counts["ambiguous_to_B"] += 1
                elif classification.category == "cache":
                    f1_5_counts["cache_to_A"] += 1

        entries.append(entry)
        # contagem (pos-F1.5)
        counts_group[entry.grupo] = counts_group.get(entry.grupo, 0) + 1
        counts_acao[entry.acao] = counts_acao.get(entry.acao, 0) + 1
        if entry.acao == "symlink_excluded":
            symlink_entries.append(entry)

    excedeu = counts_group.get("B", 0) > GROUP_B_REVIEW_THRESHOLD

    return FilterResult(
        entries=entries,
        symlink_excluded=symlink_entries,
        snapshot_pre=snap,
        counts_by_group=counts_group,
        counts_by_acao=counts_acao,
        grupo_b_excedeu_threshold=excedeu,
        cross_project_classifications=cross_classifications,
        f1_5_counts=f1_5_counts,
        project_slug=project_slug,
    )


__all__ = [
    "GIT_HISTORY_PATTERNS",
    "GROUP_A_PATTERNS",
    "GROUP_B_HEURISTICS",
    "GROUP_B_REVIEW_THRESHOLD",
    "GROUP_C_DIRS",
    "GROUP_C_FILES",
    "GROUP_C_VSCODE_WHITELIST",
    "FilterCandidate",
    "FilterResult",
    "classify_group_a",
    "classify_group_b",
    "classify_group_c",
    "classify_path",
    "run_filter",
    "walk_source",
]
