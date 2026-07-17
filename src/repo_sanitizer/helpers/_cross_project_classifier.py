"""_cross_project_classifier.py — Sub-fase F1.5 do F1 (ADR-031 + RS-NEW-033).

Heurística semântica determinística sobre nomes de pastas/arquivos para detectar
conteúdo cross-project. Promove arquivos de Grupo C para B (review) ou A
(exclude) conforme 5 regras canônicas (a..e) do ADR-031.

API canônica:

- ``sanitize_slug(name)`` — normaliza string em slug-kebab-case ASCII.
- ``extract_project_slug(source_path, context_md_path)`` — resolve slug do
  projeto-fonte via 3 estratégias em ordem (context.md > basename > sentinel).
- ``classify_cross_project(file_path, project_slug)`` — aplica regras a..e
  sobre um path relativo POSIX.

5 regras canônicas (manifesto ADR-031):

  (a) Planos cross-project — arquivos em ``Planos de Implementação/plano-*.md``
      OU arquivos no padrão ``plano-implementacao-*.md`` cujo slug não-matcha
      ``project_slug`` → Grupo B (review).
  (b) Relatórios cross-project — arquivos em ``Relatórios Staff/relatorio-staff-*.md``
      OU no padrão ``relatorio-staff-*.md`` cujo slug não-matcha → Grupo B.
  (c) Portfólio — ``**/memory/projetos.md`` ou ``**/memory/projects.md``
      → Grupo A (cache).
  (d) Eval caches — ``**/.eval-runs/**``, ``**/_eval_runs/**`` ou
      ``**/.fixtures-derivation/**`` → Grupo A.
  (e) Audit baselines — ``**/audit/baseline-*.md`` ou ``**/_baseline-*/**``
      → Grupo A.

Extensões polish-driven (positivas, documentadas):

- **Pasta-ancestral de plano** (regra a3): quando o caminho relativo tem um
  ancestral nomeado ``plano-implementacao-<slug>/``, aplica-se a regra (a)
  com o slug extraído do ancestral. Endereça o padrão Pipeline A+ de
  organizar planos em sub-pastas (``plano-implementacao-foo/00-INDEX.md``).
- **Match de slug versionado**: ``extracted_slug`` matcha ``project_slug``
  por exatamente OU por prefixo ``project_slug + '-v'`` (e.g.,
  ``repo-sanitizer-agent-v1.1.0`` matcha ``repo-sanitizer-agent``).

Resolução do ``project_slug`` (em ``extract_project_slug``):

  1. ``context.md`` > ``## Identificação`` > ``**Nome:**`` → ``sanitize_slug``.
  2. Polish-driven: YAML frontmatter ``slug:`` no início do ``context.md``.
  3. Fallback: ``source_path.name`` → ``sanitize_slug``.
  4. Sentinel defensivo: ``'unknown-project'``.

Modo defensivo (``project_slug == 'unknown-project'``):
  TODOS planos/relatórios cruzando rule (a)/(b) vão para Grupo B com
  ``evidence=['no_context_md_defensive', ...]``. Perda zero de revisão humana.

Invariantes (Pipeline A+ / context.md):

- INV-1 — NUNCA toca a source-tree. Lê context.md apenas em modo read-only.
- INV-8 — NUNCA chama LLM nem rede. Regex stdlib pura.
- INV-9 — Stdlib only; sem dependências novas.
- INV-11 — Mensagens (evidence) em pt-BR/ASCII determinístico.

Cobertura ≥90% gate Bloco 03 (Passo 3.1).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Aliases de tipo
# ---------------------------------------------------------------------------

CrossCategory = Literal["intra_project", "cross_project", "ambiguous", "cache"]
PromotedTo = Literal["A", "B", "C"]

# ---------------------------------------------------------------------------
# Constantes canônicas
# ---------------------------------------------------------------------------

UNKNOWN_PROJECT_SENTINEL: str = "unknown-project"
"""Slug sentinel devolvido por ``extract_project_slug`` quando nenhuma das
estratégias de resolução produziu slug. Quando ``classify_cross_project``
recebe esse valor, ativa **modo defensivo**: todos os planos/relatórios
detectados (regras a/b) vão para Grupo B com evidência ``no_context_md_defensive``.
"""

# ---------------------------------------------------------------------------
# Regex canônicos das 5 regras (a..e) + edge cases
# ---------------------------------------------------------------------------

# Regra (a1) — Plano dentro de "Planos de Implementação/" com prefixo "plano-"
_RE_PLANOS_FOLDER = re.compile(
    r"(?:^|/)Planos de Implementa[çc][ãa]o/(?:[^/]+/)*plano-(?P<slug>[^/]+)\.md$",
    re.IGNORECASE,
)

# Regra (a2) — Arquivo top-level (ou em qualquer pasta) "plano-implementacao-*.md"
_RE_PLANO_IMPL_FILE = re.compile(
    r"(?:^|/)plano-implementacao-(?P<slug>[^/]+)\.md$",
    re.IGNORECASE,
)

# Regra (a3) polish-driven — Pasta-ancestral "plano-implementacao-<slug>/<...>"
_RE_PLANO_FOLDER_ANCESTOR = re.compile(
    r"(?:^|/)plano-implementacao-(?P<slug>[^/]+)/",
    re.IGNORECASE,
)

# Regra (b1) — Relatório dentro de "Relatórios Staff/" com prefixo
_RE_RELATORIOS_FOLDER = re.compile(
    r"(?:^|/)Relat[óo]rios Staff/(?:[^/]+/)*relatorio-staff-(?P<slug>[^/]+)\.md$",
    re.IGNORECASE,
)

# Regra (b2) — Arquivo "relatorio-staff-*.md" em qualquer lugar
_RE_RELATORIO_STAFF_FILE = re.compile(
    r"(?:^|/)relatorio-staff-(?P<slug>[^/]+)\.md$",
    re.IGNORECASE,
)

# Regra (c) — Portfólio: memory/projetos.md (pt-BR) ou memory/projects.md (en)
_RE_PORTFOLIO = re.compile(
    r"(?:^|/)memory/(?:projetos|projects)\.md$",
    re.IGNORECASE,
)

# Regra (d) — Eval caches em qualquer profundidade
_RE_EVAL_CACHES = re.compile(
    r"(?:^|/)(?:\.eval-runs|_eval_runs|\.fixtures-derivation)/",
    re.IGNORECASE,
)

# Regra (e1) — audit/baseline-*.md
_RE_AUDIT_BASELINE = re.compile(
    r"(?:^|/)audit/baseline-[^/]+\.md$",
    re.IGNORECASE,
)

# Regra (e2) — diretório _baseline-*/
_RE_BASELINE_DIR = re.compile(
    r"(?:^|/)_baseline-[^/]+/",
    re.IGNORECASE,
)

# Edge cases — arquivos dentro das pastas pt-BR sem o prefixo esperado
_RE_IN_PLANOS_FOLDER = re.compile(
    r"(?:^|/)Planos de Implementa[çc][ãa]o/",
    re.IGNORECASE,
)
_RE_IN_RELATORIOS_FOLDER = re.compile(
    r"(?:^|/)Relat[óo]rios Staff/",
    re.IGNORECASE,
)

# context.md > ## Identificação > **Nome:**  (linhas variáveis entre os dois)
_RE_IDENTIFICACAO_HEADER = re.compile(
    r"##\s+Identifica[çc][ãa]o[^\n]*",
    re.IGNORECASE,
)
_RE_NOME_LINE = re.compile(
    r"\*\*Nome:\*\*\s*(?P<nome>.+)",
)
# YAML frontmatter ``slug:`` (polish-driven; case-insensitive)
_RE_YAML_SLUG = re.compile(
    r"^slug:\s*[\"']?(?P<slug>[A-Za-z0-9][A-Za-z0-9.\-_]*)[\"']?\s*$",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Estruturas de dados
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossProjectClassification:
    """Resultado canônico da classificação F1.5 para um arquivo.

    Atributos:
        path: caminho relativo (POSIX) do arquivo classificado.
        category: classificação semântica determinística.
        evidence: lista de strings em pt-BR/ASCII explicando a decisão (vai
            literal para o ``FILTER_DIFF.md`` seção F1.5).
        promoted_to: grupo final após F1.5 (A=exclude, B=review, C=incluir).
    """

    path: Path
    category: CrossCategory
    evidence: list[str] = field(default_factory=list)
    promoted_to: PromotedTo = "C"


# ---------------------------------------------------------------------------
# Slug normalization
# ---------------------------------------------------------------------------


def sanitize_slug(name: str) -> str:
    """Normaliza ``name`` em slug kebab-case ASCII (compatível com 03-Plan F-08).

    Pipeline determinístico:
      1. ``unicodedata.normalize('NFKD', name)`` + strip combining marks
         (``[NOME]`` → ``[NOME]``, ``Você`` → ``Voce``).
      2. ``.lower()``.
      3. Substitui qualquer char fora de ``[a-z0-9.-]`` por ``-``
         (preserva ``.`` para version-suffixes como ``v1.1.0``).
      4. Colapsa runs de ``-`` em um único hífen.
      5. Strip de hífens nas pontas.

    Returns:
        Slug determinístico. String vazia se ``name`` resultar vazio após
        normalização (NUNCA raise).
    """
    if not name:
        return ""
    nfkd = unicodedata.normalize("NFKD", name)
    no_accents = "".join(c for c in nfkd if not unicodedata.combining(c))
    lower = no_accents.lower()
    hyphenated = re.sub(r"[^a-z0-9.-]+", "-", lower)
    collapsed = re.sub(r"-+", "-", hyphenated)
    return collapsed.strip("-")


# ---------------------------------------------------------------------------
# Project slug extraction
# ---------------------------------------------------------------------------


def _extract_nome_from_context(content: str) -> str | None:
    """Procura ``## Identificação`` → ``**Nome:** <valor>``; devolve valor cru ou None.

    Limita a busca de ``**Nome:**`` à seção entre ``## Identificação`` e o
    próximo header ``## ...`` (evita ``**Nome:**`` em seções não-canônicas).
    """
    header = _RE_IDENTIFICACAO_HEADER.search(content)
    if not header:
        return None
    rest = content[header.end():]
    next_section = re.search(r"\n##\s", rest)
    section_text = rest[: next_section.start()] if next_section else rest
    nome_match = _RE_NOME_LINE.search(section_text)
    if not nome_match:
        return None
    raw = nome_match.group("nome").strip()
    # Remove trailing markdown noise (e.g., underscores, asterisks)
    raw = raw.rstrip(" *_")
    return raw or None


def _extract_yaml_slug(content: str) -> str | None:
    """Polish-driven: busca ``slug:`` em YAML frontmatter (top de ``context.md``).

    Limita busca ao frontmatter (entre 1ª e 2ª linha ``---`` no início).
    Devolve slug cru (já é kebab-case por convenção) ou None.
    """
    # Frontmatter precisa começar na linha 0 com `---`
    if not content.startswith("---\n") and not content.startswith("---\r\n"):
        return None
    end_marker = re.search(r"\n---\s*(?:\n|$)", content)
    if not end_marker:
        return None
    frontmatter = content[:end_marker.start()]
    m = _RE_YAML_SLUG.search(frontmatter)
    if not m:
        return None
    return m.group("slug").strip()


def extract_project_slug(
    source_path: Path,
    context_md_path: Path | None = None,
) -> str:
    """Resolve o slug canônico do projeto-fonte (3 estratégias + sentinel).

    Args:
        source_path: raiz do source-tree (``ctx.source_path`` em ``run_filter``).
        context_md_path: caminho opcional para ``context-[slug].md``. Se
            ``None`` ou inexistente, pula direto para o fallback de basename.

    Returns:
        Slug em formato kebab-case ASCII. Devolve ``UNKNOWN_PROJECT_SENTINEL``
        (``'unknown-project'``) quando nenhuma estratégia produz slug
        (defensive mode trigger no ``classify_cross_project``).

    NUNCA raise — falhas de leitura de arquivo degradam silenciosamente.
    """
    # Priority (a) — context.md > ## Identificação > **Nome:**
    if context_md_path is not None:
        try:
            if context_md_path.exists() and context_md_path.is_file():
                content = context_md_path.read_text(
                    encoding="utf-8", errors="replace",
                )
                nome = _extract_nome_from_context(content)
                if nome:
                    slug = sanitize_slug(nome)
                    if slug:
                        return slug
                # Polish-driven (b'): YAML frontmatter `slug:` direto
                yaml_slug = _extract_yaml_slug(content)
                if yaml_slug:
                    slug = sanitize_slug(yaml_slug)
                    if slug:
                        return slug
        except (OSError, UnicodeDecodeError):
            pass

    # Priority (b) — basename do source_path
    name = source_path.name if source_path is not None else ""
    if name:
        slug = sanitize_slug(name)
        if slug:
            return slug

    # Priority (c) — sentinel defensivo
    return UNKNOWN_PROJECT_SENTINEL


# ---------------------------------------------------------------------------
# Slug matching (com tolerância a version-suffix)
# ---------------------------------------------------------------------------


def _extracted_slug_matches(extracted: str, project_slug: str) -> bool:
    """Verifica se ``extracted`` pertence ao mesmo projeto que ``project_slug``.

    Casa em 2 cenários (ordem):
      1. Igualdade exata (``extracted == project_slug``).
      2. Versionado: ``extracted`` começa com ``project_slug + '-v'`` (e.g.,
         ``repo-sanitizer-agent-v1.1.0`` matcha ``repo-sanitizer-agent``).

    Não casa em nenhum outro caso (conservador — falsos-positivos no Grupo B
    permitem revisão [NOME]; falsos-negativos vazariam cross-project).
    """
    if not project_slug or not extracted:
        return False
    if extracted == project_slug:
        return True
    return bool(extracted.startswith(project_slug + "-v"))


# ---------------------------------------------------------------------------
# Classificação principal
# ---------------------------------------------------------------------------


def _build_planos_or_relatorios_classification(
    *,
    rel_path: str,
    extracted_slug_raw: str,
    project_slug: str,
    defensive_mode: bool,
    rule_label: str,
) -> CrossProjectClassification:
    """Helper compartilhado por regras (a)/(b) para construir o resultado."""
    extracted_slug = sanitize_slug(extracted_slug_raw)
    if (
        not defensive_mode
        and _extracted_slug_matches(extracted_slug, project_slug)
    ):
        return CrossProjectClassification(
            path=Path(rel_path),
            category="intra_project",
            evidence=[f"slug-match: {extracted_slug} == {project_slug}", rule_label],
            promoted_to="C",
        )
    if defensive_mode:
        ev_msg = "no_context_md_defensive"
    else:
        ev_msg = f"slug-mismatch: {extracted_slug} != {project_slug}"
    return CrossProjectClassification(
        path=Path(rel_path),
        category="cross_project",
        evidence=[ev_msg, rule_label],
        promoted_to="B",
    )


def classify_cross_project(
    file_path: Path | str,
    project_slug: str,
) -> CrossProjectClassification:
    """Aplica regras canônicas F1.5 (a..e) sobre um arquivo.

    Args:
        file_path: caminho relativo do arquivo (relativo à source-root). Aceita
            ``Path`` ou ``str``. Separadores Windows (``\\``) são normalizados
            para POSIX antes do matching.
        project_slug: slug canônico do projeto resolvido por
            ``extract_project_slug``. Use ``UNKNOWN_PROJECT_SENTINEL`` para
            ativar modo defensivo.

    Returns:
        ``CrossProjectClassification`` imutável com categoria, evidências
        em pt-BR e grupo final (A/B/C).

    Ordem de avaliação das regras (canônica; primeira que casa vence):
      1. (c) Portfólio → A
      2. (d) Eval caches → A
      3. (e1) Audit baseline file → A
      4. (e2) Baseline directory → A
      5. (a1) Planos dentro de "Planos de Implementação/" → C ou B
      6. (a2) Arquivo "plano-implementacao-*.md" → C ou B
      7. (a3) [polish] Ancestral "plano-implementacao-<slug>/" → C ou B
      8. (b1) Relatórios dentro de "Relatórios Staff/" → C ou B
      9. (b2) Arquivo "relatorio-staff-*.md" → C ou B
     10. Edge: dentro de pasta pt-BR sem prefixo → ambíguo → B
     11. Default: ``intra_project`` → C

    NUNCA raise.
    """
    rel = str(file_path).replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]

    defensive_mode = project_slug == UNKNOWN_PROJECT_SENTINEL

    # Regra (c) — Portfólio (Grupo A; independe de slug)
    if _RE_PORTFOLIO.search(rel):
        return CrossProjectClassification(
            path=Path(rel),
            category="cache",
            evidence=["portfolio_global", "rule:portfolio"],
            promoted_to="A",
        )

    # Regra (d) — Eval caches (Grupo A; independe de slug)
    if _RE_EVAL_CACHES.search(rel):
        return CrossProjectClassification(
            path=Path(rel),
            category="cache",
            evidence=["eval_runs_cache", "rule:eval_caches"],
            promoted_to="A",
        )

    # Regra (e1) — Audit baseline file (Grupo A)
    if _RE_AUDIT_BASELINE.search(rel):
        return CrossProjectClassification(
            path=Path(rel),
            category="cache",
            evidence=["audit_baseline_md", "rule:audit_baseline"],
            promoted_to="A",
        )

    # Regra (e2) — Baseline directory (Grupo A)
    if _RE_BASELINE_DIR.search(rel):
        return CrossProjectClassification(
            path=Path(rel),
            category="cache",
            evidence=["baseline_dir", "rule:baseline_dir"],
            promoted_to="A",
        )

    # Regra (a1) — Planos em "Planos de Implementação/"
    m = _RE_PLANOS_FOLDER.search(rel)
    if m:
        return _build_planos_or_relatorios_classification(
            rel_path=rel,
            extracted_slug_raw=m.group("slug"),
            project_slug=project_slug,
            defensive_mode=defensive_mode,
            rule_label="rule:planos_folder",
        )

    # Regra (a2) — "plano-implementacao-*.md" file
    m = _RE_PLANO_IMPL_FILE.search(rel)
    if m:
        return _build_planos_or_relatorios_classification(
            rel_path=rel,
            extracted_slug_raw=m.group("slug"),
            project_slug=project_slug,
            defensive_mode=defensive_mode,
            rule_label="rule:plano_implementacao_file",
        )

    # Regra (a3) polish-driven — pasta-ancestral "plano-implementacao-<slug>/"
    m = _RE_PLANO_FOLDER_ANCESTOR.search(rel)
    if m:
        return _build_planos_or_relatorios_classification(
            rel_path=rel,
            extracted_slug_raw=m.group("slug"),
            project_slug=project_slug,
            defensive_mode=defensive_mode,
            rule_label="rule:plano_implementacao_ancestor",
        )

    # Regra (b1) — Relatórios em "Relatórios Staff/"
    m = _RE_RELATORIOS_FOLDER.search(rel)
    if m:
        return _build_planos_or_relatorios_classification(
            rel_path=rel,
            extracted_slug_raw=m.group("slug"),
            project_slug=project_slug,
            defensive_mode=defensive_mode,
            rule_label="rule:relatorios_folder",
        )

    # Regra (b2) — "relatorio-staff-*.md" file
    m = _RE_RELATORIO_STAFF_FILE.search(rel)
    if m:
        return _build_planos_or_relatorios_classification(
            rel_path=rel,
            extracted_slug_raw=m.group("slug"),
            project_slug=project_slug,
            defensive_mode=defensive_mode,
            rule_label="rule:relatorio_staff_file",
        )

    # Edge case — arquivo dentro de "Planos de Implementação/" sem prefixo "plano-"
    if _RE_IN_PLANOS_FOLDER.search(rel):
        return CrossProjectClassification(
            path=Path(rel),
            category="ambiguous",
            evidence=["in_planos_folder_no_prefix", "rule:edge_planos"],
            promoted_to="B",
        )

    # Edge case — arquivo dentro de "Relatórios Staff/" sem prefixo
    if _RE_IN_RELATORIOS_FOLDER.search(rel):
        return CrossProjectClassification(
            path=Path(rel),
            category="ambiguous",
            evidence=["in_relatorios_folder_no_prefix", "rule:edge_relatorios"],
            promoted_to="B",
        )

    # Default — nenhuma regra cross-project disparou: intra_project
    return CrossProjectClassification(
        path=Path(rel),
        category="intra_project",
        evidence=["no_cross_project_pattern_matched"],
        promoted_to="C",
    )


__all__ = [
    "UNKNOWN_PROJECT_SENTINEL",
    "CrossCategory",
    "CrossProjectClassification",
    "PromotedTo",
    "classify_cross_project",
    "extract_project_slug",
    "sanitize_slug",
]
