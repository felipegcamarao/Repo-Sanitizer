"""filter_diff_writer.py — emit FILTER_DIFF_[slug]_[ts].md (ADR-005 + RS-018/RS-020).

Bloco 02 02.8. Gera o FILTER_DIFF.md em `/Relatorios/` apartir de FilterResult
(saida de `f1_filter.run_filter`). Estrutura canonica:

```
---
schema_version: "1.0.0"
agent: "repo-sanitizer-agent"
agent_version: "..."
slug: "..."
run_id: "..."
generated_at: "..."
counts:
  total: N
  group_A: N
  group_B: N
  group_C: N
  symlink_excluded: N
inv1_snapshot_aggregate_prefix: "..."
---

# FILTER_DIFF — <slug>

## Resumo
- ...

## Grupo A (lixo deterministico, excluido)
| path | motivo | tamanho |

## Grupo B (heuristica ambiguo, excluido — REVIEW)
| path | motivo | tamanho |

## Grupo C (whitelist canonica + default-include)
| path | motivo | tamanho |

## Symlinks excluidos (RS-006)
| path | tipo | detalhe |

<!-- HASH_TREE_PRE_START
{json snapshot ...}
HASH_TREE_PRE_END -->
```

INV-7: gravacao em `/Relatorios/` via FsWriter SSOT (ADR-020). Pre-write,
cada FilterDiffEntry ja foi validado Pydantic; ainda assim aplicamos
SECRET_REGEXES sobre o markdown final como camada extra (defesa em camadas).

API publica:
    build_filter_diff_md(result, slug, run_id, ...) -> str
    write_filter_diff(result, slug, run_id, fs_writer, relatorios_dir, ...) -> Path
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from repo_sanitizer import __version__
from repo_sanitizer.f1_filter import FilterResult
from repo_sanitizer.helpers._cross_project_classifier import (
    CrossProjectClassification,
)
from repo_sanitizer.schemas._secrets_gate import assert_no_literal_secrets
from repo_sanitizer.schemas.filter_diff_entry import FilterDiffEntry

if TYPE_CHECKING:
    from repo_sanitizer.helpers._fs_writer import FsWriter

HASH_TREE_BLOCK_RE = re.compile(
    r"<!-- HASH_TREE_PRE_START\n(.*?)\nHASH_TREE_PRE_END -->", re.DOTALL,
)


def _now_iso8601_compact() -> str:
    """Compact ISO 8601 sem `:` (compativel com Windows filename)."""
    return _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def _now_iso8601() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _md_table(headers: list[str], rows: Iterable[list[str]]) -> str:
    """Renderiza tabela markdown simples."""
    if not headers:
        return ""
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        # Escapa pipes em conteudo
        escaped = [str(c).replace("|", "\\|") for c in r]
        out.append("| " + " | ".join(escaped) + " |")
    return "\n".join(out)


def _entries_by_group(entries: list[FilterDiffEntry], grupo: str) -> list[FilterDiffEntry]:
    return [e for e in entries if e.grupo == grupo]


def _sort_entries_by_path(entries: list[FilterDiffEntry]) -> list[FilterDiffEntry]:
    return sorted(entries, key=lambda e: e.path_redacted)


def build_filter_diff_md(
    result: FilterResult,
    *,
    slug: str,
    run_id: str,
    source_path_redacted: str,
    dest_path_redacted: str,
    agent_version: str = __version__,
) -> str:
    """Renderiza FILTER_DIFF.md canonico apartir de FilterResult."""
    total = len(result.entries)
    counts = {
        "total": total,
        "group_A": result.counts_by_group.get("A", 0),
        "group_B": result.counts_by_group.get("B", 0),
        "group_C": result.counts_by_group.get("C", 0),
        "symlink_excluded": result.counts_by_acao.get("symlink_excluded", 0),
        "incluir": result.counts_by_acao.get("incluir", 0),
        "excluir": result.counts_by_acao.get("excluir", 0),
    }
    snap_prefix = (result.snapshot_pre.get("aggregate", "")[:16]) if result.snapshot_pre else ""
    file_count_pre = result.snapshot_pre.get("file_count", 0)

    # Bloco 03 — F1.5 counts (default zeros se chamado por caller v1.0.x)
    f1_5_counts = result.f1_5_counts or {
        "cross_project_to_B": 0,
        "ambiguous_to_B": 0,
        "cache_to_A": 0,
        "intra_project_kept_C": 0,
    }

    # YAML header (front-matter); evita PyYAML para nao adicionar dep
    header_lines = [
        "---",
        'schema_version: "1.0.0"',
        'agent: "repo-sanitizer-agent"',
        f'agent_version: "{agent_version}"',
        f'slug: "{slug}"',
        f'run_id: "{run_id}"',
        f'generated_at: "{_now_iso8601()}"',
        f'source_path_redacted: "{source_path_redacted}"',
        f'dest_path_redacted: "{dest_path_redacted}"',
        f'project_slug_resolved: "{result.project_slug}"',
        "counts:",
        f"  total: {counts['total']}",
        f"  group_A: {counts['group_A']}",
        f"  group_B: {counts['group_B']}",
        f"  group_C: {counts['group_C']}",
        f"  symlink_excluded: {counts['symlink_excluded']}",
        f"  incluir: {counts['incluir']}",
        f"  excluir: {counts['excluir']}",
        "f1_5_counts:",
        f"  cross_project_to_B: {f1_5_counts.get('cross_project_to_B', 0)}",
        f"  ambiguous_to_B: {f1_5_counts.get('ambiguous_to_B', 0)}",
        f"  cache_to_A: {f1_5_counts.get('cache_to_A', 0)}",
        f"  intra_project_kept_C: {f1_5_counts.get('intra_project_kept_C', 0)}",
        f'inv1_snapshot_aggregate_prefix: "{snap_prefix}"',
        f"inv1_snapshot_file_count: {file_count_pre}",
        f"grupo_b_excedeu_threshold: {str(result.grupo_b_excedeu_threshold).lower()}",
        f"grupo_b_review_threshold: {result.review_threshold}",
        "---",
        "",
    ]
    header = "\n".join(header_lines)

    body_lines = [
        f"# FILTER_DIFF — {slug}",
        "",
        "> F1 Filter (Pipeline A+ v4.1.x). Este e um relatorio dry-run; "
        "**nada foi escrito no destino ainda**. Revise antes de `/sanitize-apply`.",
        "",
        "## Resumo",
        "",
        f"- Total de arquivos walked: **{counts['total']}**",
        f"- Grupo A (lixo deterministico, excluir): **{counts['group_A']}**",
        f"- Grupo B (ambiguo, excluir + REVIEW): **{counts['group_B']}**",
        f"- Grupo C (whitelist + default-include): **{counts['group_C']}**",
        f"- Symlinks/junctions/hardlinks excluidos (RS-006): **{counts['symlink_excluded']}**",
        f"- Acao final: incluir={counts['incluir']} | excluir={counts['excluir']}",
        f"- Snapshot SHA-256 fonte (RS-002 INV-1 gate): `{snap_prefix}...` "
        f"({file_count_pre} arquivos)",
        "",
    ]
    if result.grupo_b_excedeu_threshold:
        body_lines.extend([
            "> ⚠️ **Grupo B excedeu threshold de revisao "
            f"(>{result.review_threshold} arquivos).** "
            "Revise manualmente cada item da secao 'Grupo B' antes do "
            "`/sanitize-apply`.",
            "",
        ])

    # Grupo A
    grupo_a = _sort_entries_by_path(_entries_by_group(result.entries, "A"))
    body_lines.append("## Grupo A — lixo deterministico (excluir)")
    body_lines.append("")
    if grupo_a:
        rows = [[e.path_redacted, e.motivo, str(e.size_bytes)] for e in grupo_a
                if e.acao == "excluir"]
        if rows:
            body_lines.append(_md_table(["path", "motivo", "tamanho_bytes"], rows))
        else:
            body_lines.append("_(nenhum)_")
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    # Grupo B
    grupo_b = _sort_entries_by_path(_entries_by_group(result.entries, "B"))
    body_lines.append("## Grupo B — heuristica ambiguo (excluir + REVIEW)")
    body_lines.append("")
    if grupo_b:
        rows = [[e.path_redacted, e.grupo_reason_detail or e.motivo, str(e.size_bytes)]
                for e in grupo_b]
        body_lines.append(_md_table(["path", "motivo_heuristica", "tamanho_bytes"], rows))
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    # Grupo C
    grupo_c = _sort_entries_by_path(_entries_by_group(result.entries, "C"))
    body_lines.append("## Grupo C — whitelist canonica + default-include (incluir)")
    body_lines.append("")
    if grupo_c:
        rows = [[e.path_redacted, e.motivo, str(e.size_bytes), str(e.is_binary).lower()]
                for e in grupo_c]
        body_lines.append(_md_table(
            ["path", "motivo", "tamanho_bytes", "binary"], rows,
        ))
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    # Symlinks excluidos (RS-006)
    body_lines.append("## Symlinks/junctions/hardlinks excluidos (RS-006)")
    body_lines.append("")
    if result.symlink_excluded:
        rows = [[e.path_redacted, e.motivo, str(e.size_bytes)]
                for e in _sort_entries_by_path(result.symlink_excluded)]
        body_lines.append(_md_table(["path", "motivo", "tamanho_bytes"], rows))
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    # Camada F1.5 — Cross-Project Detection (ADR-031 / RS-NEW-033 / Bloco 03)
    body_lines.append("## Camada F1.5 — Cross-Project Detection")
    body_lines.append("")
    body_lines.append(
        f"> Heuristica semantica sobre nomes de pastas/arquivos. "
        f"Slug do projeto resolvido: `{result.project_slug or 'unknown-project'}` "
        f"(via context-*.md > Identificacao | YAML slug | basename | sentinel)."
    )
    body_lines.append("")
    body_lines.append(
        f"- Cross-project promovidos para Grupo B: **{f1_5_counts.get('cross_project_to_B', 0)}**"
    )
    body_lines.append(
        f"- Ambiguos promovidos para Grupo B: **{f1_5_counts.get('ambiguous_to_B', 0)}**"
    )
    body_lines.append(
        f"- Caches promovidos para Grupo A: **{f1_5_counts.get('cache_to_A', 0)}**"
    )
    body_lines.append(
        f"- Intra-project mantidos em Grupo C: **{f1_5_counts.get('intra_project_kept_C', 0)}**"
    )
    body_lines.append("")

    classifications = list(result.cross_project_classifications or [])
    cross_rows = sorted(
        [c for c in classifications if c.category == "cross_project"],
        key=lambda c: str(c.path),
    )
    ambig_rows = sorted(
        [c for c in classifications if c.category == "ambiguous"],
        key=lambda c: str(c.path),
    )
    cache_rows = sorted(
        [c for c in classifications if c.category == "cache"],
        key=lambda c: str(c.path),
    )

    def _evidence_short(c: CrossProjectClassification) -> str:
        joined = "; ".join(c.evidence)
        return joined[:97] + "..." if len(joined) > 100 else joined

    body_lines.append("### Cross-project (Grupo B — review)")
    body_lines.append("")
    if cross_rows:
        rows = [
            [str(c.path), c.category, _evidence_short(c), c.promoted_to]
            for c in cross_rows
        ]
        body_lines.append(
            _md_table(["path", "category", "evidence", "promoted_to"], rows),
        )
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    body_lines.append("### Cache (Grupo A — exclude)")
    body_lines.append("")
    if cache_rows:
        rows = [
            [str(c.path), c.category, _evidence_short(c), c.promoted_to]
            for c in cache_rows
        ]
        body_lines.append(
            _md_table(["path", "category", "evidence", "promoted_to"], rows),
        )
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    body_lines.append("### Ambiguos (Grupo B — review defensivo)")
    body_lines.append("")
    if ambig_rows:
        rows = [
            [str(c.path), c.category, _evidence_short(c), c.promoted_to]
            for c in ambig_rows
        ]
        body_lines.append(
            _md_table(["path", "category", "evidence", "promoted_to"], rows),
        )
    else:
        body_lines.append("_(nenhum)_")
    body_lines.append("")

    # Hash-tree pre snapshot (oculto via comentario HTML; ADR-025)
    snap_minimal = {
        "root": result.snapshot_pre.get("root", ""),
        "aggregate": result.snapshot_pre.get("aggregate", ""),
        "file_count": result.snapshot_pre.get("file_count", 0),
        # NAO grava `entries` na secao oculta para nao explodir o markdown;
        # o gate RS-016 race detection verifica apenas `aggregate` que ja esta no header.
    }
    body_lines.extend([
        "<!-- HASH_TREE_PRE_START",
        json.dumps(snap_minimal, indent=2, ensure_ascii=False),
        "HASH_TREE_PRE_END -->",
        "",
    ])

    md = header + "\n".join(body_lines)

    # Defesa em camadas (ADR-024): SECRET_REGEXES sobre o markdown final.
    assert_no_literal_secrets(md)
    return md


def filter_diff_filename(slug: str, run_id_prefix: str | None = None) -> str:
    """Nome canonico: FILTER_DIFF_<slug>_<YYYYMMDDTHHMMSSZ>[_<run_id_prefix>].md"""
    ts = _now_iso8601_compact()
    if run_id_prefix:
        return f"FILTER_DIFF_{slug}_{ts}_{run_id_prefix}.md"
    return f"FILTER_DIFF_{slug}_{ts}.md"


def write_filter_diff(
    result: FilterResult,
    *,
    slug: str,
    run_id: str,
    fs_writer: FsWriter,
    relatorios_dir: Path,
    source_path_redacted: str,
    dest_path_redacted: str,
    agent_version: str = __version__,
) -> Path:
    """Renderiza + grava FILTER_DIFF.md via FsWriter (ADR-020 boundary).

    Returns: path absoluto do arquivo escrito.
    """
    md = build_filter_diff_md(
        result,
        slug=slug,
        run_id=run_id,
        source_path_redacted=source_path_redacted,
        dest_path_redacted=dest_path_redacted,
        agent_version=agent_version,
    )
    fname = filter_diff_filename(slug, run_id_prefix=run_id[:8])
    dest = Path(relatorios_dir) / fname
    return fs_writer.safe_write_text(dest, md)


def extract_hash_tree_snapshot(filter_diff_md: str) -> dict[str, Any] | None:
    """Extrai snapshot minimal embedded em FILTER_DIFF.md (race-detection gate).

    Returns dict `{root, aggregate, file_count}` ou None se ausente.
    """
    m = HASH_TREE_BLOCK_RE.search(filter_diff_md)
    if not m:
        return None
    try:
        parsed: dict[str, Any] = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return parsed


__all__ = [
    "build_filter_diff_md",
    "extract_hash_tree_snapshot",
    "filter_diff_filename",
    "write_filter_diff",
]
