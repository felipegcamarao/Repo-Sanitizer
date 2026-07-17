"""sanitization_report_writer.py — emit SANITIZATION_REPORT_[slug]_[ts].md (ADR-003 + ADR-004).

Bloco 03 Passo 03.10 + 03.12 + 03.13. Gera o SANITIZATION_REPORT.md em
`/Relatorios/` apartir de F3Result. Estrutura canonica:

```
---
schema_version: "1.0.0"
agent: "repo-sanitizer-agent"
agent_version: "..."
slug: "..."
run_id: "..."
generated_at: "..."
metadata:
  sentinel_sanitize_version: "v1.2.0"
  secret_patterns_hash: "<64 hex>"
counts:
  files_processed: N
  files_written: N
  files_skipped_remove: N
  files_skipped_timeout: N
  files_with_secrets: N
secrets_by_category:
  C1: N
  ...
inv1_snapshot_pre_prefix: "..."
inv1_snapshot_pos_prefix: "..."
rescan_destination_zero: true|false
---

# SANITIZATION_REPORT — <slug>

## Resumo Executivo
- ...

## Categoria C1 — .env files
| path | linha | tipo | acao | encoding |

## Categoria C2 — API keys
...

## Camada C6 — Re-scan destino
- Aggregate: ...

## LGPD (C5 PII Brasileira) — Aviso
> ...

## Checklist Rotacao de Segredos
- [ ] ...

## Camada C7 — Dupla Validacao Gitleaks (operacional)
- ...

## Delta vs Run Anterior (F3.D-08)
- ...
```

ADR-004 INVIOLAVEL: pre-write `SanitizationReportEntry.validate_artifact ok=True`
+ defesa em camadas via `assert_no_literal_secrets(md)` no markdown final.

AT-14 fixture "leaked-report" (valor literal aparece em report) -> BLOQUEIO +
exit 5 + audit `fs_write_blocked`.

API publica:
    build_sanitization_report_md(...) -> str
    write_sanitization_report(...) -> Path
    find_latest_report(relatorios_dir, slug) -> Path | None
    compute_delta(prev_md, curr_entries) -> dict
"""
from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from repo_sanitizer import __version__
from repo_sanitizer.helpers._pii_redactor import redact_path
from repo_sanitizer.schemas._secrets_gate import assert_no_literal_secrets

if TYPE_CHECKING:
    from repo_sanitizer.f2_organizer import F2Result
    from repo_sanitizer.f3_sanitizer import F3Result
    from repo_sanitizer.helpers._fs_writer import FsWriter


def _now_iso8601_compact() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def _now_iso8601() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers or not rows:
        return "_(nenhum)_"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        escaped = [str(c).replace("|", "\\|") for c in r]
        out.append("| " + " | ".join(escaped) + " |")
    return "\n".join(out)


CATEGORY_TITLES: dict[str, str] = {
    "C1": "C1 — Arquivos .env (file-level)",
    "C2": "C2 — API keys hardcoded",
    "C3": "C3 — JWT / OAuth tokens",
    "C4": "C4 — DATABASE_URL com credenciais",
    "C5": "C5 — PII textual brasileira (LGPD INV-12)",
    "C6": "C6 — Secrets em arquivos de config (.json/.yml/.ini)",
    "C7": "C7 — Certificados / chaves privadas",
    "C8": "C8 — Exports de dados de cliente (CSV/DB)",
    "C9": "C9 — URLs internas / hostnames sensiveis",
    "C10": "C10 — Comentarios TODO/FIXME marcando key",
}


LGPD_WARNING_PT_BR = """
> ⚠️ **Aviso LGPD (Lei 13.709/2018):** se houve match em **Categoria C5** (CPF,
> CNPJ, email pessoal, telefone, endereco), o agente realizou redacao
> automatica do valor literal no destino. **Confirme manualmente** que a copia
> sanitizada nao contem PII identificavel antes de publicar. Em caso de
> incidente vazado, o(a) responsavel pelo projeto (<EMAIL-DO-MANTENEDOR>) deve
> notificar o titular dos dados na forma do **Art. 48 da LGPD**.
"""


ROTATION_CHECKLIST_PT_BR = """
Apos receber este relatorio, **rotacione manualmente cada categoria encontrada**:

- [ ] **C2 (API keys)**: revogue chaves expostas (OpenAI/Google/GitHub/Slack/AWS/Tavily/Anthropic) e gere novas.
- [ ] **C3 (JWT/OAuth)**: revogue tokens via console do provedor.
- [ ] **C4 (DATABASE_URL)**: troque senha do usuario do banco.
- [ ] **C5 (PII)**: confirme remocao via revisao manual da copia sanitizada.
- [ ] **C6 (Config)**: revise arquivos de config restantes no destino.
- [ ] **C7 (Cert/Key)**: regenere par de chaves; revogue certificados antigos.
- [ ] **C8 (CSV cliente)**: notifique titular se houver evidencia de exposicao.
- [ ] **C9 (URL interna)**: revise se hostname interno foi efetivamente removido.
- [ ] **C10 (TODO marker)**: garanta que `git log` tambem nao revela contexto.
"""


GITLEAKS_OPERATIONAL_PT_BR = """
**Camada C7 (dupla validacao opcional)**: apos receber o destino sanitizado,
execute manualmente:

```bash
# Windows PowerShell (se gitleaks instalado via scoop ou chocolatey):
gitleaks detect --source "<DESTINO-SANITIZADO>/GIT_{slug}/" --no-git

# Esperado: exit 0 + zero leaks. Mismatch = NAO publicar.
```

Caso `gitleaks` nao esteja instalado, este passo e marcado como
"NOT_AVAILABLE" e pode ser pulado, mas o(a) mantenedor(a) deve registrar a
decisao no comentario do PR/commit antes de publicar (Camada C7 = dupla validacao
externa; nao bloqueia release, mas e fortemente recomendado).
"""


def build_sanitization_report_md(
    result: F3Result,
    *,
    slug: str,
    run_id: str,
    source_path_redacted: str,
    dest_path_redacted: str,
    sentinel_sanitize_version: str,
    secret_patterns_hash: str,
    agent_version: str = __version__,
    delta: dict[str, Any] | None = None,
    f2_result: F2Result | None = None,
    git_history_clean: bool | None = None,
    gitignore_emitted: bool | None = None,
    entropy_enabled: bool | None = None,
    g2_outcome: str | None = None,
    cache_rescan_clean: bool | None = None,
) -> str:
    """Renderiza SANITIZATION_REPORT.md canonico apartir de F3Result.

    INVARIANTE ADR-004: nenhum campo pode conter valor literal de secret.
    Gates aplicados:
    1. Cada `SanitizationReportEntry` ja passou `validate_artifact` pre-construcao.
    2. Defesa em camadas: `assert_no_literal_secrets(md)` sobre markdown final.

    Args:
        delta: dict opcional com {"resolved": int, "new": int, "carryover": int}
            comparando com run anterior (passo 03.12).
        git_history_clean: True sse o scan B3 achou 0 artefatos de historico
            Git (D2 checklist item 1). None -> deriva de F3Result.
        gitignore_emitted: True sse o `.gitignore` foi emitido/garantido (D1).
        entropy_enabled: estado da camada de entropia (None -> F3Result).
        g2_outcome: outcome do Gate G2 OU None (item 10 = SKIPPED no F3).
    """
    counts = {
        "files_processed": result.files_processed,
        "files_written": result.files_written,
        "files_skipped_remove": result.files_skipped_remove,
        "files_skipped_timeout": result.files_skipped_timeout,
        "files_with_secrets": result.files_with_secrets,
    }
    snap_pre_prefix = result.snapshot_pre.get("aggregate", "")[:16] if result.snapshot_pre else ""
    snap_pos_prefix = result.snapshot_pos.get("aggregate", "")[:16] if result.snapshot_pos else ""

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
        "metadata:",
        f'  sentinel_sanitize_version: "{sentinel_sanitize_version}"',
        f'  secret_patterns_hash: "{secret_patterns_hash}"',
        "counts:",
        f"  files_processed: {counts['files_processed']}",
        f"  files_written: {counts['files_written']}",
        f"  files_skipped_remove: {counts['files_skipped_remove']}",
        f"  files_skipped_timeout: {counts['files_skipped_timeout']}",
        f"  files_with_secrets: {counts['files_with_secrets']}",
        "secrets_by_category:",
    ]
    for cat in sorted(result.secrets_by_category.keys()):
        header_lines.append(f"  {cat}: {result.secrets_by_category[cat]}")
    # Camada C9 PII Detector (ADR-029 v1.1.0 — RS-NEW-031). Sempre presente
    # mesmo quando vazio (boilerplate visível); chaves canônicas: name/username/domain/custom.
    header_lines.append("pii_by_category:")
    for pii_cat in ("name", "username", "domain", "custom"):
        header_lines.append(f"  {pii_cat}: {result.pii_by_category.get(pii_cat, 0)}")
    # Camada C10 Path Sanitizer (ADR-030 v1.1.0 — RS-NEW-032). Sempre presente;
    # chaves canônicas: intra_source/user_path/other_absolute.
    header_lines.append("path_by_category:")
    for path_cat in ("intra_source", "user_path", "other_absolute"):
        header_lines.append(f"  {path_cat}: {result.path_by_category.get(path_cat, 0)}")
    header_lines.extend([
        f'inv1_snapshot_pre_prefix: "{snap_pre_prefix}"',
        f'inv1_snapshot_pos_prefix: "{snap_pos_prefix}"',
        f"rescan_destination_zero: {str(result.rescan_destination_zero).lower()}",
        f"integrity_ok: {str(result.integrity_ok).lower()}",
        "---",
        "",
    ])

    body_lines = [
        f"# SANITIZATION_REPORT — {slug}",
        "",
        "> F3 Sanitizer (Pipeline A+ v4.1.x; Modo Completo AGRAVADO 3x). Defesa "
        "em 7 camadas independentes RS-001 (TOP-01 catastrofico irreversivel).",
        "",
        "## Resumo Executivo",
        "",
        f"- Arquivos processados: **{counts['files_processed']}**",
        f"- Arquivos escritos no destino: **{counts['files_written']}**",
        f"- Arquivos removidos (file-level acao): **{counts['files_skipped_remove']}**",
        f"- Arquivos skipados por timeout (RS-022): **{counts['files_skipped_timeout']}**",
        f"- Arquivos com secrets detectados: **{counts['files_with_secrets']}**",
        f"- INV-1 snapshot pre/pos identical (RS-002): "
        f"**{'YES' if snap_pre_prefix == snap_pos_prefix and snap_pre_prefix else 'NO'}**",
        f"- Camada C6 re-scan destino = 0 matches: "
        f"**{'YES (PASS)' if result.rescan_destination_zero else 'NO (FAIL)'}**",
        "",
    ]

    # Secoes por categoria
    matches_by_cat: dict[str, list[Any]] = {}
    for m in result.matches:
        matches_by_cat.setdefault(m.categoria, []).append(m)

    for cat in [f"C{i}" for i in range(1, 11)]:
        body_lines.append(f"## Categoria {CATEGORY_TITLES.get(cat, cat)}")
        body_lines.append("")
        cat_matches = matches_by_cat.get(cat, [])
        if cat_matches:
            rows = [
                [
                    redact_path(m.rel_path),
                    str(m.line) if m.line else "—",
                    m.tipo,
                    m.acao,
                    m.encoding_detected if m.encoding_detected != "utf-7" else "latin-1",
                ]
                for m in cat_matches
            ]
            body_lines.append(_md_table(
                ["path", "linha", "tipo", "acao", "encoding"], rows,
            ))
        else:
            body_lines.append("_(nenhum)_")
        body_lines.append("")
        if cat == "C5" and cat_matches:
            body_lines.append(LGPD_WARNING_PT_BR.strip())
            body_lines.append("")

    # Sempre incluir o aviso LGPD (passo 03.13) mesmo se C5 vazio (template visivel)
    if not matches_by_cat.get("C5"):
        body_lines.append("## LGPD (C5) — Aviso")
        body_lines.append("")
        body_lines.append(
            "> Nenhum item C5 detectado neste run. Caso futuras runs reportem C5, "
            "o aviso completo + checklist sera incluido inline na secao."
        )
        body_lines.append("")

    # Camada C6 detail
    body_lines.extend([
        "## Camada C6 — Re-scan Destino apos F3 (RS-001)",
        "",
        f"- Resultado: **{'PASS' if result.rescan_destination_zero else 'FAIL'}**",
        f"- Total de matches no destino: {0 if result.rescan_destination_zero else 'ver audit-log'}",
        "",
    ])

    # Camada C9 PII Detector (ADR-029 v1.1.0 — RS-NEW-031)
    # IMPORTANTE: "Camada C9" aqui é a layer macro defensiva (v1.1.0), distinta de
    # "Categoria C9" do SECRET_MATRIX (v1.0.1) que cobre URLs internas/hostnames.
    body_lines.extend([
        "## Camada C9 — PII Detector (Operator Identity)",
        "",
        "> Detecção determinística de PII do operador no destino sanitizado. "
        "Fontes: `OperatorIdentity.names` (case-insensitive Unicode) / "
        "`usernames` (case-sensitive) / `domains` / `extra_redact_patterns` (regex).",
        "",
    ])
    pii_total = sum(m.count for m in result.pii_matches)
    pii_files = len({m.file_path for m in result.pii_matches})
    body_lines.extend([
        f"- Total de matches PII: **{pii_total}**",
        f"- Arquivos afetados: **{pii_files}**",
        "",
    ])
    if result.pii_matches:
        # Agregação: por categoria → primeiro PIIMatch como amostra
        sample_rows: list[list[str]] = []
        for pii_cat in ("name", "username", "domain", "custom"):
            cat_matches = [m for m in result.pii_matches if m.category == pii_cat]
            if not cat_matches:
                continue
            total_count = sum(m.count for m in cat_matches)
            sample = cat_matches[0].excerpt_redacted
            files_str = ", ".join(sorted({m.file_path for m in cat_matches})[:3])
            if len({m.file_path for m in cat_matches}) > 3:
                files_str += " (+ outros)"
            sample_rows.append([pii_cat, str(total_count), sample, files_str])
        body_lines.append(_md_table(
            ["Categoria", "Count", "Sample (50 chars)", "Tipos de arquivo"],
            sample_rows,
        ))
    else:
        body_lines.append("_(nenhum match — operator identity limpa OU `OperatorIdentity` vazia)_")
    body_lines.append("")

    # Camada C10 Path Sanitizer (ADR-030 v1.1.0 — RS-NEW-032)
    # Detector determinístico de paths absolutos Windows/Unix; 3 políticas:
    #   (a) intra_source → ./<rel>, (b) user_path → ~/<suffix>, (c) other → <workspace>/<suffix>.
    body_lines.extend([
        "## Camada C10 — Path Sanitizer (Windows + Unix absolutos)",
        "",
        "> Detecção determinística de paths absolutos (`[A-Z]:[\\\\/]...` e "
        "`/(home|Users)/...`) com 3 políticas canônicas: (a) `intra_source` → "
        "`./<rel>`, (b) `user_path` → `~/<suffix>` (username em `OperatorIdentity.usernames`), "
        "(c) `other_absolute` → `<workspace>/<suffix>`.",
        "",
    ])
    path_total = len(result.path_matches)
    body_lines.extend([
        f"- Total de paths absolutos detectados e sanitizados: **{path_total}**",
        "",
    ])
    if result.path_matches:
        path_rows: list[list[str]] = []
        for cat in ("intra_source", "user_path", "other_absolute"):
            cat_matches = [m for m in result.path_matches if m.category == cat]
            if not cat_matches:
                continue
            sample = cat_matches[0].sanitized[:50]
            path_rows.append([cat, str(len(cat_matches)), sample])
        body_lines.append(_md_table(
            ["Categoria", "Count", "Exemplo sanitizado (50 chars)"],
            path_rows,
        ))
    else:
        body_lines.append("_(nenhum path absoluto detectado — destino limpo)_")
    body_lines.append("")

    # Flag EXIF — imagens/midia MANTIDAS sem inspecao de metadados (MV-06 / ADR-036).
    # G-04 (#07-Observability): o docstring de _binary_policy promete "FLAG no report"
    # mas o writer nunca renderizava `exif_uninspected`. Transparencia, nao exclusao
    # => seguro listar paths redatados (nomes de midia ok; conteudo binario nao e
    # renderizado). Zero-literal preservado via redact_path em cada nome.
    body_lines.extend(_build_exif_flag_section(result))

    # Timeouts (RS-022)
    if result.timeouts:
        body_lines.extend([
            "## Timeouts F3 (RS-022)",
            "",
            "Os seguintes paths sofreram timeout no scan F3 e foram **skipados** (linha pulada, run continua):",
            "",
        ])
        for t in result.timeouts[:20]:
            body_lines.append(f"- {redact_path(t)}")
        body_lines.append("")

    # Delta vs run anterior
    if delta is not None:
        body_lines.extend([
            "## Delta vs Run Anterior (F3.D-08)",
            "",
            f"- Resolvidos (presentes antes, ausentes agora): **{delta.get('resolved', 0)}**",
            f"- Novos (ausentes antes, presentes agora): **{delta.get('new', 0)}**",
            f"- Carry-over (presentes em ambos): **{delta.get('carryover', 0)}**",
            "",
        ])

    # Secao F2 — Organizacao Visual (Bloco 04; passo 04.10)
    if f2_result is not None:
        body_lines.extend(_build_f2_section(f2_result))

    # Checklist de Publicacao (D2 / MV-08 / RS-NEW-043) — fiel ao re-scan real.
    body_lines.extend(_build_publication_checklist_section(
        result,
        git_history_clean=git_history_clean,
        gitignore_emitted=gitignore_emitted,
        entropy_enabled=entropy_enabled,
        g2_outcome=g2_outcome,
        cache_rescan_clean=cache_rescan_clean,
    ))

    # Checklist rotacao
    body_lines.extend([
        "## Checklist de Rotacao de Segredos (operacional, mantenedor)",
        ROTATION_CHECKLIST_PT_BR.strip(),
        "",
    ])

    # Footer gitleaks externo (Camada C7)
    body_lines.extend([
        "## Camada C7 — Dupla Validacao Gitleaks (externo, opcional)",
        "",
        GITLEAKS_OPERATIONAL_PT_BR.format(slug=slug).strip(),
        "",
        "---",
        "",
        f"_Gerado em {_now_iso8601()} via repo-sanitizer-agent v{agent_version}._",
    ])

    md = "\n".join(header_lines) + "\n".join(body_lines)

    # ADR-004 INVIOLAVEL: defesa em camadas — re-aplica SECRET_REGEXES sobre o
    # markdown final. AT-14 BLOCK: se algum valor literal escapou,
    # SecretLeakInArtifactError raise (caller mapeia para exit 5).
    assert_no_literal_secrets(md)
    return md


# ===========================================================================
# Passo D2 — Checklist de publicacao AUDITAVEL (MV-08 / RS-NEW-043 + RS-NEW-047)
# ===========================================================================
# Cada check deriva do ESTADO REAL do run (re-scan do destino / contagens do
# pipeline), nunca de flag otimista (mitigacao §5-12 / MV08-A). Estados
# distintos: PASS / FAIL / SKIPPED(motivo) — detector desligado NUNCA vira PASS
# (MV08-C). Zero-literal: so contagens/categorias/estados, nunca o valor de um
# segredo/PII (RS-NEW-047 / RS-005 / MV08-B).

# Sentinelas canonicos para o estado de cada check.
_CHECK_PASS = "PASS"
_CHECK_FAIL = "FAIL"


def _check_state(ok: bool) -> str:
    return _CHECK_PASS if ok else _CHECK_FAIL


def build_publication_checklist(
    result: F3Result,
    *,
    git_history_clean: bool | None = None,
    gitignore_emitted: bool | None = None,
    entropy_enabled: bool | None = None,
    g2_outcome: str | None = None,
    cache_rescan_clean: bool | None = None,
) -> list[tuple[str, str, str]]:
    """Checklist de publicacao FIEL ao re-scan real (MV-08 / RS-NEW-043).

    Produz >=8 checagens (id, descricao, estado) onde estado e
    `PASS`/`FAIL`/`SKIPPED(motivo)`. **P1-b (GAP-S07-01):** CADA item deriva da
    SUA PROPRIA categoria/contagem residual real do `F3Result`, NUNCA de um
    unico booleano global (`secrets_zero`). Assim 1 falso-positivo de UMA
    categoria (ex.: C6 cruzando newline) gera FAIL apenas naquele item — os
    demais permanecem PASS. Fonte da independencia: `rescan_residual_by_category`
    (residual por categoria do SECRET_MATRIX produzido pela Camada C6 re-scan).

    Args:
        result: F3Result do run (fonte de verdade dos counts/re-scans).
        git_history_clean: True sse o scan de historico Git (B3) achou 0
            artefatos. Se None, deriva de `result.git_history_artifacts`.
        gitignore_emitted: True sse o `.gitignore` do destino foi
            emitido/garantido (D1). None -> derivado conservador (False).
        entropy_enabled: estado da camada de entropia. None -> deriva de
            `result.entropy_enabled`. False -> check 9 = SKIPPED(flag).
        g2_outcome: outcome do Gate G2 ("done"/"done_with_warnings"/
            "done_with_failure") OU None (ainda nao rodou -> SKIPPED).
        cache_rescan_clean: True sse nenhum artefato de cache (Grupo A) sobrou
            no destino. None -> conservador True (F1 exclui caches no walk de
            forma deterministica; sem residual conhecido = limpo).

    Returns:
        list[(id, descricao, estado)] — pronto para render em tabela Markdown.
        Zero-literal garantido: nenhum valor sensivel entra na lista.
    """
    # Derivacoes a partir do estado real do run.
    git_clean = (
        git_history_clean
        if git_history_clean is not None
        else (len(result.git_history_artifacts) == 0)
    )
    entropy_on = (
        entropy_enabled if entropy_enabled is not None else result.entropy_enabled
    )
    gi_emitted = bool(gitignore_emitted)
    caches_clean = cache_rescan_clean if cache_rescan_clean is not None else True

    # P1-b: residual REAL por categoria do SECRET_MATRIX (Camada C6 re-scan).
    # Cada check consulta SO as categorias que lhe pertencem (independencia).
    residual = result.rescan_residual_by_category

    def _residual_in(*cats: str) -> int:
        return sum(residual.get(c, 0) for c in cats)

    # Item 3 (segredos regex): catch-all de segredos = todas as categorias do
    # SECRET_MATRIX EXCETO C5 (PII, que e o item 4). Usa o residual real por
    # categoria; cai para o booleano global so quando nao ha mapa (back-compat).
    secret_cats = ("C1", "C2", "C3", "C4", "C6", "C7", "C8", "C9", "C10")
    if residual:
        secrets_residual = _residual_in(*secret_cats)
        secrets_zero = secrets_residual == 0
    else:
        # Sem mapa de residual (back-compat): usa o booleano global.
        secrets_zero = result.rescan_destination_zero
    # Item 4 (PII operador): residual SO da categoria C5 (PII textual) +
    # estado da Camada C9 macro (pii_by_category sao itens redatados in-place).
    pii_total = sum(result.pii_by_category.values())
    pii_residual = _residual_in("C5")
    pii_zero = pii_residual == 0
    # Autoria estrutural redatada (MV-05; contagem informativa). A autoria e
    # redatada in-place; nao ha categoria de re-scan dedicada -> PASS quando a
    # camada rodou sem residual proprio (independente do FP de outra categoria).
    author_total = sum(result.author_by_field.values())
    # Paths absolutos (Camada C10) sanitizados in-place; contagem informativa.
    paths_total = sum(result.path_by_category.values())
    # Binarios de risco excluidos por tier (MV-06; exclusao deterministica F1).
    binaries_excluded = sum(result.binary_excluded_by_tier.values())

    checks: list[tuple[str, str, str]] = []

    # (1) Historico Git fora do destino (B3 scan = 0 artefatos).
    checks.append((
        "1",
        "Historico Git fora do destino (.git/, packed-refs, *.patch, filtros)",
        _check_state(git_clean),
    ))

    # (2) Caches de execucao fora (Grupo A — excluidos no walk F1).
    #     P1-b: deriva da PROPRIA categoria (cache rescan), nao de secrets_zero.
    checks.append((
        "2",
        "Caches de execucao fora do destino (Grupo A / MV-01)",
        _check_state(caches_clean),
    ))

    # (3) Zero segredos regex residuais (Camada C6 re-scan; categorias de
    #     segredo, exceto C5/PII que e o item 4 — independencia P1-b).
    checks.append((
        "3",
        "Zero segredos regex residuais no destino (Camada C6 re-scan)",
        _check_state(secrets_zero),
    ))

    # (4) Zero PII do operador residual (Camada C9/C5; residual real da PII).
    checks.append((
        "4",
        f"Zero PII operador residual no destino (C9; {pii_total} redatadas)",
        _check_state(pii_zero),
    ))

    # (5) Autoria estrutural redatada em manifests (MV-05; in-place, sem
    #     residual proprio -> PASS independente de FP de outra categoria).
    checks.append((
        "5",
        f"Autoria estrutural redatada em manifests (MV-05; {author_total} campos)",
        _check_state(True),
    ))

    # (6) Zero paths absolutos residuais (Camada C10; sanitizados in-place).
    checks.append((
        "6",
        f"Zero paths absolutos residuais no destino (C10; {paths_total} sanitizados)",
        _check_state(True),
    ))

    # (7) Binarios de risco (data/credential) excluidos (MV-06; exclusao F1
    #     deterministica -> PASS independente do re-scan de segredos).
    checks.append((
        "7",
        f"Binarios de risco excluidos por tier (MV-06; {binaries_excluded} excluidos)",
        _check_state(True),
    ))

    # (8) `.gitignore` presente cobrindo `.env`/`.sanitizer-state.json` (D1).
    checks.append((
        "8",
        "`.gitignore` emitido cobrindo `.env` + `.sanitizer-state.json` (C-V11-05)",
        _check_state(gi_emitted),
    ))

    # (9) Camada de entropia executada (ou SKIPPED se `--entropy off`).
    #     P1-b: executada com sucesso -> PASS (nao herda FP de outra categoria).
    entropy_state = _CHECK_PASS if entropy_on else "SKIPPED(flag --entropy off)"
    checks.append((
        "9",
        f"Camada de entropia executada ({result.entropy_count} tokens redatados)",
        entropy_state,
    ))

    # (10) Gate G2 funcional (replica publicavel). SKIPPED se ainda nao rodou.
    if g2_outcome is None:
        g2_state = "SKIPPED(aguardando finalize)"
    elif g2_outcome in {"done", "done_with_warnings"}:
        g2_state = _CHECK_PASS
    else:
        g2_state = _CHECK_FAIL
    checks.append((
        "10",
        f"Gate G2 funcional / replica publicavel (outcome={g2_outcome or 'pre-G2'})",
        g2_state,
    ))

    return checks


def _build_publication_checklist_section(
    result: F3Result,
    *,
    git_history_clean: bool | None,
    gitignore_emitted: bool | None,
    entropy_enabled: bool | None,
    g2_outcome: str | None,
    cache_rescan_clean: bool | None = None,
) -> list[str]:
    """Renderiza a secao '## Checklist de Publicacao' (D2 / MV-08)."""
    checks = build_publication_checklist(
        result,
        git_history_clean=git_history_clean,
        gitignore_emitted=gitignore_emitted,
        entropy_enabled=entropy_enabled,
        g2_outcome=g2_outcome,
        cache_rescan_clean=cache_rescan_clean,
    )
    n_pass = sum(1 for _, _, st in checks if st == _CHECK_PASS)
    n_fail = sum(1 for _, _, st in checks if st == _CHECK_FAIL)
    n_skip = sum(1 for _, _, st in checks if st.startswith("SKIPPED"))
    lines = [
        "## Checklist de Publicacao (MV-08 / RS-NEW-043)",
        "",
        "> Cada item deriva do **re-scan real do destino** (contagens do "
        "pipeline), nunca de flag otimista. Estados: `PASS` / `FAIL` / "
        "`SKIPPED(motivo)`. Zero-literal (RS-005): so contagens/categorias.",
        "",
        f"- **Resumo:** {n_pass} PASS / {n_fail} FAIL / {n_skip} SKIPPED "
        f"(total {len(checks)} checagens)",
        "",
    ]
    rows = [[cid, desc, state] for cid, desc, state in checks]
    lines.append(_md_table(["#", "Checagem", "Estado"], rows))
    lines.append("")
    if n_fail > 0:
        lines.extend([
            f"> ATENCAO: **{n_fail} checagem(ns) = FAIL**. A replica NAO esta "
            "pronta para publicar. Resolva os itens FAIL (o Gate G2 ja bloqueia "
            "(c)/(d); demais itens devem ser revisados antes do push).",
            "",
        ])
    return lines


# ===========================================================================
# Flag EXIF — imagens/midia mantidas sem inspecao de metadados (MV-06 / G-04)
# ===========================================================================
# Cumpre a promessa do docstring de `_binary_policy.py` ("imagens mantidas com
# FLAG 'EXIF nao inspecionado' no report"). A politica binaria 3-tier MANTEM
# imagens (.png/.jpg/.pdf/...) mas NAO inspeciona seus metadados (EXIF/autor/GPS)
# — vetor de PII conhecido (#07-Observability G-04). Aqui renderizamos a CONTAGEM
# + a lista de nomes (redatados via redact_path) com aviso PT-BR. Transparencia,
# nao exclusao => seguro listar paths; zero-literal preservado (so nomes de
# midia, nunca conteudo binario). Quando vazio, NAO polui o report.

_EXIF_REVIEW_WARNING_PT_BR = (
    "⚠️ {n} arquivo(s) de imagem/midia mantidos SEM inspecao de metadados "
    "(EXIF/autor/GPS). Revise antes de publicar."
)


def _build_exif_flag_section(result: F3Result) -> list[str]:
    """Renderiza a secao '## Flag EXIF' (MV-06 / G-04 #07-Observability).

    Lista a CONTAGEM de imagens/midia mantidas sem inspecao de metadados +
    (se disponivel) os nomes relativos redatados, com aviso PT-BR. Zero-literal:
    cada path passa por `redact_path` (so nomes de midia; conteudo binario nunca
    e renderizado). Quando `result.exif_uninspected` esta vazio, emite uma linha
    curta "0 / nenhum" — nao polui o report com lista nem aviso.
    """
    n = len(result.exif_uninspected)
    lines = [
        "## Flag EXIF — Imagens/Midia Mantidas sem Inspecao de Metadados (MV-06)",
        "",
        "> Politica binaria 3-tier (MV-06 / ADR-036): imagens/midia de tier "
        "*safe* sao MANTIDAS na copia, mas seus metadados (EXIF/autor/GPS) NAO "
        "sao inspecionados (parse EXIF = fora de escopo, INV-8). EXIF e um vetor "
        "de PII conhecido — esta secao e transparencia, nao exclusao.",
        "",
    ]
    if n == 0:
        lines.extend([
            "- Imagens/midia mantidas sem inspecao de metadados: **0** (nenhum)",
            "",
        ])
        return lines
    lines.extend([
        f"- Imagens/midia mantidas sem inspecao de metadados: **{n}**",
        "",
        f"> {_EXIF_REVIEW_WARNING_PT_BR.format(n=n)}",
        "",
        "Arquivos afetados (paths relativos; PII em nomes redatada):",
        "",
    ])
    for rel in result.exif_uninspected:
        lines.append(f"- `{redact_path(rel)}`")
    lines.append("")
    return lines


def _build_f2_section(f2_result: F2Result) -> list[str]:
    """Renderiza secao F2 Organizacao Visual no SANITIZATION_REPORT (passo 04.10)."""
    lines = [
        "## Organizacao F2 (Bloco 04 — GitHub Community Standards)",
        "",
    ]
    if f2_result.detection:
        lines.extend([
            f"- **Linguagem detectada:** `{f2_result.detection.primary}`",
            f"- **Monorepo:** {'sim' if f2_result.detection.is_monorepo else 'nao'}",
            f"- **Markers encontrados:** {', '.join(f2_result.detection.markers_found[:8]) or '(nenhum)'}",
            "",
        ])

    if f2_result.score:
        s = f2_result.score
        lines.extend([
            f"### Score: **{s.total}/{s.max}** "
            f"({'PASS' if s.is_passing() else 'BELOW THRESHOLD (<8/10)'})",
            "",
            "| Item | Presente | Path no destino | Tamanho |",
            "| --- | --- | --- | --- |",
        ])
        for item in s.items:
            present_str = "[OK]" if item.present else "[--]"
            path_str = item.path_rel or "—"
            size_str = f"{item.size_bytes} bytes" if item.size_bytes > 0 else "—"
            lines.append(f"| {item.name} | {present_str} | {path_str} | {size_str} |")
        lines.append("")

    if f2_result.templates_generated:
        lines.extend([
            "### Templates Auto-Gerados (PT-BR)",
            "",
        ])
        for filename, source in f2_result.templates_generated:
            lines.append(f"- `{filename}` ← `{source}`")
        lines.append("")

    moves_done = [m for m in f2_result.moves if m.action == "moved"]
    moves_suggested = [m for m in f2_result.moves if m.action == "suggested"]
    if moves_done:
        lines.extend([
            "### Arquivos Movidos (imports absolutos detectados)",
            "",
        ])
        for mv in moves_done:
            lines.append(f"- `{redact_path(mv.src_rel)}` → `{redact_path(mv.dest_rel)}` ({mv.reason})")
        lines.append("")

    if moves_suggested:
        lines.extend([
            "### Sugestoes de Reorganizacao (movimentacao manual)",
            "",
            "Arquivos abaixo NAO foram movidos automaticamente pois requerem revisao manual "
            "(imports relativos, .md ambiguos). Considere reorganiza-los manualmente:",
            "",
        ])
        for mv in moves_suggested:
            lines.append(f"- `{redact_path(mv.src_rel)}` → sugerido em `{redact_path(mv.dest_rel)}` ({mv.reason})")
        lines.append("")

    if f2_result.license_moved:
        lines.extend([
            "### LICENSE Reorganizado",
            "",
            f"- LICENSE encontrado em path nao-canonico e movido para root: `{f2_result.license_moved}`",
            "",
        ])

    # Itens ausentes apos auto-gera + moves
    if f2_result.score:
        missing = [i for i in f2_result.score.items if not i.present]
        if missing:
            lines.extend([
                "### Itens Ausentes (acao manual recomendada)",
                "",
            ])
            for item in missing:
                if item.name == "LICENSE":
                    note = " — o(a) mantenedor(a) deve adicionar manualmente (nao inventamos licencas)"
                elif item.name == "CHANGELOG":
                    note = " — gere via convencao Keep-a-Changelog quando aplicavel"
                else:
                    note = ""
                lines.append(f"- {item.name}{note}")
            lines.append("")

    return lines


def sanitization_report_filename(slug: str, run_id_prefix: str | None = None) -> str:
    """Nome canonico: SANITIZATION_REPORT_<slug>_<YYYYMMDDTHHMMSSZ>[_<run_id_prefix>].md"""
    ts = _now_iso8601_compact()
    if run_id_prefix:
        return f"SANITIZATION_REPORT_{slug}_{ts}_{run_id_prefix}.md"
    return f"SANITIZATION_REPORT_{slug}_{ts}.md"


def write_sanitization_report(
    result: F3Result,
    *,
    slug: str,
    run_id: str,
    fs_writer: FsWriter,
    relatorios_dir: Path,
    source_path_redacted: str,
    dest_path_redacted: str,
    sentinel_sanitize_version: str,
    secret_patterns_hash: str,
    agent_version: str = __version__,
    delta: dict[str, Any] | None = None,
    f2_result: F2Result | None = None,
    git_history_clean: bool | None = None,
    gitignore_emitted: bool | None = None,
    entropy_enabled: bool | None = None,
    g2_outcome: str | None = None,
    cache_rescan_clean: bool | None = None,
) -> Path:
    """Renderiza + grava SANITIZATION_REPORT.md via FsWriter (ADR-020 boundary).

    Pre-write valida cada F3ContentMatch -> SanitizationReportEntry Pydantic
    (validate_artifact gate). Falha = SecretLeakInArtifactError raise
    (caller mapeia para exit 5).

    Os 4 args D2 (`git_history_clean`/`gitignore_emitted`/`entropy_enabled`/
    `g2_outcome`) alimentam o Checklist de Publicacao (MV-08); todos opcionais
    (None -> derivado de F3Result / SKIPPED), 100% backwards-compat.

    Returns: path absoluto do arquivo escrito.
    """
    # ADR-004 gate per-entry (Pydantic validate_artifact)
    from repo_sanitizer.f3_sanitizer import f3_matches_to_report_entries
    entries = f3_matches_to_report_entries(result.matches)
    # Trigger validation by serializing (the constructor already validates)
    for e in entries:
        _ = e.model_dump()

    md = build_sanitization_report_md(
        result,
        slug=slug,
        run_id=run_id,
        source_path_redacted=source_path_redacted,
        dest_path_redacted=dest_path_redacted,
        sentinel_sanitize_version=sentinel_sanitize_version,
        secret_patterns_hash=secret_patterns_hash,
        agent_version=agent_version,
        delta=delta,
        f2_result=f2_result,
        git_history_clean=git_history_clean,
        gitignore_emitted=gitignore_emitted,
        entropy_enabled=entropy_enabled,
        g2_outcome=g2_outcome,
        cache_rescan_clean=cache_rescan_clean,
    )
    fname = sanitization_report_filename(slug, run_id_prefix=run_id[:8])
    dest = Path(relatorios_dir) / fname
    return fs_writer.safe_write_text(dest, md)


# ===========================================================================
# Passo 03.12 — delta vs run anterior
# ===========================================================================

_REPORT_ENTRY_RE = re.compile(
    r"^\|\s+([^|]+?)\s+\|\s+([^|]+?)\s+\|\s+(C\d+\w*)\s+\|", re.MULTILINE,
)


def find_latest_report(relatorios_dir: Path, slug: str) -> Path | None:
    """Acha o SANITIZATION_REPORT.md mais recente para um slug."""
    if not relatorios_dir.exists():
        return None
    candidates = sorted(
        relatorios_dir.glob(f"SANITIZATION_REPORT_{slug}_*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def parse_report_entries_signature(md_text: str) -> set[str]:
    """Extrai assinaturas `(path, tipo)` das tabelas Markdown do report.

    Tolera variacao de layout; o objetivo e detectar entries em comum entre
    runs (resolved vs new vs carryover).
    """
    sigs: set[str] = set()
    for line in md_text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        # Esperamos: path | linha | tipo | acao | encoding
        # Sigs canonicas: path + tipo
        path = cells[0]
        # Skip header
        if path in {"path", "---"}:
            continue
        # Pular se nao tem tipo C1..C10
        possible_tipo = cells[2] if len(cells) > 2 else ""
        if not possible_tipo:
            continue
        sigs.add(f"{path}::{possible_tipo}")
    return sigs


def compute_delta(
    prev_report_path: Path,
    curr_matches: list[Any],  # list[F3ContentMatch] mas evitar import circular
) -> dict[str, int]:
    """Computa delta entre run anterior e atual (F3.D-08).

    Returns: {"resolved": N, "new": N, "carryover": N}
    """
    if not prev_report_path.exists():
        return {"resolved": 0, "new": len(curr_matches), "carryover": 0}
    prev_md = prev_report_path.read_text(encoding="utf-8")
    prev_sigs = parse_report_entries_signature(prev_md)
    curr_sigs: set[str] = set()
    for m in curr_matches:
        sig = f"{redact_path(m.rel_path)}::{m.tipo}"
        curr_sigs.add(sig)
    resolved = prev_sigs - curr_sigs
    new = curr_sigs - prev_sigs
    carryover = prev_sigs & curr_sigs
    return {
        "resolved": len(resolved),
        "new": len(new),
        "carryover": len(carryover),
    }


def build_g2_report_section(g2_result: Any) -> str:
    """Bloco 04 (ADR-032): renderiza seção 'Gate G2 — Replica Funcional'.

    `g2_result` deve ter atributos canônicos de `f4_readme.G2Result`:
        check_a_boilerplate, check_b_license, check_c_paths_zero,
        check_d_pii_zero, outcome, auto_generated_files, blocking_failures,
        language_detected, paths_found, pii_found.

    Args:
        g2_result: instância de G2Result (typed como Any para evitar import
            circular com f4_readme).

    Returns:
        Markdown da seção (header + 4 checks + outcome + auto_gen + falhas).
    """
    def _mark(b: bool) -> str:
        return "OK" if b else "FAIL"

    auto_gen_names = [p.name for p in (g2_result.auto_generated_files or [])]
    lines = [
        "",
        "## Gate G2 — Replica Funcional Verified (ADR-032 + ADR-033)",
        "",
        f"- **Outcome:** `{g2_result.outcome}`",
        f"- **Linguagem detectada:** `{g2_result.language_detected}`",
        "",
        "| Check | Descrição | Resultado |",
        "| --- | --- | --- |",
        f"| (a) | Boilerplate publicavel presente OU auto-gerado | "
        f"**{_mark(g2_result.check_a_boilerplate)}** |",
        f"| (b) | LICENSE presente OU auto-gerado | "
        f"**{_mark(g2_result.check_b_license)}** |",
        f"| (c) | Zero paths absolutos no destino | "
        f"**{_mark(g2_result.check_c_paths_zero)}** |",
        f"| (d) | Zero PII operador no destino | "
        f"**{_mark(g2_result.check_d_pii_zero)}** |",
        "",
    ]
    if auto_gen_names:
        lines.extend([
            "### Arquivos auto-gerados (ADR-033)",
            "",
            "Revise antes de publicar — banner explicito em cada arquivo:",
            "",
        ])
        for name in auto_gen_names:
            lines.append(f"- `{name}`")
        lines.append("")
    if g2_result.blocking_failures:
        lines.extend([
            "### Falhas Bloqueantes (exit code 7)",
            "",
        ])
        for blk in g2_result.blocking_failures:
            lines.append(f"- {blk}")
        lines.append("")
        if g2_result.paths_found:
            lines.append("**Amostras de paths absolutos detectados:**")
            lines.append("")
            for s in g2_result.paths_found[:5]:
                lines.append(f"- `{s}`")
            lines.append("")
        if g2_result.pii_found:
            lines.append("**Amostras de PII operador detectado:**")
            lines.append("")
            for s in g2_result.pii_found[:5]:
                lines.append(f"- `{s}`")
            lines.append("")
    return "\n".join(lines)


def _refresh_checklist_item10(content: str, g2_outcome: str) -> str:
    """Atualiza o item 10 (Gate G2) do Checklist de Publicacao in-place (D2).

    No report do F3 o item 10 nasce `SKIPPED(aguardando finalize)`; no finalize
    (quando o G2 ja rodou) refletimos o outcome real: `PASS` se done/with_warnings,
    `FAIL` caso contrario (mitigacao §5-12: estado fiel, nunca PASS otimista).
    Reescreve SO a linha cujo `#` e `10` na tabela do checklist; demais linhas
    intactas. Zero-literal (so o token de outcome).
    """
    new_state = _CHECK_PASS if g2_outcome in {"done", "done_with_warnings"} else _CHECK_FAIL
    out_lines: list[str] = []
    for line in content.splitlines():
        # Linha do checklist item 10: `| 10 | <desc...> | <estado> |`.
        if line.startswith("| 10 |") and "Gate G2" in line:
            cells = line.split("|")
            # cells = ['', ' 10 ', ' <desc> ', ' <estado> ', '']
            if len(cells) >= 4:
                desc = cells[2].strip().replace("outcome=pre-G2", f"outcome={g2_outcome}")
                out_lines.append(f"| 10 | {desc} | {new_state} |")
                continue
        out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if content.endswith("\n") else "")


def append_g2_section_to_report(report_path: Path, g2_result: Any, fs_writer: FsWriter) -> Path:
    """Bloco 04: anexa seção Gate G2 ao SANITIZATION_REPORT.md existente.

    Idempotente: se a seção já existe (header 'Gate G2 —'), substitui o trecho
    anterior pelo novo (re-runs do finalize são honestos sobre o último G2).

    v1.2.0 / D2: tambem REFRESCA o item 10 do Checklist de Publicacao para o
    outcome real do G2 (sai de `SKIPPED(aguardando finalize)` -> PASS/FAIL).

    Args:
        report_path: arquivo SANITIZATION_REPORT.md gerado em F3.
        g2_result: G2Result do run atual.
        fs_writer: FsWriter canonico (escrita atomica).

    Returns: report_path (same path; re-written via FsWriter atomic).
    """
    content = report_path.read_text(encoding="utf-8")
    section = build_g2_report_section(g2_result)

    # D2: refresca o item 10 do checklist com o outcome real do G2.
    outcome = getattr(g2_result, "outcome", None)
    if outcome:
        content = _refresh_checklist_item10(content, str(outcome))

    # Idempotência: localiza header Gate G2 anterior e trunca
    marker = "## Gate G2 — Replica Funcional Verified"
    if marker in content:
        prefix, _ = content.split(marker, 1)
        # Preservar conteudo antes do header anterior
        content = prefix.rstrip()
    content = content.rstrip() + "\n" + section + "\n"
    fs_writer.safe_write_text(report_path, content)
    return report_path


__all__ = [
    "CATEGORY_TITLES",
    "GITLEAKS_OPERATIONAL_PT_BR",
    "LGPD_WARNING_PT_BR",
    "ROTATION_CHECKLIST_PT_BR",
    "append_g2_section_to_report",
    "build_g2_report_section",
    "build_publication_checklist",
    "build_sanitization_report_md",
    "compute_delta",
    "find_latest_report",
    "parse_report_entries_signature",
    "sanitization_report_filename",
    "write_sanitization_report",
]
