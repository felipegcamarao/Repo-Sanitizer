# Changelog

Todas as mudanças notáveis a este projeto seguem [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
e [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — 2026-07-12 — Auditoria de Confiança Total

> Codename: Trusted Output. Release derivada da **auditoria de confiança total**
> (red team com cobaia contaminada + 2 rodadas limpas consecutivas com ZERO
> vazamento). Corrige 6 vazamentos reais provados em campo e alinha a versão do
> pacote (pyproject/`__version__` estavam em 1.1.0 com código v1.2.0). Ver
> `auditoria-confianca-v1-2026-07-12.md` na raiz.

### Corrigido (achados do red team — cada um com teste de regressão AUD-xx)

- **F1 não excluía históricos de sessão de IA** — `.claude/`, `.specstory/`,
  `.cursor/`, `.windsurf/`, `.aider*`, `.history/`, `safelog*.jsonl` e
  `.claude.json` agora são Grupo A (AUD-01). Antes, transcripts inteiros eram
  copiados ao destino com mera redação regex.
- **`github_pat_` estrito demais** — o formato exato `{22}_{59}` deixou VAZAR um
  token `24_59` na cobaia; regra relaxada para `[A-Za-z0-9_]{30,200}` mantendo a
  âncora anti-ReDoS (AUD-02).
- **Nome do operador hardcoded chegava ao destino** — o `reason` da transição FSM
  ("[REDACTED-NAME] aprovou…") era gravado em `.sanitizer-state.json` DENTRO da réplica;
  de-personalizado (AUD-06).
- **Exceção LICENSE implementada** — o nome do copyright holder é preservado
  APENAS em `LICENSE*` (C9 `skip_names` + split de patterns no Gate G2);
  usernames/domínios continuam redatados até em LICENSE (AUD-03/AUD-05).
- **PII em NOME DE ARQUIVO passava** — `[REDACTED-NAME]-helper.py` atravessava todas as
  camadas; o Gate G2 agora escaneia também os paths relativos do destino e
  bloqueia com amostra `FILENAME:` (AUD-04).
- **`DEFAULT_FORBIDDEN_PATHS` com username hardcoded** — agora derivado do
  ambiente (`Path.home()`, `SystemRoot`, `ProgramFiles*`) — portável e sem PII no
  código (AUD-07).

### Adicionado

- Flags CLI `--dest-root` e `--relatorios-dir` (destino e relatórios eram
  hardcoded para o workspace do operador).
- `operator_identity.json` completado com variações SEM ACENTO e derivados
  (`[REDACTED-NAME]`, `[REDACTED-NAME]`, `[REDACTED-NAME]`, backstop `(?i)[REDACTED-NAME][a-z0-9]*`,
  `<REDACTED-EMAIL_PESSOAL>`) — o detector de nomes é case-insensitive mas
  acento-sensível.
- Suite `tests/security/test_auditoria_confianca_2026_07.py` (29 testes AUD-01..07).

### Alterado

- Versão alinhada: código v1.2.0 declarava 1.1.0 no pacote → 1.3.0.
- Raiz do projeto limpa: ~20 artefatos de processo movidos para `docs/processo/`.
- Gate técnico re-verde: ruff 0 (eram 22), mypy strict 0 (eram 16), pip-audit 0
  CVE (pytest ≥9.0.3, msgpack ≥1.2.1).

## [1.2.0] — 2026-06-03 — RELEASE OFICIAL

> Codename: Deep Clean Coverage. Entrega **10 melhorias (MV-01..MV-10)** que
> fecham os flancos estruturais ainda abertos na v1.1.0: histórico Git, segredos
> sem prefixo conhecido, autoria estrutural, política binária e checklist de
> publicação auditável. **13/13 RS-NEW (035..047)** rastreados a teste; **zero
> regressão** sobre o baseline de 947 testes. Ver `release-notes-v1.2.0.md` para
> o resumo executivo + métricas + carry-overs.

### Adicionado

- **Camada de entropia Shannon (MV-04 / ADR-034)** — rede de segurança ADITIVA
  (última camada de texto do F3) para tokens de alta entropia SEM prefixo
  conhecido que a matriz regex não pega. Nova flag CLI `--entropy {on,off}`
  (**default `on`**). Thresholds calibrados (4.5 bits/char base64, 3.0 hex; token
  isolado 24–512 chars). Allowlist DURA HARDCODED preserva git-SHA40/SHA256,
  UUID v1–v5, SRI e lockfiles (anti-FP que quebraria o build). Placeholder
  `<REDACTED-HIGH-ENTROPY>`. Módulo novo `helpers/_entropy_detector.py`.
- **Gate de histórico Git no destino (MV-02 / ADR-035)** — scan BLOQUEANTE por
  NOME e por CONTEÚDO (`.git/`, `packed-refs`, `ORIG_HEAD`/`FETCH_HEAD`/
  `MERGE_HEAD`/`HEAD`, `.gitmodules`, `*.bundle/.orig/.rej/.patch/.diff`; ponteiro
  `gitdir:`; `.gitattributes` com filtros `clean/smudge`). Resíduo de histórico no
  destino → **exit 8** (novo). Allowlist HARDCODED (`.gitignore`/`.gitkeep`/
  `.editorconfig`/`.gitattributes` sem filtros). Módulo novo
  `helpers/_git_history_scan.py`.
- **Política binária 3-tier (MV-06 / ADR-036)** — classifica binários em
  `safe`/`data`/`credential`: dados (`.sqlite/.csv/.parquet/.xlsx/.pkl/...`) e
  credenciais (`.jks/.pfx/.p12/.keystore/.kdbx/.pem/...`) são EXCLUÍDOS;
  imagens/mídia são mantidas com **flag EXIF no report** (transparência, não
  remoção); neutros (`.wasm/.ico/.woff2/...`) mantidos. Re-classificação por
  magic-label (anti-rename-spoof). Módulo novo `helpers/_binary_policy.py`.
- **Detector de autoria estrutural (MV-05 / ADR-038)** — redata SÓ campos de
  autoria (nome+email) em manifests `pyproject.toml`/`package.json`/`Cargo.toml`/
  `composer.json`/`AUTHORS`/`CITATION.cff`, preservando estrutura do manifest
  (`name`/`dependencies`/`version` intactos; output permanece JSON/TOML válido).
  Parsing defensivo com fallback textual. Auto-derivação de identidade do ambiente
  (variáveis de ambiente, sem subprocess git). Placeholders
  `<REDACTED-AUTHOR-NAME>`/`<REDACTED-AUTHOR-EMAIL>`. Módulo novo
  `helpers/_author_detector.py`.
- **Prefixos modernos de chave (MV-03)** — +7 regras C2 ancoradas (anti-ReDoS):
  `github_pat_`, `sk-proj-` (OpenAI), Stripe (`sk/rk/pk_live/test_`, `whsec_`),
  GitLab (`glpat-`), Slack app (`xapp-`/`xoxe-`), AWS temporário (`ASIA`/`AROA`).
  Regras existentes (incl. `AKIA`) preservadas.
- **`.gitignore` robusto no destino (MV-07)** — merge ADITIVO idempotente: anexa
  só as entradas canônicas faltantes (caches espelhando MV-01 + artefatos do
  sanitizador, incluindo `.sanitizer-state.json`) SEM sobrescrever nem reordenar
  as regras do autor.
- **Checklist de Publicação auditável (MV-08)** — 10 checks `PASS`/`FAIL`/
  `SKIPPED` no SANITIZATION_REPORT, cada um derivado do estado REAL do re-scan
  (Camada C6), nunca de flag otimista. Detector desligado nunca vira PASS;
  `--entropy off` → check de entropia `SKIPPED`. Zero-literal.
- **Lista canônica EXAUSTIVA de caches (MV-01)** — +27 entradas ancoradas no
  Grupo A (ambientes Python, bytecode, egg-info, caches de test/lint/type/cov,
  bundlers JS, infra), com fixture anti-falso-positivo de pastas de produto.
- **`release-notes-v1.2.0.md`** — release notes detalhadas (10 MVs + métricas +
  carry-overs + upgrade notes da flag `--entropy`).

### Modificado

- **Exit codes CLI: `0..7` → `0..8`** (+8 = histórico Git no destino, bloqueante).
- **ADRs canônicos: `33` → `38`** (+ADR-034 entropia, ADR-035 gate histórico,
  ADR-036 binário 3-tier, ADR-037 lookbehind anti-URL, ADR-038 autoria/identidade
  de ambiente).
- **`AuditAction` enum** estendido (`git_history_detected`/`git_history_clean`,
  `f3_author_done`, `f3_entropy_done`).
- **Camada de entropia executada como ÚLTIMA etapa de texto do F3**, após
  paths (C10) e autoria (MV-05), antes do write — sempre aditiva, nunca substitui
  regra dedicada (INV-10).
- **`.sanitizer-state.json`** persiste o **basename redatado** (`dest_name`) em vez
  do path absoluto do destino — sem drive/usuário/PII.
- **Suíte de testes: `947` → `1269`** passing / 8 skipped / 0 failed; cobertura
  global **90.44%** (módulos novos 95.96–100%).

### Corrigido

- **C-V11-02** — 2 erros mypy strict pré-existentes em `f3_sanitizer.py`
  resolvidos na causa (anotação explícita + `cast` legítimo guardado), sem
  `# type: ignore`. Superfície v1.2.0 = **0 erros mypy**.
- **C-V11-04** — `WINDOWS_PATH_RE` deixava de redatar mas casava `https://`/
  `http://`/`ftp://`/`file://` como falso-positivo. Fix: negative lookbehind de
  largura fixa `(?<![A-Za-z])` (anti-ReDoS); paths Windows reais continuam
  casando (MV-09 / ADR-037).
- **C-V11-05** — `.sanitizer-state.json` agora está SEMPRE no `.gitignore`
  emitido no destino e não vaza mais o path absoluto.

### Segurança

- **ReDoS latente (SEC-01, MÉDIO)** nos regex de bloco de autoria corrigido por
  hotfix dentro do ciclo: sub-padrão `(?:[^\[\]]|\n)*?` (alternante `\n`
  redundante → backtracking exponencial) trocado por `[^\[\]]*?` (linear; mesma
  semântica). Gate de regressão `tests/security/test_author_redos.py`.
- **Detectores v1.2.0 read-only (INV-1)** provados com SHA-256 do source idêntico
  byte-a-byte mesmo com autoria+entropia ATIVAS (redatando). Allowlists/tiers/
  campos HARDCODED no código (zero leitura de config do source — anti-bypass).
  Score Dimensão Segurança **8.9/10** (0 crítico / 0 alto; bandit 0 High/0 Medium;
  pip-audit 0 CVE nas deps declaradas).

### Carry-overs ABERTOS (v1.2.1 / v1.3.0+)

- C-V11-03 (`bootstrap --rebuild` reverte patch local) e C-V11-06 (`--dest-path`/
  auto-resume CLI) — não endereçados neste ciclo (UX/manutenção; v1.2.1).
- `redact_authorship` ainda não envolto em `safe_finditer`/timeout (mitigado pelo
  gate de parse) — fast-follow v1.2.1.
- EXIF/metadados binários flagados mas NÃO removidos; scan dentro do `.git/`
  empacotado; autoria fora dos manifests canônicos — diferidos para v1.3.0+
  (sob INV-8). 6 CVE em pacotes de ambiente/dev (não-runtime) — DEFER-HUMAN.

## [1.1.0] — 2026-05-27 — RELEASE OFICIAL

> Consolida 1.1.0-alpha.1 + 1.1.0-alpha.2 + 1.1.0-alpha.3 + 1.1.0-rc.1.
> Endereça os **5 gaps críticos** (A/B/C/D/E) do audit produtivo
> 2026-05-22 sobre A+ AGENTS. Ver `release-notes-v1.1.0.md` para o resumo
> executivo + métricas + smoke E2E resultado + migration guide.

### Adicionado em v1.1.0 (sobre v1.1.0-rc.1)

- **Multi-pass loop em `sanitize_paths`** (`helpers/_path_sanitizer.py`) — itera
  o pipeline regex Windows + Unix até ponto-fixo (cap MAX_PASSES=8). Resolve
  caso de greedy match que consumia o `c` inicial de paths subsequentes na
  mesma linha em prose com 2+ paths. Comportamento idempotente preservado
  para inputs limpos (no-op em 1 iteração). **Sem regressão sobre os 947
  testes** (R-01 inviolável).
- **3 cenários v1.1.0 em `scripts/smoke_e2e_phase5.py`** — grupos
  pytest novos para C9 PII Detector + C10 Path Sanitizer + F1.5
  Cross-Project Detection (unit + integration + threat-tree).
  Total: 12 grupos (vs 9 em v1.0.1), 947 verdes.
- **`scripts/smoke_e2e_a_plus_agents_v110.py`** — driver Python canônico
  para reproduzir audit 2026-05-22 fim-a-fim usando `OrchestratorContext`
  programático único (contorna gap UX multi-comando CLI documentado em
  C-V11-06). Saída em `scripts/smoke_e2e_phase5_v110.log`.
- **`release-notes-v1.1.0.md`** — release notes detalhadas com migration
  guide para `operator_identity.json` setup.

### Carry-overs FECHADOS

- RS-NEW-030, 031, 032, 033, 034 — todos endereçados (ver release notes).
- Smoke E2E A+ AGENTS: 4 gaps + Gate G2 validados em pipeline real.

### Carry-overs ABERTOS (v1.1.1 / v1.2.0)

- C-V11-01 (`.git/` ausente) — fechamento manual [REDACTED-NAME] (passo 5.4).
- C-V11-02 (mypy `f3_sanitizer.py:237,1113`) — polish v1.1.1.
- C-V11-03 (bootstrap --rebuild bug) — `--preserve-local-extras` v1.1.1.
- C-V11-04 (URL false-positive em WINDOWS_PATH_RE) — ADR-034 v1.2.0.
- C-V11-05 (`.sanitizer-state.json` contém dest_path) — gitignore destino.
- C-V11-06 (CLI multi-comando auto-versioning UX) — `--dest-path` flag v1.1.1.

### Métricas finais v1.0.1 → v1.1.0

| Métrica | v1.0.1 | v1.1.0 | Δ |
|---|---|---|---|
| Total testes | 789 | **947** | +158 |
| ADRs canônicos | 28 | **33** | +5 |
| RS-NEW fechados | 0 | **5** | +5 |
| FSM estados | 8 | **10** | +2 |
| Exit codes CLI | 0..6 | **0..7** | +1 |
| Camadas | C1..C8 + F1..F4 | + **C9, C10, F1.5, G2** | +4 |
| pip-audit (deps declaradas) | 0 CVE | **0 CVE** | mantido |

## [1.1.0-rc.1] — 2026-05-26

> Release técnico interno (Bloco 04 do plano v1.1.0). Adiciona **Gate G2 Replica
> Funcional Verified** ao F4 finalize com 4 checks determinísticos +
> **auto-geração de boilerplate publicável (ADR-033)** para 4 linguagens +
> **flag CLI `--license`** + 2 novos estados FSM terminais
> (`done_with_warnings` / `done_with_failure`) + **exit code 7** para falhas
> bloqueantes G2. Endereça RS-NEW-034 (gap E do audit 2026-05-22: destino
> sanitizado mas não-publicável). Aguarda Bloco 05 para o release oficial v1.1.0.

### Adicionado

- **Gate G2 Replica Funcional Verified** (ADR-032) — gate executado em
  `orchestrator.run_finalize` APÓS `run_f4_finalize` (markdownlint +
  link-check + cleanup .tmp) e ANTES da FSM transition. 4 checks:
  - **(a) Boilerplate publicável** — `pyproject.toml` (Python) | `package.json`
    (Node) | `Cargo.toml` (Rust) | `go.mod` (Go) conforme language detection
    via `f2_organizer.detect_language`. Se ausente OU 0 bytes → auto-gera
    esqueleto mínimo (ADR-033).
  - **(b) LICENSE** — auto-gera MIT default com banner explícito quando ausente;
    override via CLI `--license={MIT|APACHE-2.0|BSD-3|GPL-3.0}`.
  - **(c) Zero paths absolutos** — re-grep `WINDOWS_PATH_RE` + `UNIX_PATH_RE`
    (exports de `_path_sanitizer`, Bloco 02). Match count > 0 → bloqueante.
  - **(d) Zero PII operador** — re-grep literal case-insensitive sobre
    `OperatorIdentitySchema.{names,usernames,domains}` (Bloco 01). Match
    count > 0 → bloqueante.
- **3 outcomes G2** mapeados em FSM (ADR-032):
  - `done` (legacy) → tudo OK + sem auto-gen → exit 0.
  - `done_with_warnings` → (a)/(b) auto-gerados → exit 0.
  - `done_with_failure` → (c) ou (d) bloqueia → **exit 7** + `G2BlockingFailure`.
- **Auto-geração de boilerplate publicável** (ADR-033) — novo módulo
  `helpers/_boilerplate_generator.py` com 4 generators + LICENSE multi-variant:
  - `generate_pyproject(slug)` — esqueleto PEP 517/setuptools.
  - `generate_package_json(slug)` — esqueleto NPM private + script test.
  - `generate_cargo_toml(slug)` — esqueleto crate Rust edition 2021.
  - `generate_go_mod(slug)` — module + go 1.21.
  - `generate_license(license_id, year)` — MIT default + 3 alternativas
    (APACHE-2.0 / BSD-3 / GPL-3.0) com banner `[REPO-SANITIZER NOTICE —
    INFERRED LICENSE]`.
  - Slugs sanitizados via `sanitize_slug` canonico (Bloco 03 helper) com
    fallback `"project"` para vazios.
  - Cobertura 100%.
- **Flag CLI `--license`** (ADR-033) — `repo-sanitize sanitize-finalize
  --license=APACHE-2.0` (choices: MIT|APACHE-2.0|BSD-3|GPL-3.0, default=MIT).
  Propagado via `ctx.extra['license_override']` até `run_g2_replica_funcional`.
- **2 novos estados FSM terminais** (ADR-032) em
  `helpers/_state_machine.py`:
  - `State.DONE_WITH_WARNINGS = "done_with_warnings"` — terminal, só `reset`.
  - `State.DONE_WITH_FAILURE = "done_with_failure"` — terminal, só `reset`.
  - 2 novas TRANSITION_ACTIONS: `finalize_done_with_warnings` +
    `finalize_done_with_failure` a partir de `AWAITING_FINALIZE`.
- **Exit code 7** — `G2BlockingFailure` em `orchestrator.py` mapeado pelo CLI
  para exit 7 (novo, fora dos 0..6 anteriores). Hint PT-BR explícito sugere
  re-executar `/sanitize-apply` e inspecionar SANITIZATION_REPORT seção G2.
- **AuditAction `"f4_g2_done"`** — emitido após G2 com
  `detail={check_a..d, outcome, auto_generated_files, language_detected,
  license_override, paths_found_count, pii_found_count, samples[:5]}`.
- **Seção "Gate G2 — Replica Funcional" no SANITIZATION_REPORT.md** —
  `build_g2_report_section(g2_result)` renderiza tabela 4 checks + outcome +
  sub-seções "Arquivos auto-gerados (ADR-033)" e "Falhas Bloqueantes (exit
  code 7)" com amostras de paths/PII. `append_g2_section_to_report` anexa
  idempotente (substitui seção anterior em re-runs).
- **8 testes integration G2** em `tests/integration/test_g2_replica_funcional.py`
  cobrindo 3 outcomes + auto-gen + license override + Node fixture +
  language=generic trivial pass.

### Extensões polish-driven (positivas, documentadas)

- **Skip lists G2 para falsos-positivos e agent-metadata**
  (`_G2_PII_SKIP_FILES` + `_G2_PATHS_SKIP_FILES` em `f4_readme.py`):
  - **PII skip:** `CODE_OF_CONDUCT.md` + `CONTRIBUTING.md` + `SECURITY.md`
    (F2 templates injetam intencionalmente `<REDACTED-EMAIL_PESSOAL>` como contato
    público canônico do operador) + `*_AUDIT.md` (audit reports do agente
    DENTRO do destino documentam exatamente patterns redatados) +
    `.sanitizer-state.json` (FSM state com paths reais do destino).
  - **Paths skip:** mesmos arquivos do PII skip + `LICENSE` / `LICENSE.md` /
    `LICENSE.txt` (textos Apache 2.0 contêm `http://www.apache.org/licenses/...`
    que dispara falso-positivo no `WINDOWS_PATH_RE` — `p:` matches `[A-Za-z]:`;
    limitação pre-existente da regex, fix completo programado pós-v1.1.0).
- **Skip dirs G2 walk**: `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`,
  `.tmp`, `dist`, `build`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache` —
  consistente com C9/C10 walk patterns.
- **30 testes vs 13 plano (2.31× polish-driven)** — sub-plano pedia 13 testes
  mínimo (4 FSM + 8 boilerplate + 2 CLI + 5 G2 integration + 1 writer);
  entreguei **30 testes** (5 FSM + 13 boilerplate + 4 CLI + 8 G2 integration
  + 4 writer = 34, mais 4 do test_cli.py que cobrem default/override/invalid/help).

### Métricas

| Métrica | Antes (1.1.0-alpha.3) | Depois (1.1.0-rc.1) | Δ |
|---|---|---|---|
| Total testes | 913 | **943** | **+30 ✅** (2.31× plano) |
| Falhas testes | 0 | 0 | mantido |
| Skips testes | 8 | 8 | mantido |
| Cobertura `_boilerplate_generator.py` | n/a | **100%** | NOVO |
| ADRs canônicos | 30 | **33** | +3 (ADR-031/032/033 operacionalizados) |
| RS-NEW críticos fechados | 3 | **4** (+RS-NEW-034) | +1 |
| AuditAction enum | 26 | **27** (+`f4_g2_done`) | +1 |
| FSM Estados | 8 | **10** (+done_with_warnings/done_with_failure) | +2 |
| Exit codes CLI | 0..6 | **0..7** (+7 G2 bloqueante) | +1 |
| Arquivos código novo | — | 1 (`_boilerplate_generator.py`) | — |
| Arquivos modificados | — | 6 (`_state_machine` + `cli` + `orchestrator` + `f4_readme` + `audit_entry` + `sanitization_report_writer`) | — |

### Carry-overs documentados (Bloco 04 → Bloco 05)

- **C-V11-01** (herdado) — `.git/` ausente: NÃO bloqueante; tag formal no Bloco 05.
- **C-V11-02** (herdado) — 2 mypy errors pré-existentes em `f3_sanitizer.py`
  (linhas 237 e 1113); NÃO foram corrigidos neste bloco (escopo de polish
  excedido pelas mudanças G2). Endereçar em Bloco 05 polish ou v1.1.0 final.
- **C-V11-03** (herdado Bloco 02) — Bug `bootstrap_local_copies.py --rebuild`:
  EVITADO neste bloco (integrity gate exit 0 sem rebuild). Endereçar em Bloco 05.
- **C-V11-04** (NOVO) — `WINDOWS_PATH_RE` em `_path_sanitizer.py` matcha
  `https://` URLs como falso-positivo (`s:` matches `[A-Za-z]:`). Workaround
  via skip list `_G2_PATHS_SKIP_FILES` cobrindo LICENSE/templates. Fix
  apropriado: lookbehind anti-URL na regex; programar como ADR-034
  pós-v1.1.0 (risco regressão sobre 943 testes em camada C10).

## [1.1.0-alpha.3] — 2026-05-26

> Release técnico interno (Bloco 03 do plano v1.1.0). Adiciona **Sub-fase F1.5
> Cross-Project Content Detection** ao F1, endereçando RS-NEW-033 (gap D do
> audit 2026-05-22 — 8 planos + 8 relatórios staff + portfólio global de outros
> projetos vazando no destino). Aguarda Blocos 04–05 para o release oficial v1.1.0.

### Adicionado

- **Sub-fase F1.5 Cross-Project Content Detection** (ADR-031) — heurística
  semântica determinística sobre nomes de pastas/arquivos após walk + classify
  A/B/C do F1. 5 regras canônicas:
  - **(a) Planos cross-project** — `Planos de Implementação/plano-*.md` OU
    `plano-implementacao-*.md` cujo slug NÃO matcha → promove C → **B** (review).
  - **(b) Relatórios cross-project** — `Relatórios Staff/relatorio-staff-*.md`
    OU `relatorio-staff-*.md` cujo slug NÃO matcha → promove C → **B**.
  - **(c) Portfólio** — `**/memory/projetos.md` ou `**/memory/projects.md`
    → promove C → **A** (cache).
  - **(d) Eval caches** — `**/.eval-runs/**`, `**/_eval_runs/**`,
    `**/.fixtures-derivation/**` → promove C → **A**.
  - **(e) Audit baselines** — `**/audit/baseline-*.md` ou `**/_baseline-*/**`
    → promove C → **A**.
- `_cross_project_classifier.py` em `src/repo_sanitizer/helpers/` — módulo NOVO
  com `sanitize_slug`, `extract_project_slug` (3 modos + sentinel),
  `classify_cross_project`, dataclass `CrossProjectClassification`. Cobertura 90.72%.
- `FilterResult.cross_project_classifications` + `FilterResult.f1_5_counts`
  (`cross_project_to_B` + `ambiguous_to_B` + `cache_to_A` + `intra_project_kept_C`)
  + `FilterResult.project_slug` — campos NOVOS com defaults (backwards-compat ✅).
- `run_filter(source, *, context_md_path=None)` — assinatura backward-compat;
  kwarg opcional aceita `context-[slug].md` explícito OU auto-discovery via
  `source.glob("context-*.md")`.
- `AuditAction "f1_5_cross_project_done"` — audit emitido pelo orchestrator
  após `f1_filter_done` com `detail={project_slug, f1_5_counts}`.
- `FILTER_DIFF.md` — frontmatter `project_slug_resolved:` + `f1_5_counts:`
  (4 chaves YAML) + nova seção body "## Camada F1.5 — Cross-Project Detection"
  com 4 linhas-resumo bold + 3 sub-tabelas (Cross-project / Cache / Ambíguos)
  + nota sobre origem do slug resolvido.
- Fixture adversarial `tests/fixtures/adversarial/cross_project_fixture/` —
  11 arquivos cobrindo intra + cross planos + cross relatorio + portfolio +
  eval-runs + audit baseline + ambíguo, alimentando o threat tree RS-NEW-033.
- `tests/security/test_threat_tree_F1_5.py` — 7 testes adversariais
  (RS-NEW-033 gate-resumo + 4 AT específicos + 2 smoke direct).

### Extensões polish-driven (positivas, documentadas)

- **YAML frontmatter `slug:` em `extract_project_slug`** — além da fonte
  canônica `## Identificação > **Nome:**`, aceita YAML frontmatter (formato
  real dos contexts.md do Pipeline A+).
- **Regra (a3) ancestor folder** — além de matchar `plano-implementacao-*.md`
  no nome do arquivo, F1.5 também matcha quando o caminho contém
  `plano-implementacao-<slug>/` em qualquer ancestral (caso de uso real:
  sub-planos organizados em sub-pastas).
- **Match de slug versionado** — `extracted_slug == project_slug + '-v<ver>'`
  conta como match (evita promover planos versionados do próprio projeto para B).

### Métricas

- Cobertura `_cross_project_classifier.py`: **90.72%** (gate ≥90% ✅)
- Total testes: **859 → 906** (+47 novos = 38 unit + 7 integration + 2 writer
  + 7 threat tree = **47 novos**, polish-driven 3.4× sobre o mínimo 14)
- pip-audit: **0 CVE** nas deps do projeto (mantido)
- AuditAction enum: 25 → 26 (+`f1_5_cross_project_done`)
- Camadas F1: walk + classify → **F1.5 cross-project** → emit FILTER_DIFF
- ADRs canônicos: 30 → 30 (ADR-031 operacionalizado, já estava no manifesto)
- RS-NEW críticos fechados: 2 → 3 (+RS-NEW-033)

### Comportamento INTENCIONAL documentado

- **Modo defensivo** — quando `extract_project_slug` retorna
  `UNKNOWN_PROJECT_SENTINEL` ('unknown-project') por falta de context.md E
  basename inválido, F1.5 entra em modo defensivo: TODOS planos/relatórios
  detectados pelas regras (a)/(b) vão para Grupo B com `evidence=['no_context_md_defensive']`,
  garantindo perda zero de revisão humana.
- **Cascading F1 → F1.5** (PT-RS-04 layer 3) — F1.5 só re-classifica entries
  do Grupo C `incluir` (default-include). Grupos A/B já decididos pelo F1
  deterministicamente são preservados. Promoções F1.5 sempre saem de C → A/B,
  nunca o inverso.

### Pendente / Carry-overs ativos

- C-V11-01 (.git/ ausente) — endereçar em Bloco 05 (release-tag formal).
- C-V11-02 (2 mypy errors pré-existentes em `f3_sanitizer.py`) — endereçar em Bloco 04 polish.
- C-V11-03 (bootstrap_local_copies.py --rebuild reverte injection_patterns) —
  endereçar via flag `--preserve-local-extras` em Bloco 04 polish.
  **Nesta release evitamos rodar `--rebuild` para preservar o patch v1.0.1.**

## [1.1.0-alpha.2] — 2026-05-26

> Release técnico interno (Bloco 02 do plano v1.1.0). Adiciona **Camada C10
> Path Sanitizer** ao F3, endereçando RS-NEW-032 (gap B do audit 2026-05-22 —
> 3.401 ocorrências de paths absolutos no destino). Aguarda Blocos 03–05 para
> o release oficial v1.1.0.

### Adicionado

- **Camada C10 Path Sanitizer** (ADR-030) — detector determinístico de paths
  absolutos Windows (`[A-Z]:[\\/]...`) e Unix (`/(home|Users)/<user>/...`) em
  arquivos texto. Aplicado entre Camada C9 (PII) e Camada C7 (leak-rescan).
  Três políticas canônicas por match:
  - **(a) `intra_source`** — path dentro da source-tree → relativiza para `./<rel>`
    via `Path.relative_to` (preserva semântica para clones).
  - **(b) `user_path`** — path contendo username em `OperatorIdentity.usernames`
    → redata prefixo até segmento do username por `~/<suffix>`.
  - **(c) `other_absolute`** — qualquer outro absoluto → redata para
    `<workspace>/<suffix>` (extrai suffix após `/VS Code/`, `<workspace>/` ou `<workspace>/`).
- `_path_sanitizer.py` em `src/repo_sanitizer/helpers/` — módulo NOVO com 2
  regex pré-compilados (`WINDOWS_PATH_RE` + `UNIX_PATH_RE`), `PathMatch`
  dataclass, `classify_path` + `sanitize_paths` API pública. Cobertura 94.29%.
- `F3Result.path_matches` + `F3Result.path_by_category` — agregados Camada C10
  no resultado canônico do `run_f3`.
- `AuditAction "f3_c10_paths_done"` — audit emitido SEMPRE (mesmo com zero
  paths) para trail completo do gate G2 (ADR-032, próximo bloco).
- `SANITIZATION_REPORT.md` — frontmatter `path_by_category:` SEMPRE presente
  (chaves: `intra_source` / `user_path` / `other_absolute`) + nova seção
  body "## Camada C10 — Path Sanitizer" com tabela por categoria.
- Fixture adversarial `tests/fixtures/adversarial/path_leakage_fixture/` —
  3 arquivos (README + .py + diff) com 5 Win + 3 /home/ + 2 /Users/ + 1
  username canônico, alimentando o threat tree RS-NEW-032.
- `tests/security/test_threat_tree_C10.py` — 4 testes adversariais
  (RS-NEW-032 + AT-C10-01..03) com re-grep canônico contra os regex exports.

### Comportamento INTENCIONAL documentado

- **Cascading sanitization C9 → C10** (PT-RS-04 layer 3) — C9 redata
  `OperatorIdentity.usernames` para `[REDACTED-USER]` ANTES de C10 ver o texto.
  Logo, paths como `<workspace>/[REDACTED-NAME]/...` chegam ao C10 como
  `<workspace>/[REDACTED-USER]/...` e caem na política (c) `other_absolute` em
  vez de (b) `user_path`. **O objetivo final (zero path absoluto + zero PII)
  é atingido** — apenas a atribuição final de categoria muda. Documentado no
  docstring do `_path_sanitizer.py` e nos testes integration/threat tree.

### Métricas

- **+26 testes novos** (18 unit + 4 integration + 4 threat tree) — plano pedia
  12+; entregue 2.17× polish-driven.
- **R-01 zero regressão**: 833 → 859 testes verdes.
- Ruff + mypy strict verdes nos arquivos novos.
- pip-audit 0 CVE em deps.
- `repo-sanitize --version` → `1.1.0-alpha.2`.

## [1.1.0-alpha.1] — 2026-05-26

> Release técnico interno (Bloco 01 do plano v1.1.0). Funcionalidade nova mas
> ainda em alpha; aguarda Blocos 02–05 para o release oficial v1.1.0.

### Adicionado
- **Camada C9 PII Detector** (ADR-029) — detecção determinística de PII do operador
  no destino sanitizado. Cobre 4 categorias:
  - `names` — nomes próprios case-insensitive Unicode-aware via `regex` lib
    (essencial para PT-BR: "[REDACTED-NAME]", "Gonç[NOME]", "João"). Match → `[REDACTED-NAME]`.
  - `usernames` — username de SO case-sensitive (auto-populated via
    `os.getlogin` + `getpass.getuser` quando vazio). Match → `[REDACTED-USER]`.
  - `domains` — domínios privados (ex.: `[REDACTED-NAME].ai`). Match → `[REDACTED-DOMAIN]`.
  - `extra_redact_patterns` — regex custom (validados por `re.compile` no schema).
    Match → `[REDACTED-CUSTOM]`.
- `OperatorIdentitySchema` (Pydantic v2, `ConfigDict(extra="forbid")`) em
  `src/repo_sanitizer/schemas/operator_identity_schema.py` — modelo canônico
  com auto-populate de usernames via `@model_validator(mode="before")`.
- `load_operator_identity(project_root)` em
  `src/repo_sanitizer/helpers/_operator_identity_loader.py` — loader best-effort
  com degrade gracioso em 4 cenários (ausente / malformado / schema-fail / OSError).
- `PIIMatch` dataclass em `src/repo_sanitizer/helpers/_pii_match.py` —
  representação imutável de matches com `excerpt_redacted` (50-char context já
  redatado; nunca vaza valor literal — PT-RS-04 layer 3).
- `run_c9_pii_detector(text, identity)` em `src/repo_sanitizer/f3_sanitizer.py` —
  4 detectors em ordem canônica A → B → C → D.
- `F3Result.pii_matches` + `F3Result.pii_by_category` — novos campos.
- `run_f3(..., identity=)` — novo kwarg opcional (default `None` → carrega
  via loader; permite injeção em tests).
- `AuditAction` Literal estendido com `"f3_c9_pii_done"`.
- `SANITIZATION_REPORT.md` — nova seção "Camada C9 — PII Detector (Operator Identity)"
  com counts agregados + tabela canônica `| Categoria | Count | Sample | Tipos de arquivo |`.
- Frontmatter YAML do report inclui `pii_by_category:` (sempre presente — boilerplate).
- `src/repo_sanitizer/operator_identity.json.template` (committed) — boilerplate JSON.
- `src/repo_sanitizer/operator_identity.json` (gitignored) — per-operator config.
- Entries `.gitignore`: `src/repo_sanitizer/operator_identity.json` +
  `!src/repo_sanitizer/operator_identity.json.template`.
- Seção "Setup do operador (Camada C9 PII Detector — v1.1.0+)" em `README.md`.
- **+50 testes novos** (11 schema + 8 loader + 18 unit C9 + 5 threat-tree + 2 report writer).

### Modificado
- `pyproject.toml` — version `1.0.1` → `1.1.0-alpha.1`.
- `src/repo_sanitizer/__init__.py` — `__version__` atualizado.
- `src/repo_sanitizer/schemas/__init__.py` — export adicional `OperatorIdentitySchema`.

### Notas arquiteturais
- **Cascading sanitization** intencional: detectors A→B→C→D podem consumir prefixos
  de patterns posteriores quando há overlap (ex.: `username="[REDACTED-NAME]"` consome
  o início de `extra_redact_patterns=["<REDACTED-EMAIL_PESSOAL>"]`). Resultado final:
  zero PII vazada (objetivo atingido), mas atribuição de categoria pode mudar de
  "custom" para "username". Documentado no docstring de `run_c9_pii_detector`.
- **Namespace duplo "C9"**: `CATEGORY_TITLES["C9"]` v1.0.1 (categoria SECRET_MATRIX —
  URLs internas / hostnames) coexiste com a nova **Camada C9 PII Detector** (layer
  macro v1.1.0). Distinção mantida via seções distintas no report (`secrets_by_category`
  vs `pii_by_category`).
- **Backward-compat 100%**: 783+ testes v1.0.1 continuam passing. Comandos CLI
  inalterados.

### Carry-overs documentados
- **C-V11-01**: Pasta-fonte do agente sem `.git/` — Gate 5 Opção A não pôde ser
  executado (tag/branch). [REDACTED-NAME] decide no Bloco 05 sobre `git init` + tag v1.1.0
  vs continuar local-first.
- **C-V11-02**: 2 mypy errors pré-existentes em `f3_sanitizer.py` (linhas 237 +
  1113) — limitações de inferência v1.0.1 não-introduzidas no Bloco 01.
  Endereçar em Bloco 04 polish ou v1.1.0-rc.1.

## [1.0.1] — 2026-05-13

> v1.0.0 RELEASE OFICIAL com 4 fast-follows aplicados em ~50min pós-release
> (SA-01 patch INJ-01/04 + AP-RS-01 timeout subprocess + AP-RS-02 naming plural +
> AP-RS-03 README status). Pipeline A+ Fases 0..8 ENCERRADAS.

Ver `release-notes-v1.0.1.md` para detalhes.

## [1.0.0] — 2026-05-12

> Primeira release oficial. F1 Filter + F2 Organizer + F3 Sanitizer + F4 README.
> 7 Camadas defensivas + 10 categorias SECRET_MATRIX + 30 RS rastreados.

Ver `release-notes-v1.0.0.md` para detalhes.
