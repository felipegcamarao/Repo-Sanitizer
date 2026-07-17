# repo-sanitizer-agent

> Agente local-first (PT-BR, Windows 11) que duplica um repositório local e produz
> uma réplica **publish-ready** para o GitHub: filtra lixo/pessoal (F1), sanitiza
> segredos e PII (F3), organiza a árvore (F2) e prepara o README (F4) — **sem
> nunca tocar no repositório-fonte** (INV-1) e **sem nunca publicar sozinho** (INV-2).

**v1.3.0 (2026-07-12)** — auditada por red team com veredito registrado em
`auditoria-confianca-v1-2026-07-12.md`. Gate: 1305 testes / 0 falhas, ruff 0,
mypy strict 0, pip-audit 0 CVE.

## Quickstart (5 passos)

```powershell
# 1. Instale (venv própria + editable install)
cd "./"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# 2. Configure sua identidade (o que o agente deve redatar de VOCÊ)
copy src\repo_sanitizer\operator_identity.json.template src\repo_sanitizer\operator_identity.json
notepad src\repo_sanitizer\operator_identity.json   # preencha nomes/domínios/padrões

# 3. Dry-run (só relatório; ZERO escrita no destino)
.\.venv\Scripts\repo-sanitize.exe dry-run --source-path "<workspace>/"

# 4. Revise o FILTER_DIFF gerado e aplique de verdade
.\.venv\Scripts\repo-sanitize.exe sanitize-apply --slug meu-repo --source-path "<workspace>/"

# 5. Finalize (gate G2 bloqueante) e revise o SANITIZATION_REPORT antes de publicar
.\.venv\Scripts\repo-sanitize.exe sanitize-finalize --slug meu-repo --source-path "<workspace>/"
```

Entre os passos 4 e 5, opcionalmente rode `generate-readme --slug meu-repo
--source-path ...` para gerar um README novo via Claude Code (senão o README
sanitizado do fonte é mantido; se ausente, um stub é criado).

Por default o destino nasce em `<workspace>/Git Hub - [REDACTED-NAME]/GIT_[slug]` e os
relatórios em `...\Relatorios\`. Use `--dest-root` e `--relatorios-dir` para
mudar.

## Como interpretar o resultado

| Sinal | Significado | Ação |
|---|---|---|
| `exit 0` + G2 `a=OK b=OK c=OK d=OK` | Réplica limpa e verificada | Revisar report + publicar manualmente |
| `exit 7` (Gate G2) | Paths absolutos OU PII do operador AINDA no destino (amostras no audit-log e no report; `FILENAME:` = PII no nome do arquivo) | Renomear/ajustar no FONTE e re-rodar. NÃO publicar |
| `exit 8` | Artefato de histórico Git na réplica | NÃO publicar; remover e re-rodar |
| `exit 2/3` | Fonte mudou durante o run / integrity mismatch | Investigar antes de qualquer coisa |
| `SANITIZATION_REPORT_[slug]_[ts].md` | O QUE foi removido/redatado (categoria + arquivo + linha; NUNCA o valor literal) + Checklist de Publicação 10 itens | Ler INTEIRO antes do push |
| `FILTER_DIFF_[slug]_[ts].md` | O que entra (C), o que sai (A) e o que ficou ambíguo (B — revisar) | Conferir grupo B |

## Checklist de uso seguro (antes de publicar QUALQUER repo)

1. Rode SEMPRE `dry-run` primeiro e leia o FILTER_DIFF (especialmente Grupo B).
2. Confirme que `operator_identity.json` cobre TODAS as variações do seu nome —
   **inclusive sem acento** (`[REDACTED-NAME]` além de `[REDACTED-NAME]`) e derivados
   (`[REDACTED-NAME]`, `[REDACTED-NAME]`): o detector é case-insensitive, mas
   acento-sensível e delimitado por palavra.
3. `exit 7` é seu amigo: identificadores tipo `seunome_score` e arquivos tipo
   `[REDACTED-NAME]-helper.py` NÃO são renomeados automaticamente (quebraria o build) —
   renomeie no fonte e re-rode.
4. Leia o SANITIZATION_REPORT inteiro + o Checklist de Publicação (10 itens).
5. No destino, rode uma verificação independente (não confie só no agente):
   `Get-ChildItem -Recurse -File | Select-String -Pattern "seunome|seudominio|sk-|AKIA|ghp_"`.
6. Opcional (recomendado): rode `gitleaks`/`trufflehog` externos sobre o destino.
7. Faça `git init` NOVO no destino — nunca reaproveite o `.git` do fonte
   (histórico é o vetor nº 1 de vazamento; o gate exit 8 existe por isso).
8. Se um segredo REAL apareceu em qualquer relatório: **rotacione a credencial**
   (LGPD/INV-12) — assuma comprometida.

## Limitações conhecidas (honestas)

- **Não reescreve histórico Git** — a réplica nasce SEM `.git/` (histórico
  excluído por inteiro). Se você quer publicar preservando histórico, este
  agente não é a ferramenta.
- **Nomes embutidos em identificadores/nomes de arquivo não são redatados**
  (ex.: `seunome_score`) — são BLOQUEADOS (exit 7) para você renomear no fonte.
- **Binários "safe" são copiados com scan parcial**: só os primeiros 64 KB
  recebem deep scan; EXIF/metadados de imagens NÃO são inspecionados (apenas
  flagados no report).
- **Segredos sem prefixo conhecido dependem da camada de entropia** (default
  ON) — senha curta de baixa entropia em prosa livre pode escapar da matriz.
- **Detector de nomes é acento- e palavra-sensível** — variações não declaradas
  no `operator_identity.json` escapam da C9 (o G2 pega substring
  case-insensitive, mas apenas dos nomes/usernames/domínios declarados).
- **EXCEÇÃO ÚNICA**: em `LICENSE*`, o NOME do titular do copyright é preservado
  (obrigação da licença MIT); usernames/domínios/e-mails são redatados até lá.
- **PT-BR/Windows-first**: templates e heurísticas de PII são calibrados para
  BR (CPF/CNPJ/telefone) e paths Windows/Unix.
- `markdownlint`/`markdown-link-check` são opcionais (degrade gracioso se
  ausentes — o report registra `NOT_AVAILABLE`).

## Pipeline e exit codes

```
dry-run (F1) -> sanitize-apply (F3 sanitiza -> F2 organiza) -> generate-readme (F4) -> sanitize-finalize (G2)
```

Exit codes: `0` ok · `1` erro genérico · `2` INV-1 (fonte mudou) · `3` integrity
mismatch · `4` transição FSM inválida · `5` escrita fora do boundary · `6`
timeout regex F3 · `7` Gate G2 bloqueante · `8` histórico Git no destino.

Camadas F3: matriz 10 categorias (C1 `.env` → `.env.example`, C2 chaves API,
C3 JWT/Bearer, C4 DB-URLs, C5 PII BR, C6 secrets em config, C7 certificados/PEM,
C8 exports de clientes, C9 hosts internos, C10 TODO-markers) + PII do operador
(C9-op) + paths absolutos (C10-op) + autoria em manifests + entropia Shannon +
re-scan do destino + gate de histórico Git + política binária 3-tier.

## Estrutura

```
Repo Sanitizer Agent/
├── pyproject.toml            # v1.3.0; deps runtime: pydantic + regex
├── integrity.md              # SHA-256 manifest (verificado a CADA invocação)
├── auditoria-confianca-v1-2026-07-12.md   # veredito da auditoria red team
├── src/repo_sanitizer/       # cli, orchestrator, f1..f4, helpers/, schemas/
│   └── operator_identity.json.template    # copie para operator_identity.json (gitignored)
├── tests/                    # unit / integration / security (incl. AUD-01..07)
├── scripts/                  # bootstrap_local_copies, verify_integrity_manifest
└── docs/processo/            # artefatos do pipeline A+ (histórico do projeto)
```

## Validação local

```powershell
.\.venv\Scripts\python.exe -m pytest --cov -q      # 1305 passed / cobertura ~90%
.\.venv\Scripts\python.exe -m ruff check src tests # 0 erros
.\.venv\Scripts\python.exe -m mypy src             # strict, 0 erros
.\.venv\Scripts\python.exe -m pip_audit            # 0 CVE
python scripts\verify_integrity_manifest.py        # gate anti-tampering
```

---

**O operador revisa o FILTER_DIFF e o SANITIZATION_REPORT em CADA execução —
humano-no-loop é a última camada de defesa.**
