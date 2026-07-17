"""cross_project_fixture — Fixture adversarial F1.5 (ADR-031 + RS-NEW-033 + Bloco 03 / 3.4).

Simula source-tree de um projeto fictício chamado "projeto-atual" contendo:

- Arquivos intra-projeto (slug match) que DEVEM permanecer em Grupo C.
- Arquivos cross-project (planos/relatorios de OUTROS projetos) que DEVEM
  ser promovidos para Grupo B (review).
- Arquivos cache (portfolio + .eval-runs + audit baselines) que DEVEM ser
  promovidos para Grupo A (exclude).
- Arquivos ambíguos (dentro de pasta pt-BR sem prefixo) que DEVEM ir para B.

Estrutura canônica:

```
cross_project_fixture/
├── context-projeto-atual.md            # slug='projeto-atual'
├── README.md                            # intra → C (default)
├── plano-implementacao-projeto-atual.md # intra → C (rule a2 match)
├── plano-implementacao-outro-projeto.md # cross → B (rule a2 mismatch)
├── Planos de Implementação/
│   ├── plano-projeto-atual.md          # intra → C (rule a1 match)
│   ├── plano-caden-platform-v7.md      # cross → B (rule a1 mismatch)
│   └── README.md                        # ambíguo → B (sem prefixo)
├── Relatórios Staff/
│   └── relatorio-staff-nexus.md        # cross → B
├── memory/projetos.md                   # cache → A (portfolio)
├── .eval-runs/run.jsonl                # cache → A
└── audit/baseline-2026-05-15.md        # cache → A
```

Gate determinístico do threat tree: re-classificar todos os files via F1.5
e verificar promoções EXATAS (zero false-positive + zero false-negative).
"""
