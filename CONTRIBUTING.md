# Como Contribuir

Obrigado pelo interesse em contribuir com este projeto! Este documento explica
como propor mudancas, abrir issues e enviar pull requests.

## Codigo de Conduta

Este projeto e regido por um [Codigo de Conduta](CODE_OF_CONDUCT.md). Ao
participar, espera-se que voce respeite estes termos. Reporte comportamento
inaceitavel para **<EMAIL-DO-MANTENEDOR>**.

## Como Reportar Bugs

1. Verifique se o bug ja nao foi reportado em [Issues](../../issues).
2. Crie uma nova issue com:
   - Titulo descritivo (ex: "Erro ao processar arquivo X com encoding Y").
   - Passos para reproduzir o problema.
   - Comportamento esperado vs comportamento observado.
   - Versao do projeto / sistema operacional / versao de Python (ou stack
     relevante).
   - Logs ou screenshots quando aplicavel.

## Como Sugerir Melhorias

1. Abra uma issue com a tag `enhancement`.
2. Descreva o problema que a melhoria resolve.
3. Proponha uma solucao concreta (com exemplos quando possivel).
4. Aguarde feedback dos mantenedores antes de comecar a implementar.

## Fluxo de Pull Request

1. Fork o repositorio.
2. Crie uma branch a partir de `main` com nome descritivo:
   - `feat/<descricao>` para novas funcionalidades.
   - `fix/<descricao>` para correcao de bug.
   - `docs/<descricao>` para mudancas em documentacao.
   - `refactor/<descricao>` para refatoracoes.
3. Faca commits atomicos com mensagens claras em portugues ou ingles
   (escolha um e mantenha consistencia dentro do PR).
4. Adicione ou atualize testes cobrindo as mudancas.
5. Garanta que o linter e os testes passem localmente antes de abrir o PR.
6. Abra o PR descrevendo:
   - O que mudou e por que.
   - Issues fechadas (ex: "Fecha #42").
   - Riscos e quem deve revisar.

## Padroes de Codigo

- Siga o estilo ja estabelecido no projeto (`.editorconfig`, formatador
  configurado, linter).
- Documente funcoes publicas com docstrings claras.
- Evite acoplamentos desnecessarios entre modulos.
- Prefira composicao a heranca.
- Escreva codigo legivel: prefira clareza sobre concisao "esperta".

## Testes

- Toda PR de codigo deve incluir teste novo ou atualizado.
- Bugs corrigidos devem ter teste de regressao.
- Teste local (`pytest`, `npm test`, `cargo test`, etc) deve passar antes
  do PR.

## Revisao

- PRs sao revisados por pelo menos 1 mantenedor.
- Comentarios de review devem ser tratados antes do merge.
- Discussoes longas devem ser movidas para issues separadas.

## Licenca

Ao contribuir, voce concorda que sua contribuicao sera licenciada sob a mesma
licenca do projeto (ver arquivo `LICENSE`).
