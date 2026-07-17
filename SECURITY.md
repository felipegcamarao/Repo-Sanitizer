# Politica de Seguranca

## Reporte de Vulnerabilidades

Levamos seguranca a serio. Se voce descobriu uma vulnerabilidade neste projeto,
**NAO abra uma issue publica**. Em vez disso:

1. Envie um email para **<EMAIL-DO-MANTENEDOR>** com o assunto
   `[SECURITY] <breve descricao>`.
2. Inclua:
   - Descricao da vulnerabilidade.
   - Passos para reproduzir (com detalhes suficientes para validacao).
   - Impacto potencial (que dados ou comportamento sao afetados).
   - Versao(oes) afetada(s).
   - Sugestao de correcao quando disponivel.

## Resposta Esperada

- Confirmacao de recebimento em ate **72 horas**.
- Avaliacao inicial e estimativa de resolucao em ate **7 dias corridos**.
- Comunicado publico apos a correcao (creditando voce, se desejar).

## Politica de Disclosure

- Pedimos um periodo razoavel para investigar e corrigir antes da divulgacao
  publica (tipicamente **30 a 90 dias** dependendo da severidade).
- Comunicaremos progresso periodico durante a investigacao.
- Creditaremos quem reportou, salvo solicitacao explicita de anonimato.

## Escopo de Vulnerabilidades

Aceitamos reports sobre:

- Vazamento ou exposicao de credenciais / dados sensiveis.
- Execucao remota de codigo (RCE).
- Injecao (SQL, comando, prompt em LLM, etc.).
- Path traversal e escape de sandbox.
- Bypass de autenticacao / autorizacao.
- DoS / consumo excessivo de recursos.
- Outras classes OWASP Top 10.

## Fora do Escopo

- Testes em ambientes de producao de terceiros.
- Engenharia social, phishing, ataques fisicos.
- Vulnerabilidades exigindo acesso ja autenticado privilegiado (a menos que
  representem escalada de privilegio).
- Reports automatizados sem reproducao manual.

## Reconhecimento

Mantemos uma lista publica de pesquisadores que reportaram vulnerabilidades
validas (com permissao). Veja [SECURITY_ACKNOWLEDGEMENTS.md](SECURITY_ACKNOWLEDGEMENTS.md)
ou o release notes do projeto.

## Contato

**Email canonico**: <EMAIL-DO-MANTENEDOR>

Obrigado por ajudar a manter este projeto seguro.
