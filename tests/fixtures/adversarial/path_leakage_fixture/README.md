# Fixture adversarial — Path Leakage (RS-NEW-032)

Este README é uma fixture (não documentação real do projeto). Contém 5 paths
Windows + 3 paths Unix `/home/...` + 2 paths `/Users/...` + 1 path com username
do operador (variantes case/slash/backslash) para o threat tree
`tests/security/test_threat_tree_C10.py` validar a Camada C10.

## Paths Windows (5 variantes)

- `C:/Users/usra/projeto/principal.py`
- `c:/Users/usra/AppData/Local/cache.db`
- `D:\\Projetos\\Pessoais\\nota.md`
- `C:\\VS Code\\Outro Projeto\\config.json`
- `E:/dados/relatorios/2026/Q2/run.log`

## Paths Unix `/home/`

- `/home/usra/projeto/build/index.html`
- `/home/stranger/dotfiles/.config.yml`
- `/home/operator2/devops/secrets.txt`

## Paths Unix `/Users/` (macOS)

- `/Users/usra/Library/Application Support/cache.db`
- `/Users/operator2/Documents/notas.txt`

## Path com username canônico do operador

- `c:\\Users\\usra\\AppData\\Roaming\\settings.json`
