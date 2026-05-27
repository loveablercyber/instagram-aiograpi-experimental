# Test Report Phase 1

Executado em ambiente local Windows, em `2026-05-27`.

## Resultado

- Dependencias instaladas em `.venv` local.
- `py -m pytest -q`: **21 passed**.
- `py -m pip check`: **No broken requirements found**.
- Importacao da factory ASGI: **ok**.
- Runtime local com env ficticio: `/health` e `/internal/status` responderam sem expor segredos.
- Build Docker: **nao executado localmente**, porque `docker` nao esta instalado/disponivel no PATH deste ambiente.

## Observacoes

- Nenhuma conta Instagram foi conectada.
- Nenhuma mensagem foi enviada.
- Nenhum MongoDB real foi acessado.
- Testes de sessao usam store em memoria e settings ficticias criptografadas.
- Teste de build Docker deve ser executado no novo Render ou em uma maquina com Docker instalado.
