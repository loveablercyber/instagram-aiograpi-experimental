# Infrastructure Separation

## Fora do Escopo

O servico atual de WhatsApp/Baileys nao e parte desta POC. Este diretorio nao importa codigo, variaveis, collections, arquivos de sessao ou credenciais do ambiente existente.

## Novo Ambiente Experimental

Componentes esperados:

- Novo Web Service no Render: `instagram-aiograpi-experimental`.
- Novo projeto/cluster MongoDB Atlas.
- Database exclusivo: `instagram_aiograpi_experimental`.
- Collections exclusivas:
  - `instagram_experimental_sessions`
  - `instagram_experimental_audit`
  - `instagram_experimental_messages`

## Garantias Implementadas

- `MONGODB_DATABASE` precisa ser exatamente `instagram_aiograpi_experimental`.
- Collections precisam usar os nomes experimentais esperados.
- Configuracoes com termos `baileys` ou `whatsapp` sao rejeitadas.
- `INSTAGRAM_PASSWORD` precisa ficar vazio nesta fase.
- Polling nao pode ser habilitado enquanto conexao real estiver desabilitada.
