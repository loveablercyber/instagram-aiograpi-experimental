# Phase 0 Approved

Decisao aprovada: **B. Viavel para teste, mas exige adaptacao de sessao**.

Motivos:

- `aiograpi` suporta funcionalidades de Instagram Direct sem navegador automatizado.
- A imagem REST completa armazena sessao em TinyDB/arquivo local.
- Render Free possui filesystem efemero.
- A POC precisa salvar settings de sessao fora do container, criptografadas, em MongoDB Atlas exclusivo.

Restricoes mantidas:

- Nao alterar o servico WhatsApp/Baileys.
- Nao reutilizar banco, collections, variaveis ou segredos do servico existente.
- Nao conectar Instagram nesta fase.
- Nao enviar mensagens reais.
- Nao habilitar polling real.
