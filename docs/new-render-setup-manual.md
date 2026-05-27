# New Render Setup Manual

Execute manualmente no dashboard do Render. Nao aceite termos, crie contas ou autorize GitHub por automacao.

1. Entre no novo ambiente Render autorizado para a POC.
2. Conecte o GitHub manualmente em **Account Settings > Git Providers** ou durante a criacao do Web Service.
3. Autorize somente o repositorio que contem `integrations/instagram-aiograpi-experimental`.
4. Crie um novo **Web Service** com Docker.
5. Configure o root directory como `integrations/instagram-aiograpi-experimental`.
6. Use o nome `instagram-aiograpi-experimental`.
7. Mantenha `autoDeploy` desabilitado ate validar as variaveis.
8. Configure as variaveis seguras do `.env.example` no painel do Render.
9. Confirme que `INSTAGRAM_REAL_CONNECTION_ENABLED=false`.
10. Confirme que `INSTAGRAM_POLLING_ENABLED=false`.
11. Use a URL gratuita gerada pelo Render inicialmente; nao configure dominio.
12. Verifique que o servico antigo de WhatsApp/Baileys nao foi aberto, editado ou redeployado.

## Variaveis Secretas

Configure manualmente:

- `INTERNAL_API_TOKEN`
- `HEALTH_TOKEN`, se decidir usar no futuro
- `MONGODB_URI`
- `SESSION_ENCRYPTION_KEY`

Nao copie variaveis do servico Baileys.

## Remocao

Para remover a POC, delete somente o Web Service `instagram-aiograpi-experimental` e revogue o acesso GitHub se ele foi concedido apenas para este teste.
