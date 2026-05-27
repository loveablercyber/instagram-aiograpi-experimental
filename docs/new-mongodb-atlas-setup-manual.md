# New MongoDB Atlas Setup Manual

Execute manualmente no MongoDB Atlas. Nao reutilize cluster, usuario ou database do WhatsApp/Baileys.

1. Crie ou acesse um projeto Atlas exclusivo para esta POC.
2. Crie um cluster experimental.
3. Crie o database `instagram_aiograpi_experimental`.
4. Crie um usuario exclusivo para a POC.
5. Conceda permissao apenas ao database `instagram_aiograpi_experimental`.
6. Configure Network Access para o novo Render.
7. Se precisar liberar acesso amplo temporariamente para Render Free, registre o risco e endureca depois.
8. Copie a URI com senha somente para o painel seguro do novo Render.
9. Configure `MONGODB_URI` somente no novo servico Render.
10. A aplicacao criara indices nas collections experimentais durante startup.

## Collections Esperadas

- `instagram_experimental_sessions`
- `instagram_experimental_audit`
- `instagram_experimental_messages`

## Exposicao de URI

Se a URI vazar:

1. Troque imediatamente a senha do usuario Atlas experimental.
2. Revogue o usuario se necessario.
3. Apague sessoes experimentais.
4. Gere nova `SESSION_ENCRYPTION_KEY` se houver risco de exposicao conjunta da chave.
5. Atualize somente o novo Render.
