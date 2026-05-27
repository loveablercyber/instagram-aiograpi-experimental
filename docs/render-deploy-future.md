# Render Deploy Future

Deploy so deve ocorrer apos o novo ambiente Render e o novo MongoDB Atlas serem autorizados manualmente.

Checklist:

- Novo Render autorizado.
- GitHub conectado manualmente.
- Root directory configurado para `integrations/instagram-aiograpi-experimental`.
- `MONGODB_URI` aponta para o Atlas experimental.
- `SESSION_ENCRYPTION_KEY` e uma chave Fernet valida.
- `INTERNAL_API_TOKEN` forte.
- `INSTAGRAM_REAL_CONNECTION_ENABLED=false`.
- `INSTAGRAM_POLLING_ENABLED=false`.
- `INSTAGRAM_PASSWORD` vazio.
- Auto-deploy revisado pelo usuario.

Teste inicial:

```bash
curl https://<render-url>/health
curl -H "X-Internal-Token: <token>" https://<render-url>/internal/status
```

Nao chamar endpoints de login ou envio, pois eles nao existem nesta fase.
