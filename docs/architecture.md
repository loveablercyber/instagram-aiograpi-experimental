# Architecture

```mermaid
flowchart TD
  A["Render Web Service: instagram-aiograpi-experimental"] --> B["FastAPI internal endpoints"]
  B --> C["InstagramClientService"]
  C --> D["SessionStore"]
  D --> E["MongoDB Atlas experimental database"]
  B --> F["AuditService"]
  F --> E
  C -. "blocked in Phase 1" .-> G["Instagram Private API via aiograpi"]
```

## Runtime

- Python 3.13.
- FastAPI/Uvicorn.
- `aiograpi==1.0.9`, pinado conforme a decisao da Fase 0.
- PyMongo async client.
- Fernet authenticated encryption via `cryptography`.

## Security Defaults

- Swagger/OpenAPI apenas em `APP_ENV=development`.
- Endpoints internos exigem token.
- Settings ficticias sao criptografadas antes de persistir.
- Real Instagram API permanece bloqueada.
- Polling permanece bloqueado.
