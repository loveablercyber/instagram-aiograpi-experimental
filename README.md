# Instagram aiograpi Experimental

Microservico experimental e isolado para preparar uma POC de Instagram Direct com FastAPI, `aiograpi==1.0.9` e sessao criptografada em MongoDB Atlas.

Esta fase nao conecta Instagram, nao faz login, nao envia mensagens e nao inicia polling.

## Escopo

- Servico separado do WhatsApp/Baileys.
- MongoDB Atlas exclusivo para esta POC.
- Endpoints internos protegidos por `X-Internal-Token` ou `Authorization: Bearer`.
- Sessao futura salva somente como JSON criptografado com Fernet.
- Swagger/OpenAPI desabilitado fora de `APP_ENV=development`.
- `INSTAGRAM_REAL_CONNECTION_ENABLED=false` e `INSTAGRAM_POLLING_ENABLED=false`.

## Endpoints

- `GET /health`: publico, minimo, sem dados sensiveis.
- `GET /internal/status`: protegido, status tecnico sem segredos.
- `POST /internal/session/test-store`: protegido, salva settings ficticias criptografadas.
- `POST /internal/session/test-restore`: protegido, valida restauracao sem retornar payload.
- `DELETE /internal/session`: protegido, remove a sessao experimental ficticia quando o body confirma `REMOVE_EXPERIMENTAL_SESSION`.

Nao existem endpoints de login, threads, mensagens, envio, midia, challenge ou logout real nesta fase.

## Variaveis

Use `.env.example` como referencia. Valores reais devem ficar somente no novo Render.

Gere a chave Fernet com:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Desenvolvimento Local

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest
```

No Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m pytest
```

## Docker

```bash
docker build -t instagram-aiograpi-experimental .
docker run --rm -p 8000:8000 --env-file .env instagram-aiograpi-experimental
```

Nao use `.env` real no GitHub.

## Fase 2

A autenticacao real so deve ocorrer depois que o novo Render e o novo MongoDB Atlas estiverem autorizados manualmente, com uma conta secundaria descartavel de teste.
