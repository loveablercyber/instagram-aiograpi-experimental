# Manual Login Future

Nao executar nesta fase.

Fluxo planejado para Fase 2:

1. Criar conta secundaria de teste.
2. Configurar temporariamente `INSTAGRAM_USERNAME`.
3. Inserir senha somente se a Fase 2 exigir login por usuario/senha.
4. Manter `INSTAGRAM_REAL_CONNECTION_ENABLED` habilitado apenas durante janela controlada da Fase 2, apos revisao do codigo.
5. Ao obter settings reais via `aiograpi`, salvar imediatamente em MongoDB criptografado.
6. Remover senha das variaveis depois de validar restauracao.
7. Reiniciar o servico e validar sessao sem novo login.
8. Parar em caso de challenge recorrente ou bloqueio.

Nao usar conta principal, conta de cliente, Selenium, Chromium, Playwright ou API oficial da Meta.

## Fluxo seguro de primeira autenticacao do Instagram

Estado obrigatorio antes de uma tentativa real:

1. `INSTAGRAM_REAL_CONNECTION_ENABLED=true`.
2. `INSTAGRAM_POLLING_ENABLED=false`.
3. `INSTAGRAM_USERNAME` e `INSTAGRAM_PASSWORD` configurados somente no Render, nunca no GitHub.
4. Nenhuma tentativa automatica ou repetida em loop.

Executar somente uma tentativa manual por comando explicito:

```http
POST /internal/instagram/login
Authorization: Bearer <INTERNAL_API_TOKEN>
Content-Type: application/json

{
  "confirmManualAttempt": "RUN_ONE_MANUAL_LOGIN_ATTEMPT"
}
```

O endpoint pode retornar diagnosticos sanitizados como:

- `success`: settings reais foram capturadas e salvas criptografadas.
- `two_factor_required`: enviar codigo somente por endpoint interno protegido.
- `challenge_required`: revisar o contexto sanitizado antes de enviar codigo.
- `checkpoint_required`: parar e verificar app/e-mail do Instagram.
- `unknown_error`: nao repetir automaticamente; analisar diagnostico sanitizado.
- `blocked`: parar e verificar conta, IP, rate limit ou contexto de rede.
- `invalid_credentials`: nao assumir senha errada sem revisar contexto/IP/dispositivo.
- `transport_error`: falha de rede/transporte, ainda sem retry automatico.

Consultar a ultima tentativa:

```http
GET /internal/instagram/auth-attempts/latest
Authorization: Bearer <INTERNAL_API_TOKEN>
```

O diagnostico nunca deve conter senha, cookies completos, `sessionid`, `csrftoken`, header de autorizacao, codigo 2FA, settings em claro ou URI do MongoDB.

Se a tentativa retornar `unknown_error`, `checkpoint_required`, `blocked`, `sentry_block`, `throttled` ou `please_wait`, interrompa o teste. A proxima tentativa exige nova autorizacao manual e novo corpo com `confirmManualAttempt`.

Polling permanece separado da autenticacao. Ele so podera ser estudado depois que existir sessao persistida, restaurada e validada por `/internal/instagram/session/validate`.
