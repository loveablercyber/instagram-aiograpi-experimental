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
