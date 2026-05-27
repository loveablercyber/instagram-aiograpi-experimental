# Security Checklist

- [x] Sem alteracao no Baileys.
- [x] Sem WhatsApp neste servico.
- [x] Sem Beeper, mautrix ou API oficial da Meta.
- [x] Sem navegador automatizado.
- [x] Sem Swagger em `APP_ENV=experimental`.
- [x] Endpoints internos protegidos por token.
- [x] Sessao ficticia criptografada antes de persistir.
- [x] MongoDB database validado como experimental.
- [x] Collections validadas como experimentais.
- [x] Senha Instagram rejeitada durante Fase 1.
- [x] Polling bloqueado por padrao.
- [x] Chamada real ao Instagram bloqueada por padrao.
- [x] Logs/auditoria sem payload sensivel.

Pendencias antes da Fase 2:

- Autorizar novo Render manualmente.
- Criar novo MongoDB Atlas manualmente.
- Validar IP/network access do Atlas.
- Testar deploy sem login.
- Revisar codigo antes de permitir login real.
