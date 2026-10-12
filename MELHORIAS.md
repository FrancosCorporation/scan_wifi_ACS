# MELHORIAS — scan_wifi_ACS

## Resultado da implementação

Revisão e implementação concluídas em 2026-10-11 sobre o projeto Node.js/Express. O serviço controla roteadores reais pelo Flashman ACS; qualquer implantação precisa configurar credenciais, `API_TOKEN` e acesso de rede privado.

| ID | Item | Estado |
|---|---|---|
| SEC-01 | Token Bearer obrigatório antes de todas as rotas `/api/*`; respostas sem cache | Concluído |
| SEC-02 | TLS Flashman validado; CA privada configurável por PEM | Concluído |
| SEC-03 | Validação estrita e codificação do número de série | Concluído |
| SEC-04 | Arquivamento de logs e auditoria antes de alterar roteadores | Concluído |
| SEC-05 | Remoção de partes de token dos logs | Concluído |
| SEC-06 | Helmet, CSP com nonce e remoção de handlers inline | Concluído |
| SEC-07 | Limite de corpo JSON de 100 KB | Concluído |
| BUG-01 | Rate limit global e limites próprios para Flashman e Ollama | Concluído |
| BUG-02 | Respostas genéricas sem payload interno do provedor | Concluído |
| BUG-03 | Expiração e limpeza explícita do cache OAuth2 | Concluído |
| BUG-04 | Cache de falha OAuth2 por 30 segundos e `Retry-After` | Concluído |
| IMP-01 | `/health` com estado degradado e limite de consultas | Concluído |
| IMP-02 | URL do Ollama configurável por `OLLAMA_URL` | Concluído |
| TEST-01 | Testes automatizados de rotas e recomendação | Pendente para tarefa própria |
| DEVOPS-01 | CI com verificação estática, auditoria npm e barreira de autenticação | Concluído |
| DEVOPS-02 | Dockerfile não root, healthcheck e volume de dados persistente | Concluído |
| DEVOPS-03 | CI previsível em Ubuntu 24.04, Actions atuais e Node 22/24 | Concluído |
| DOC-01 | README documenta poderes de alteração dos roteadores e o risco | Concluído |
| DOC-02 | Política de segurança e operação em `SECURITY.md` | Concluído |

## Decisões e operação

- `API_TOKEN` precisa conter pelo menos 32 bytes aleatórios. Gere com `openssl rand -base64 48` e configure no ambiente antes de iniciar o servidor. Todas as rotas `/api/*` usam `Cache-Control: no-store`.
- O processo local usa `127.0.0.1` por padrão. No Docker, a aplicação usa `0.0.0.0` dentro do container; publique a porta do host em loopback ou use uma rede protegida com proxy TLS.
- O limite de requisições é mantido em memória e usa o IP observado pelo Express. Com proxy reverso, configure `TRUST_PROXY` somente com os endereços confiáveis.
- `/health` retorna `200` com estado `degraded` se o Ollama estiver indisponível, pois a consulta determinística continua funcional.
- `TEST-01` permanece pendente. A execução atual não adicionou nem executou testes automatizados.
- `DEVOPS-03`: workflow fixado em Ubuntu 24.04, Actions v7 e matriz Node 22/24, alinhada ao mínimo declarado no pacote. A matriz valida os dois majors suportados sem chamar APIs externas nem iniciar o serviço.
- CI `38195212808` passou nos dois jobs (Node 22 e 24), incluindo `npm ci`, `npm run check`, `npm audit --audit-level=high` e a barreira do middleware Bearer. Localmente, `npm run check`, audit (0 vulnerabilidades), assertions estruturais do workflow e `git diff --check` passaram. Commit `5d41103` está publicado em `origin/main`; nenhum teste, serviço, Ollama, Flashman ou roteador foi acessado.

## Verificação estática

Executar em CI ou antes de publicar:

```bash
npm run check
npm audit --audit-level=high
grep -F "app.use('/api', noStore, apiRateLimit, requireApiToken)" serve.js
```

Não fazer chamadas de validação às credenciais Flashman nem alterar roteadores durante verificações de código.
