# Segurança

Este serviço possui credenciais OAuth2 com acesso de leitura e alteração de configurações de roteadores Flashman. Trate o processo, suas variáveis de ambiente, o token de API e os arquivos de dados como componentes sensíveis.

## Invariantes

- Todas as rotas `/api/*` passam pelo middleware `requireApiToken` e usam `Cache-Control: no-store`. Gere `API_TOKEN` com `openssl rand -base64 48`, mantenha pelo menos 32 bytes e não o compartilhe em URLs, logs ou tickets.
- O cliente Flashman exige HTTPS e valida certificados por padrão. Para uma CA privada, configure `FLASHMAN_CA_FILE` com o PEM confiável. Não desative a validação TLS.
- O número de série é validado antes de compor as rotas externas e também é codificado como segmento de URL.
- Alterações de canal exigem evento de auditoria antes do envio à Flashman. Os logs operacionais são limitados; ao arquivá-los, o painel cria uma cópia e registra o evento no arquivo append-only `AUDIT_FILE`.
- O processo escuta em `127.0.0.1` por padrão. O servidor Express não termina TLS. Para acesso remoto, use uma rede privada e um proxy TLS configurado corretamente; não publique HTTP sem proteção.

## Dados e acesso

`API_TOKEN` é um segredo compartilhado, não uma conta individual. Qualquer pessoa que o conheça pode listar dispositivos, executar diagnósticos, consultar logs e mudar canais. O painel guarda o token em `sessionStorage` da aba e o remove ao sair. Rotacione o segredo se houver suspeita de exposição.

`flashman_logs.json`, `flashman_audit.jsonl` e os arquivos em `log_archive/` podem conter números de série, endereços IP e detalhes operacionais. Restrinja o acesso ao usuário do serviço, preserve o volume de dados do Docker e não os envie ao Git.

O rate limit usa memória local e o endereço IP observado pelo Express. Em proxy reverso, configure `TRUST_PROXY` apenas com os endereços exatos dos proxies antes de depender do IP para limitação ou auditoria. Não use `true` nem confie em redes públicas.

## Relato de vulnerabilidade

Informe vulnerabilidades ao mantenedor do repositório de forma privada. Não publique credenciais, tokens, números de série ou exemplos que permitam alterar roteadores reais.
