# scan_wifi_ACS

Painel interno para consultar dispositivos no Flashman ACS, executar diagnósticos de redes vizinhas e recomendar canais Wi-Fi. A recomendação pode usar o algoritmo local ou o Ollama.

## Permissões e cuidado operacional

Este serviço acessa a API Flashman com credenciais OAuth2. Ele lista números de série, inicia diagnósticos nos roteadores e pode **alterar o canal Wi-Fi de equipamentos reais**. Uma alteração pode desconectar dispositivos por alguns instantes.

Todas as rotas `/api/*` exigem o segredo `API_TOKEN`. Não exponha o serviço à internet ou a uma rede compartilhada sem TLS e controle de acesso de rede. Por padrão, o processo escuta apenas em `127.0.0.1`. Em Docker, o processo escuta na rede do container; o exemplo publica a porta somente no loopback do host.

O token é compartilhado por quem opera o painel e fica em `sessionStorage` apenas na aba atual. Ele dá acesso a todas as funções do serviço. Guarde-o como uma credencial e não o envie em chamados ou logs.

## Configuração local

Requer Node.js 22 ou mais recente.

```bash
npm ci
cp .env.example .env
```

Edite `.env`, informe as credenciais OAuth2 Flashman e crie um token aleatório:

```bash
openssl rand -base64 48
```

Cole o resultado em `API_TOKEN` e inicie o painel:

```bash
npm start
```

Abra `http://127.0.0.1:3000`, conecte usando o valor de `API_TOKEN` e escolha um roteador. A interface pede confirmação antes de enviar uma alteração de canal.

Para usar recomendações via IA, inicie o Ollama, baixe `qwen3.5:0.8b` e configure `OLLAMA_URL` se ele não estiver em `http://127.0.0.1:11434`.

## Docker

O projeto tem `Dockerfile`, mas não contém um arquivo Compose. Crie `.env` com os valores acima e execute:

```bash
docker build -t scan-wifi-acs .
docker volume create scan-wifi-acs-data
docker run -d --name scan-wifi-acs \
  --env-file .env \
  -p 127.0.0.1:3000:3000 \
  --mount source=scan-wifi-acs-data,target=/data \
  scan-wifi-acs
```

O volume mantém logs, auditoria e arquivos arquivados entre reinícios. O container roda como usuário sem privilégios e inclui healthcheck em `/health`. Para conectar o Ollama que roda no host, ajuste `OLLAMA_URL` para um endereço acessível a partir do container.

Se Flashman usar uma CA privada, monte o arquivo PEM como somente leitura no container e configure `FLASHMAN_CA_FILE` para o caminho dentro dele.

## Variáveis de ambiente

| Variável | Uso |
|---|---|
| `FLASHMAN_CLIENT_ID` | Client ID OAuth2 Flashman |
| `FLASHMAN_CLIENT_SECRET` | Client secret OAuth2 Flashman |
| `API_TOKEN` | Segredo aleatório de pelo menos 32 bytes para as rotas da API |
| `FLASHMAN_API_BASE_URL` | Base HTTPS da API Flashman |
| `FLASHMAN_CA_FILE` | PEM opcional da CA privada da API Flashman |
| `OLLAMA_URL` | Base HTTP(S) do Ollama |
| `HOST` / `PORT` | Interface e porta locais; padrão `127.0.0.1:3000` |
| `TRUST_PROXY` | IPs ou sub-redes dos proxies reversos confiáveis; mantenha vazio sem proxy |
| `LOG_FILE` | Caminho do log operacional persistido |
| `AUDIT_FILE` | Caminho do registro de auditoria append-only |
| `LOG_ARCHIVE_DIR` | Diretório dos arquivos de log arquivados |

Se credenciais antigas foram publicadas ou compartilhadas, rotacione o client secret no provedor. Veja [SECURITY.md](SECURITY.md) para as regras de segurança e operação.

## Verificação estática

```bash
npm run check
npm audit --audit-level=high
```

## Licença

MIT — veja [LICENSE](LICENSE).
