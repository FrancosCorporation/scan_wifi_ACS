# scan_wifi_ACS

## 🐳 Instalação e Execução (Docker) — recomendado

### Pré-requisitos
- [Docker](https://docs.docker.com/get-docker/) + Docker Compose

### Rodar com Docker
```bash
docker compose up --build
```


### Sem Docker (local)
```bash
npm install
npm start
```


Serviço de integração em **Node.js/Express** que consulta a API do sistema
**Flashman** (gestão de provedores/ACS), pagina os resultados, mantém um log
local e usa IA local (Ollama) para analisar os logs.

![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=flat-square&logo=express&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-IA%20local-black?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-ferramenta%20interna-orange?style=flat-square)

## Sobre

Ferramenta de uso interno para integrar com a API do Flashman (OLV Telecom),
coletando dados paginados com credenciais de cliente e registrando tudo em
arquivo, com endpoints próprios para consultar os logs. Há integração opcional
com o Ollama para análise dos registros por IA local.

## Funcionalidades

Comprovadas pelo código em `serve.js`:

- Servidor Express na porta `3000` com `dns` forçado a IPv4.
- Autenticação na API do Flashman via **client id/secret** (agora lidos de
  variáveis de ambiente — veja `.env.example`).
- Consumo paginado da API (`FLASHMAN_MAX_PAGE_SIZE = 50`).
- Sistema próprio de **logs** persistidos em `flashman_logs.json`, com
  endpoints para listar/filtrar logs.
- Integração opcional com **Ollama** (`qwen3.5:0.8b`) para análise dos logs.

## Como rodar

```bash
npm install
cp .env.example .env   # preencha as credenciais do Flashman
node server.js         # ou: node --watch server.js
```

Consultar logs:

```bash
curl http://localhost:3000/api/logs
```

Para análise com IA, tenha o Ollama rodando (`ollama serve`) e o modelo
baixado (`ollama pull qwen3.5:0.8b`).

## Configuração

| Variável | Descrição |
|---|---|
| `FLASHMAN_CLIENT_ID` | Client ID da API do Flashman |
| `FLASHMAN_CLIENT_SECRET` | Client secret da API do Flashman |
| `FLASHMAN_API_BASE_URL` | Base da API (padrão: `https://flashman.olvtelecom.com.br`) |
| `OLLAMA_URL` | URL do Ollama (opcional) |

> As credenciais que estavam embutidas no código foram movidas para variáveis
> de ambiente. Se a versão antiga vazou, **rotacione o client secret** no
> painel do provedor.

## Estrutura do projeto

```
serve.js          # servidor Express + integração Flashman + logs
package.json      # dependências (express, axios)
readme.md         # roteiro original de setup
```

## Licença

MIT — veja [LICENSE](LICENSE).
