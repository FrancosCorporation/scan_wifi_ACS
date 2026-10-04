# MELHORIAS — scan_wifi_ACS

> **Gerado por análise de código em 2026-10-02** · Stack: Node + Express (arquivo único, 801 linhas) + axios (OAuth2 Flashman) + Ollama local
> Branch `main` · base `de015b2` · 801 LOC · **0 testes** · sem CI
>
> **Este arquivo é um plano de execução.** Cada item tem ID, `arquivo:linha`, mudança exata,
> critério de aceite e comando de verificação.
>
> **⚠️ Este serviço controla roteadores de verdade.** As rotas `POST /api/update-channel` e
> `GET /api/scan/:sn` chamam a API de gerenciamento Flashman e **alteram a rede Wi-Fi real**.

---

## 0. Como usar este documento

1. Execute na ordem **P0 → P1 → P2 → P3**, respeitando as ondas da §8.
2. Ao terminar um item: marque `- [x]`, rode o **Verificação**, comite `fix(<ID>): descrição`.
3. **Não existe autenticação nenhuma** — confirmado por `grep` (nenhum middleware de auth, nenhum
   token de sessão, nenhum login na interface). Não há tela de login porque não há auth.
4. **Idioma:** português.

---

## 1. Diagnóstico executivo

Painel de análise Wi-Fi: busca roteadores Flashman (OAuth2), lê status, recomenda canal melhor e
**aplica a mudança no roteador**. A recomendação tem versão determinística (canais 1/6/11 em 2G) e
versão com Ollama local.

**O que está bem (não reaça):**

| Item | Evidência |
|---|---|
| OAuth2 com `client_credentials` **real** (env, não hardcode) | `serve.js:91-95` (`CLIENT_ID`/`CLIENT_SECRET` de `process.env`) |
| Header de autenticação montado só para a API Flashman | `serve.js:115` (`Authorization: Bearer`) |
| Retentativa automática em `401`/`400` (limpa o token) | `serve.js:170` |
| Validação de entrada no update (campos obrigatórios) | `serve.js:214-217` |
| `parseInt(channel)` — **não** string cru no payload | `serve.js:225` |
| Recomendação **determinística** com fallback (não depende de IA) | `getBestChannelsDeterministic` |
| `timeout: 30000` no cliente da API | `serve.js:75` |
| Registro de ações (logs) com contexto | `addLog(...)` — presente em toda rota |

**O que está quebrado:**

1. **Zero autenticação** em **9 rotas** (`app.get/post/delete`), sendo duas que **alteram** o roteador
   de terceiros.
2. **`rejectUnauthorized: false`** (`serve.js:77`) — no agente que leva as **credenciais OAuth2**.
3. **`sn` interpolado cru em 3 URLs** (`serve.js:185,191,228`) — injeção de path na API Flashman.
4. **Token com prefixo logado** (`serve.js:105`) e **logs apagáveis sem auth** (`DELETE /api/logs`).

---

## 2. Tabela de prioridades

| ID | Título | Sev | Arquivo | Depende de |
|---|---|---|---|---|
| SEC-01 | **Zero autenticação** em 9 rotas (duas alteram roteador real) | **P0** | `serve.js:122-377` | — |
| SEC-02 | `rejectUnauthorized: false` no agente OAuth2 (credenciais sem TLS verificado) | **P0** | `serve.js:77` | — |
| SEC-03 | `sn` interpolado cru em 3 URLs da API Flashman | **P1** | `serve.js:185,191,228` | — |
| SEC-04 | `DELETE /api/logs` sem auth (apaga evidências) | **P1** | `serve.js:377` | SEC-01 |
| SEC-05 | Token com prefixo de 10 chars logado | **P2** | `serve.js:105` | — |
| SEC-06 | Sem `helmet`/headers de segurança | **P2** | `serve.js` | — |
| SEC-07 | Sem limite de body no `express.json()` | **P2** | `serve.js` | — |
| BUG-01 | Sem rate limit (recomendação + update + scan) | **P1** | rotas | SEC-01 |
| BUG-02 | `error.response?.data`/`error.message` exposto ao cliente | **P2** | `serve.js:246,264` | — |
| BUG-03 | Token global em memória sem invalidação por logout | **P2** | `serve.js:86` | — |
| BUG-04 | Sem tratamento de erro no `getAccessToken` (retry em loop) | **P2** | `serve.js:89-110` | — |
| IMP-01 | Sem healthcheck (Ollama pode estar fora) | **P2** | *(ausente)* | — |
| IMP-02 | `ollamaApi` aponta para `localhost:11434` hardcoded | **P3** | `serve.js:82` | — |
| TEST-01 | Zero testes | **P1** | *(ausente)* | SEC-01, SEC-03 |
| DEVOPS-01 | Sem CI | **P2** | *(ausente)* | — |
| DEVOPS-02 | Sem Dockerfile | **P3** | *(ausente)* | — |
| DOC-01 | README não avisa que altera roteador | **P1** | `README.md` | SEC-01 |
| DOC-02 | Falta `SECURITY.md` | **P3** | *(ausente)* | — |

**Placar: 2 P0 · 4 P1 · 8 P2 · 3 P3 = 17 itens.**

---

## 3. Segurança

### SEC-01 · Zero autenticação em 9 rotas (duas alteram roteador real) · [P0]

- **Arquivo:** `serve.js:122,176,213,268,299,352,377,385,582`
- **Evidência:** `grep -n "app.get('/api\|app.post('/api\|app.delete('/api" serve.js` → **9 rotas**,
  **nenhuma** com middleware. Não existe autenticação no projeto (confirmei por `grep`: nenhum
  token, nenhuma sessão, nenhuma tela de login).
- **Impacto:**
  | Rota | Consequência sem auth |
  |---|---|
  | `POST /api/update-channel` (`:213`) | **Altera o canal Wi-Fi** de um roteador real da rede — reconecta dispositivos e pode derrubar a conectividade |
  | `GET /api/scan/:sn` (`:176`) | Dispara diagnóstico de vizinhança no roteador (`:185,191`) |
  | `GET /api/devices` (`:122`) | **Lista os roteadores** (serial numbers) — enumeração |
  | `POST /api/ai-recommend` (`:299`) | Chama **Ollama local** — consumo de GPU/CPU |
  | `DELETE /api/logs` (`:377`) | **Apaga logs** (antiforensics) |
  Qualquer pessoa na rede (ou na internet, se exposto) executa essas ações. `sn` e `channel` vêm do
  cliente, então é ataque **direcionado a um roteador específico**.
- **Mudança:** (1) **autenticação obrigatória** em todas as rotas `/api` — token simples
  (`API_TOKEN` de env, comparado com `timingSafeEqual`) via header `Authorization`, ou,
  melhor, **Bearer** com JWT se existir sessão de usuário; (2) aplicar `app.use('/api', auth)`
  **antes** das rotas; (3) deixar `GET /` (painel) público **apenas se** for o dono; (4) manter
  `/health` público.
- **Aceite:** qualquer `/api/*` sem token → `401`; com token → `200`.
- **Verificação:**
  ```bash
  for r in /api/devices /api/logs; do
    curl -s -o /dev/null -w "$r -> %{http_code}\n" "http://localhost:3000$r"   # 401
  done
  curl -s -o /dev/null -w 'DELETE /api/logs -> %{http_code}\n' -X DELETE http://localhost:3000/api/logs  # 401
  curl -s -o /dev/null -w 'POST update-channel -> %{http_code}\n' -X POST http://localhost:3000/api/update-channel \
    -H 'Content-Type: application/json' -d '{"sn":"x","band":"2G","channel":6}'   # 401
  ```

### SEC-02 · `rejectUnauthorized: false` no agente OAuth2 · [P0]

- **Arquivo:** `serve.js:77` (`httpsAgent: new https.Agent({ rejectUnauthorized: false, family: 4 })`)
- **Evidência:** o `flashmanApi` é o cliente que envia `client_id`/`client_secret` para
  `/api/v2/token/oauth` (`serve.js:97`) e depois carrega `Authorization: Bearer` (`:115`).
- **Impacto:** **credenciais OAuth2 entregues sem validar o certificado do servidor**. Um ataque
  **MITM** (proxy/ARP spoofing na mesma rede, ou DNS malicioso) termina a conexão TLS com certificado
  forjado e **captura `client_id` + `client_secret`** — e depois todos os tokens emitidos. Com essas
  credenciais, o atacante age **como este sistema** na API Flashman (leitura de roteadores e mudança
  de parâmetros). O `rejectUnauthorized: false` não é "dev mode" — está no caminho de produção.
- **Mudança:** (1) **remover** `rejectUnauthorized: false` (validar o certificado);
  (2) se o servidor Flashman usa CA própria, passar `ca:` com o PEM específico (não desativar
  a verificação); (3) se for para ambiente de desenvolvimento, condicionar por env
  (`NODE_ENV !== 'production'`) com **aviso no log**;
  (4) garantir que o `API_BASE_URL` é `https:` (não `http:`).
- **Aceite:** credenciais só trafegam com certificado **validado** (ou CA própria explícita).
- **Verificação:**
  ```bash
  grep -n 'rejectUnauthorized' serve.js && echo 'FALHA: TLS desativado' || echo OK
  grep -n 'API_BASE_URL' serve.js   # deve ser https://
  ```

### SEC-03 · `sn` interpolado cru em 3 URLs da API Flashman · [P1]

- **Arquivo:** `serve.js:185`, `:191`, `:228`
- **Evidência:**
  ```javascript
  await flashmanApi.post(`/api/v2/devices/${sn}/diagnostics/neighbor/start`, ...)
  await flashmanApi.get(`/api/v2/devices/${sn}/diagnostics/neighbor/state`, ...)
  await flashmanApi.post(`/api/v2/devices/${sn}/parameters/update`, payload, ...)
  ```
  `sn` vem de `req.params.sn` (linha 176) ou `req.body.sn` (linha 214) — **não validado**.
- **Impacto:** path traversal/URL injection na API Flashman. `sn = "../admin/..."` ou
  `sn = "x/../other"` muda o endpoint chamado — o servidor do Flashman **tenta** acessar rota que o
  atacante escolhe, com as credenciais do sistema. Também: `sn` com `?` ou `#` injeta query/fragment.
  Combinado com `SEC-01` (sem auth), é ataque direto.
- **Mudança:** (1) validar `sn` com regex estrita (serial number real: `[A-Za-z0-9-]{6,32}`);
  (2) rejeitar `400` se não casar, **antes** de montar a URL; (3) usar `encodeURIComponent(sn)` como
  defesa em profundidade; (4) **não** montar path com string crua — passar por `URL` + `encodeURI`.
- **Aceite:** `sn=../../x` → `400`; nenhuma URL externa é montada sem validação.
- **Verificação:**
  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' "http://localhost:3000/api/scan/..%2f..%2fadmin" \
    -H "Authorization: Bearer $API_TOKEN"   # 400
  ```

### SEC-04 · `DELETE /api/logs` sem auth (apaga evidências) · [P1]

- **Arquivo:** `serve.js:377`
- **Evidência:** `app.delete('/api/logs', ...)` — sem middleware; devolve
  `{ removed: N }` (a quantidade de entradas apagadas).
- **Impacto:** **qualquer um apaga os logs** do sistema. Isso é **antiforensics**: após um ataque
  (com `SEC-01`), o atacante apaga o rastro antes de ir embora. E a contagem devolvida é um
  **oracle** (quantas entradas existiam).
- **Mudança:** (1) exigir o mesmo token das demais rotas (`SEC-01`); (2) **melhor**: manter os logs
  e fazer `DELETE` com confirmação dupla (ou arquivar em vez de apagar); (3) `audit.log` imutável
  (append-only, `0600`).
- **Aceite:** `DELETE /api/logs` sem token → `401`; log de auditoria não é removível.
- **Verificação:**
  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' -X DELETE http://localhost:3000/api/logs   # 401
  ```

### SEC-05 · Token com prefixo de 10 chars logado · [P2]

- **Arquivo:** `serve.js:105`
- **Evidência:**
  ```javascript
  addLog('AUTH', 'Autenticação OAuth2 realizada com sucesso', 'success', { tokenPrefix: authToken.substring(0, 10) + '...' });
  ```
- **Impacto:** os **10 primeiros chars** do token OAuth2 vão para o log. Dependendo do provedor, isso
  pode ser suficiente para identificar/reativar o token (parcialmente reconstruir) ou, no mínimo,
  associar o token a uma sessão observável. Combinado com `SEC-04` (logs apagáveis), é inconsistente:
  loga detalhe e depois deixa o atacante apagar.
- **Mudança:** (1) **não** logar qualquer parte do token — logar só `success` + timestamp + IP;
  (2) se precisar de identificador, usar um **hash** (`sha256(token).slice(0,8)`), nunca o prefixo
  real; (3) garantir que `.env` com `CLIENT_SECRET` nunca é logado (hoje não é — só o token).
- **Aceite:** log de auth não contém nenhuma fatia do token.
- **Verificação:**
  ```bash
  grep -n 'tokenPrefix\|substring' serve.js && echo 'FALHA: parte do token logada' || echo OK
  ```

### SEC-06 · Sem `helmet`/headers de segurança · [P2]

- **Arquivo:** `serve.js` (só `express.json()` + rotas)
- **Evidência:** nenhum `helmet`.
- **Impacto:** o painel serve HTML (`GET /`, `GET /logs`) — sem `nosniff`, `X-Frame-Options` (painel
  pode ser embutido/clickjacked), HSTS.
- **Mudança:** `npm i helmet` + `app.use(helmet())`.
- **Aceite:** headers presentes.
- **Verificação:**
  ```bash
  curl -sI http://localhost:3000/ | grep -iE 'x-frame-options|x-content-type-options'
  ```

### SEC-07 · Sem limite de body · [P2]

- **Arquivo:** `serve.js` (`app.use(express.json())`)
- **Evidência:** sem `limit`.
- **Impacto:** payload ilimitado em memória (DoS). Com `SEC-01`, o risco cai, mas é barato de fechar.
- **Mudança:** `express.json({ limit: '100kb' })`.
- **Aceite:** body > 100 KB → `413`.
- **Verificação:**
  ```bash
  head -c 200000 /dev/zero | tr '\0' 'a' > /tmp/big.json
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/api/update-channel \
    -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' --data-binary @/tmp/big.json   # 413
  ```

---

## 4. Bugs e defeitos funcionais

### BUG-01 · Sem rate limit · [P1]

- **Arquivo:** rotas de `serve.js:122,176,213,268,299`
- **Evidência:** nenhuma proteção de taxa. Cada chamada dispara **rede externa** (Flashman, com
  OAuth2) ou **Ollama local** (`:299,330`) — as duas caras.
- **Impacto:** um laço dispara `POST /api/ai-recommend` repetidas vezes → Ollama saturado (GPU/CPU);
  e `POST /api/scan/:sn` gera chamadas de diagnóstico ao Flashman → estoura a cota/rate limit do
  provedor, que pode **bloquear** o acesso legítimo. Junto com `SEC-01`, é DoS externo.
- **Mudança:** (1) rate limit global (ex.: 60/min); (2) **limite separado e mais frouxo** nas rotas
  que chamam a API Flashman e no Ollama (ex.: 10/min); (3) com token por usuário (`SEC-01`), aplicar
  por token, não só por IP.
- **Aceite:** 61ª chamada na hora → `429`; rotas de IA/scan com teto menor.
- **Verificação:**
  ```bash
  for i in $(seq 1 70); do
    curl -s -o /dev/null -w "%{http_code} " http://localhost:3000/api/devices -H "Authorization: Bearer $API_TOKEN"
  done; echo   # deve terminar em 429
  ```

### BUG-02 · `error.response?.data`/`error.message` exposto ao cliente · [P2]

- **Arquivo:** `serve.js:246`, `:264`
- **Evidência:** `res.status(500).json({ error: error.response?.data || error.message })` — devolve a
  resposta **crua da API Flashman** ou a mensagem interna.
- **Impacto:** vaza detalhe interno da API externa (estrutura de erro, endpoint, possivelmente dados
  do roteador) e a mensagem do próprio axios (URL completa = expõe `API_BASE_URL` e `sn`).
- **Mudança:** mensagem genérica ao cliente + log estruturado (o `addLog` já existe — usar ele).
- **Aceite:** erro 500 não traz dados da Flashman nem URL interna.
- **Verificação:**
  ```bash
  curl -s -X POST http://localhost:3000/api/update-channel -H "Authorization: Bearer $API_TOKEN" \
    -H 'Content-Type: application/json' -d '{"sn":"naoexiste","band":"2G","channel":6}' \
    | grep -qiE 'api/v2|undefined|axios' && echo 'FALHA: vazou' || echo OK
  ```

### BUG-03 · Token global em memória sem invalidação por logout · [P2]

- **Arquivo:** `serve.js:86` (`let authToken = null`)
- **Evidência:** o token é global (não por usuário), cacheado até um `401`/`400` limpar (`serve.js:170`).
  Não há `logout` nem invalidação manual.
- **Impacto:** (a) **ambíguo** se houver mais de um usuário (não há auth, então é implícito que é
  um sistema solo — mas isso se quebra se virar multi); (b) se o token for revogado no provedor, o
  sistema continua usando o antigo até que um `401` limpe (lag de revogação).
- **Mudança:** (1) expor `POST /api/auth/logout` (limpa o token e força novo OAuth); (2) se houver
  auth de usuário (`SEC-01`), armazenar token por usuário, não global; (3) TTL curto no cache.
- **Aceite:** `POST /api/auth/logout` força nova autenticação no próximo request.
- **Verificação:**
  ```bash
  curl -s -X POST http://localhost:3000/api/auth/logout -H "Authorization: Bearer $API_TOKEN"
  # proxima chamada deve refazer o OAuth (logar um novo getAccessToken)
  ```

### BUG-04 · Sem tratamento de erro no `getAccessToken` (retry) · [P2]

- **Arquivo:** `serve.js:89-110`
- **Evidência:** `getAccessToken()` faz POST, e o `catch` loga e pode deixar `authToken = null`.
  Não há backoff nem limite de tentativas — e quem chama (`:114` → `getAuthHeaders`) pode chamar
  repetidamente.
- **Impacto:** provedor fora → cada chamada de rota repete o OAuth (fila de tentativas sem
  backoff), gerando **flood ao provedor** e latência alta para o cliente. Sem `Retry-After`, o
  cliente não sabe quando parar.
- **Mudança:** (1) backoff exponencial + teto de tentativas; (2) cache de falha (não tentar por N s);
  (3) responder `503` com `Retry-After` em vez de esperar o provedor a cada vez.
- **Aceite:** provedor fora → respostas rápidas `503` (sem fila), e retry com backoff.
- **Verificação:**
  ```bash
  # apontar API_BASE_URL para porta morta: deve responder 503 rapido, nao pendurar
  ```

---

## 5. Qualidade: testes e observabilidade

### TEST-01 · Zero testes · [P1]

- **Arquivo:** *(ausente)*
- **Evidência:** 801 linhas de um arquivo só, sem nenhum teste.
- **Impacto:** os 2 P0 (`SEC-01` auth, `SEC-02` TLS) não têm como ser detectados. E a lógica
  **determinística** de recomendação (`getBestChannelsDeterministic`, canal 1/6/11) é o perfeito
  alvo de teste — é pura, sem rede, e é o valor do produto.
- **Mudança:** (1) `node --test` + `supertest` para as rotas (auth → `401`, validação de `sn`);
  (2) testar `getBestChannelsDeterministic` com dados sintéticos (rede com canal 1 ocupado →
  recomenda 6); (3) `mock` do axios para não bater na rede.
- **Aceite:** `npm test` roda e passa; falha se a auth for removida.
- **Verificação:**
  ```bash
  npm test 2>&1 | tail -3
  ```

### IMP-01 · Sem healthcheck · [P2]

- **Arquivo:** *(ausente)*
- **Evidência:** nenhuma rota `/health`.
- **Impacto:** o orquestrador não sabe se o serviço está saudável — em particular, se o **Ollama**
  (`localhost:11434`) está respondendo, que é o que faz a funcionalidade de IA funcionar.
- **Mudança:** `GET /health` verificando: (a) app OK; (b) Ollama alcançável (com timeout curto);
  (c) último token OAuth válido. Devolver `503` se a IA estiver indisponível (mas `200` se só a IA
  caiu — é degradado, não morto).
- **Aceite:** `/health` reflete Ollama e autenticação; `503` quando crítico caiu.
- **Verificação:**
  ```bash
  curl -s localhost:3000/health | jq .   # antes/depois de parar o Ollama
  ```

---

## 6. DevOps / Infra

### DEVOPS-01 · Sem CI · [P2]

- **Arquivo:** *(ausente)* `.github/workflows/`
- **Evidência:** sem workflow.
- **Impacto:** nada trava a remoção da auth (`SEC-01`) — que é a correção mais importante.
- **Mudança:** `ci.yml`: `npm ci`, `npm test`, e barreira `grep` que falhe se o middleware de auth
  sumir (padrão usado nos outros projetos).
- **Aceite:** PR que remove a auth é bloqueado.
- **Verificação:**
  ```bash
  grep -n "app.use('/api'" serve.js   # presente
  ```

### DEVOPS-02 · Sem Dockerfile · [P3]

- **Arquivo:** *(ausente)* `Dockerfile`
- **Evidência:** não há container.
- **Impacto:** baixo (roda com `node serve.js`), mas sem container não há como isolar rede
  (importante para `SEC-02`, que precisa de rede externa para a Flashman).
- **Mudança:** `Dockerfile` com `USER node`, `EXPOSE`, e `HEALTHCHECK` (após `IMP-01`).
- **Aceite:** `docker build` + `run` sobe o painel.
- **Verificação:**
  ```bash
  docker build -t wifiacs . && docker run --rm -p 3000:3000 wifiacs &
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000/
  ```

---

## 7. Documentação

### DOC-01 · README não avisa que altera roteador · [P1]

- **Arquivo:** `README.md`
- **Evidência:** o README explica a análise Wi-Fi, mas não declara que `POST /api/update-channel`
  **altera a configuração de roteadores reais** com as credenciais OAuth2 do sistema.
- **Impacto:** quem implanta não entende que o serviço tem **poder de escrita** na rede. Sem saber,
  pode expor o serviço sem auth e permitir que terceiros mudem canais (DoS de conectividade).
- **Mudança:** seção "Riscos e permissões": (1) o que este serviço **faz** (muda canal, lê estado);
  (2) que exige credenciais OAuth2 de um provedor **que controla roteadores**; (3) que **não pode**
  ser exposto sem `API_TOKEN` (`SEC-01`).
- **Aceite:** README declara o alcance de escrita do serviço.
- **Verificação:** `grep -ni 'roteador\|atualiz\|canal\|risc' README.md`.

### DOC-02 · Falta `SECURITY.md` · [P3]

- **Arquivo:** *(ausente)* `SECURITY.md`
- **Evidência:** sem política.
- **Impacto:** as invariantes (toda rota `/api` exige token; TLS sempre validado; `sn` validado)
  não ficam registradas.
- **Mudança:** criar com canal + as 3 invariantes + ameaça "controle de roteador por API de terceiros".
- **Aceite:** arquivo existe com as 3 invariantes.
- **Verificação:** `ls SECURITY.md`

---

## 8. Ordem de execução (waves)

### Wave 1 — Fechar o controle remoto (P0)
1. **`SEC-01`** — `app.use('/api', auth)` em **todas** as rotas (a correção mais importante).
2. **`SEC-02`** — `rejectUnauthorized` na verdade (ou CA própria).
3. **`TEST-01`** — testes de auth (travam o `SEC-01`).

> Depois da Wave 1, ninguém altera roteador sem token e as credenciais não são roubeáveis por MITM.

### Wave 2 — Fronteira e conteúdo (P1)
4. **`SEC-03`** — validar `sn` (`encodeURIComponent` + regex) nas 3 URLs.
5. **`SEC-04`** — `DELETE /api/logs` protegido (ou arquivado).
6. **`BUG-01`** — rate limit (global + separado para Flashman/Ollama).
7. **`DOC-01`** — README com o risco de controle de roteador.

### Wave 3 — Robustez (P2)
8. **`SEC-05`** — parar de logar fatia do token.
9. **`BUG-02`** — resposta de erro genérica; **`BUG-04`** — backoff no OAuth.
10. **`BUG-03`** — logout que invalida o token.
11. **`SEC-06`** + **`SEC-07`** — `helmet` e limite de body.
12. **`IMP-01`** — `/health` com Ollama; **`DEVOPS-01`** — CI.

### Wave 4 — Higiene (P3)
13. **`DEVOPS-02`**, **`IMP-02`** (Ollama por env), **`DOC-02`**.

**Dependências que não podem ser invertidas:**
`SEC-01` antes de `SEC-04` (a mesma auth protege as duas) · `SEC-03` antes de `BUG-02` (a URL
validada reduz o que vaza no erro) · `TEST-01` depois de `SEC-01` · `IMP-01` depois de `SEC-01`
(o `/health` público é permitido; as demais rotas não).

---

## 9. Fora de escopo / riscos

| Item | Decisão | Motivo |
|---|---|---|
| Remover a capacidade de alterar roteador | **Não** | É a finalidade do projeto. O risco é gerenciado por auth (`SEC-01`) + validação de `sn` (`SEC-03`). |
| Trocar Ollama por API externa | **Não** | O local é escolha de privacidade/custo; a recomendação determinística já é o fallback. |
| UI/UX do painel | **Não** | Não é o foco de segurança. |
| Adicionar histórico de mudanças por usuário | **Não, ainda** | Depois que houver auth (`SEC-01`), fazer log de auditoria por usuário (o `addLog` já é a base). |

**Riscos desta execução:**

- **`SEC-01` (auth) quebra o uso local atual**: o painel hoje não pede senha. Se você usa de casa e
  prefere sem token, ao menos restrinja por rede (`listen` em `127.0.0.1`) ou por IP (`API_ALLOWED_IPS`).
  Mas **não** deixe exposto sem token — as rotas alteram roteador.
- **`SEC-02` (remover `rejectUnauthorized: false`) pode quebrar** se o servidor Flashman usar certificado
  auto-assinado/CA própria. Solução: `ca:` com o PEM, **não** desativar a validação.
- **`SEC-03` (validar `sn`) pode rejeitar serial real** se o provedor usar formato fora da regex.
  Confira o formato com dados reais antes.
- **`BUG-01` (rate limit) pode bloquear teste de scan** (que dispara muitas chamadas). Use teto
  por usuário/token mais alto.

---

## 10. Definição de pronto (DoD)

**Segurança**
- [ ] `SEC-01` — todas as rotas `/api` exigem token; sem → `401`
- [ ] `SEC-02` — TLS validado (ou CA própria explícita); sem `rejectUnauthorized: false` no default
- [ ] `SEC-03` — `sn=../../x` → `400`; URLs montadas com `encodeURIComponent` + regex
- [ ] `SEC-04` — `DELETE /api/logs` exige token; log append-only
- [ ] `SEC-05` — nenhum prefixo de token no log
- [ ] `SEC-06` — headers do `helmet` presentes
- [ ] `SEC-07` — body > 100 KB → `413`

**Funcional**
- [ ] `BUG-01` — 61ª chamada → `429`; rotas Flashman/Ollama com teto menor
- [ ] `BUG-02` — erro 500 sem dados da Flashman/URL
- [ ] `BUG-03` — `POST /api/auth/logout` força novo OAuth
- [ ] `BUG-04` — provedor fora → `503` rápido com backoff
- [ ] `IMP-01` — `/health` reflete Ollama e autenticação
- [ ] `IMP-02` — Ollama por env (se feito)

**Testes e infra**
- [ ] `TEST-01` — `npm test` (auth + recomendação determinística)
- [ ] `DEVOPS-01` — CI com barreira anti-remoção da auth
- [ ] `DEVOPS-02` — Dockerfile com `USER node` e `HEALTHCHECK`

**Documentação**
- [ ] `DOC-01` — README declara que altera roteadores e o alcance
- [ ] `DOC-02` — `SECURITY.md` com as 3 invariantes

**Validação final:**
```bash
npm test 2>&1 | tail -3
grep -n 'rejectUnauthorized' serve.js && echo FALHA || echo OK
curl -s -o /dev/null -w '/api/devices -> %{http_code}\n' http://localhost:3000/api/devices   # 401
```

---

*Fim do plano. Gerado por leitura direta do código em 2026-10-02. Nenhum item já estava corrigido.*
