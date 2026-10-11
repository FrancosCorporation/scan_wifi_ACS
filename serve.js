require('dotenv').config();
const express = require('express');
const axios = require('axios');
const https = require('https');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const TRUST_PROXY = process.env.TRUST_PROXY;
if (TRUST_PROXY) app.set('trust proxy', TRUST_PROXY);
const MAX_LOG_ENTRIES = 5000;
const LOG_FILE = process.env.LOG_FILE || path.join(__dirname, 'flashman_logs.json');
const AUDIT_FILE = process.env.AUDIT_FILE || path.join(__dirname, 'flashman_audit.jsonl');
const LOG_ARCHIVE_DIR = process.env.LOG_ARCHIVE_DIR || path.join(__dirname, 'log_archive');
const API_TOKEN = (process.env.API_TOKEN || '').trim();
const API_TOKEN_BUFFER = Buffer.from(API_TOKEN, 'utf8');

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error('ERRO: PORT deve ser um inteiro entre 1 e 65535');
  process.exit(1);
}
if (API_TOKEN_BUFFER.length < 32) {
  console.error('ERRO: Defina API_TOKEN com pelo menos 32 bytes aleatórios (veja .env.example)');
  process.exit(1);
}

const cspNonce = (req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(32).toString('hex');
  next();
};
app.use(cspNonce);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      fontSrc: ["'self'", 'https:', 'data:'],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      styleSrcAttr: ["'unsafe-inline'"],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
  },
}));

const apiRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Limite de requisições atingido. Aguarde um minuto e tente novamente.' },
});
const flashmanRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Limite de operações Flashman atingido. Aguarde um minuto.' },
});
const ollamaRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Limite de consultas à IA atingido. Aguarde um minuto.' },
});
const healthRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
function noStore(_req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}

function requireApiToken(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!match) return res.status(401).json({ error: 'Autenticação necessária.' });
  const supplied = Buffer.from(match[1], 'utf8');
  if (supplied.length !== API_TOKEN_BUFFER.length || !crypto.timingSafeEqual(supplied, API_TOKEN_BUFFER)) {
    return res.status(401).json({ error: 'Token inválido.' });
  }
  return next();
}

app.use('/api', noStore, apiRateLimit, requireApiToken);
app.use('/api/devices', flashmanRateLimit);
app.use('/api/scan', flashmanRateLimit);
app.use('/api/update-channel', flashmanRateLimit);
app.use('/api/ai-recommend', ollamaRateLimit);
app.use(express.json({ limit: '100kb' }));

dns.setDefaultResultOrder('ipv4first');

const API_BASE_URL = process.env.FLASHMAN_API_BASE_URL || 'https://flashman.olvtelecom.com.br';
const CLIENT_ID = process.env.FLASHMAN_CLIENT_ID;
const CLIENT_SECRET = process.env.FLASHMAN_CLIENT_SECRET;
let flashmanBaseUrl;

try {
  const parsedBaseUrl = new URL(API_BASE_URL);
  if (parsedBaseUrl.protocol !== 'https:' || parsedBaseUrl.username || parsedBaseUrl.password || parsedBaseUrl.search || parsedBaseUrl.hash) {
    throw new Error('FLASHMAN_API_BASE_URL deve ser uma URL HTTPS sem credenciais, query ou fragmento');
  }
  flashmanBaseUrl = parsedBaseUrl.toString().replace(/\/$/, '');
} catch (error) {
  console.error(`ERRO: ${error.message}`);
  process.exit(1);
}

let ollamaBaseUrl = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
try {
  const parsedOllamaUrl = new URL(ollamaBaseUrl);
  if (!['http:', 'https:'].includes(parsedOllamaUrl.protocol) || parsedOllamaUrl.username || parsedOllamaUrl.password || parsedOllamaUrl.search || parsedOllamaUrl.hash) {
    throw new Error('OLLAMA_URL deve ser uma URL HTTP(S) sem credenciais, query ou fragmento');
  }
  ollamaBaseUrl = parsedOllamaUrl.toString().replace(/\/$/, '');
} catch (error) {
  console.error(`ERRO: ${error.message}`);
  process.exit(1);
}

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('ERRO: Defina FLASHMAN_CLIENT_ID e FLASHMAN_CLIENT_SECRET (veja .env.example)');
  process.exit(1);
}

const FLASHMAN_MAX_PAGE_SIZE = 50;
const SERIAL_NUMBER_PATTERN = /^[A-Za-z0-9-]{6,32}$/;

// ============================================================
// 📝 SISTEMA DE LOGS
// ============================================================

let logs = [];
let nextLogId = 1;

function loadLogsFromFile() {
  try {
    if (fs.existsSync(LOG_FILE)) {
      const raw = fs.readFileSync(LOG_FILE, 'utf8');
      const stored = JSON.parse(raw);
      logs = Array.isArray(stored) ? stored.slice(-MAX_LOG_ENTRIES) : [];
      nextLogId = logs.reduce((max, entry) => Math.max(max, Number(entry.id) || 0), 0) + 1;
    }
  } catch (e) {
    logs = [];
    nextLogId = 1;
  }
}

function saveLogsToFile() {
  const tempFile = `${LOG_FILE}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
    fs.writeFileSync(tempFile, JSON.stringify(logs, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    fs.renameSync(tempFile, LOG_FILE);
    return true;
  } catch (e) {
    try { fs.unlinkSync(tempFile); } catch {}
    console.error('Erro salvando logs em arquivo:', e.code || e.message);
    return false;
  }
}

function addLog(type, detail, status, extra = {}) {
  const entry = {
    id: nextLogId++,
    timestamp: new Date().toISOString(),
    timestampLocal: new Date().toLocaleString('pt-BR'),
    type,
    detail,
    status,
    extra
  };
  logs.push(entry);
  if (logs.length > MAX_LOG_ENTRIES) logs.splice(0, logs.length - MAX_LOG_ENTRIES);
  saveLogsToFile();
  console.log(`[LOG #${entry.id}] ${type} | ${status} | ${detail}`);
  return entry;
}

loadLogsFromFile();

function appendAudit(event, details = {}) {
  let fd;
  try {
    fs.mkdirSync(path.dirname(AUDIT_FILE), { recursive: true, mode: 0o700 });
    fd = fs.openSync(AUDIT_FILE, 'a', 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, `${JSON.stringify({ timestamp: new Date().toISOString(), event, ...details })}\n`, { encoding: 'utf8' });
    fs.closeSync(fd);
    fd = undefined;
    return true;
  } catch (error) {
    console.error('Erro gravando auditoria:', error.code || error.message);
    return false;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function writeLogsArchive(entries) {
  fs.mkdirSync(LOG_ARCHIVE_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(LOG_ARCHIVE_DIR, 0o700);
  const archiveName = `flashman_logs_${new Date().toISOString().replace(/[:.]/g, '-')}_${crypto.randomBytes(4).toString('hex')}.json`;
  const archivePath = path.join(LOG_ARCHIVE_DIR, archiveName);
  fs.writeFileSync(archivePath, JSON.stringify(entries, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return archiveName;
}

// ============================================================
// 🔑 AUTENTICAÇÃO OAUTH2
// ============================================================

const flashmanApi = axios.create({
  baseURL: flashmanBaseUrl,
  timeout: 15000,
  maxRedirects: 0,
  httpsAgent: new https.Agent({
    family: 4,
    ...(process.env.FLASHMAN_CA_FILE ? { ca: fs.readFileSync(path.resolve(process.env.FLASHMAN_CA_FILE)) } : {}),
  }),
  headers: { 'Accept': 'application/json' }
});

const ollamaApi = axios.create({
  baseURL: ollamaBaseUrl,
  timeout: 300000
});

let authToken = null;
let authTokenExpiresAt = 0;
let authTokenPromise = null;
let authRetryAt = 0;
let authGeneration = 0;
const AUTH_FAILURE_BACKOFF_MS = 30_000;

function invalidateAuthToken() {
  authToken = null;
  authTokenExpiresAt = 0;
  authTokenPromise = null;
  authGeneration++;
}

function authUnavailableError() {
  const error = new Error('Autenticação Flashman temporariamente indisponível.');
  error.code = 'AUTH_UNAVAILABLE';
  error.retryAfterSeconds = Math.max(1, Math.ceil((authRetryAt - Date.now()) / 1000));
  return error;
}

flashmanApi.interceptors.response.use(
  (response) => {
    if (response.status === 401 && !String(response.config?.url || '').includes('/token/oauth')) invalidateAuthToken();
    return response;
  },
  (error) => {
    if (error.response?.status === 401 && !String(error.config?.url || '').includes('/token/oauth')) invalidateAuthToken();
    return Promise.reject(error);
  }
);

async function getAccessToken() {
  if (authToken && authTokenExpiresAt > Date.now()) return authToken;
  if (authTokenPromise) return authTokenPromise;
  if (authRetryAt > Date.now()) throw authUnavailableError();

  const generation = authGeneration;
  const pending = (async () => {
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('client_id', CLIENT_ID);
    params.append('client_secret', CLIENT_SECRET);
    try {
      addLog('AUTH', 'Iniciando autenticação OAuth2', 'info');
      const response = await flashmanApi.post('/api/v2/token/oauth', params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      if (generation !== authGeneration) throw new Error('Credencial invalidada durante a autenticação.');
      const token = response.data.access_token || response.data.token || response.data.accessToken;
      if (typeof token !== 'string' || !token.trim()) {
        addLog('AUTH', 'Token não encontrado na resposta OAuth2', 'error', { responseKeys: Object.keys(response.data || {}) });
        throw new Error('Token não encontrado');
      }
      authToken = token;
      const expiresIn = Number(response.data.expires_in);
      const lifetimeMs = Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn * 1000 : 5 * 60 * 1000;
      const refreshSkewMs = Math.min(60_000, Math.max(5_000, lifetimeMs / 10));
      authTokenExpiresAt = Date.now() + Math.max(0, lifetimeMs - refreshSkewMs);
      authRetryAt = 0;
      addLog('AUTH', 'Autenticação OAuth2 realizada com sucesso', 'success');
      return authToken;
    } catch (error) {
      if (generation === authGeneration) {
        authToken = null;
        authTokenExpiresAt = 0;
        authRetryAt = Date.now() + AUTH_FAILURE_BACKOFF_MS;
      }
      addLog('AUTH', 'Falha na autenticação OAuth2', 'error', { status: error.response?.status, errorCode: error.code || 'AUTH_ERROR' });
      throw authUnavailableError();
    } finally {
      if (authTokenPromise === pending) authTokenPromise = null;
    }
  })();
  authTokenPromise = pending;
  return pending;
}

async function getAuthHeaders() {
  const token = await getAccessToken();
  return { 'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
}

app.get('/health', noStore, healthRateLimit, async (_req, res) => {
  let ollama = 'unavailable';
  try {
    const response = await ollamaApi.get('/api/tags', { timeout: 1500, maxRedirects: 0, validateStatus: () => true });
    if (response.status >= 200 && response.status < 300) ollama = 'ok';
  } catch {}

  const flashmanAuth = authToken && authTokenExpiresAt > Date.now()
    ? 'valid'
    : (authRetryAt > Date.now() ? 'backoff' : 'not_checked');
  const degraded = ollama !== 'ok' || flashmanAuth === 'backoff';
  res.status(200).json({
    status: degraded ? 'degraded' : 'ok',
    services: { app: 'ok', ollama, flashmanAuth },
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/auth/status', (_req, res) => {
  res.json({ authenticated: true });
});

app.post('/api/auth/logout', (req, res) => {
  invalidateAuthToken();
  authRetryAt = 0;
  appendAudit('flashman_oauth_cache_cleared', { ip: req.ip });
  res.json({ success: true, message: 'A próxima operação autenticará novamente na Flashman.' });
});

// ============================================================
// 📡 ROTAS DA API FLASHMAN
// ============================================================

app.get('/api/devices', async (req, res) => {
  const qty = req.query.qty === undefined ? 10 : Number(req.query.qty);
  if (!Number.isInteger(qty) || qty < 1 || qty > 5000) {
    return res.status(400).json({ error: 'A quantidade deve ser um inteiro entre 1 e 5000.' });
  }
  try {
    addLog('DEVICES', `Buscando ${qty} dispositivos (paginação automática)`, 'info', { qty, maxPageSize: FLASHMAN_MAX_PAGE_SIZE });

    const headers = await getAuthHeaders();
    const totalPages = Math.ceil(qty / FLASHMAN_MAX_PAGE_SIZE);
    let allDevices = [];

    for (let page = 1; page <= totalPages; page++) {
      const remaining = qty - allDevices.length;
      const size = Math.min(remaining, FLASHMAN_MAX_PAGE_SIZE);

      addLog('DEVICES', `Request página ${page}/${totalPages} (pageSize=${size})`, 'info', { page, totalPages, size });

      const response = await flashmanApi.get('/api/v2/devices/views/natural', {
        headers,
        params: {
          'pagination[pageSize]': size,
          'pagination[currentPage]': page,
          'sorting[sortBy]': 'lastInform',
          'sorting[sortOrder]': 'desc'
        }
      });

      const registers = response.data.registers || [];
      allDevices = allDevices.concat(registers);

      addLog('DEVICES', `Página ${page}/${totalPages} carregada — ${registers.length} dispositivos retornados`, 'info', {
        page, totalPages, fetchedThisPage: registers.length, totalFetchedSoFar: allDevices.length
      });

      // Se retornou menos que o esperado, não há mais páginas
      if (registers.length < size) {
        addLog('DEVICES', `API retornou menos registros que o esperado — fim dos dados disponíveis`, 'warn', {
          expected: size, received: registers.length, totalFetched: allDevices.length
        });
        break;
      }
    }

    addLog('DEVICES', `Total: ${allDevices.length} dispositivos carregados em ${totalPages} páginas`, 'success', {
      requested: qty, fetched: allDevices.length, pagesUsed: Math.min(totalPages, Math.ceil(allDevices.length / FLASHMAN_MAX_PAGE_SIZE)),
      sampleSNs: allDevices.slice(0, 5).map(d => d.serialNumber || d.sn || d._id || '?')
    });

    res.json({ devices: allDevices, totalFetched: allDevices.length, pagesUsed: totalPages });
  } catch (error) {
    if (error.retryAfterSeconds) res.set('Retry-After', String(error.retryAfterSeconds));
    addLog('DEVICES', 'Erro ao buscar dispositivos', 'error', { qty, errorCode: error.code || 'FLASHMAN_ERROR', status: error.response?.status });
    res.status(error.code === 'AUTH_UNAVAILABLE' ? 503 : 502).json({
      error: error.code === 'AUTH_UNAVAILABLE' ? 'Autenticação Flashman temporariamente indisponível.' : 'Não foi possível consultar os dispositivos Flashman.',
    });
  }
});

app.get('/api/scan/:sn', async (req, res) => {
  const { sn } = req.params;
  if (typeof sn !== 'string' || !SERIAL_NUMBER_PATTERN.test(sn)) {
    addLog('SCAN', 'SN inválido recebido', 'error');
    return res.status(400).json({ error: 'SN inválido.' });
  }
  try {
    addLog('SCAN', `Iniciando scan de redes vizinhas para SN: ${sn}`, 'info', { sn });
    const headers = await getAuthHeaders();
    const encodedSn = encodeURIComponent(sn);
    const startResponse = await flashmanApi.post(`/api/v2/devices/${encodedSn}/diagnostics/neighbor/start`, {}, { headers });
    if (startResponse.status < 200 || startResponse.status >= 300) throw new Error('Falha ao iniciar o diagnóstico Flashman.');

    addLog('SCAN', `Scan iniciado, aguardando resultado... (SN: ${sn})`, 'info', { sn });

    const maxAttempts = 30;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const stateResp = await flashmanApi.get(`/api/v2/devices/${encodedSn}/diagnostics/neighbor/state`, { headers, validateStatus: (status) => status < 500 });
      if (stateResp.status === 401) throw new Error('Autenticação Flashman expirada.');
      if (stateResp.status === 200 && Array.isArray(stateResp.data) && stateResp.data.length > 0) {
        const channelList = stateResp.data.map(n => n.channel).filter(Boolean);
        addLog('SCAN', `Scan concluído com sucesso! ${stateResp.data.length} redes encontradas`, 'success', {
          sn,
          networksFound: stateResp.data.length,
          channelsDetected: channelList,
          attemptNumber: attempt,
          durationSeconds: attempt * 2
        });
        return res.json(stateResp.data);
      }
      await new Promise(r => setTimeout(r, 2000));
    }
    addLog('SCAN', `Scan expirou após ${maxAttempts * 2}s para SN: ${sn}`, 'error', { sn, maxAttempts, timeoutSeconds: maxAttempts * 2 });
    res.status(408).json({ error: 'Tempo esgotado.' });
  } catch (error) {
    if (error.retryAfterSeconds) res.set('Retry-After', String(error.retryAfterSeconds));
    addLog('SCAN', 'Erro ao executar o scan Flashman', 'error', { sn, errorCode: error.code || 'FLASHMAN_ERROR', status: error.response?.status });
    res.status(error.code === 'AUTH_UNAVAILABLE' ? 503 : 502).json({
      error: error.code === 'AUTH_UNAVAILABLE' ? 'Autenticação Flashman temporariamente indisponível.' : 'Não foi possível concluir o scan Flashman.',
    });
  }
});

app.post('/api/update-channel', async (req, res) => {
  const { sn, band, channel } = req.body || {};
  const numericChannel = Number(channel);
  if (typeof sn !== 'string' || !SERIAL_NUMBER_PATTERN.test(sn) || !['2G', '5G'].includes(band) || !Number.isInteger(numericChannel)) {
    addLog('UPDATE', 'Dados inválidos para atualização de canal', 'error');
    return res.status(400).json({ error: 'Informe um SN, banda e canal válidos.' });
  }
  if ((band === '2G' && (numericChannel < 1 || numericChannel > 11)) || (band === '5G' && (numericChannel < 36 || numericChannel > 144))) {
    return res.status(400).json({ error: 'Canal fora do intervalo permitido para a banda selecionada.' });
  }
  const encodedSn = encodeURIComponent(sn);
  if (!appendAudit('router_channel_update_requested', { ip: req.ip, sn, band, channel: numericChannel })) {
    return res.status(503).json({ error: 'Auditoria indisponível; nenhuma alteração foi enviada ao roteador.' });
  }
  try {
    addLog('UPDATE', `Aplicando canal ${numericChannel} na banda ${band} para SN: ${sn}`, 'info', { sn, band, channel: numericChannel });
    const headers = await getAuthHeaders();
    const instancePath = band === '2G' ? '1' : '5';
    const payload = [{
      "parameter": `InternetGatewayDevice.LANDevice.1.WLANConfiguration.${instancePath}.Channel`,
      "value": numericChannel,
      "type": "xsd:unsignedInt"
    }];
    const flashResp = await flashmanApi.post(`/api/v2/devices/${encodedSn}/parameters/update`, payload, { headers });
    appendAudit('router_channel_update_succeeded', { ip: req.ip, sn, band, channel: numericChannel, status: flashResp.status });
    addLog('UPDATE', `Canal ${numericChannel} (${band}) aplicado com sucesso no SN: ${sn}`, 'success', { sn, band, channel: numericChannel });
    res.json({ success: true });
  } catch (error) {
    appendAudit('router_channel_update_failed', { ip: req.ip, sn, band, channel: numericChannel, status: error.response?.status, errorCode: error.code || 'FLASHMAN_ERROR' });
    if (error.retryAfterSeconds) res.set('Retry-After', String(error.retryAfterSeconds));
    addLog('UPDATE', `Falha ao aplicar canal ${numericChannel} (${band}) no roteador`, 'error', { sn, band, channel: numericChannel, status: error.response?.status, errorCode: error.code || 'FLASHMAN_ERROR' });
    res.status(error.code === 'AUTH_UNAVAILABLE' ? 503 : 502).json({
      error: error.code === 'AUTH_UNAVAILABLE' ? 'Autenticação Flashman temporariamente indisponível.' : 'Não foi possível alterar o canal do roteador.',
    });
  }
});

// ============================================================
// 🧠 ROTAS: CÁLCULO INSTANTÂNEO E IA
// ============================================================

function getBestChannelsDeterministic(scanData) {
  const valid2G = [1, 6, 11];
  const counts2G = { 1: 0, 6: 0, 11: 0 };
  const valid5G = [];
  for (let i = 144; i >= 36; i -= 4) valid5G.push(i);
  const counts5G = {};
  valid5G.forEach(c => counts5G[c] = 0);

  scanData.forEach(net => {
    const ch = parseInt(net.channel);
    if (valid2G.includes(ch)) counts2G[ch]++;
    if (counts5G.hasOwnProperty(ch)) counts5G[ch]++;
  });

  let best2G = 1, min2G = Infinity;
  for (const ch of valid2G) { if (counts2G[ch] < min2G) { min2G = counts2G[ch]; best2G = ch; } }

  let best5G = 36, min5G = Infinity;
  for (const ch of valid5G) { if (counts5G[ch] < min5G) { min5G = counts5G[ch]; best5G = ch; if (min5G === 0) break; } }

  return { channel2G: String(best2G), channel5G: String(best5G), counts2G, counts5G };
}

function validScanData(scanData) {
  return Array.isArray(scanData) && scanData.length > 0 && scanData.length <= 500 &&
    scanData.every((network) => network && typeof network === 'object' &&
      Number.isInteger(Number(network.channel)) && Number(network.channel) >= 1 && Number(network.channel) <= 196);
}

app.post('/api/instant-recommend', async (req, res) => {
  const scanData = req.body?.scanData;
  if (!validScanData(scanData)) {
    addLog('INSTANT', `Scan data vazio na recomendação instantânea`, 'error');
    return res.status(400).json({ error: 'Envie entre 1 e 500 redes com canais válidos.' });
  }
  try {
    const startTime = Date.now();
    const result = getBestChannelsDeterministic(scanData);
    const elapsed = Date.now() - startTime;

    addLog('INSTANT', `Recomendação instantânea calculada`, 'success', {
      channel2G: result.channel2G,
      channel5G: result.channel5G,
      counts2G: result.counts2G,
      counts5G: result.counts5G,
      networksAnalyzed: scanData.length,
      elapsedMs: elapsed
    });

    res.json({
      channel2G: result.channel2G,
      channel5G: result.channel5G,
      raw: `Calculado pelo algoritmo do servidor em ${elapsed}ms. Redes analisadas: ${scanData.length}. Contagens 2G: ${JSON.stringify(result.counts2G)}. Contagens 5G (top 5): ${JSON.stringify(Object.entries(result.counts5G).sort((a, b) => b[1] - a[1]).slice(0, 5))}`
    });
  } catch (error) {
    addLog('INSTANT', 'Erro na recomendação instantânea', 'error', { errorCode: error.code || 'CALCULATION_ERROR' });
    res.status(500).json({ error: 'Não foi possível calcular a recomendação.' });
  }
});

app.post('/api/ai-recommend', async (req, res) => {
  const scanData = req.body?.scanData;
  if (!validScanData(scanData)) {
    addLog('AI', `Scan data vazio na recomendação IA`, 'error');
    return res.status(400).json({ error: 'Envie entre 1 e 500 redes com canais válidos.' });
  }
  try {
    const startTime = Date.now();
    addLog('AI', `Iniciando recomendação via IA local (Ollama)`, 'info', { networksAnalyzed: scanData.length });

    const allChannels = scanData.map(net => net.channel).filter(c => c !== undefined && c !== null);
    const uniqueChannels = [...new Set(allChannels)].join(', ');

    const prompt = `You are a Wi-Fi optimizer. Occupied channels: [${uniqueChannels}]. Rules: 2.4GHz channel must be 1-11. 5GHz channel must be 36-144. Choose the best channel for each band. Output format: 2G:X,5G:Y`;

    const ollamaResp = await ollamaApi.post('/api/generate', {
      model: 'qwen3.5:0.8b',
      prompt: prompt,
      stream: false
    });

    const elapsed = Date.now() - startTime;
    const iaText = ollamaResp.data?.response || '';
    addLog('AI', 'IA respondeu', 'info', { elapsedMs: elapsed, model: 'qwen3.5:0.8b' });

    const match2G = iaText.match(/2G\s*:\s*(-?\d+(?:\.\d+)?)/i);
    const match5G = iaText.match(/5G\s*:\s*(-?\d+(?:\.\d+)?)/i);

    if (!match2G || !match5G) {
      addLog('AI', 'IA não retornou no formato esperado', 'error', { elapsedMs: elapsed });
      return res.status(502).json({ error: 'A IA não retornou uma recomendação válida.' });
    }

    const channel2G = match2G[1];
    const channel5G = match5G[1];
    const numericChannel2G = Number(channel2G);
    const numericChannel5G = Number(channel5G);
    if (!Number.isInteger(numericChannel2G) || numericChannel2G < 1 || numericChannel2G > 11 ||
        !Number.isInteger(numericChannel5G) || numericChannel5G < 36 || numericChannel5G > 144) {
      addLog('AI', 'IA retornou canais fora dos intervalos permitidos', 'error', { elapsedMs: elapsed });
      return res.status(502).json({ error: 'A IA não retornou uma recomendação válida.' });
    }

    addLog('AI', `Recomendação IA concluída com sucesso`, 'success', {
      channel2G, channel5G, elapsedMs: elapsed, model: 'qwen3.5:0.8b'
    });

    res.json({ channel2G, channel5G, raw: iaText });
  } catch (error) {
    addLog('AI', 'Erro na recomendação IA', 'error', { errorCode: error.code || 'OLLAMA_ERROR', ollamaConnected: false });
    res.status(500).json({ error: "Ollama desconectado ou demorou demais (limite 5 min)." });
  }
});

// ============================================================
// 📋 ROTA DE LOGS (API + INTERFACE)
// ============================================================

app.get('/api/logs', (req, res) => {
  const typeFilter = typeof req.query.type === 'string' ? req.query.type.slice(0, 32) : '';
  const statusFilter = typeof req.query.status === 'string' ? req.query.status.slice(0, 32) : '';
  const search = typeof req.query.search === 'string' ? req.query.search.slice(0, 100) : '';
  const requestedLimit = Number(req.query.limit || 200);
  const limit = Number.isInteger(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 500)) : 200;

  let filtered = [...logs].reverse();

  if (typeFilter) filtered = filtered.filter(l => l.type === typeFilter);
  if (statusFilter) filtered = filtered.filter(l => l.status === statusFilter);
  if (search) filtered = filtered.filter(l =>
    String(l.detail || '').toLowerCase().includes(search.toLowerCase()) ||
    JSON.stringify(l.extra || {}).toLowerCase().includes(search.toLowerCase())
  );

  filtered = filtered.slice(0, limit);

  res.json({
    total: logs.length,
    showing: filtered.length,
    filters: { type: typeFilter, status: statusFilter, search, limit },
    logs: filtered
  });
});

app.delete('/api/logs', (req, res) => {
  let archiveName;
  try {
    archiveName = writeLogsArchive(logs);
  } catch (error) {
    addLog('SYSTEM', 'Falha ao arquivar logs', 'error', { errorCode: error.code || 'ARCHIVE_ERROR' });
    return res.status(500).json({ error: 'Não foi possível arquivar os logs.' });
  }

  if (!appendAudit('logs_archived', { ip: req.ip, archiveName, count: logs.length })) {
    return res.status(503).json({ error: 'Auditoria indisponível; os logs ativos foram preservados.' });
  }

  const previousLogs = logs;
  logs = [];
  if (!saveLogsToFile()) {
    logs = previousLogs;
    return res.status(500).json({ error: 'O arquivo foi arquivado, mas os logs ativos não puderam ser reiniciados.' });
  }
  addLog('SYSTEM', `Logs arquivados (${previousLogs.length} entradas)`, 'info', { archiveName });
  return res.json({ success: true, archived: previousLogs.length, archiveName });
});

app.get('/logs', noStore, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Flashman Logs</title>
      <style nonce="${res.locals.cspNonce}">
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e1a; color: #e2e8f0; min-height: 100vh; }
        .topbar {
          background: #1e293b; border-bottom: 2px solid #334155; padding: 1rem 2rem;
          display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;
        }
        .topbar h1 { font-size: 1.3rem; display: flex; align-items: center; gap: 0.5rem; }
        .topbar h1 span { color: #f59e0b; }
        .topbar a { color: #38bdf8; text-decoration: none; font-size: 0.9rem; }
        .topbar a:hover { text-decoration: underline; }
        .stats-bar {
          display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem;
          padding: 1.5rem 2rem; background: #111827; border-bottom: 1px solid #1e293b;
        }
        .stat-card {
          background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1rem; text-align: center;
        }
        .stat-card .num { font-size: 2rem; font-weight: bold; }
        .stat-card .label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }
        .stat-card.success .num { color: #10b981; }
        .stat-card.error .num { color: #ef4444; }
        .stat-card.info .num { color: #38bdf8; }
        .stat-card.warn .num { color: #f59e0b; }
        .stat-card.total .num { color: #e2e8f0; }
        .filters {
          padding: 1rem 2rem; background: #0f172a; border-bottom: 1px solid #1e293b;
          display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;
        }
        .filters label { font-size: 0.8rem; color: #64748b; }
        .filters select, .filters input {
          padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid #334155;
          background: #1e293b; color: #e2e8f0; font-size: 0.85rem; min-width: 120px;
        }
        .filters input[type="text"] { min-width: 200px; }
        .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; font-size: 0.85rem; cursor: pointer; font-weight: bold; color: #fff; }
        .btn.refresh { background: #3b82f6; }
        .btn.clear { background: #ef4444; }
        .btn.clear:hover { background: #dc2626; }
        .btn.refresh:hover { background: #2563eb; }
        .btn.export { background: #10b981; }
        .btn.export:hover { background: #059669; }
        .log-container { padding: 1rem 2rem; max-height: calc(100vh - 240px); overflow-y: auto; }
        .log-container::-webkit-scrollbar { width: 8px; }
        .log-container::-webkit-scrollbar-track { background: #0f172a; }
        .log-container::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        .log-entry {
          background: #1e293b; border: 1px solid #334155; border-radius: 8px;
          padding: 0.75rem 1rem; margin-bottom: 0.5rem; transition: all 0.2s;
        }
        .log-entry:hover { border-color: #475569; background: #233044; }
        .log-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.4rem; }
        .log-id { background: #334155; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; color: #94a3b8; }
        .log-type-badge { padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; letter-spacing: 0.5px; }
        .log-type-badge.AUTH { background: #1e3a5f; color: #38bdf8; }
        .log-type-badge.DEVICES { background: #1e3a5f; color: #60a5fa; }
        .log-type-badge.SCAN { background: #312e81; color: #a78bfa; }
        .log-type-badge.INSTANT { background: #78350f; color: #fbbf24; }
        .log-type-badge.AI { background: #4c1d95; color: #c084fc; }
        .log-type-badge.UPDATE { background: #064e3b; color: #6ee7b7; }
        .log-type-badge.SYSTEM { background: #334155; color: #94a3b8; }
        .log-status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        .log-status-dot.success { background: #10b981; }
        .log-status-dot.error { background: #ef4444; }
        .log-status-dot.info { background: #38bdf8; }
        .log-status-dot.warn { background: #f59e0b; }
        .log-time { font-size: 0.75rem; color: #64748b; }
        .log-detail { font-size: 0.9rem; color: #e2e8f0; }
        .log-extra-toggle { border: 0; background: transparent; padding: 0; font-size: 0.75rem; color: #38bdf8; cursor: pointer; margin-top: 0.3rem; user-select: none; width: auto; font-weight: normal; }
        .log-extra-toggle:hover { color: #7dd3fc; }
        .log-extra-content {
          display: none; margin-top: 0.5rem; padding: 0.5rem; background: #0f172a;
          border-radius: 6px; border: 1px solid #1e293b; font-size: 0.75rem; color: #94a3b8;
          white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto;
        }
        .log-extra-content.open { display: block; }
        .empty-state { text-align: center; padding: 3rem; color: #64748b; }
        .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; }
        .auth-panel { padding: 1rem 2rem; display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; background: #111827; border-bottom: 1px solid #1e293b; }
        .auth-panel input { padding: 0.55rem 0.75rem; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: #e2e8f0; min-width: 260px; }
        .auth-status { color: #94a3b8; font-size: 0.85rem; }
      </style>
    </head>
    <body>
      <div class="topbar">
        <h1>📋 <span>Flashman</span> Logs</h1>
        <div style="display: flex; gap: 1rem; align-items: center;">
          <a href="/">← Voltar ao Optimizer</a>
          <span style="color: #64748b; font-size: 0.8rem;" id="lastUpdate"></span>
        </div>
      </div>
      <form class="auth-panel" id="apiAuthForm">
        <label for="apiTokenInput">Token de acesso</label>
        <input id="apiTokenInput" type="password" autocomplete="current-password" placeholder="Cole o API_TOKEN" />
        <button class="btn refresh" type="submit">Conectar</button>
        <button class="btn clear" type="button" id="logoutButton" hidden>Sair</button>
        <span class="auth-status" id="authStatus" role="status">Conecte-se para consultar os logs.</span>
      </form>
      <div class="stats-bar" id="statsBar">
        <div class="stat-card total"><div class="num" id="statTotal">0</div><div class="label">Total</div></div>
        <div class="stat-card success"><div class="num" id="statSuccess">0</div><div class="label">Sucessos</div></div>
        <div class="stat-card error"><div class="num" id="statError">0</div><div class="label">Erros</div></div>
        <div class="stat-card info"><div class="num" id="statInfo">0</div><div class="label">Info</div></div>
        <div class="stat-card warn"><div class="num" id="statWarn">0</div><div class="label">Avisos</div></div>
      </div>
      <div class="filters">
        <label>Tipo</label>
        <select id="filterType" data-requires-auth disabled>
          <option value="">Todos</option>
          <option value="AUTH">Auth</option>
          <option value="DEVICES">Devices</option>
          <option value="SCAN">Scan</option>
          <option value="INSTANT">Instant</option>
          <option value="AI">IA</option>
          <option value="UPDATE">Update</option>
          <option value="SYSTEM">System</option>
        </select>
        <label>Status</label>
        <select id="filterStatus" data-requires-auth disabled>
          <option value="">Todos</option>
          <option value="success">Sucesso</option>
          <option value="error">Erro</option>
          <option value="info">Info</option>
          <option value="warn">Aviso</option>
        </select>
        <label>Buscar</label>
        <input id="filterSearch" data-requires-auth disabled type="text" placeholder="Buscar nos logs..." />
        <button class="btn refresh" id="refreshButton" data-requires-auth disabled type="button">🔄 Atualizar</button>
        <button class="btn export" id="exportButton" data-requires-auth disabled type="button">📥 Exportar JSON</button>
        <button class="btn clear" id="clearButton" data-requires-auth disabled type="button">🗃️ Arquivar logs</button>
      </div>
      <div class="log-container" id="logContainer">
        <div class="empty-state"><div class="icon">📋</div>Carregando logs...</div>
      </div>
      <script nonce="${res.locals.cspNonce}">
        const API_TOKEN_STORAGE_KEY = 'scanWifiApiToken';
        let currentLogs = [];
        let refreshTimer = null;
        function setAuthStatus(message, isError = false) {
          const status = document.getElementById('authStatus');
          status.textContent = message;
          status.style.color = isError ? '#fca5a5' : '#94a3b8';
        }
        function setAuthConnected(connected) {
          document.querySelectorAll('[data-requires-auth]').forEach((element) => { element.disabled = !connected; });
          if (refreshTimer !== null) clearInterval(refreshTimer);
          refreshTimer = connected ? setInterval(refreshLogs, 5000) : null;
        }
        async function apiFetch(url, options = {}) {
          const token = sessionStorage.getItem(API_TOKEN_STORAGE_KEY);
          if (!token) throw new Error('Conecte-se com o API_TOKEN para continuar.');
          const headers = new Headers(options.headers || {});
          headers.set('Authorization', 'Bearer ' + token);
          const response = await fetch(url, { ...options, headers });
          if (response.status === 401) {
            sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
            document.getElementById('logoutButton').hidden = true;
            setAuthStatus('Token inválido ou expirado. Conecte-se novamente.', true);
            setAuthConnected(false);
          }
          return response;
        }
        async function connectApi(event) {
          event.preventDefault();
          const token = document.getElementById('apiTokenInput').value.trim();
          if (!token) { setAuthStatus('Informe o API_TOKEN configurado no servidor.', true); return; }
          try {
            const response = await fetch('/api/auth/status', { headers: { Authorization: 'Bearer ' + token } });
            if (!response.ok) throw new Error('Token inválido. Confira o valor configurado no servidor.');
            sessionStorage.setItem(API_TOKEN_STORAGE_KEY, token);
            document.getElementById('apiTokenInput').value = '';
            document.getElementById('logoutButton').hidden = false;
            setAuthConnected(true);
            setAuthStatus('Conectado. O token fica guardado nesta aba até ela ser fechada.');
            await refreshLogs();
          } catch (error) {
            setAuthStatus(error.message, true);
          }
        }
        async function logoutApi() {
          try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch {}
          sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
          setAuthConnected(false);
          location.reload();
        }
        function escapeHtml(value) {
          return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
        }
        function updateStats(logs) {
          document.getElementById('statTotal').textContent = logs.length;
          document.getElementById('statSuccess').textContent = logs.filter(l => l.status === 'success').length;
          document.getElementById('statError').textContent = logs.filter(l => l.status === 'error').length;
          document.getElementById('statInfo').textContent = logs.filter(l => l.status === 'info').length;
          document.getElementById('statWarn').textContent = logs.filter(l => l.status === 'warn').length;
        }
        function renderLogs(logs) {
          const container = document.getElementById('logContainer');
          if (logs.length === 0) { container.innerHTML = '<div class="empty-state"><div class="icon">📭</div>Nenhum log encontrado.</div>'; return; }
          container.innerHTML = logs.map(l => {
            const extraStr = l.extra && Object.keys(l.extra).length > 0 ? JSON.stringify(l.extra, null, 2) : '';
            const hasExtra = extraStr.length > 0;
            const typeClass = ['AUTH', 'DEVICES', 'SCAN', 'INSTANT', 'AI', 'UPDATE', 'SYSTEM'].includes(l.type) ? l.type : 'SYSTEM';
            const statusClass = ['success', 'error', 'info', 'warn'].includes(l.status) ? l.status : 'info';
            return '<div class="log-entry">'
              + '<div class="log-header">'
              + '<span class="log-id">#' + escapeHtml(l.id) + '</span>'
              + '<span class="log-type-badge ' + typeClass + '">' + escapeHtml(l.type) + '</span>'
              + '<span class="log-status-dot ' + statusClass + '"></span>'
              + '<span class="log-time">' + escapeHtml(l.timestampLocal) + '</span>'
              + '</div>'
              + '<div class="log-detail">' + escapeHtml(l.detail) + '</div>'
              + (hasExtra ? '<button class="log-extra-toggle" type="button" data-toggle-extra>▸ Detalhes (' + Object.keys(l.extra).length + ' campos)</button><div class="log-extra-content">' + escapeHtml(extraStr) + '</div>' : '')
              + '</div>';
          }).join('');
        }
        async function refreshLogs() {
          const type = document.getElementById('filterType').value;
          const status = document.getElementById('filterStatus').value;
          const search = document.getElementById('filterSearch').value;
          try {
            const params = new URLSearchParams();
            if (type) params.set('type', type);
            if (status) params.set('status', status);
            if (search) params.set('search', search);
            params.set('limit', '200');
            const res = await apiFetch('/api/logs?' + params.toString());
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Erro ao carregar logs.');
            currentLogs = data.logs; updateStats(data.logs); renderLogs(data.logs);
            document.getElementById('lastUpdate').textContent = 'Atualizado: ' + new Date().toLocaleTimeString('pt-BR');
          } catch(e) { document.getElementById('logContainer').textContent = 'Erro ao carregar logs: ' + e.message; }
        }
        async function clearLogs() {
          if (!confirm('Arquivar os logs atuais? O arquivo ficará preservado no servidor.')) return;
          try {
            const res = await apiFetch('/api/logs', { method: 'DELETE' }); const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Falha ao arquivar os logs.');
            alert('Logs arquivados: ' + data.archived + ' entradas.'); refreshLogs();
          } catch(e) { alert('Erro: ' + e.message); }
        }
        function exportLogs() {
          const data = JSON.stringify(currentLogs, null, 2);
          const blob = new Blob([data], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a'); a.href = url; a.download = 'flashman_logs_' + new Date().toISOString().slice(0, 10) + '.json'; a.click(); URL.revokeObjectURL(url);
        }
        document.getElementById('apiAuthForm').addEventListener('submit', connectApi);
        document.getElementById('logoutButton').addEventListener('click', logoutApi);
        document.getElementById('refreshButton').addEventListener('click', refreshLogs);
        document.getElementById('exportButton').addEventListener('click', exportLogs);
        document.getElementById('clearButton').addEventListener('click', clearLogs);
        document.getElementById('filterType').addEventListener('change', refreshLogs);
        document.getElementById('filterStatus').addEventListener('change', refreshLogs);
        document.getElementById('filterSearch').addEventListener('input', refreshLogs);
        document.getElementById('logContainer').addEventListener('click', (event) => {
          const button = event.target.closest('[data-toggle-extra]');
          if (!button) return;
          const content = button.nextElementSibling;
          const isOpen = content.classList.toggle('open');
          button.textContent = isOpen ? '▾ Detalhes' : '▸ Detalhes';
        });
        if (sessionStorage.getItem(API_TOKEN_STORAGE_KEY)) {
          document.getElementById('logoutButton').hidden = false;
          setAuthConnected(true);
          setAuthStatus('Conectado nesta aba.');
          refreshLogs();
        } else setAuthConnected(false);
      </script>
    </body>
    </html>
  `);
});

// ============================================================
// 🌐 INTERFACE WEB PRINCIPAL
// ============================================================

app.get('/', noStore, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Flashman Wi-Fi Optimizer</title>
      <style nonce="${res.locals.cspNonce}">
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; display: flex; justify-content: center; margin: 0; }
        .card { background: #1e293b; padding: 2rem; border-radius: 12px; border: 1px solid #334155; max-width: 1200px; width: 100%; }
        h1 { margin-top: 0; border-bottom: 1px solid #334155; padding-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; }
        h1 a { font-size: 0.85rem; color: #f59e0b; text-decoration: none; }
        h1 a:hover { text-decoration: underline; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; }
        input, select, button { padding: 0.75rem; border-radius: 8px; border: 1px solid #334155; background: #090d16; color: #fff; font-size: 1rem; width: 100%; box-sizing: border-box; }
        button { background: #3b82f6; cursor: pointer; font-weight: bold; text-align: center; }
        button:disabled { opacity: 0.4; cursor: not-allowed; }
        button.ai { background: #8b5cf6; }
        button.instant { background: #f59e0b; color: #000; }
        button.apply { background: #10b981; }
        pre { background: #090d16; padding: 1rem; border-radius: 8px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; max-height: 300px; overflow-y: auto; font-size: 0.8rem; border: 1px solid #334155; }
        .status { margin-top: 1rem; padding: 0.75rem; border-radius: 8px; display: none; }
        .error { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
        .success { background: #052e16; color: #86efac; border: 1px solid #166534; }
        .warn { background: #422006; color: #fcd34d; border: 1px solid #92400e; }
        .mt-2 { margin-top: 1.5rem; }
        .mb-1 { margin-bottom: 1rem; }
        label { font-size: 0.85rem; color: #94a3b8; display: block; margin-bottom: 0.5rem; }
        .section-box { background: #0f172a; padding: 1.5rem; border-radius: 8px; border: 1px solid #334155; }
        .log-counter { font-size: 0.8rem; color: #64748b; margin-top: 0.5rem; }
        .pagination-info { font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }
        .auth-panel { display: flex; align-items: end; gap: 0.75rem; flex-wrap: wrap; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
        .auth-panel > div { flex: 1 1 260px; }
        .auth-panel input { max-width: 420px; }
        .auth-status { color: #94a3b8; font-size: 0.85rem; align-self: center; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>
          <span>📶 Flashman Wi-Fi Optimizer</span>
          <a href="/logs">📋 Ver Logs →</a>
        </h1>

        <form class="auth-panel" id="apiAuthForm">
          <div>
            <label for="apiTokenInput">Token de acesso</label>
            <input id="apiTokenInput" type="password" autocomplete="current-password" placeholder="Cole o API_TOKEN" />
          </div>
          <button type="submit" style="width: auto;">Conectar</button>
          <button type="button" id="logoutButton" hidden style="width: auto;">Sair</button>
          <span class="auth-status" id="authStatus" role="status">Conecte-se antes de consultar ou alterar roteadores.</span>
        </form>
        
        <div class="grid-3 mb-1">
          <div>
            <label>Qtd. de Aparelhos</label>
            <input id="qtyInput" data-requires-auth disabled type="number" value="100" min="1" max="5000" />
            <div class="pagination-info" id="paginationInfo"></div>
          </div>
          <div><label>Selecionar da Lista</label><select id="devSel" data-requires-auth disabled><option>Conecte-se para carregar.</option></select></div>
          <div><label>Ou digite o SN Manual</label><input id="snInput" data-requires-auth disabled type="text" placeholder="Ex: ZTEEQL4Q3B06071" /></div>
        </div>
        
        <div class="mb-1" style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem;">
          <button type="button" data-requires-auth disabled id="loadDevicesButton">🔄 Carregar Lista</button>
          <button type="button" data-requires-auth disabled id="startScanButton">🔍 Escanear Redes</button>
          <button type="button" data-requires-auth disabled class="instant" id="btnInstant">⚡ Recomendar (Instantâneo)</button>
        </div>
        
        <div style="margin-bottom: 1rem;">
           <button type="button" data-requires-auth disabled class="ai" id="btnAI" disabled style="width: 100%; background: #4c1d95;">🧠 Recomendar com IA Local (Demora ~4 minutos! Use só para testar)</button>
        </div>

        <div class="grid-2 mb-1 section-box">
          <div>
            <label>Canal 2.4GHz (1 a 11)</label>
            <div class="grid-2" style="gap: 0.5rem;">
              <input id="channel2G" data-requires-auth disabled type="number" placeholder="Ex: 6" min="1" max="11" />
              <button type="button" data-requires-auth disabled class="apply" data-apply-band="2G">Aplicar 2G</button>
            </div>
          </div>
          <div>
            <label>Canal 5GHz (36 a 144)</label>
            <div class="grid-2" style="gap: 0.5rem;">
              <input id="channel5G" data-requires-auth disabled type="number" placeholder="Ex: 100" min="36" max="144" />
              <button type="button" data-requires-auth disabled class="apply" data-apply-band="5G">Aplicar 5G</button>
            </div>
          </div>
        </div>

        <div id="status" class="status"></div>
        <div id="logCounter" class="log-counter"></div>

        <div class="mt-2 grid-2" id="resultsSection" style="display:none;">
          <div><label>Resultados do Scan</label><pre id="out"></pre></div>
          <div><label>🤖 Log</label><pre id="aiLog" style="color: #a78bfa;"></pre></div>
        </div>
      </div>

      <script nonce="${res.locals.cspNonce}">
        const API_TOKEN_STORAGE_KEY = 'scanWifiApiToken';
        let lastScanData = null;

        function setAuthConnected(connected) {
          document.querySelectorAll('[data-requires-auth]').forEach((element) => { element.disabled = !connected; });
          document.getElementById('btnInstant').disabled = !connected || !lastScanData;
          document.getElementById('btnAI').disabled = !connected || !lastScanData;
        }

        function setAuthStatus(message, isError = false) {
          const status = document.getElementById('authStatus');
          status.textContent = message;
          status.style.color = isError ? '#fca5a5' : '#94a3b8';
        }

        async function apiFetch(url, options = {}) {
          const token = sessionStorage.getItem(API_TOKEN_STORAGE_KEY);
          if (!token) throw new Error('Conecte-se com o API_TOKEN para continuar.');
          const headers = new Headers(options.headers || {});
          headers.set('Authorization', 'Bearer ' + token);
          const response = await fetch(url, { ...options, headers });
          if (response.status === 401) {
            sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
            document.getElementById('logoutButton').hidden = true;
            setAuthStatus('Token inválido ou expirado. Conecte-se novamente.', true);
            setAuthConnected(false);
          }
          return response;
        }

        async function connectApi(event) {
          event.preventDefault();
          const token = document.getElementById('apiTokenInput').value.trim();
          if (!token) { setAuthStatus('Informe o API_TOKEN configurado no servidor.', true); return; }
          try {
            const response = await fetch('/api/auth/status', { headers: { Authorization: 'Bearer ' + token } });
            if (!response.ok) throw new Error('Token inválido. Confira o valor configurado no servidor.');
            sessionStorage.setItem(API_TOKEN_STORAGE_KEY, token);
            document.getElementById('apiTokenInput').value = '';
            document.getElementById('logoutButton').hidden = false;
            setAuthConnected(true);
            setAuthStatus('Conectado. O token fica guardado nesta aba até ela ser fechada.');
            await Promise.all([loadDevices(), updateLogCounter()]);
          } catch (error) {
            setAuthStatus(error.message, true);
          }
        }

        async function logoutApi() {
          try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch {}
          sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
          document.getElementById('logoutButton').hidden = true;
          lastScanData = null;
          setAuthConnected(false);
          document.getElementById('devSel').replaceChildren(new Option('Conecte-se para carregar.', ''));
          document.getElementById('resultsSection').style.display = 'none';
          document.getElementById('channel2G').value = '';
          document.getElementById('channel5G').value = '';
          setAuthStatus('Sessão encerrada.');
          showStatus('Conecte-se para consultar ou alterar roteadores.', 'warn');
        }

        function showStatus(msg, type) {
          const el = document.getElementById('status');
          el.style.display = 'block'; el.className = 'status ' + type; el.textContent = msg;
        }
        function hideStatus() { document.getElementById('status').style.display = 'none'; }
        function getActiveSN() { return document.getElementById('snInput').value.trim(); }
        function syncSN() { document.getElementById('snInput').value = document.getElementById('devSel').value; }

        async function updateLogCounter() {
          try {
            const res = await apiFetch('/api/logs?limit=1');
            if (!res.ok) return;
            const data = await res.json();
            document.getElementById('logCounter').textContent = '📋 ' + data.total + ' logs registrados → Ver em /logs';
          } catch(e) {}
        }

        async function loadDevices() {
          if (!sessionStorage.getItem(API_TOKEN_STORAGE_KEY)) return;
          const sel = document.getElementById('devSel');
          const qty = document.getElementById('qtyInput').value || 10;
          const pages = Math.ceil(qty / 50);
          document.getElementById('paginationInfo').textContent = qty + ' dispositivos = ' + pages + ' páginas (50/página)';
          document.getElementById('btnInstant').disabled = true;
          document.getElementById('btnAI').disabled = true;
          document.getElementById('resultsSection').style.display = 'none';
          sel.replaceChildren(new Option('Carregando ' + qty + ' em ' + pages + ' páginas...', '')); sel.disabled = true;
          try {
            showStatus('⏳ Buscando ' + qty + ' equipamentos (' + pages + ' páginas)...', 'warn');
            const res = await apiFetch('/api/devices?qty=' + encodeURIComponent(qty));
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            const devs = data.devices || [];
            const pagesUsed = data.pagesUsed || pages;
            document.getElementById('paginationInfo').textContent = qty + ' solicitados → ' + devs.length + ' carregados em ' + pagesUsed + ' páginas';
            sel.replaceChildren(new Option('-- Selecione (' + devs.length + ') --', ''));
            devs.forEach(d => {
              if (!d || typeof d !== 'object') return;
              const sn = [d.serialNumber, d.sn, d.deviceInfo?.serialNumber, d._id, d.macs?.[0]]
                .find(value => typeof value === 'string' && value.trim());
              if (!sn) return;
              const label = [d.deviceInfo?.manufacturer, d.deviceInfo?.modelName, 'SN:' + sn]
                .filter(value => typeof value === 'string' && value.trim()).join(' - ');
              const option = document.createElement('option');
              option.value = sn;
              option.textContent = label;
              sel.append(option);
            });
            sel.disabled = false; hideStatus();
            updateLogCounter();
          } catch(e) { showStatus('Erro: ' + e.message, 'error'); updateLogCounter(); }
        }

        async function startScan() {
          const sn = getActiveSN(); if (!sn) { alert('Selecione ou digite o SN!'); return; }
          lastScanData = null;
          document.getElementById('resultsSection').style.display = 'grid';
          document.getElementById('out').textContent = 'Escaneando...';
          document.getElementById('aiLog').textContent = '';
          document.getElementById('btnInstant').disabled = true;
          document.getElementById('btnAI').disabled = true;
          try {
            showStatus('⏳ Escaneando redes vizinhas...', 'warn');
            const res = await apiFetch('/api/scan/' + encodeURIComponent(sn));
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            lastScanData = data; hideStatus();
            document.getElementById('out').textContent = JSON.stringify(data, null, 2);
            setAuthConnected(true);
            updateLogCounter();
          } catch(e) { showStatus('Erro: ' + e.message, 'error'); updateLogCounter(); }
        }

        async function instantRecommend() {
          if (!lastScanData) return;
          document.getElementById('aiLog').textContent = 'Calculando algoritmo matemático...';
          try {
            const res = await apiFetch('/api/instant-recommend', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ scanData: lastScanData })
            });
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            document.getElementById('channel2G').value = data.channel2G || '';
            document.getElementById('channel5G').value = data.channel5G || '';
            document.getElementById('aiLog').textContent = '✅ ' + data.raw;
            showStatus('✅ Canais calculados instantaneamente!', 'success');
            updateLogCounter();
          } catch(e) { document.getElementById('aiLog').textContent = '❌ Erro: ' + e.message; updateLogCounter(); }
        }

        async function askAI() {
          if (!lastScanData) return;
          document.getElementById('aiLog').textContent = '🧠 IA Pensando... Isso demora cerca de 4 minutos, por favor aguarde sem fechar a página.';
          try {
            const res = await apiFetch('/api/ai-recommend', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ scanData: lastScanData })
            });
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            document.getElementById('channel2G').value = data.channel2G || '';
            document.getElementById('channel5G').value = data.channel5G || '';
            document.getElementById('aiLog').textContent = '✅ Resposta da IA:\\n' + data.raw;
            showStatus('✅ IA respondeu!', 'success');
            updateLogCounter();
          } catch(e) { 
            document.getElementById('aiLog').textContent = '❌ Erro: ' + e.message; 
            showStatus('Erro na IA: ' + e.message, 'error');
            updateLogCounter();
          }
        }

        async function applyChannel(band) {
          const sn = getActiveSN();
          const channel = document.getElementById(band === '2G' ? 'channel2G' : 'channel5G').value;
          const numericChannel = Number(channel);
          const channelIsValid = Number.isInteger(numericChannel) && (band === '2G'
            ? numericChannel >= 1 && numericChannel <= 11
            : numericChannel >= 36 && numericChannel <= 144);
          if (!sn || !channelIsValid) { alert('Informe um SN e um canal inteiro dentro do intervalo da banda.'); return; }
          if (!confirm('Aplicar Canal ' + channel + ' (' + band + ') no ' + sn + '?')) return;
          try {
            showStatus('⏳ Aplicando Canal...', 'warn');
            const res = await apiFetch('/api/update-channel', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ sn, band, channel: numericChannel })
            });
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            showStatus('✅ Canal ' + channel + ' (' + band + ') aplicado!', 'success');
            updateLogCounter();
          } catch(e) { showStatus('Erro: ' + e.message, 'error'); updateLogCounter(); }
        }

        document.getElementById('apiAuthForm').addEventListener('submit', connectApi);
        document.getElementById('logoutButton').addEventListener('click', logoutApi);
        document.getElementById('loadDevicesButton').addEventListener('click', loadDevices);
        document.getElementById('startScanButton').addEventListener('click', startScan);
        document.getElementById('btnInstant').addEventListener('click', instantRecommend);
        document.getElementById('btnAI').addEventListener('click', askAI);
        document.getElementById('devSel').addEventListener('change', syncSN);
        document.querySelectorAll('[data-apply-band]').forEach(button => {
          button.addEventListener('click', () => applyChannel(button.dataset.applyBand));
        });
        if (sessionStorage.getItem(API_TOKEN_STORAGE_KEY)) {
          document.getElementById('logoutButton').hidden = false;
          setAuthStatus('Validando sessão desta aba...');
          fetch('/api/auth/status', { headers: { Authorization: 'Bearer ' + sessionStorage.getItem(API_TOKEN_STORAGE_KEY) } })
            .then(response => {
              if (!response.ok) throw new Error('Token inválido. Conecte-se novamente.');
              setAuthConnected(true);
              setAuthStatus('Conectado nesta aba.');
              return Promise.all([loadDevices(), updateLogCounter()]);
            })
            .catch(error => {
              sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
              document.getElementById('logoutButton').hidden = true;
              setAuthConnected(false);
              setAuthStatus(error.message, true);
            });
        } else setAuthConnected(false);
      </script>
    </body>
    </html>
  `);
});

app.use((error, _req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.type === 'entity.too.large') return res.status(413).json({ error: 'Corpo da requisição excede o limite de 100 KB.' });
  if (error.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido.' });
  console.error('Erro interno ao processar requisição:', error.code || 'REQUEST_ERROR');
  return res.status(500).json({ error: 'Não foi possível processar a solicitação.' });
});

app.listen(PORT, HOST, () => {
  addLog('SYSTEM', `Servidor iniciado na porta ${PORT}`, 'success', { port: PORT, nodeVersion: process.version, maxPageSize: FLASHMAN_MAX_PAGE_SIZE });
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
  console.log(`📋 Logs disponíveis em http://localhost:${PORT}/logs`);
  console.log(`📄 Paginação automática: max ${FLASHMAN_MAX_PAGE_SIZE} por página`);
});
