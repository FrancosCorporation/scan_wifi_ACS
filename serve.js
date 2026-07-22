const express = require('express');
const axios = require('axios');
const https = require('https');
const dns = require('dns');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = 3000;
dns.setDefaultResultOrder('ipv4first');

const API_BASE_URL = 'https://flashman.olvtelecom.com.br';
const CLIENT_ID = 'REDACTED';
const CLIENT_SECRET = 'REDACTED';

const LOG_FILE = path.join(__dirname, 'flashman_logs.json');

// ============================================================
// 📝 SISTEMA DE LOGS
// ============================================================

let logs = [];

function loadLogsFromFile() {
  try {
    if (fs.existsSync(LOG_FILE)) {
      const raw = fs.readFileSync(LOG_FILE, 'utf8');
      logs = JSON.parse(raw);
    }
  } catch (e) {
    logs = [];
  }
}

function saveLogsToFile() {
  try {
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2), 'utf8');
  } catch (e) {
    console.error('Erro salvando logs em arquivo:', e.message);
  }
}

function addLog(type, detail, status, extra = {}) {
  const entry = {
    id: logs.length + 1,
    timestamp: new Date().toISOString(),
    timestampLocal: new Date().toLocaleString('pt-BR'),
    type,
    detail,
    status,
    extra
  };
  logs.push(entry);
  saveLogsToFile();
  console.log(`[LOG #${entry.id}] ${type} | ${status} | ${detail}`);
  return entry;
}

loadLogsFromFile();

// ============================================================
// 🔑 AUTENTICAÇÃO OAUTH2
// ============================================================

const flashmanApi = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  httpsAgent: new https.Agent({ rejectUnauthorized: false, family: 4 }),
  headers: { 'Accept': 'application/json' }
});

const ollamaApi = axios.create({
  baseURL: 'http://localhost:11434',
  timeout: 300000
});

let authToken = null;

async function getAccessToken() {
  if (authToken) return authToken;
  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');
  params.append('client_id', CLIENT_ID);
  params.append('client_secret', CLIENT_SECRET);

  try {
    addLog('AUTH', 'Iniciando autenticação OAuth2', 'info');
    const response = await flashmanApi.post('/api/v2/token/oauth', params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    authToken = response.data.access_token || response.data.token || response.data.accessToken;
    if (!authToken) {
      addLog('AUTH', 'Token não encontrado na resposta', 'error', { responseKeys: Object.keys(response.data) });
      throw new Error('Token não encontrado');
    }
    addLog('AUTH', 'Autenticação OAuth2 realizada com sucesso', 'success', { tokenPrefix: authToken.substring(0, 10) + '...' });
    return authToken;
  } catch (error) {
    addLog('AUTH', 'Falha na autenticação OAuth2', 'error', { message: error.message, status: error.response?.status });
    throw new Error('Falha na autenticação.');
  }
}

async function getAuthHeaders() {
  const token = await getAccessToken();
  return { 'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
}

// ============================================================
// 📡 ROTAS DA API FLASHMAN
// ============================================================

app.get('/api/devices', async (req, res) => {
  const qty = req.query.qty || 10;
  try {
    addLog('DEVICES', `Buscando ${qty} dispositivos`, 'info', { qty });
    const headers = await getAuthHeaders();
    const response = await flashmanApi.get('/api/v2/devices/views/natural', {
      headers, params: {
        'pagination[pageSize]': qty,
        'pagination[currentPage]': 1,
        'sorting[sortBy]': 'lastInform',
        'sorting[sortOrder]': 'desc'
      }
    });
    const devices = response.data.registers || [];
    addLog('DEVICES', `${devices.length} dispositivos carregados`, 'success', {
      qty,
      count: devices.length,
      sampleSNs: devices.slice(0, 3).map(d => d.serialNumber || d.sn || d._id || '?')
    });
    res.json({ devices });
  } catch (error) {
    if (error.response?.status === 401 || error.response?.status === 400) authToken = null;
    addLog('DEVICES', `Erro ao buscar dispositivos`, 'error', { qty, message: error.message, status: error.response?.status });
    res.status(error.response?.status || 500).json({ error: error.response?.data?.message || error.message });
  }
});

app.get('/api/scan/:sn', async (req, res) => {
  const { sn } = req.params;
  if (!sn || sn.length < 5) {
    addLog('SCAN', `SN inválido recebido: "${sn}"`, 'error', { sn });
    return res.status(400).json({ error: 'SN inválido.' });
  }
  try {
    addLog('SCAN', `Iniciando scan de redes vizinhas para SN: ${sn}`, 'info', { sn });
    const headers = await getAuthHeaders();
    await flashmanApi.post(`/api/v2/devices/${sn}/diagnostics/neighbor/start`, {}, { headers, validateStatus: () => true });

    addLog('SCAN', `Scan iniciado, aguardando resultado... (SN: ${sn})`, 'info', { sn });

    const maxAttempts = 30;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const stateResp = await flashmanApi.get(`/api/v2/devices/${sn}/diagnostics/neighbor/state`, { headers, validateStatus: () => true });
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
    addLog('SCAN', `Erro no scan para SN: ${sn}`, 'error', { sn, message: error.message });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/update-channel', async (req, res) => {
  const { sn, band, channel } = req.body;
  if (!sn || !band || !channel) {
    addLog('UPDATE', `Dados incompletos para atualização de canal`, 'error', { sn, band, channel });
    return res.status(400).json({ error: 'Dados incompletos.' });
  }
  try {
    addLog('UPDATE', `Aplicando canal ${channel} na banda ${band} para SN: ${sn}`, 'info', { sn, band, channel });
    const headers = await getAuthHeaders();
    const instancePath = band === '2G' ? '1' : '5';
    const payload = [{
      "parameter": `InternetGatewayDevice.LANDevice.1.WLANConfiguration.${instancePath}.Channel`,
      "value": parseInt(channel),
      "type": "xsd:unsignedInt"
    }];
    const flashResp = await flashmanApi.post(`/api/v2/devices/${sn}/parameters/update`, payload, { headers });
    addLog('UPDATE', `Canal ${channel} (${band}) aplicado com sucesso no SN: ${sn}`, 'success', {
      sn, band, channel, flashmanResponse: flashResp.data
    });
    res.json({ success: true, flashmanResponse: flashResp.data });
  } catch (error) {
    addLog('UPDATE', `Erro ao aplicar canal ${channel} (${band}) no SN: ${sn}`, 'error', {
      sn, band, channel, message: error.message, flashmanError: error.response?.data
    });
    res.status(500).json({ error: error.response?.data || error.message });
  }
});

// ============================================================
// 🧠 ROTAS: CÁLCULO INSTANTÂNEO E IA
// ============================================================

function getBestChannelsDeterministic(scanData) {
  // 1. Canais ideais (2.4G apenas não sobrepostos; 5G inclui faixas limpas e DFS altas)
  const valid2G = [1, 6, 11];
  const valid5G = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149];

  // 2. Inicializa o "peso de interferência". Quanto menor a pontuação, melhor o canal.
  const weights2G = { 1: 0, 6: 0, 11: 0 };
  const weights5G = {};
  valid5G.forEach(c => weights5G[c] = 0);

  // 3. Função para calcular o peso do sinal (Interferência)
  // Sinal -40 (Forte) gera peso 60. Sinal -90 (Fraco) gera peso 10.
  const getSignalPenalty = (net) => {
    const rssi = parseInt(net.rssi || net.signal || net.noise); // Busca a chave que a API devolver
    if (isNaN(rssi) || rssi > 0) return 30; // Peso médio padrão caso o roteador não informe o RSSI
    return Math.max(0, 100 + rssi); // Ex: 100 + (-70) = 30 pontos de penalidade
  };

  scanData.forEach(net => {
    const netChannel = parseInt(net.channel);
    if (isNaN(netChannel)) return;

    const penalty = getSignalPenalty(net);

    // ==========================================
    // 📡 Lógica 2.4 GHz (Cálculo de Sobreposição)
    // ==========================================
    if (netChannel >= 1 && netChannel <= 14) {
      valid2G.forEach(candidate => {
        const distance = Math.abs(netChannel - candidate);
        // Penaliza canais próximos com base na distância de sobreposição
        if (distance === 0) weights2G[candidate] += penalty;         // 100% de impacto
        else if (distance === 1) weights2G[candidate] += penalty * 0.8; // 80% de impacto
        else if (distance === 2) weights2G[candidate] += penalty * 0.6; // 60% de impacto
        else if (distance === 3) weights2G[candidate] += penalty * 0.4; // 40% de impacto
        else if (distance === 4) weights2G[candidate] += penalty * 0.2; // 20% de impacto
      });
    }

    // ==========================================
    // 🚀 Lógica 5 GHz (Cálculo de Largura de Banda)
    // ==========================================
    if (netChannel >= 36) {
      // Tenta extrair a largura de banda (ex: "40MHz" -> 40)
      let bw = 20;
      if (net.bandwidth) {
        const parsedBw = parseInt(net.bandwidth.replace(/[^0-9]/g, ''));
        if (!isNaN(parsedBw)) bw = parsedBw;
      }

      // Aplica a penalidade no canal base da rede vizinha
      if (weights5G.hasOwnProperty(netChannel)) {
        weights5G[netChannel] += penalty;
      }

      // Se a rede for "larga" (40, 80, 160MHz), ela invade os canais adjacentes (de 4 em 4)
      if (bw >= 40) {
        if (weights5G.hasOwnProperty(netChannel + 4)) weights5G[netChannel + 4] += (penalty * 0.8);
        if (weights5G.hasOwnProperty(netChannel - 4)) weights5G[netChannel - 4] += (penalty * 0.8);
      }
      if (bw >= 80) {
        if (weights5G.hasOwnProperty(netChannel + 8)) weights5G[netChannel + 8] += (penalty * 0.5);
        if (weights5G.hasOwnProperty(netChannel - 8)) weights5G[netChannel - 8] += (penalty * 0.5);
      }
    }
  });

  // 4. Encontra o canal com o MENOR peso (menos interferência) no 2.4G
  let best2G = 1, minWeight2G = Infinity;
  for (const ch in weights2G) {
    if (weights2G[ch] < minWeight2G) {
      minWeight2G = weights2G[ch];
      best2G = ch;
    }
  }

  // 5. Encontra o canal com o MENOR peso no 5G
  // Invertemos a ordem do array (usando reverse) para que o algoritmo DÊ PREFERÊNCIA aos canais
  // mais altos (ex: 149, 144...) em caso de empate (peso igual a 0).
  let best5G = 149, minWeight5G = Infinity; 
  for (const ch of [...valid5G].reverse()) { 
    if (weights5G[ch] < minWeight5G) {
      minWeight5G = weights5G[ch];
      best5G = ch;
    }
  }

  // 6. Arredonda os números para os logs da interface ficarem legíveis
  Object.keys(weights2G).forEach(k => weights2G[k] = Math.round(weights2G[k]));
  Object.keys(weights5G).forEach(k => weights5G[k] = Math.round(weights5G[k]));

  // Mantive a nomenclatura "counts2G/5G" no retorno para não quebrar a sua rota '/api/instant-recommend'
  return { 
    channel2G: String(best2G), 
    channel5G: String(best5G), 
    counts2G: weights2G, 
    counts5G: weights5G 
  };
}

app.post('/api/instant-recommend', async (req, res) => {
  const { scanData } = req.body;
  if (!scanData || scanData.length === 0) {
    addLog('INSTANT', `Scan data vazio na recomendação instantânea`, 'error');
    return res.status(400).json({ error: 'Escanee primeiro.' });
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
    addLog('INSTANT', `Erro na recomendação instantânea`, 'error', { message: error.message });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ai-recommend', async (req, res) => {
  const { scanData } = req.body;
  if (!scanData || scanData.length === 0) {
    addLog('AI', `Scan data vazio na recomendação IA`, 'error');
    return res.status(400).json({ error: 'Escanee primeiro.' });
  }
  try {
    const startTime = Date.now();
    addLog('AI', `Iniciando recomendação via IA local (Ollama)`, 'info', { networksAnalyzed: scanData.length });

    const allChannels = scanData.map(net => net.channel).filter(c => c !== undefined && c !== null);
    const uniqueChannels = [...new Set(allChannels)].join(', ');

    const prompt = `You are a Wi-Fi optimizer. Occupied channels: [${uniqueChannels}]. Rules: 2.4GHz channel must be 1-11. 5GHz channel must be 36-144. Choose the best channel for each band. Output format: 2G:X,5G:Y`;

    addLog('AI', `Prompt enviado ao Ollama`, 'info', { prompt, uniqueChannels });

    const ollamaResp = await ollamaApi.post('/api/generate', {
      model: 'qwen3.5:0.8b',
      prompt: prompt,
      stream: false
    });

    const elapsed = Date.now() - startTime;
    const iaText = ollamaResp.data?.response || '';
    addLog('AI', `IA respondeu`, 'info', { rawResponse: iaText, elapsedMs: elapsed, model: 'qwen3.5:0.8b' });

    const match2G = iaText.match(/2G[:\s]*([0-9]+)/i);
    const match5G = iaText.match(/5G[:\s]*([0-9]+)/i);

    if (!match2G || !match5G) {
      addLog('AI', `IA não retornou no formato esperado`, 'error', { rawResponse: iaText, elapsedMs: elapsed });
      return res.status(400).json({ error: `IA não retornou no formato esperado. Resposta: "${iaText}"` });
    }

    const channel2G = match2G[1];
    const channel5G = match5G[1];

    addLog('AI', `Recomendação IA concluída com sucesso`, 'success', {
      channel2G, channel5G, rawResponse: iaText, elapsedMs: elapsed, model: 'qwen3.5:0.8b'
    });

    res.json({ channel2G, channel5G, raw: iaText });
  } catch (error) {
    addLog('AI', `Erro na recomendação IA`, 'error', { message: error.message, ollamaConnected: false });
    res.status(500).json({ error: "Ollama desconectado ou demorou demais (limite 5 min)." });
  }
});

// ============================================================
// 📋 ROTA DE LOGS (API + INTERFACE)
// ============================================================

app.get('/api/logs', (req, res) => {
  const typeFilter = req.query.type || '';
  const statusFilter = req.query.status || '';
  const search = req.query.search || '';
  const limit = parseInt(req.query.limit) || 200;

  let filtered = [...logs].reverse();

  if (typeFilter) filtered = filtered.filter(l => l.type === typeFilter);
  if (statusFilter) filtered = filtered.filter(l => l.status === statusFilter);
  if (search) filtered = filtered.filter(l =>
    l.detail.toLowerCase().includes(search.toLowerCase()) ||
    JSON.stringify(l.extra).toLowerCase().includes(search.toLowerCase())
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
  const count = logs.length;
  logs = [];
  saveLogsToFile();
  addLog('SYSTEM', `Logs limpos pelo usuário (${count} entradas removidas)`, 'info');
  res.json({ success: true, removed: count });
});

app.get('/logs', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Flashman Logs</title>
      <style>
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
          background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1rem;
          text-align: center;
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
        .btn {
          padding: 0.5rem 1rem; border-radius: 6px; border: none; font-size: 0.85rem;
          cursor: pointer; font-weight: bold; color: #fff;
        }
        .btn.refresh { background: #3b82f6; }
        .btn.clear { background: #ef4444; }
        .btn.clear:hover { background: #dc2626; }
        .btn.refresh:hover { background: #2563eb; }
        .btn.export { background: #10b981; }
        .btn.export:hover { background: #059669; }

        .log-container {
          padding: 1rem 2rem; max-height: calc(100vh - 240px); overflow-y: auto;
        }
        .log-container::-webkit-scrollbar { width: 8px; }
        .log-container::-webkit-scrollbar-track { background: #0f172a; }
        .log-container::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }

        .log-entry {
          background: #1e293b; border: 1px solid #334155; border-radius: 8px;
          padding: 0.75rem 1rem; margin-bottom: 0.5rem; transition: all 0.2s;
        }
        .log-entry:hover { border-color: #475569; background: #233044; }

        .log-header {
          display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.4rem;
        }
        .log-id {
          background: #334155; padding: 0.15rem 0.5rem; border-radius: 4px;
          font-size: 0.7rem; font-weight: bold; color: #94a3b8;
        }
        .log-type-badge {
          padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.7rem;
          font-weight: bold; letter-spacing: 0.5px;
        }
        .log-type-badge.AUTH { background: #1e3a5f; color: #38bdf8; }
        .log-type-badge.DEVICES { background: #1e3a5f; color: #60a5fa; }
        .log-type-badge.SCAN { background: #312e81; color: #a78bfa; }
        .log-type-badge.INSTANT { background: #78350f; color: #fbbf24; }
        .log-type-badge.AI { background: #4c1d95; color: #c084fc; }
        .log-type-badge.UPDATE { background: #064e3b; color: #6ee7b7; }
        .log-type-badge.SYSTEM { background: #334155; color: #94a3b8; }

        .log-status-dot {
          width: 8px; height: 8px; border-radius: 50%; display: inline-block;
        }
        .log-status-dot.success { background: #10b981; }
        .log-status-dot.error { background: #ef4444; }
        .log-status-dot.info { background: #38bdf8; }
        .log-status-dot.warn { background: #f59e0b; }

        .log-time { font-size: 0.75rem; color: #64748b; }
        .log-detail { font-size: 0.9rem; color: #e2e8f0; }

        .log-extra-toggle {
          font-size: 0.75rem; color: #38bdf8; cursor: pointer; margin-top: 0.3rem;
          user-select: none;
        }
        .log-extra-toggle:hover { color: #7dd3fc; }

        .log-extra-content {
          display: none; margin-top: 0.5rem; padding: 0.5rem;
          background: #0f172a; border-radius: 6px; border: 1px solid #1e293b;
          font-size: 0.75rem; color: #94a3b8; white-space: pre-wrap; word-break: break-all;
          max-height: 200px; overflow-y: auto;
        }
        .log-extra-content.open { display: block; }

        .empty-state {
          text-align: center; padding: 3rem; color: #64748b;
        }
        .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; }
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

      <div class="stats-bar" id="statsBar">
        <div class="stat-card total"><div class="num" id="statTotal">0</div><div class="label">Total</div></div>
        <div class="stat-card success"><div class="num" id="statSuccess">0</div><div class="label">Sucessos</div></div>
        <div class="stat-card error"><div class="num" id="statError">0</div><div class="label">Erros</div></div>
        <div class="stat-card info"><div class="num" id="statInfo">0</div><div class="label">Info</div></div>
        <div class="stat-card warn"><div class="num" id="statWarn">0</div><div class="label">Avisos</div></div>
      </div>

      <div class="filters">
        <label>Tipo</label>
        <select id="filterType" onchange="refreshLogs()">
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
        <select id="filterStatus" onchange="refreshLogs()">
          <option value="">Todos</option>
          <option value="success">Sucesso</option>
          <option value="error">Erro</option>
          <option value="info">Info</option>
          <option value="warn">Aviso</option>
        </select>

        <label>Buscar</label>
        <input id="filterSearch" type="text" placeholder="Buscar nos logs..." oninput="refreshLogs()" />

        <button class="btn refresh" onclick="refreshLogs()">🔄 Atualizar</button>
        <button class="btn export" onclick="exportLogs()">📥 Exportar JSON</button>
        <button class="btn clear" onclick="clearLogs()">🗑️ Limpar Todos</button>
      </div>

      <div class="log-container" id="logContainer">
        <div class="empty-state">
          <div class="icon">📋</div>
          Carregando logs...
        </div>
      </div>

      <script>
        let currentLogs = [];

        function updateStats(logs) {
          document.getElementById('statTotal').textContent = logs.length;
          document.getElementById('statSuccess').textContent = logs.filter(l => l.status === 'success').length;
          document.getElementById('statError').textContent = logs.filter(l => l.status === 'error').length;
          document.getElementById('statInfo').textContent = logs.filter(l => l.status === 'info').length;
          document.getElementById('statWarn').textContent = logs.filter(l => l.status === 'warn').length;
        }

        function renderLogs(logs) {
          const container = document.getElementById('logContainer');
          if (logs.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="icon">📭</div>Nenhum log encontrado.</div>';
            return;
          }

          container.innerHTML = logs.map(l => {
            const extraStr = l.extra && Object.keys(l.extra).length > 0
              ? JSON.stringify(l.extra, null, 2) : '';
            const hasExtra = extraStr.length > 0;

            return '<div class="log-entry">'
              + '<div class="log-header">'
              + '<span class="log-id">#' + l.id + '</span>'
              + '<span class="log-type-badge ' + l.type + '">' + l.type + '</span>'
              + '<span class="log-status-dot ' + l.status + '"></span>'
              + '<span class="log-time">' + l.timestampLocal + '</span>'
              + '</div>'
              + '<div class="log-detail">' + l.detail + '</div>'
              + (hasExtra
                ? '<div class="log-extra-toggle" onclick="toggleExtra(this)">▸ Detalhes (' + Object.keys(l.extra).length + ' campos)</div>'
                  + '<div class="log-extra-content">' + extraStr + '</div>'
                : '')
              + '</div>';
          }).join('');
        }

        function toggleExtra(el) {
          const content = el.nextElementSibling;
          const isOpen = content.classList.contains('open');
          content.classList.toggle('open');
          el.textContent = isOpen ? '▸ Detalhes' : '▾ Detalhes';
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

            const res = await fetch('/api/logs?' + params.toString());
            const data = await res.json();

            currentLogs = data.logs;
            updateStats(data.logs);
            renderLogs(data.logs);
            document.getElementById('lastUpdate').textContent = 'Atualizado: ' + new Date().toLocaleTimeString('pt-BR');
          } catch(e) {
            document.getElementById('logContainer').innerHTML = '<div class="empty-state"><div class="icon">❌</div>Erro ao carregar logs: ' + e.message + '</div>';
          }
        }

        async function clearLogs() {
          if (!confirm('Tem certeza que deseja limpar TODOS os logs? Essa ação não pode ser desfeita.')) return;
          try {
            const res = await fetch('/api/logs', { method: 'DELETE' });
            const data = await res.json();
            alert('Logs limpos! ' + data.removed + ' entradas removidas.');
            refreshLogs();
          } catch(e) { alert('Erro: ' + e.message); }
        }

        function exportLogs() {
          const data = JSON.stringify(currentLogs, null, 2);
          const blob = new Blob([data], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'flashman_logs_' + new Date().toISOString().slice(0, 10) + '.json';
          a.click();
          URL.revokeObjectURL(url);
        }

        // Auto-refresh every 5 seconds
        setInterval(refreshLogs, 5000);

        window.onload = refreshLogs;
      </script>
    </body>
    </html>
  `);
});

// ============================================================
// 🌐 INTERFACE WEB PRINCIPAL
// ============================================================

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Flashman Wi-Fi Optimizer</title>
      <style>
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
      </style>
    </head>
    <body>
      <div class="card">
        <h1>
          <span>📶 Flashman Wi-Fi Optimizer</span>
          <a href="/logs">📋 Ver Logs →</a>
        </h1>
        
        <div class="grid-3 mb-1">
          <div><label>Qtd. Aparelhos</label><input id="qtyInput" type="number" value="10" min="1" max="1000" /></div>
          <div><label>Selecionar da Lista</label><select id="devSel" disabled onchange="syncSN()"><option>Carregando...</option></select></div>
          <div><label>Ou digite o SN Manual</label><input id="snInput" type="text" placeholder="Ex: ZTEEQL4Q3B06071" /></div>
        </div>
        
        <div class="mb-1" style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem;">
          <button onclick="loadDevices()">🔄 Carregar Lista</button>
          <button onclick="startScan()">🔍 Escanear Redes</button>
          <button class="instant" onclick="instantRecommend()" id="btnInstant" disabled>⚡ Recomendar (Instantâneo)</button>
        </div>
        
        <div style="margin-bottom: 1rem;">
           <button class="ai" onclick="askAI()" id="btnAI" disabled style="width: 100%; background: #4c1d95;">🧠 Recomendar com IA Local (Demora ~4 minutos! Use só para testar)</button>
        </div>

        <div class="grid-2 mb-1 section-box">
          <div>
            <label>Canal 2.4GHz (1 a 11)</label>
            <div class="grid-2" style="gap: 0.5rem;">
              <input id="channel2G" type="number" placeholder="Ex: 6" min="1" max="11" />
              <button class="apply" onclick="applyChannel('2G')">Aplicar 2G</button>
            </div>
          </div>
          <div>
            <label>Canal 5GHz (36 a 144)</label>
            <div class="grid-2" style="gap: 0.5rem;">
              <input id="channel5G" type="number" placeholder="Ex: 100" min="36" max="144" />
              <button class="apply" onclick="applyChannel('5G')">Aplicar 5G</button>
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

      <script>
        let lastScanData = null;

        function showStatus(msg, type) {
          const el = document.getElementById('status');
          el.style.display = 'block'; el.className = 'status ' + type; el.textContent = msg;
        }
        function hideStatus() { document.getElementById('status').style.display = 'none'; }
        function getActiveSN() { return document.getElementById('snInput').value.trim(); }
        function syncSN() { document.getElementById('snInput').value = document.getElementById('devSel').value; }

        async function updateLogCounter() {
          try {
            const res = await fetch('/api/logs?limit=1');
            const data = await res.json();
            document.getElementById('logCounter').textContent = '📋 ' + data.total + ' logs registrados → Ver em /logs';
          } catch(e) {}
        }

        async function loadDevices() {
          const sel = document.getElementById('devSel');
          const qty = document.getElementById('qtyInput').value || 10;
          document.getElementById('btnInstant').disabled = true;
          document.getElementById('btnAI').disabled = true;
          document.getElementById('resultsSection').style.display = 'none';
          sel.innerHTML = '<option>Carregando...</option>'; sel.disabled = true;
          try {
            showStatus('⏳ Buscando equipamentos...', 'warn');
            const res = await fetch('/api/devices?qty=' + qty);
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            const devs = data.devices || [];
            sel.innerHTML = '<option value="">-- Selecione (' + devs.length + ') --</option>';
            devs.forEach(d => {
              const sn = d.serialNumber || d.sn || d.deviceInfo?.serialNumber || d._id || d.macs?.[0];
              const label = [d.deviceInfo?.manufacturer, d.deviceInfo?.modelName, 'SN:'+sn].filter(Boolean).join(' - ');
              sel.innerHTML += '<option value="' + sn + '">' + label + '</option>';
            });
            sel.disabled = false; hideStatus();
            updateLogCounter();
          } catch(e) { showStatus('Erro: ' + e.message, 'error'); updateLogCounter(); }
        }

        async function startScan() {
          const sn = getActiveSN(); if (!sn) { alert('Selecione ou digite o SN!'); return; }
          document.getElementById('resultsSection').style.display = 'grid';
          document.getElementById('out').textContent = 'Escaneando...';
          document.getElementById('aiLog').textContent = '';
          document.getElementById('btnInstant').disabled = true;
          document.getElementById('btnAI').disabled = true;
          try {
            showStatus('⏳ Escaneando redes vizinhas...', 'warn');
            const res = await fetch('/api/scan/' + encodeURIComponent(sn));
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            lastScanData = data; hideStatus();
            document.getElementById('out').textContent = JSON.stringify(data, null, 2);
            document.getElementById('btnInstant').disabled = false;
            document.getElementById('btnAI').disabled = false;
            updateLogCounter();
          } catch(e) { showStatus('Erro: ' + e.message, 'error'); updateLogCounter(); }
        }

        async function instantRecommend() {
          if (!lastScanData) return;
          document.getElementById('aiLog').textContent = 'Calculando algoritmo matemático...';
          try {
            const res = await fetch('/api/instant-recommend', {
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
            const res = await fetch('/api/ai-recommend', {
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
          if (!sn || !channel) { alert('SN e Canal são obrigatórios!'); return; }
          if (!confirm('Aplicar Canal ' + channel + ' (' + band + ') no ' + sn + '?')) return;
          try {
            showStatus('⏳ Aplicando Canal...', 'warn');
            const res = await fetch('/api/update-channel', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ sn, band, channel: parseInt(channel) })
            });
            const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Erro');
            showStatus('✅ Canal ' + channel + ' (' + band + ') aplicado!', 'success');
            updateLogCounter();
          } catch(e) { showStatus('Erro: ' + e.message, 'error'); updateLogCounter(); }
        }

        window.onload = loadDevices;
      </script>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  addLog('SYSTEM', `Servidor iniciado na porta ${PORT}`, 'success', { port: PORT, nodeVersion: process.version });
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
  console.log(`📋 Logs disponíveis em http://localhost:${PORT}/logs`);
});