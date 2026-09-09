"""
r3con v7.2 - Web Dashboard PRO v2 - WebSocket Real-time + ML + All domains
Real-time updates via Flask-SocketIO with polling fallback
"""
from __future__ import annotations
from flask import Flask, render_template_string, jsonify, request
import json
from datetime import datetime
from pathlib import Path
import threading
import time
from collections import deque

# Try to import SocketIO
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['SECRET_KEY'] = 'r3con-v7.2-secret-key'

socketio = None
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# In-memory real-time data
realtime_logs = deque(maxlen=100)
realtime_stats = {
    "total_analyses": 0,
    "total_findings": 0,
    "active_scans": 0,
    "last_update": datetime.now().isoformat(),
}
connected_clients = 0

DASHBOARD_HTML_V2 = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>r3con v7.2 — PRO Dashboard Real-time</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Courier New',monospace; background: linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 100%); color:#e2e8f0; padding:20px; min-height:100vh; }
        .container { max-width:1800px; margin:0 auto; }
        .header { text-align:center; margin-bottom:20px; border-bottom:2px solid #22d3ee; padding-bottom:15px; }
        .header h1 { color:#22d3ee; font-size:2.4em; margin-bottom:6px; }
        .header .subtitle { color:#94a3b8; font-size:0.9em; }
        .header .version { color:#f59e0b; font-size:0.8em; margin-top:4px; }
        .realtime-bar { background:#0f172a; border:1px solid #22d3ee; border-radius:6px; padding:10px; margin-bottom:15px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; }
        .realtime-status { display:flex; gap:15px; align-items:center; }
        .status-dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
        .dot-green { background:#22c55e; box-shadow:0 0 8px #22c55e; animation:pulse 2s infinite; }
        .dot-yellow { background:#eab308; }
        .dot-red { background:#ef4444; }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.5; } }
        .tabs { display:flex; gap:6px; margin-bottom:15px; flex-wrap:wrap; }
        .tab-btn { background:#1e293b; border:1px solid #334155; color:#94a3b8; padding:7px 14px; border-radius:5px; cursor:pointer; font-family:inherit; font-size:0.8em; }
        .tab-btn.active { background:#22d3ee; color:#0f0f1a; border-color:#22d3ee; font-weight:bold; }
        .tab-content { display:none; }
        .tab-content.active { display:block; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; margin-bottom:18px; }
        .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:18px; }
        .grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; margin-bottom:18px; }
        .grid-4 { display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:14px; margin-bottom:18px; }
        .card { background:#1e293b; border:1px solid #334155; border-radius:7px; padding:14px; box-shadow:0 4px 6px rgba(0,0,0,0.3); }
        .card h2 { color:#7dd3fc; font-size:1em; margin-bottom:10px; border-bottom:1px solid #475569; padding-bottom:6px; }
        .stat-row { display:flex; justify-content:space-between; margin-bottom:5px; padding:5px 0; border-bottom:1px solid #334155; font-size:0.85em; }
        .stat-label { color:#94a3b8; }
        .stat-value { color:#22d3ee; font-weight:bold; }
        .sev-critical { color:#dc2626; } .sev-high { color:#ea580c; } .sev-medium { color:#ca8a04; } .sev-low { color:#16a34a; }
        .findings-list { max-height:450px; overflow-y:auto; }
        .finding-item { background:#0f172a; padding:9px; margin-bottom:6px; border-left:3px solid #475569; border-radius:3px; font-size:0.8em; transition:all 0.3s; }
        .finding-item.critical { border-left-color:#dc2626; } .finding-item.high { border-left-color:#ea580c; } .finding-item.medium { border-left-color:#ca8a04; } .finding-item.low { border-left-color:#16a34a; }
        .finding-item.new { background:#1a2a1a; animation:highlight 2s; }
        @keyframes highlight { 0% { background:#2a3a2a; } 100% { background:#0f172a; } }
        .finding-type { color:#e2e8f0; font-weight:bold; font-size:0.85em; }
        .finding-desc { color:#94a3b8; font-size:0.8em; margin-top:3px; }
        .log-box { background:#0a0a0f; border:1px solid #334155; border-radius:6px; padding:10px; max-height:300px; overflow-y:auto; font-size:0.75em; font-family:monospace; }
        .log-entry { margin-bottom:3px; padding:2px 0; }
        .log-time { color:#64748b; }
        .log-info { color:#22d3ee; }
        .log-warn { color:#eab308; }
        .log-error { color:#ef4444; }
        .log-success { color:#22c55e; }
        .progress-bar { width:100%; height:5px; background:#334155; border-radius:3px; overflow:hidden; margin-top:4px; }
        .progress-fill { height:100%; background:linear-gradient(90deg,#22d3ee,#7dd3fc); transition:width 0.5s; }
        .badge { display:inline-block; padding:2px 7px; border-radius:12px; font-size:0.65em; font-weight:bold; }
        .badge-ok { background:#16a34a; color:#fff; } .badge-warn { background:#ca8a04; color:#fff; } .badge-crit { background:#dc2626; color:#fff; } .badge-info { background:#334155; color:#94a3b8; }
        .search-box { width:100%; padding:7px; background:#0f172a; border:1px solid #334155; border-radius:5px; color:#e2e8f0; font-family:inherit; margin-bottom:10px; font-size:0.85em; }
        .btn { background:#22d3ee; color:#0f0f1a; border:none; padding:5px 10px; border-radius:4px; cursor:pointer; font-family:inherit; font-weight:bold; font-size:0.8em; }
        .btn:hover { background:#7dd3fc; }
        .btn-sm { padding:3px 8px; font-size:0.7em; }
        .chart-box { width:100%; height:200px; background:#0f172a; border-radius:6px; border:1px solid #334155; display:flex; align-items:center; justify-content:center; color:#64748b; position:relative; overflow:hidden; }
        .chart-bar { position:absolute; bottom:0; background:linear-gradient(to top, #22d3ee, #7dd3fc); border-radius:3px 3px 0 0; transition:height 0.5s; }
        .footer { text-align:center; color:#64748b; margin-top:30px; padding-top:12px; border-top:1px solid #334155; font-size:0.75em; }
        .ml-badge { background:linear-gradient(90deg,#8b5cf6,#a78bfa); color:white; padding:2px 8px; border-radius:12px; font-size:0.7em; }
        .ws-indicator { display:inline-block; padding:3px 8px; border-radius:4px; font-size:0.7em; font-weight:bold; }
        .ws-connected { background:#16a34a; color:white; }
        .ws-disconnected { background:#dc2626; color:white; }
        .ws-polling { background:#ca8a04; color:white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ r3con v7.2 PRO Dashboard — Real-time</h1>
            <p class="subtitle">Binary • Malware • Network • Web • Cloud • Container • AI • Secrets • Decompiler • Symbolic</p>
            <p class="version">v7.2 Titan-Omega-Full-Rival-Plus | WebSocket Real-time + ML Embeddings TF-IDF + sentence-transformers + 25 CLI groups</p>
        </div>

        <div class="realtime-bar">
            <div class="realtime-status">
                <span><span class="status-dot dot-green"></span> <span id="ws-status" class="ws-indicator ws-connected">WebSocket: Connected</span></span>
                <span>📊 Analyses: <strong id="rt-analyses" style="color:#22d3ee">0</strong></span>
                <span>🐛 Findings: <strong id="rt-findings" style="color:#f59e0b">0</strong></span>
                <span>🔄 Active: <strong id="rt-active" style="color:#22c55e">0</strong></span>
                <span>👥 Clients: <strong id="rt-clients" style="color:#a78bfa">1</strong></span>
            </div>
            <div>
                <span style="font-size:0.75em; color:#64748b" id="rt-last-update">Last: now</span>
                <button class="btn btn-sm" onclick="clearLogs()">Clear Logs</button>
            </div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('overview')">📊 Overview</button>
            <button class="tab-btn" onclick="switchTab('realtime')">⚡ Real-time</button>
            <button class="tab-btn" onclick="switchTab('findings')">🐛 Findings</button>
            <button class="tab-btn" onclick="switchTab('malware')">🦠 Malware</button>
            <button class="tab-btn" onclick="switchTab('network')">🌐 Network</button>
            <button class="tab-btn" onclick="switchTab('web')">🌐 Web</button>
            <button class="tab-btn" onclick="switchTab('cloud')">☁️ Cloud</button>
            <button class="tab-btn" onclick="switchTab('secrets')">🔑 Secrets</button>
            <button class="tab-btn" onclick="switchTab('ai')">🧠 AI/ML</button>
            <button class="tab-btn" onclick="switchTab('chains')">🔗 Chains</button>
            <button class="tab-btn" onclick="switchTab('knowledge')">🧠 Knowledge</button>
            <button class="tab-btn" onclick="switchTab('workspaces')">📁 Workspaces</button>
            <button class="tab-btn" onclick="switchTab('tools')">🛠️ Tools</button>
            <button class="tab-btn" onclick="switchTab('reports')">📄 Reports</button>
        </div>

        <!-- Overview Tab -->
        <div id="tab-overview" class="tab-content active">
            <div class="grid-4">
                <div class="card"><h2>📊 Overview</h2><div id="overview-content">Loading...</div></div>
                <div class="card"><h2>🎯 Severity</h2><div id="severity-content">Loading...</div></div>
                <div class="card"><h2>⚙️ Stats</h2><div id="stats-content">Loading...</div></div>
                <div class="card"><h2>📈 Risk</h2><div id="risk-content">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📊 Findings Chart <span class="ml-badge">ML</span></h2><div class="chart-box" id="findings-chart">Loading chart...</div></div>
                <div class="card"><h2>🔍 Quick Search <span class="ml-badge">Embeddings</span></h2><input class="search-box" id="quick-search" placeholder="Search with ML embeddings (TF-IDF + transformers)..." onkeyup="doSearch(this.value)"><div id="search-results" style="max-height:200px;overflow-y:auto"></div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>🦠 Malware Summary</h2><div id="malware-summary">Loading...</div></div>
                <div class="card"><h2>🌐 Network Summary</h2><div id="network-summary">Loading...</div></div>
            </div>
        </div>

        <!-- Real-time Tab -->
        <div id="tab-realtime" class="tab-content">
            <div class="grid-2">
                <div class="card">
                    <h2>⚡ Real-time Logs <span id="log-count" style="color:#64748b;font-weight:normal">(0)</span></h2>
                    <div class="log-box" id="realtime-logs">Connecting...</div>
                </div>
                <div class="card">
                    <h2>📈 Live Metrics</h2>
                    <div id="live-metrics">Loading...</div>
                    <div style="margin-top:12px">
                        <h3 style="color:#22d3ee;font-size:0.9em;margin-bottom:6px">Active Scans</h3>
                        <div id="active-scans">No active scans</div>
                    </div>
                </div>
            </div>
            <div class="card" style="margin-top:14px">
                <h2>🔄 Task Queue <span class="ml-badge">Distributed</span></h2>
                <div id="task-queue">Loading...</div>
            </div>
        </div>

        <!-- Findings Tab -->
        <div id="tab-findings" class="tab-content">
            <div class="card">
                <h2>🐛 Findings <span id="findings-count" style="color:#64748b;font-weight:normal"></span></h2>
                <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
                    <button class="btn" onclick="filterFindings('ALL')">All</button>
                    <button class="btn" style="background:#dc2626;color:#fff" onclick="filterFindings('CRITICAL')">Critical</button>
                    <button class="btn" style="background:#ea580c;color:#fff" onclick="filterFindings('HIGH')">High</button>
                    <button class="btn" style="background:#ca8a04;color:#fff" onclick="filterFindings('MEDIUM')">Medium</button>
                    <button class="btn" style="background:#16a34a;color:#fff" onclick="filterFindings('LOW')">Low</button>
                </div>
                <div class="findings-list" id="findings-list">Loading...</div>
            </div>
        </div>

        <!-- Malware Tab -->
        <div id="tab-malware" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🦠 Malware Analysis</h2><div id="malware-analysis">Loading...</div></div>
                <div class="card"><h2>🏷️ Classification</h2><div id="malware-classification">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📦 Packer & Entropy</h2><div id="malware-packer">Loading...</div></div>
                <div class="card"><h2>🛡️ Anti-Analysis</h2><div id="malware-anti">Loading...</div></div>
            </div>
            <div class="card"><h2>🔍 IoC Extractor</h2><div id="malware-iocs">Loading...</div></div>
            <div class="card"><h2>🧬 Behavior</h2><div id="malware-behavior">Loading...</div></div>
        </div>

        <!-- Network Tab -->
        <div id="tab-network" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🌐 Protocol</h2><div id="network-protocol">Loading...</div></div>
                <div class="card"><h2>🚨 Threat</h2><div id="network-threat">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📊 Flow</h2><div id="network-flow">Loading...</div></div>
                <div class="card"><h2>🔍 DNS</h2><div id="network-dns">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>🔒 TLS</h2><div id="network-tls">Loading...</div></div>
                <div class="card"><h2>🌍 HTTP</h2><div id="network-http">Loading...</div></div>
            </div>
        </div>

        <!-- Web Tab -->
        <div id="tab-web" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🌐 Web SAST 6 Cats</h2><div id="web-sast">Loading...</div></div>
                <div class="card"><h2>🎯 Nuclei DAST</h2><div id="web-nuclei">Loading...</div></div>
            </div>
        </div>

        <!-- Cloud Tab -->
        <div id="tab-cloud" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>☁️ Dockerfile 10 Rules</h2><div id="cloud-docker">Loading...</div></div>
                <div class="card"><h2>☸️ K8s 8 Rules</h2><div id="cloud-k8s">Loading...</div></div>
            </div>
            <div class="card"><h2>🏗️ Terraform 5 Rules</h2><div id="cloud-terraform">Loading...</div></div>
        </div>

        <!-- Secrets Tab -->
        <div id="tab-secrets" class="tab-content">
            <div class="card"><h2>🔑 Secrets 20 Patterns + High Entropy <span class="ml-badge">Trufflehog-like</span></h2><div id="secrets-content">Loading...</div></div>
        </div>

        <!-- AI/ML Tab -->
        <div id="tab-ai" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🧠 RAG Engine v2 <span class="ml-badge">ML Embeddings</span></h2><div id="ai-rag">Loading...</div></div>
                <div class="card"><h2>🤖 Agent OODA</h2><div id="ai-agent">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📊 Embeddings Stats</h2><div id="ai-embeddings">Loading...</div></div>
                <div class="card"><h2>🔗 Clustering</h2><div id="ai-clustering">Loading...</div></div>
            </div>
        </div>

        <!-- Chains Tab -->
        <div id="tab-chains" class="tab-content">
            <div id="chains-container" style="display:grid;gap:10px"></div>
        </div>

        <!-- Knowledge Tab -->
        <div id="tab-knowledge" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🧠 KG Stats</h2><div id="kg-stats">Loading...</div></div>
                <div class="card"><h2>🔗 IoC Correlations</h2><div id="ioc-stats">Loading...</div></div>
            </div>
        </div>

        <!-- Workspaces Tab -->
        <div id="tab-workspaces" class="tab-content">
            <div class="card"><h2>📁 Workspaces Hybrid Federation</h2><div id="workspaces-list">Loading...</div></div>
        </div>

        <!-- Tools Tab -->
        <div id="tab-tools" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🦠 Malware Tools</h2><div id="malware-tools">Loading...</div></div>
                <div class="card"><h2>🌐 Network Tools</h2><div id="network-tools">Loading...</div></div>
            </div>
            <div class="card"><h2>🛠️ All Tools</h2><div id="all-tools">Loading...</div></div>
        </div>

        <!-- Reports Tab -->
        <div id="tab-reports" class="tab-content">
            <div class="card">
                <h2>📄 Reports</h2>
                <div id="reports-content">Loading...</div>
                <div style="margin-top:10px;display:flex;gap:6px">
                    <button class="btn" onclick="exportReport('json')">JSON</button>
                    <button class="btn" onclick="exportReport('sarif')">SARIF</button>
                    <button class="btn" onclick="exportReport('markdown')">Markdown</button>
                    <button class="btn" onclick="exportReport('pdf')">PDF</button>
                    <button class="btn" onclick="exportReport('html')">HTML</button>
                    <button class="btn" onclick="exportReport('jira')">JIRA</button>
                    <button class="btn" onclick="exportReport('mitre')">MITRE</button>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>r3con v7.2 PRO — Real-time WebSocket + ML Embeddings + 25 CLI groups + 50+ commands</p>
            <p style="margin-top:4px">Binary • Malware 8 engines • Network 6 analyzers • Web SAST 6 cats + Nuclei • Cloud 23 rules • Container • Secrets 20 patterns • Decompiler 3 engines • Symbolic angr/z3 • AI RAG v2 ML + Agent OODA • Reporting 7 exporters • Distributed ES/PG + TaskQueue • Workspaces Hybrid Federation</p>
        </div>
    </div>

<script>
let allFindings = [];
let currentFilter = 'ALL';
let socket = null;
let wsConnected = false;
let pollingInterval = null;

function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
}

function safeText(s) { return String(s||'').replace(/[&<>\"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[m])); }

function initWebSocket() {
    if (typeof io === 'undefined') {
        document.getElementById('ws-status').textContent = 'WebSocket: Polling Fallback';
        document.getElementById('ws-status').className = 'ws-indicator ws-polling';
        startPolling();
        return;
    }

    try {
        socket = io();

        socket.on('connect', () => {
            wsConnected = true;
            document.getElementById('ws-status').textContent = 'WebSocket: Connected';
            document.getElementById('ws-status').className = 'ws-indicator ws-connected';
            addLog('WebSocket connected', 'success');
            if (pollingInterval) { clearInterval(pollingInterval); pollingInterval = null; }
        });

        socket.on('disconnect', () => {
            wsConnected = false;
            document.getElementById('ws-status').textContent = 'WebSocket: Disconnected';
            document.getElementById('ws-status').className = 'ws-indicator ws-disconnected';
            addLog('WebSocket disconnected - falling back to polling', 'warn');
            startPolling();
        });

        socket.on('realtime_update', (data) => {
            updateRealtimeBar(data);
        });

        socket.on('new_finding', (finding) => {
            allFindings.unshift(finding);
            addLog(`New finding: [${finding.severity}] ${finding.type}`, 'info', true);
            renderFindings(allFindings);
            renderSeverity(allFindings);
        });

        socket.on('log', (logEntry) => {
            addLog(logEntry.message, logEntry.level || 'info');
        });

        socket.on('connect_error', () => {
            wsConnected = false;
            document.getElementById('ws-status').textContent = 'WebSocket: Error - Polling';
            document.getElementById('ws-status').className = 'ws-indicator ws-polling';
            startPolling();
        });

    } catch(e) {
        console.error('WebSocket init failed', e);
        startPolling();
    }
}

function startPolling() {
    if (pollingInterval) return;
    addLog('Starting polling fallback (30s)', 'warn');
    pollingInterval = setInterval(() => {
        fetch('/api/realtime').then(r=>r.json()).then(data=>{
            updateRealtimeBar(data);
            if (data.logs) data.logs.forEach(l=>addLog(l.message, l.level));
        }).catch(()=>{});
        loadDashboard();
    }, 30000);
}

function updateRealtimeBar(data) {
    if (data.stats) {
        document.getElementById('rt-analyses').textContent = data.stats.total_analyses || 0;
        document.getElementById('rt-findings').textContent = data.stats.total_findings || allFindings.length;
        document.getElementById('rt-active').textContent = data.stats.active_scans || 0;
        document.getElementById('rt-clients').textContent = data.stats.connected_clients || 1;
        document.getElementById('rt-last-update').textContent = 'Last: ' + new Date().toLocaleTimeString();
    }
}

function addLog(message, level='info', isNewFinding=false) {
    const logsEl = document.getElementById('realtime-logs');
    const countEl = document.getElementById('log-count');
    if (!logsEl) return;

    const entry = document.createElement('div');
    entry.className = 'log-entry log-' + level;
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-${level}">${safeText(message)}</span>`;
    if (isNewFinding) entry.style.background = '#1a2a1a';

    logsEl.insertBefore(entry, logsEl.firstChild);

    // Keep max 100
    while (logsEl.children.length > 100) logsEl.removeChild(logsEl.lastChild);

    if (countEl) countEl.textContent = '(' + logsEl.children.length + ')';
}

function clearLogs() {
    document.getElementById('realtime-logs').innerHTML = '';
    document.getElementById('log-count').textContent = '(0)';
    addLog('Logs cleared', 'info');
}

async function loadDashboard() {
    try {
        const res = await fetch('/api/analysis');
        if (!res.ok) throw new Error('API '+res.status);
        const data = await res.json();
        allFindings = data.findings || [];
        renderOverview(data.analysis||{});
        renderSeverity(allFindings);
        renderStats(data.stats||{});
        renderRisk(data.stats||{}, allFindings);
        renderFindings(allFindings);
        renderFindingsChart(allFindings);
        renderChains(data.exploit_chains||[]);
        renderKG(data.knowledge_graph||{});
        renderWorkspaces(data.workspaces||[]);
        renderMalware(data.malware||{});
        renderNetwork(data.network||{});
        renderWeb(data.web||{});
        renderCloud(data.cloud||{});
        renderSecrets(data.secrets||{});
        renderAI(data.ai||{});
        renderTools(data.tools||{});
        renderReports(data.reports||{});

        // Update realtime bar
        if (data.stats) {
            document.getElementById('rt-analyses').textContent = data.stats.total_analyses || 0;
            document.getElementById('rt-findings').textContent = data.stats.total_findings || allFindings.length;
        }

        if (!wsConnected) addLog(`Dashboard loaded: ${allFindings.length} findings`, 'info');
    } catch(e) {
        console.error(e);
        document.getElementById('overview-content').textContent = 'Error: '+e.message;
        addLog('Failed to load dashboard: '+e.message, 'error');
    }
}

function renderOverview(a) {
    const c = document.getElementById('overview-content'); c.innerHTML='';
    [['Target',a.target||'unknown'],['Type',a.analysis_type||'static'],['Status',a.status||'in_progress'],['Created',a.created_at?new Date(a.created_at).toLocaleString():'-']].forEach(([l,v])=>{
        const d=document.createElement('div');d.className='stat-row';
        const ls=document.createElement('span');ls.className='stat-label';ls.textContent=l;
        const vs=document.createElement('span');vs.className='stat-value';vs.textContent=v;
        d.appendChild(ls);d.appendChild(vs);c.appendChild(d);
    });
}

function renderSeverity(findings) {
    const c=document.getElementById('severity-content');c.innerHTML='';
    const counts={CRITICAL:findings.filter(f=>f.severity==='CRITICAL').length,HIGH:findings.filter(f=>f.severity==='HIGH').length,MEDIUM:findings.filter(f=>f.severity==='MEDIUM'||f.severity==='MED').length,LOW:findings.filter(f=>f.severity==='LOW').length,INFO:findings.filter(f=>!['CRITICAL','HIGH','MEDIUM','MED','LOW'].includes(f.severity)).length};
    Object.entries(counts).forEach(([sev,count])=>{
        const d=document.createElement('div');d.className='stat-row';
        const ls=document.createElement('span');ls.className='stat-label';ls.textContent=sev;
        const vs=document.createElement('span');vs.className='stat-value sev-'+sev.toLowerCase();vs.textContent=count;
        d.appendChild(ls);d.appendChild(vs);c.appendChild(d);
        const pb=document.createElement('div');pb.className='progress-bar';
        const pf=document.createElement('div');pf.className='progress-fill';pf.style.width=Math.min(100,(count/Math.max(1,findings.length))*100)+'%';
        c.appendChild(pb);pb.appendChild(pf);
    });
}

function renderStats(s) {
    const c=document.getElementById('stats-content');c.innerHTML='';
    [['Total Findings',s.total_findings||0],['Exploit Chains',s.exploit_chains||0],['IoCs',s.ioc_count||0],['YARA Hits',s.yara_hits||0],['Malware Score',s.malware_score||0],['Threats',s.threat_count||0]].forEach(([l,v])=>{
        const d=document.createElement('div');d.className='stat-row';
        const ls=document.createElement('span');ls.className='stat-label';ls.textContent=l;
        const vs=document.createElement('span');vs.className='stat-value';vs.textContent=v;
        d.appendChild(ls);d.appendChild(vs);c.appendChild(d);
    });
}

function renderRisk(s, findings) {
    const c=document.getElementById('risk-content');c.innerHTML='';
    let score=0; findings.forEach(f=>{ if(f.severity==='CRITICAL')score+=10; else if(f.severity==='HIGH')score+=5; else if(f.severity==='MEDIUM')score+=2; else score+=1; });
    let level='LOW'; let color='#16a34a';
    if(score>=30){level='CRITICAL';color='#dc2626';} else if(score>=15){level='HIGH';color='#ea580c';} else if(score>=5){level='MEDIUM';color='#ca8a04';}
    c.innerHTML=`<div style="text-align:center;padding:10px"><div style="font-size:2.2em;color:${color};font-weight:bold">${score}</div><div class="badge" style="background:${color};color:#fff;margin-top:6px">${level}</div><div style="color:#64748b;margin-top:6px;font-size:0.8em">${findings.length} findings</div><div class="progress-bar" style="margin-top:10px"><div class="progress-fill" style="width:${Math.min(100,score*2)}%;background:${color}"></div></div><div style="color:#94a3b8;margin-top:10px;font-size:0.75em">Bounty: $${(findings.filter(f=>f.severity==='CRITICAL').length*2000+findings.filter(f=>f.severity==='HIGH').length*500).toLocaleString()}</div></div>`;
}

function renderFindingsChart(findings) {
    const c=document.getElementById('findings-chart');c.innerHTML='';
    if(!findings.length){c.textContent='No data';return;}
    const counts={CRITICAL:findings.filter(f=>f.severity==='CRITICAL').length,HIGH:findings.filter(f=>f.severity==='HIGH').length,MEDIUM:findings.filter(f=>f.severity==='MEDIUM').length,LOW:findings.filter(f=>f.severity==='LOW').length};
    const max=Math.max(1,...Object.values(counts));
    const colors={CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#ca8a04',LOW:'#16a34a'};
    let left=10;
    Object.entries(counts).forEach(([sev,count])=>{
        if(count===0) return;
        const bar=document.createElement('div');bar.className='chart-bar';
        bar.style.left=left+'%';bar.style.width='18%';bar.style.height=(count/max*80)+'%';bar.style.background=colors[sev];
        bar.title=`${sev}: ${count}`;
        const label=document.createElement('div');label.style.position='absolute';label.style.bottom='-20px';label.style.left='0';label.style.width='100%';label.style.textAlign='center';label.style.fontSize='0.7em';label.style.color='#94a3b8';label.textContent=sev[0];
        bar.appendChild(label);
        c.appendChild(bar);
        left+=22;
    });
}

function renderFindings(findings) {
    const c=document.getElementById('findings-list'); const countEl=document.getElementById('findings-count');
    if(countEl) countEl.textContent=`(${findings.length})`;
    c.innerHTML='';
    if(!findings.length){c.textContent='No findings';return;}
    let filtered = currentFilter==='ALL'?findings:findings.filter(f=>f.severity===currentFilter);
    filtered.slice(0,100).forEach(f=>{
        const item=document.createElement('div');item.className='finding-item '+(f.severity||'info').toLowerCase();
        const typeDiv=document.createElement('div');typeDiv.className='finding-type';typeDiv.textContent=`[${f.severity||'INFO'}] ${f.type||f.finding_type||'Unknown'}`;
        const descDiv=document.createElement('div');descDiv.className='finding-desc';descDiv.textContent=f.description||'';
        item.appendChild(typeDiv);item.appendChild(descDiv);c.appendChild(item);
    });
}

function filterFindings(sev){currentFilter=sev;renderFindings(allFindings);}

function renderChains(chains){
    const c=document.getElementById('chains-container');c.innerHTML='';
    if(!chains.length){c.textContent='No exploitation chains';c.style.color='#64748b';return;}
    chains.slice(0,20).forEach(chain=>{
        const box=document.createElement('div');box.className='card';box.style.borderLeft='3px solid #22d3ee';
        const nameDiv=document.createElement('div');nameDiv.style.color='#22d3ee';nameDiv.style.fontWeight='bold';nameDiv.textContent='🔗 '+(chain.name||'Chain');
        const impactDiv=document.createElement('div');impactDiv.style.color='#fbbf24';impactDiv.style.marginTop='4px';impactDiv.style.fontSize='0.85em';impactDiv.textContent='Impact: '+(chain.impact||'Unknown');
        box.appendChild(nameDiv);box.appendChild(impactDiv);c.appendChild(box);
    });
}

function renderKG(kg){
    const statsEl=document.getElementById('kg-stats'); if(statsEl) statsEl.innerHTML=`<div class="stat-row"><span class="stat-label">Nodes</span><span class="stat-value">${kg.total_nodes||0}</span></div><div class="stat-row"><span class="stat-label">Edges</span><span class="stat-value">${kg.total_edges||0}</span></div>`;
}

function renderWorkspaces(ws){
    const c=document.getElementById('workspaces-list');c.innerHTML='';
    if(!ws.length){c.textContent='No workspaces';return;}
    ws.forEach(w=>{
        const d=document.createElement('div');d.className='card';d.style.marginBottom='6px';d.style.padding='8px';
        d.innerHTML=`<strong style="color:#22d3ee">${safeText(w.name||'ws')}</strong> <span class="badge badge-ok">${safeText(w.status||'active')}</span><br><small>${safeText(w.target||'')} • ${w.findings||0} findings</small>`;
        c.appendChild(d);
    });
}

function renderMalware(malware){
    const analysisEl=document.getElementById('malware-analysis');
    if(analysisEl){
        if(!malware || Object.keys(malware).length===0){analysisEl.textContent='No malware analysis';}
        else {
            let html = '';
            if(malware.summary) html+=`<div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value">${safeText(malware.summary.verdict||'CLEAN')}</span></div><div class="stat-row"><span class="stat-label">Score</span><span class="stat-value">${malware.summary.score||0}</span></div>`;
            analysisEl.innerHTML=html||'No data';
        }
    }
}

function renderNetwork(network){
    const protoEl=document.getElementById('network-protocol');
    if(protoEl){protoEl.innerHTML=network.protocol?`<div class="stat-row"><span class="stat-label">Packets</span><span class="stat-value">${network.protocol.packets_read||0}</span></div>`:'No protocol';}
}

function renderWeb(web){
    const sastEl=document.getElementById('web-sast');
    if(sastEl){sastEl.innerHTML=web.sast?`<div class="stat-row"><span class="stat-label">Findings</span><span class="stat-value">${web.sast.count||0}</span></div>`:'No web SAST';}
}

function renderCloud(cloud){
    const dockerEl=document.getElementById('cloud-docker');
    if(dockerEl){dockerEl.innerHTML=cloud.docker?`<div class="stat-row"><span class="stat-label">Findings</span><span class="stat-value">${cloud.docker.count||0}</span></div>`:'No cloud';}
}

function renderSecrets(secrets){
    const c=document.getElementById('secrets-content');
    if(c){c.innerHTML=secrets.count?`<div class="stat-row"><span class="stat-label">Secrets</span><span class="stat-value sev-critical">${secrets.count}</span></div><div style="margin-top:8px">${Object.entries(secrets.by_type||{}).map(([k,v])=>`<span class="badge badge-crit">${safeText(k)}:${v}</span>`).join(' ')}</div>`:'No secrets';}
}

function renderAI(ai){
    const ragEl=document.getElementById('ai-rag');
    if(ragEl){ragEl.innerHTML=ai.rag?`<div class="stat-row"><span class="stat-label">Findings</span><span class="stat-value">${ai.rag.total||0}</span></div><div class="stat-row"><span class="stat-label">Embeddings</span><span class="stat-value">${ai.rag.embeddings?'Yes':'No'}</span></div>`:'No AI';}
    const embEl=document.getElementById('ai-embeddings');
    if(embEl){embEl.innerHTML=ai.embeddings?`<div class="stat-row"><span class="stat-label">Vocab</span><span class="stat-value">${ai.embeddings.vocab_size||0}</span></div><div class="stat-row"><span class="stat-label">Docs</span><span class="stat-value">${ai.embeddings.doc_count||0}</span></div><div class="stat-row"><span class="stat-label">Transformers</span><span class="stat-value">${ai.embeddings.use_transformers?'Yes':'No'}</span></div>`:'No embeddings';}
}

function renderTools(tools){
    const allEl=document.getElementById('all-tools');
    if(allEl){
        if(!tools.all){allEl.textContent='No tools info';}
        else {
            let html='<table><tr><th>Tool</th><th>Available</th><th>Category</th></tr>';
            (tools.all||[]).forEach(t=>{html+=`<tr><td>${safeText(t.name)}</td><td><span class="badge ${t.available?'badge-ok':'badge-info'}">${t.available?'Yes':'No'}</span></td><td>${safeText((t.capabilities||[]).join(', '))}</td></tr>`;});
            html+='</table>';
            allEl.innerHTML=html;
        }
    }
}

function renderReports(reports){
    const c=document.getElementById('reports-content');c.innerHTML='';
    if(!reports.summary){c.innerHTML='<div style="color:#64748b">No reports yet</div>';return;}
    c.innerHTML=`<div class="stat-row"><span class="stat-label">Risk Level</span><span class="stat-value">${safeText(reports.summary.risk_level||'LOW')}</span></div><div class="stat-row"><span class="stat-label">Risk Score</span><span class="stat-value">${reports.summary.risk_score||0}</span></div><div class="stat-row"><span class="stat-label">Bounty</span><span class="stat-value" style="color:#fbbf24">$${reports.summary.estimated_bounty||0}</span></div>`;
}

function doSearch(q){
    const c=document.getElementById('search-results');c.innerHTML='';
    if(!q||q.length<2)return;
    const results=allFindings.filter(f=>(f.type||'').toLowerCase().includes(q.toLowerCase())||(f.description||'').toLowerCase().includes(q.toLowerCase())).slice(0,10);
    results.forEach(f=>{const d=document.createElement('div');d.className='card';d.style.marginBottom='4px';d.style.padding='6px';d.innerHTML=`<strong>${safeText(f.type||'')}</strong> [${safeText(f.severity||'')}]<br><small>${safeText((f.description||'').slice(0,100))}</small>`;c.appendChild(d);});
    if(!results.length)c.textContent='No results';
}

function exportReport(fmt){window.open('/api/export?format='+fmt,'_blank');}

initWebSocket();
loadDashboard();
if (!wsConnected) setInterval(loadDashboard, 30000);
</script>
</body>
</html>
"""

def create_app_v2(data_provider=None):
    """Create Flask app v7.2 with WebSocket real-time."""

    @app.route('/')
    def dashboard():
        resp = app.make_response(render_template_string(DASHBOARD_HTML_V2))
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        resp.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:;"
        return resp

    @app.route('/api/analysis', methods=['GET'])
    def api_analysis():
        if data_provider:
            try:
                data = data_provider()
                if isinstance(data, dict):
                    if 'findings' in data and isinstance(data['findings'], list):
                        data['findings'] = data['findings'][:300]
                    if 'exploit_chains' in data and isinstance(data['exploit_chains'], list):
                        data['exploit_chains'] = data['exploit_chains'][:20]
                return jsonify(data)
            except Exception as e:
                return jsonify({"error": str(e)[:200], "findings": [], "analysis": {"target": "error", "analysis_type": "error", "status": "error", "created_at": "2026-05-10T15:00:00"}, "stats": {}}), 500

        return jsonify({
            "analysis": {"target": "unknown", "analysis_type": "static", "status": "in_progress", "created_at": datetime.now().isoformat()},
            "findings": [], "exploit_chains": [],
            "stats": {"total_findings": 0, "ioc_count": 0, "yara_hits": 0, "malware_score": 0, "threat_count": 0, "total_analyses": realtime_stats["total_analyses"], "active_scans": realtime_stats["active_scans"]},
            "knowledge_graph": {"total_nodes": 0, "total_edges": 0, "nodes": []},
            "workspaces": [],
            "web": {"sast": {"count": 0}},
            "cloud": {"docker": {"count": 0}},
            "secrets": {"count": 0, "by_type": {}},
            "ai": {"rag": {"total": 0, "embeddings": False}, "embeddings": {"vocab_size": 0, "doc_count": 0, "use_transformers": False}},
            "malware": {}, "network": {},
            "tools": {"malware": {}, "network": {}, "all": []},
            "reports": {},
        })

    @app.route('/api/realtime', methods=['GET'])
    def api_realtime():
        return jsonify({
            "stats": realtime_stats,
            "logs": list(realtime_logs)[-20:],
            "timestamp": datetime.now().isoformat(),
        })

    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({
            "status": "ok",
            "version": "7.2.0-PRO-RealTime",
            "websocket": SOCKETIO_AVAILABLE,
            "domains": ["binary", "malware", "network", "web", "cloud", "container", "secrets", "decompiler", "ai", "reporting"],
            "realtime": realtime_stats,
        })

    @app.route('/api/export', methods=['GET'])
    def api_export():
        fmt = request.args.get('format', 'json')
        if data_provider:
            try:
                data = data_provider()
                if fmt == 'json':
                    return jsonify(data)
            except Exception as e:
                return jsonify({"error": str(e)[:200]}), 500
        return jsonify({"error": "no data"}), 404

    # WebSocket events
    if SOCKETIO_AVAILABLE and socketio:
        @socketio.on('connect')
        def handle_connect():
            global connected_clients
            connected_clients += 1
            realtime_stats["connected_clients"] = connected_clients
            realtime_stats["last_update"] = datetime.now().isoformat()
            emit('realtime_update', {"stats": realtime_stats})
            # Send recent logs
            for log in list(realtime_logs)[-10:]:
                emit('log', log)

        @socketio.on('disconnect')
        def handle_disconnect():
            global connected_clients
            connected_clients = max(0, connected_clients - 1)
            realtime_stats["connected_clients"] = connected_clients

        @socketio.on('start_scan')
        def handle_start_scan(data):
            realtime_stats["active_scans"] += 1
            realtime_stats["total_analyses"] += 1
            log_entry = {"message": f"Scan started: {data.get('target','unknown')}", "level": "info", "timestamp": datetime.now().isoformat()}
            realtime_logs.append(log_entry)
            emit('realtime_update', {"stats": realtime_stats}, broadcast=True)
            emit('log', log_entry, broadcast=True)

        @socketio.on('new_finding')
        def handle_new_finding(data):
            realtime_stats["total_findings"] += 1
            log_entry = {"message": f"New finding: [{data.get('severity','')}] {data.get('type','')}", "level": "info", "timestamp": datetime.now().isoformat()}
            realtime_logs.append(log_entry)
            emit('new_finding', data, broadcast=True)
            emit('log', log_entry, broadcast=True)
            emit('realtime_update', {"stats": realtime_stats}, broadcast=True)

    return app, socketio

def add_realtime_log(message: str, level: str = "info"):
    """Add log to realtime buffer and broadcast if possible."""
    entry = {"message": message, "level": level, "timestamp": datetime.now().isoformat()}
    realtime_logs.append(entry)
    if SOCKETIO_AVAILABLE and socketio:
        try:
            socketio.emit('log', entry, broadcast=True)
        except Exception:
            pass

def update_realtime_stats(**kwargs):
    """Update realtime stats and broadcast."""
    for k, v in kwargs.items():
        realtime_stats[k] = v
    realtime_stats["last_update"] = datetime.now().isoformat()
    if SOCKETIO_AVAILABLE and socketio:
        try:
            socketio.emit('realtime_update', {"stats": realtime_stats}, broadcast=True)
        except Exception:
            pass

# Backward compat - create_app without websocket
def create_app(data_provider=None):
    app_v2, _ = create_app_v2(data_provider)
    return app_v2

if __name__ == '__main__':
    application, sio = create_app_v2()
    print("⚡ r3con v7.2 PRO Dashboard Real-time")
    print("http://127.0.0.1:5000")
    print(f"WebSocket: {'Available (Flask-SocketIO)' if SOCKETIO_AVAILABLE else 'Fallback polling (install flask-socketio)'}")
    if SOCKETIO_AVAILABLE and sio:
        sio.run(application, debug=False, host='0.0.0.0', port=5000, use_reloader=False)
    else:
        application.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)
