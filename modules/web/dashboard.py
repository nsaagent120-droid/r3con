"""
r3con v6.2 - Web Dashboard PRO - Malware + Network domains
Dashboard temps réel + knowledge graph + malware + network + workspaces + API complète
"""
from __future__ import annotations
from flask import Flask, render_template_string, jsonify, request
import json
from datetime import datetime

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';">
    <title>r3con v6.2 — PRO Dashboard - Malware + Network</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Courier New',monospace; background: linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 100%); color:#e2e8f0; padding:20px; min-height:100vh; }
        .container { max-width:1700px; margin:0 auto; }
        .header { text-align:center; margin-bottom:30px; border-bottom:2px solid #22d3ee; padding-bottom:20px; }
        .header h1 { color:#22d3ee; font-size:2.6em; margin-bottom:8px; }
        .header .subtitle { color:#94a3b8; font-size:0.95em; }
        .header .version { color:#f59e0b; font-size:0.85em; margin-top:6px; }
        .tabs { display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }
        .tab-btn { background:#1e293b; border:1px solid #334155; color:#94a3b8; padding:8px 16px; border-radius:6px; cursor:pointer; font-family:inherit; font-size:0.85em; }
        .tab-btn.active { background:#22d3ee; color:#0f0f1a; border-color:#22d3ee; font-weight:bold; }
        .tab-content { display:none; }
        .tab-content.active { display:block; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:18px; margin-bottom:25px; }
        .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:25px; }
        .grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:18px; margin-bottom:25px; }
        .card { background:#1e293b; border:1px solid #334155; border-radius:8px; padding:18px; box-shadow:0 4px 6px rgba(0,0,0,0.3); }
        .card h2 { color:#7dd3fc; font-size:1.1em; margin-bottom:12px; border-bottom:1px solid #475569; padding-bottom:8px; }
        .card h3 { color:#22d3ee; font-size:0.95em; margin-bottom:8px; }
        .stat-row { display:flex; justify-content:space-between; margin-bottom:6px; padding:6px 0; border-bottom:1px solid #334155; font-size:0.9em; }
        .stat-label { color:#94a3b8; }
        .stat-value { color:#22d3ee; font-weight:bold; }
        .sev-critical { color:#dc2626; } .sev-high { color:#ea580c; } .sev-medium { color:#ca8a04; } .sev-low { color:#16a34a; } .sev-info { color:#64748b; }
        .findings-list { max-height:500px; overflow-y:auto; }
        .finding-item { background:#0f172a; padding:10px; margin-bottom:8px; border-left:4px solid #475569; border-radius:4px; font-size:0.85em; }
        .finding-item.critical { border-left-color:#dc2626; } .finding-item.high { border-left-color:#ea580c; } .finding-item.medium { border-left-color:#ca8a04; } .finding-item.low { border-left-color:#16a34a; }
        .finding-type { color:#e2e8f0; font-weight:bold; font-size:0.9em; }
        .finding-desc { color:#94a3b8; font-size:0.85em; margin-top:4px; }
        .chain-box { background:#1a1a2e; border:2px solid #22d3ee; border-radius:6px; padding:12px; margin-bottom:12px; }
        .chain-name { color:#22d3ee; font-weight:bold; }
        .chain-impact { color:#fbbf24; margin-top:4px; font-size:0.9em; }
        .section-title { color:#22d3ee; font-size:1.3em; margin-top:25px; margin-bottom:12px; border-bottom:2px solid #22d3ee; padding-bottom:6px; }
        .footer { text-align:center; color:#64748b; margin-top:50px; padding-top:15px; border-top:1px solid #334155; font-size:0.8em; }
        .badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:0.7em; font-weight:bold; }
        .badge-ok { background:#16a34a; color:#fff; } .badge-warn { background:#ca8a04; color:#fff; } .badge-crit { background:#dc2626; color:#fff; } .badge-info { background:#334155; color:#94a3b8; }
        .knowledge-node { background:#0f172a; border:1px solid #334155; padding:8px; margin-bottom:6px; border-radius:4px; font-size:0.85em; }
        .graph-viz { width:100%; height:300px; background:#0f172a; border-radius:8px; border:1px solid #334155; display:flex; align-items:center; justify-content:center; color:#64748b; }
        .progress-bar { width:100%; height:6px; background:#334155; border-radius:4px; overflow:hidden; margin-top:4px; }
        .progress-fill { height:100%; background:linear-gradient(90deg,#22d3ee,#7dd3fc); transition:width 0.3s; }
        .search-box { width:100%; padding:8px; background:#0f172a; border:1px solid #334155; border-radius:6px; color:#e2e8f0; font-family:inherit; margin-bottom:12px; font-size:0.9em; }
        .btn { background:#22d3ee; color:#0f0f1a; border:none; padding:6px 12px; border-radius:4px; cursor:pointer; font-family:inherit; font-weight:bold; font-size:0.85em; }
        .btn:hover { background:#7dd3fc; }
        .workspace-item { background:#0f172a; padding:10px; margin-bottom:6px; border-radius:6px; border:1px solid #334155; cursor:pointer; font-size:0.85em; }
        .workspace-item:hover { border-color:#22d3ee; }
        table { width:100%; border-collapse:collapse; }
        th { text-align:left; color:#7dd3fc; padding:6px; border-bottom:1px solid #334155; font-size:0.8em; }
        td { padding:6px; border-bottom:1px solid #1e293b; font-size:0.8em; color:#94a3b8; }
        .malware-family { background:#1a0f1a; border:1px solid #ec4899; padding:10px; margin-bottom:8px; border-radius:6px; }
        .malware-family .family-name { color:#ec4899; font-weight:bold; }
        .network-flow { background:#0f1a1a; border:1px solid #22d3ee; padding:8px; margin-bottom:6px; border-radius:4px; font-size:0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ r3con v6.2 PRO Dashboard</h1>
            <p class="subtitle">Binary • Malware • Network • Firmware • Knowledge Graph • Bug Bounty</p>
            <p class="version">v6.2 PRO | Malware: PE/ELF/Behavior/Classifier/Unpacker | Network: Threat/Flow/DNS/TLS/HTTP | External Tools: pefile/DIE/capa/YARA/tshark/suricata/zeek/nmap</p>
            <p style="color:#f59e0b;font-size:0.7em;margin-top:6px">⚠ Local use only — no auth — do not expose to internet</p>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('overview')">📊 Overview</button>
            <button class="tab-btn" onclick="switchTab('findings')">🐛 Findings</button>
            <button class="tab-btn" onclick="switchTab('malware')">🦠 Malware</button>
            <button class="tab-btn" onclick="switchTab('network')">🌐 Network</button>
            <button class="tab-btn" onclick="switchTab('chains')">🔗 Chains</button>
            <button class="tab-btn" onclick="switchTab('knowledge')">🧠 Knowledge</button>
            <button class="tab-btn" onclick="switchTab('workspaces')">📁 Workspaces</button>
            <button class="tab-btn" onclick="switchTab('yara')">🎯 YARA</button>
            <button class="tab-btn" onclick="switchTab('deps')">📦 Deps</button>
            <button class="tab-btn" onclick="switchTab('tools')">🛠️ Tools</button>
            <button class="tab-btn" onclick="switchTab('reports')">📄 Reports</button>
        </div>

        <!-- Overview Tab -->
        <div id="tab-overview" class="tab-content active">
            <div class="grid-3">
                <div class="card"><h2>📊 Analysis Overview</h2><div id="overview-content">Loading...</div></div>
                <div class="card"><h2>🎯 Severity Breakdown</h2><div id="severity-content">Loading...</div></div>
                <div class="card"><h2>⚙️ Statistics</h2><div id="stats-content">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📈 Risk Score</h2><div id="risk-content">Loading...</div></div>
                <div class="card"><h2>🔍 Quick Search</h2><input class="search-box" id="quick-search" placeholder="Search findings, CVEs, IoCs, malware families..." onkeyup="doSearch(this.value)"><div id="search-results" style="max-height:250px;overflow-y:auto"></div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>🦠 Malware Summary</h2><div id="malware-summary">Loading...</div></div>
                <div class="card"><h2>🌐 Network Summary</h2><div id="network-summary">Loading...</div></div>
            </div>
        </div>

        <!-- Findings Tab -->
        <div id="tab-findings" class="tab-content">
            <div class="card">
                <h2>🐛 Detailed Findings <span id="findings-count" style="color:#64748b;font-weight:normal"></span></h2>
                <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
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
                <div class="card"><h2>🏷️ Malware Classification</h2><div id="malware-classification">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📦 Packer & Entropy</h2><div id="malware-packer">Loading...</div></div>
                <div class="card"><h2>🛡️ Anti-Analysis</h2><div id="malware-anti">Loading...</div></div>
            </div>
            <div class="card"><h2>🔍 IoC Extractor</h2><div id="malware-iocs">Loading...</div></div>
            <div class="card"><h2>🧬 Behavior Analysis</h2><div id="malware-behavior">Loading...</div></div>
        </div>

        <!-- Network Tab -->
        <div id="tab-network" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🌐 Protocol Analysis</h2><div id="network-protocol">Loading...</div></div>
                <div class="card"><h2>🚨 Threat Detection</h2><div id="network-threat">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>📊 Flow Analysis</h2><div id="network-flow">Loading...</div></div>
                <div class="card"><h2>🔍 DNS Analysis</h2><div id="network-dns">Loading...</div></div>
            </div>
            <div class="grid-2">
                <div class="card"><h2>🔒 TLS Analysis</h2><div id="network-tls">Loading...</div></div>
                <div class="card"><h2>🌍 HTTP Analysis</h2><div id="network-http">Loading...</div></div>
            </div>
        </div>

        <!-- Chains Tab -->
        <div id="tab-chains" class="tab-content">
            <div class="section-title">🔗 Exploitation Chains</div>
            <div id="chains-container" style="display:grid;gap:12px"></div>
            <div class="section-title">📞 Call Graph Paths</div>
            <div class="card"><div id="callgraph-container">Loading...</div></div>
        </div>

        <!-- Knowledge Tab -->
        <div id="tab-knowledge" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🧠 Knowledge Graph Stats</h2><div id="kg-stats">Loading...</div></div>
                <div class="card"><h2>🔗 IoC Correlations</h2><div id="ioc-stats">Loading...</div></div>
            </div>
            <div class="card" style="margin-top:15px">
                <h2>🕸️ Knowledge Graph</h2>
                <div class="graph-viz" id="graph-viz">Knowledge Graph Visualization<br><small>Nodes & edges from cross-workspace correlations</small></div>
                <div id="kg-nodes" style="max-height:300px;overflow-y:auto;margin-top:12px"></div>
            </div>
        </div>

        <!-- Workspaces Tab -->
        <div id="tab-workspaces" class="tab-content">
            <div class="card"><h2>📁 Workspaces (Hybrid Federation)</h2><div id="workspaces-list">Loading...</div></div>
        </div>

        <!-- YARA Tab -->
        <div id="tab-yara" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🎯 YARA Rules</h2><div id="yara-rules">Loading...</div></div>
                <div class="card"><h2>🔍 YARA Scan Results</h2><div id="yara-scans">Loading...</div></div>
            </div>
        </div>

        <!-- Deps Tab -->
        <div id="tab-deps" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>📦 Dependencies</h2><div id="deps-list">Loading...</div></div>
                <div class="card"><h2>📋 SBOM</h2><div id="sbom-content">Loading...</div></div>
            </div>
        </div>

        <!-- Tools Tab -->
        <div id="tab-tools" class="tab-content">
            <div class="grid-2">
                <div class="card"><h2>🦠 Malware Tools</h2><div id="malware-tools">Loading...</div></div>
                <div class="card"><h2>🌐 Network Tools</h2><div id="network-tools">Loading...</div></div>
            </div>
            <div class="card"><h2>🛠️ All External Tools</h2><div id="all-tools">Loading...</div></div>
        </div>

        <!-- Reports Tab -->
        <div id="tab-reports" class="tab-content">
            <div class="card">
                <h2>📄 Bug Bounty Reports</h2>
                <div id="reports-content">Loading...</div>
                <div style="margin-top:12px;display:flex;gap:8px">
                    <button class="btn" onclick="exportReport('json')">Export JSON</button>
                    <button class="btn" onclick="exportReport('sarif')">Export SARIF</button>
                    <button class="btn" onclick="exportReport('markdown')">Export Markdown</button>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>r3con v6.2 PRO | Malware + Network + Binary + Firmware</p>
            <p style="margin-top:4px;font-size:0.75em">Malware: PE/ELF/Behavior/Classifier/Unpacker/Anti-Analysis/Extractor | Network: Threat/Flow/DNS/TLS/HTTP | Tools: pefile/DIE/capa/YARA/tshark/suricata/zeek/nmap | Knowledge: CVE 50+ | YARA 5+ | IoC | Graph | SARIF | SBOM</p>
        </div>
    </div>

<script>
let allFindings = [];
let currentFilter = 'ALL';

function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
}

function safeText(s) { return String(s||'').replace(/[&<>\"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

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
        renderChains(data.exploit_chains||[]);
        renderFindings(allFindings);
        renderKG(data.knowledge_graph||{});
        renderWorkspaces(data.workspaces||[]);
        renderYara(data.yara||{});
        renderDeps(data.deps||{});
        renderReports(data.reports||{});
        renderCallGraph(data.call_graph||{});
        renderMalware(data.malware||{});
        renderNetwork(data.network||{});
        renderTools(data.tools||{});
        renderSummaries(data);
    } catch(e) {
        console.error(e);
        document.getElementById('overview-content').textContent = 'Error: '+e.message;
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
    c.innerHTML=`<div style="text-align:center;padding:15px"><div style="font-size:2.5em;color:${color};font-weight:bold">${score}</div><div class="badge" style="background:${color};color:#fff;margin-top:8px">${level}</div><div style="color:#64748b;margin-top:8px;font-size:0.85em">${findings.length} findings</div><div class="progress-bar" style="margin-top:12px"><div class="progress-fill" style="width:${Math.min(100,score*2)}%;background:${color}"></div></div><div style="color:#94a3b8;margin-top:12px;font-size:0.8em">Est. Bounty: $${(findings.filter(f=>f.severity==='CRITICAL').length*2000+findings.filter(f=>f.severity==='HIGH').length*500).toLocaleString()}</div></div>`;
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
        const box=document.createElement('div');box.className='chain-box';
        const nameDiv=document.createElement('div');nameDiv.className='chain-name';nameDiv.textContent='🔗 '+(chain.name||'Chain');
        const impactDiv=document.createElement('div');impactDiv.className='chain-impact';impactDiv.textContent='Impact: '+(chain.impact||'Unknown');
        box.appendChild(nameDiv);box.appendChild(impactDiv);c.appendChild(box);
    });
}

function renderKG(kg){
    const statsEl=document.getElementById('kg-stats'); if(statsEl) statsEl.innerHTML=`<div class="stat-row"><span class="stat-label">Nodes</span><span class="stat-value">${kg.total_nodes||0}</span></div><div class="stat-row"><span class="stat-label">Edges</span><span class="stat-value">${kg.total_edges||0}</span></div>`;
    const nodesEl=document.getElementById('kg-nodes'); if(nodesEl){nodesEl.innerHTML=''; (kg.nodes||[]).slice(0,15).forEach(n=>{const d=document.createElement('div');d.className='knowledge-node';d.innerHTML=`<strong>${safeText(n.id||'')}</strong><br><small>${safeText((n.data||{}).type||'')}</small>`;nodesEl.appendChild(d);});}
}

function renderWorkspaces(ws){
    const c=document.getElementById('workspaces-list');c.innerHTML='';
    if(!ws.length){c.textContent='No workspaces';return;}
    ws.forEach(w=>{
        const d=document.createElement('div');d.className='workspace-item';
        d.innerHTML=`<strong style="color:#22d3ee">${safeText(w.name||'ws')}</strong> <span class="badge badge-ok">${safeText(w.status||'active')}</span><br><small>${safeText(w.target||'')} • ${w.findings||0} findings</small>`;
        c.appendChild(d);
    });
}

function renderYara(yara){
    const rulesEl=document.getElementById('yara-rules'); if(rulesEl){rulesEl.innerHTML=''; if(!yara.rules||!yara.rules.length){rulesEl.textContent='No YARA rules';} else {yara.rules.slice(0,15).forEach(r=>{const d=document.createElement('div');d.className='knowledge-node';d.innerHTML=`<strong style="color:#22d3ee">${safeText(r.name||r)}</strong> <span class="badge badge-info">${safeText(r.severity||'')}</span>`;rulesEl.appendChild(d);});}}
    const scansEl=document.getElementById('yara-scans'); if(scansEl){scansEl.innerHTML=''; if(!yara.hits||!yara.hits.length){scansEl.textContent='No YARA hits';} else {yara.hits.slice(0,15).forEach(h=>{const d=document.createElement('div');d.className='finding-item high';d.innerHTML=`<div class="finding-type">${safeText(h.rule||'rule')}</div><div class="finding-desc">${safeText(h.description||'')}</div>`;scansEl.appendChild(d);});}}
}

function renderDeps(deps){
    const listEl=document.getElementById('deps-list'); if(listEl){listEl.innerHTML=''; if(!deps.dependencies||!deps.dependencies.length){listEl.textContent='No dependencies';} else {const table=document.createElement('table');table.innerHTML='<tr><th>Package</th><th>Version</th><th>Status</th></tr>';deps.dependencies.slice(0,30).forEach(d=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${safeText(d.name)}</td><td>${safeText(d.version)}</td><td>${d.vulnerable?'<span class="badge badge-crit">VULN</span>':'<span class="badge badge-ok">OK</span>'}</td>`;table.appendChild(tr);});listEl.appendChild(table);}}
    const sbomEl=document.getElementById('sbom-content'); if(sbomEl){sbomEl.innerHTML=''; if(deps.sbom){sbomEl.innerHTML=`<div class="stat-row"><span class="stat-label">Components</span><span class="stat-value">${(deps.sbom.components||[]).length}</span></div>`;} else {sbomEl.textContent='No SBOM';}}
}

function renderReports(reports){
    const c=document.getElementById('reports-content');c.innerHTML='';
    if(!reports.summary){c.innerHTML='<div style="color:#64748b">No reports yet</div>';return;}
    c.innerHTML=`<div class="stat-row"><span class="stat-label">Risk Level</span><span class="stat-value sev-${(reports.summary.risk_level||'low').toLowerCase()}">${safeText(reports.summary.risk_level||'LOW')}</span></div><div class="stat-row"><span class="stat-label">Risk Score</span><span class="stat-value">${reports.summary.risk_score||0}</span></div><div class="stat-row"><span class="stat-label">Bounty</span><span class="stat-value" style="color:#fbbf24">$${reports.summary.estimated_bounty||0}</span></div>`;
}

function renderCallGraph(cg){
    const c=document.getElementById('callgraph-container');c.innerHTML='';
    if(!cg.functions){c.textContent='No call graph';return;}
    c.innerHTML=`<div class="stat-row"><span class="stat-label">Functions</span><span class="stat-value">${cg.functions||0}</span></div><div class="stat-row"><span class="stat-label">Calls</span><span class="stat-value">${cg.calls||0}</span></div>`;
}

function renderMalware(malware){
    const analysisEl=document.getElementById('malware-analysis');
    if(analysisEl){
        if(!malware || Object.keys(malware).length===0){analysisEl.textContent='No malware analysis';}
        else {
            let html = '';
            if(malware.summary) html+=`<div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value sev-${(malware.summary.verdict||'clean').toLowerCase().includes('malicious')?'critical':'low'}">${safeText(malware.summary.verdict||'CLEAN')}</span></div><div class="stat-row"><span class="stat-label">Score</span><span class="stat-value">${malware.summary.score||0}</span></div><div class="stat-row"><span class="stat-label">PE</span><span class="stat-value">${malware.summary.is_pe?'Yes':'No'}</span></div><div class="stat-row"><span class="stat-label">ELF</span><span class="stat-value">${malware.summary.is_elf?'Yes':'No'}</span></div><div class="stat-row"><span class="stat-label">Packed</span><span class="stat-value">${malware.summary.is_packed?'Yes':'No'}</span></div>`;
            analysisEl.innerHTML=html;
        }
    }
    const classEl=document.getElementById('malware-classification');
    if(classEl){
        if(!malware.classifier || !malware.classifier.families){classEl.textContent='No classification';}
        else {
            let html='';
            Object.entries(malware.classifier.families).forEach(([fam,data])=>{
                html+=`<div class="malware-family"><span class="family-name">${safeText(fam)}</span> <span class="badge badge-crit">${data.score}</span><br><small style="color:#94a3b8">${safeText(data.description||'')}</small></div>`;
            });
            if(!html) html='No families detected';
            classEl.innerHTML=html;
        }
    }
    const packerEl=document.getElementById('malware-packer');
    if(packerEl){
        if(!malware.unpacker){packerEl.textContent='No packer info';}
        else {
            packerEl.innerHTML=`<div class="stat-row"><span class="stat-label">Packed</span><span class="stat-value">${malware.unpacker.is_packed?'Yes':'No'}</span></div><div class="stat-row"><span class="stat-label">Entropy</span><span class="stat-value">${malware.unpacker.entropy||0}</span></div><div style="margin-top:8px">${(malware.unpacker.packers||[]).map(p=>`<span class="badge badge-warn">${safeText(p)}</span>`).join(' ')}</div>`;
        }
    }
    const antiEl=document.getElementById('malware-anti');
    if(antiEl){
        if(!malware.anti_analysis){antiEl.textContent='No anti-analysis info';}
        else {
            antiEl.innerHTML=`<div class="stat-row"><span class="stat-label">Protected</span><span class="stat-value">${malware.anti_analysis.is_protected?'Yes':'No'}</span></div><div class="stat-row"><span class="stat-label">Score</span><span class="stat-value">${malware.anti_analysis.anti_analysis_score||0}</span></div><div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value">${safeText(malware.anti_analysis.verdict||'')}</span></div>`;
        }
    }
    const iocsEl=document.getElementById('malware-iocs');
    if(iocsEl){
        if(!malware.extractor || !malware.extractor.iocs){iocsEl.textContent='No IoCs';}
        else {
            let html='';
            Object.entries(malware.extractor.iocs).forEach(([type,items])=>{
                if(items && items.length) html+=`<div style="margin-bottom:8px"><strong style="color:#22d3ee">${safeText(type)} (${items.length})</strong><br><small style="color:#94a3b8">${items.slice(0,5).map(i=>safeText(i)).join(', ')}${items.length>5?'...':''}</small></div>`;
            });
            iocsEl.innerHTML=html||'No IoCs';
        }
    }
    const behEl=document.getElementById('malware-behavior');
    if(behEl){
        if(!malware.behavior){behEl.textContent='No behavior';}
        else {
            let html=`<div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value">${safeText(malware.behavior.verdict||'')}</span></div><div class="stat-row"><span class="stat-label">Score</span><span class="stat-value">${malware.behavior.malicious_score||0}</span></div>`;
            if(malware.behavior.behaviors) html+=`<div style="margin-top:8px">${Object.entries(malware.behavior.behaviors).map(([k,v])=>`<span class="badge badge-info">${safeText(k)}:${v}</span>`).join(' ')}</div>`;
            behEl.innerHTML=html;
        }
    }
}

function renderNetwork(network){
    const protoEl=document.getElementById('network-protocol');
    if(protoEl){
        if(!network.protocol){protoEl.textContent='No protocol analysis';}
        else {
            protoEl.innerHTML=`<div class="stat-row"><span class="stat-label">Packets</span><span class="stat-value">${network.protocol.packets_read||0}</span></div><div class="stat-row"><span class="stat-label">Flows</span><span class="stat-value">${network.protocol.stats?.total_flows||0}</span></div><div class="stat-row"><span class="stat-label">Protocols</span><span class="stat-value">${Object.keys(network.protocol.protocols||{}).length}</span></div>`;
        }
    }
    const threatEl=document.getElementById('network-threat');
    if(threatEl){
        if(!network.threat){threatEl.textContent='No threats';}
        else {
            threatEl.innerHTML=`<div class="stat-row"><span class="stat-label">Threats</span><span class="stat-value sev-critical">${network.threat.threat_count||0}</span></div><div style="margin-top:8px">${(network.threat.rules_triggered||[]).map(r=>`<span class="badge badge-crit">${safeText(r)}</span>`).join(' ')}</div>`;
        }
    }
    const flowEl=document.getElementById('network-flow');
    if(flowEl){
        if(!network.flow){flowEl.textContent='No flow analysis';}
        else {
            flowEl.innerHTML=`<div class="stat-row"><span class="stat-label">Total Flows</span><span class="stat-value">${network.flow.total_flows||0}</span></div><div class="stat-row"><span class="stat-label">Beacons</span><span class="stat-value sev-high">${(network.flow.beacons||[]).length}</span></div>`;
        }
    }
    const dnsEl=document.getElementById('network-dns');
    if(dnsEl){
        if(!network.dns){dnsEl.textContent='No DNS analysis';}
        else {
            dnsEl.innerHTML=`<div class="stat-row"><span class="stat-label">Queries</span><span class="stat-value">${network.dns.total_queries||0}</span></div><div class="stat-row"><span class="stat-label">DGA</span><span class="stat-value sev-high">${network.dns.dga_count||0}</span></div>`;
        }
    }
    const tlsEl=document.getElementById('network-tls');
    if(tlsEl){tlsEl.innerHTML=network.tls?`<div class="stat-row"><span class="stat-label">TLS Flows</span><span class="stat-value">${network.tls.tls_flows||0}</span></div><div class="stat-row"><span class="stat-label">Suspicious</span><span class="stat-value">${network.tls.suspicious_count||0}</span></div>`:'No TLS';}
    const httpEl=document.getElementById('network-http');
    if(httpEl){httpEl.innerHTML=network.http?`<div class="stat-row"><span class="stat-label">HTTP Flows</span><span class="stat-value">${network.http.http_flows||0}</span></div><div class="stat-row"><span class="stat-label">Suspicious</span><span class="stat-value">${network.http.urls_analyzed||0}</span></div>`:'No HTTP';}
}

function renderTools(tools){
    const malEl=document.getElementById('malware-tools');
    if(malEl){
        if(!tools.malware){malEl.textContent='No malware tools info';}
        else {
            let html='';
            Object.entries(tools.malware).forEach(([name,avail])=>{html+=`<div class="stat-row"><span class="stat-label">${safeText(name)}</span><span class="badge ${avail?'badge-ok':'badge-info'}">${avail?'OK':'N/A'}</span></div>`;});
            malEl.innerHTML=html;
        }
    }
    const netEl=document.getElementById('network-tools');
    if(netEl){
        if(!tools.network){netEl.textContent='No network tools info';}
        else {
            let html='';
            Object.entries(tools.network).forEach(([name,avail])=>{html+=`<div class="stat-row"><span class="stat-label">${safeText(name)}</span><span class="badge ${avail?'badge-ok':'badge-info'}">${avail?'OK':'N/A'}</span></div>`;});
            netEl.innerHTML=html;
        }
    }
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

function renderSummaries(data){
    const malSum=document.getElementById('malware-summary');
    if(malSum){
        const mal=data.malware||{};
        if(!mal.summary){malSum.innerHTML='<span style="color:#64748b">No malware analysis</span>';}
        else {malSum.innerHTML=`<div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value sev-${mal.summary.verdict?.includes('MALICIOUS')?'critical':'low'}">${safeText(mal.summary.verdict||'CLEAN')}</span></div><div class="stat-row"><span class="stat-label">Score</span><span class="stat-value">${mal.summary.score||0}</span></div><div class="stat-row"><span class="stat-label">Family</span><span class="stat-value">${safeText(mal.summary.primary_family||'None')}</span></div><div class="stat-row"><span class="stat-label">IoCs</span><span class="stat-value">${mal.summary.ioc_count||0}</span></div>`;}
    }
    const netSum=document.getElementById('network-summary');
    if(netSum){
        const net=data.network||{};
        if(!net.summary){netSum.innerHTML='<span style="color:#64748b">No network analysis</span>';}
        else {netSum.innerHTML=`<div class="stat-row"><span class="stat-label">Flows</span><span class="stat-value">${net.summary.total_flows||0}</span></div><div class="stat-row"><span class="stat-label">Findings</span><span class="stat-value">${net.summary.total_findings||0}</span></div><div class="stat-row"><span class="stat-label">Threats</span><span class="stat-value sev-critical">${net.summary.threat_count||0}</span></div><div class="stat-row"><span class="stat-label">Beacons</span><span class="stat-value">${net.summary.beacon_count||0}</span></div>`;}
    }
}

function doSearch(q){
    const c=document.getElementById('search-results');c.innerHTML='';
    if(!q||q.length<2)return;
    const results=allFindings.filter(f=>(f.type||'').toLowerCase().includes(q.toLowerCase())||(f.description||'').toLowerCase().includes(q.toLowerCase())).slice(0,10);
    results.forEach(f=>{const d=document.createElement('div');d.className='knowledge-node';d.innerHTML=`<strong>${safeText(f.type||'')}</strong> [${safeText(f.severity||'')}]<br><small>${safeText((f.description||'').slice(0,100))}</small>`;c.appendChild(d);});
    if(!results.length)c.textContent='No results';
}

function exportReport(fmt){window.open('/api/export?format='+fmt,'_blank');}

loadDashboard();
setInterval(loadDashboard,30000);
</script>
</body>
</html>
"""

def create_app(data_provider=None):
    """Create Flask app PRO v6.2."""

    @app.route('/')
    def dashboard():
        resp = app.make_response(render_template_string(DASHBOARD_HTML))
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';"
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
            "stats": {"total_findings": 0, "ioc_count": 0, "yara_hits": 0, "malware_score": 0, "threat_count": 0},
            "knowledge_graph": {"total_nodes": 0, "total_edges": 0, "nodes": []},
            "workspaces": [],
            "yara": {"rules": [], "hits": []},
            "deps": {"dependencies": [], "sbom": None},
            "reports": {},
            "call_graph": {"functions": 0, "calls": 0},
            "malware": {},
            "network": {},
            "tools": {"malware": {}, "network": {}, "all": []},
        })

    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({"status": "ok", "version": "6.2.0-PRO", "domains": ["binary", "malware", "network", "firmware", "knowledge"]})

    @app.route('/api/export', methods=['GET'])
    def api_export():
        fmt = request.args.get('format', 'json')
        if data_provider:
            try:
                data = data_provider()
                if fmt == 'json':
                    return jsonify(data)
                elif fmt == 'sarif':
                    from modules.reporting.enhanced_reporting import EnhancedReporting
                    reporter = EnhancedReporting()
                    sarif = reporter.generate_sarif(data.get('findings', []), data.get('analysis', {}).get('target', 'unknown'))
                    return jsonify(sarif)
            except Exception as e:
                return jsonify({"error": str(e)[:200]}), 500
        return jsonify({"error": "no data"}), 404

    @app.route('/api/knowledge/search', methods=['GET'])
    def api_kg_search():
        q = request.args.get('q', '')
        if not q:
            return jsonify({"results": []})
        try:
            from modules.knowledge.graph import KnowledgeGraph
            kg = KnowledgeGraph()
            results = kg.search(q, limit=20)
            return jsonify({"query": q, "results": results, "count": len(results)})
        except Exception as e:
            return jsonify({"error": str(e)[:200], "results": []}), 500

    @app.route('/api/yara/rules', methods=['GET'])
    def api_yara_rules():
        try:
            from modules.knowledge.yara_manager import YaraManager
            ym = YaraManager()
            rules = ym.list_rules()
            stats = ym.get_stats()
            return jsonify({"rules": rules, "stats": stats})
        except Exception as e:
            return jsonify({"error": str(e)[:200], "rules": []}), 500

    @app.route('/api/tools', methods=['GET'])
    def api_tools():
        try:
            from modules.integration.malware_tools import detect_malware_tools
            from modules.integration.network_tools import detect_network_tools
            from core.plugin_system import default_registry
            malware_tools = detect_malware_tools()
            network_tools = detect_network_tools()
            registry = default_registry()
            all_tools = registry.list()
            return jsonify({"malware": malware_tools, "network": network_tools, "all": all_tools})
        except Exception as e:
            return jsonify({"error": str(e)[:200]}), 500

    @app.route('/api/malware/scan', methods=['POST'])
    def api_malware_scan():
        try:
            data = request.get_json() or {}
            file_path = data.get("file_path", "")
            if not file_path:
                return jsonify({"error": "file_path required"}), 400
            from modules.malware import analyze_malware
            result = analyze_malware(file_path)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)[:500]}), 500

    @app.route('/api/network/scan', methods=['POST'])
    def api_network_scan():
        try:
            data = request.get_json() or {}
            pcap_path = data.get("pcap_path", "")
            if not pcap_path:
                return jsonify({"error": "pcap_path required"}), 400
            from modules.network import analyze_network
            result = analyze_network(pcap_path)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)[:500]}), 500

    return app

if __name__ == '__main__':
    application = create_app()
    print("⚡ r3con v6.2 PRO Dashboard - Malware + Network")
    print("http://127.0.0.1:5000")
    application.run(debug=False, host='127.0.0.1', port=5000, use_reloader=False)
