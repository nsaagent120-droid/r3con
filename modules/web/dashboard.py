"""
r3con v6.1 - Web Dashboard PRO renforcé
Dashboard temps réel + knowledge graph visuel + gestion workspaces + API complète
"""
from __future__ import annotations
from flask import Flask, render_template_string, jsonify, request
import html
import re
import json
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';">
    <title>r3con v6.1 — PRO Dashboard</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Courier New',monospace; background: linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 100%); color:#e2e8f0; padding:20px; min-height:100vh; }
        .container { max-width:1600px; margin:0 auto; }
        .header { text-align:center; margin-bottom:30px; border-bottom:2px solid #22d3ee; padding-bottom:20px; }
        .header h1 { color:#22d3ee; font-size:2.5em; margin-bottom:8px; }
        .header .subtitle { color:#64748b; font-size:0.9em; }
        .header .version { color:#f59e0b; font-size:0.8em; margin-top:6px; }
        .tabs { display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap; }
        .tab-btn { background:#1e293b; border:1px solid #334155; color:#94a3b8; padding:10px 20px; border-radius:6px; cursor:pointer; font-family:inherit; }
        .tab-btn.active { background:#22d3ee; color:#0f0f1a; border-color:#22d3ee; font-weight:bold; }
        .tab-content { display:none; }
        .tab-content.active { display:block; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:20px; margin-bottom:30px; }
        .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:30px; }
        .card { background:#1e293b; border:1px solid #334155; border-radius:8px; padding:20px; box-shadow:0 4px 6px rgba(0,0,0,0.3); }
        .card h2 { color:#7dd3fc; font-size:1.15em; margin-bottom:15px; border-bottom:1px solid #475569; padding-bottom:10px; }
        .card h3 { color:#22d3ee; font-size:1em; margin-bottom:10px; }
        .stat-row { display:flex; justify-content:space-between; margin-bottom:8px; padding:8px 0; border-bottom:1px solid #334155; }
        .stat-label { color:#94a3b8; }
        .stat-value { color:#22d3ee; font-weight:bold; }
        .sev-critical { color:#dc2626; } .sev-high { color:#ea580c; } .sev-medium { color:#ca8a04; } .sev-low { color:#16a34a; } .sev-info { color:#64748b; }
        .findings-list { max-height:500px; overflow-y:auto; }
        .finding-item { background:#0f172a; padding:12px; margin-bottom:10px; border-left:4px solid #475569; border-radius:4px; }
        .finding-item.critical { border-left-color:#dc2626; } .finding-item.high { border-left-color:#ea580c; } .finding-item.medium { border-left-color:#ca8a04; } .finding-item.low { border-left-color:#16a34a; }
        .finding-type { color:#e2e8f0; font-weight:bold; font-size:0.9em; }
        .finding-desc { color:#94a3b8; font-size:0.85em; margin-top:5px; }
        .chain-box { background:#1a1a2e; border:2px solid #22d3ee; border-radius:6px; padding:15px; margin-bottom:15px; }
        .chain-name { color:#22d3ee; font-weight:bold; }
        .chain-impact { color:#fbbf24; margin-top:5px; }
        .chain-steps { color:#94a3b8; font-size:0.9em; margin-top:8px; }
        .taint-flow { background:#0f172a; border-left:3px solid #f59e0b; padding:12px; margin-bottom:10px; border-radius:4px; }
        .taint-source { color:#f59e0b; font-weight:bold; } .taint-sink { color:#ec4899; font-weight:bold; }
        .section-title { color:#22d3ee; font-size:1.4em; margin-top:30px; margin-bottom:15px; border-bottom:2px solid #22d3ee; padding-bottom:8px; }
        .footer { text-align:center; color:#64748b; margin-top:60px; padding-top:20px; border-top:1px solid #334155; font-size:0.85em; }
        .badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:0.75em; font-weight:bold; }
        .badge-ok { background:#16a34a; color:#fff; } .badge-warn { background:#ca8a04; color:#fff; } .badge-crit { background:#dc2626; color:#fff; }
        .knowledge-node { background:#0f172a; border:1px solid #334155; padding:10px; margin-bottom:8px; border-radius:4px; }
        .knowledge-node .node-type { color:#22d3ee; font-size:0.8em; }
        .graph-viz { width:100%; height:400px; background:#0f172a; border-radius:8px; border:1px solid #334155; display:flex; align-items:center; justify-content:center; color:#64748b; }
        .progress-bar { width:100%; height:8px; background:#334155; border-radius:4px; overflow:hidden; margin-top:5px; }
        .progress-fill { height:100%; background:linear-gradient(90deg,#22d3ee,#7dd3fc); transition:width 0.3s; }
        .search-box { width:100%; padding:10px; background:#0f172a; border:1px solid #334155; border-radius:6px; color:#e2e8f0; font-family:inherit; margin-bottom:15px; }
        .btn { background:#22d3ee; color:#0f0f1a; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-family:inherit; font-weight:bold; }
        .btn:hover { background:#7dd3fc; }
        .workspace-item { background:#0f172a; padding:12px; margin-bottom:8px; border-radius:6px; border:1px solid #334155; cursor:pointer; }
        .workspace-item:hover { border-color:#22d3ee; }
        table { width:100%; border-collapse:collapse; }
        th { text-align:left; color:#7dd3fc; padding:8px; border-bottom:1px solid #334155; font-size:0.85em; }
        td { padding:8px; border-bottom:1px solid #1e293b; font-size:0.85em; color:#94a3b8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ r3con v6.1 PRO Dashboard</h1>
            <p class="subtitle">Advanced Vulnerability Analysis • Knowledge Graph • Bug Bounty Reporting</p>
            <p class="version">v6.1 PRO | Hybrid Workspaces | Federation | YARA + CVE + IoC + CallGraph</p>
            <p style="color:#f59e0b;font-size:0.75em;margin-top:8px">⚠ Local use only — no auth — do not expose to internet</p>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('overview')">📊 Overview</button>
            <button class="tab-btn" onclick="switchTab('findings')">🐛 Findings</button>
            <button class="tab-btn" onclick="switchTab('chains')">🔗 Chains</button>
            <button class="tab-btn" onclick="switchTab('knowledge')">🧠 Knowledge</button>
            <button class="tab-btn" onclick="switchTab('workspaces')">📁 Workspaces</button>
            <button class="tab-btn" onclick="switchTab('yara')">🎯 YARA</button>
            <button class="tab-btn" onclick="switchTab('deps')">📦 Deps & SBOM</button>
            <button class="tab-btn" onclick="switchTab('reports')">📄 Reports</button>
        </div>

        <!-- Overview Tab -->
        <div id="tab-overview" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <h2>📊 Analysis Overview</h2>
                    <div id="overview-content">Loading...</div>
                </div>
                <div class="card">
                    <h2>🎯 Severity Breakdown</h2>
                    <div id="severity-content">Loading...</div>
                </div>
                <div class="card">
                    <h2>⚙️ Statistics</h2>
                    <div id="stats-content">Loading...</div>
                </div>
            </div>
            <div class="grid-2">
                <div class="card">
                    <h2>📈 Risk Score</h2>
                    <div id="risk-content">Loading...</div>
                </div>
                <div class="card">
                    <h2>🔍 Quick Search</h2>
                    <input class="search-box" id="quick-search" placeholder="Search findings, CVEs, IoCs..." onkeyup="doSearch(this.value)">
                    <div id="search-results" style="max-height:300px;overflow-y:auto"></div>
                </div>
            </div>
            <div class="section-title">💧 Taint Flows</div>
            <div class="card"><div id="taint-flows" style="max-height:400px;overflow-y:auto">Loading...</div></div>
        </div>

        <!-- Findings Tab -->
        <div id="tab-findings" class="tab-content">
            <div class="card">
                <h2>🐛 Detailed Findings <span id="findings-count" style="color:#64748b;font-weight:normal"></span></h2>
                <div style="display:flex;gap:10px;margin-bottom:15px">
                    <button class="btn" onclick="filterFindings('ALL')">All</button>
                    <button class="btn" onclick="filterFindings('CRITICAL')" style="background:#dc2626;color:#fff">Critical</button>
                    <button class="btn" onclick="filterFindings('HIGH')" style="background:#ea580c;color:#fff">High</button>
                    <button class="btn" onclick="filterFindings('MEDIUM')" style="background:#ca8a04;color:#fff">Medium</button>
                </div>
                <div class="findings-list" id="findings-list">Loading...</div>
            </div>
        </div>

        <!-- Chains Tab -->
        <div id="tab-chains" class="tab-content">
            <div class="section-title">🔗 Exploitation Chains</div>
            <div id="chains-container" style="display:grid;gap:15px"></div>
            <div class="section-title">📞 Call Graph Paths</div>
            <div class="card"><div id="callgraph-container">Loading...</div></div>
        </div>

        <!-- Knowledge Tab -->
        <div id="tab-knowledge" class="tab-content">
            <div class="grid-2">
                <div class="card">
                    <h2>🧠 Knowledge Graph Stats</h2>
                    <div id="kg-stats">Loading...</div>
                </div>
                <div class="card">
                    <h2>🔗 IoC Correlations</h2>
                    <div id="ioc-stats">Loading...</div>
                </div>
            </div>
            <div class="card" style="margin-top:20px">
                <h2>🕸️ Knowledge Graph</h2>
                <div class="graph-viz" id="graph-viz">Knowledge Graph Visualization<br><small>Nodes & edges from cross-workspace correlations</small></div>
                <div id="kg-nodes" style="max-height:400px;overflow-y:auto;margin-top:15px"></div>
            </div>
        </div>

        <!-- Workspaces Tab -->
        <div id="tab-workspaces" class="tab-content">
            <div class="card">
                <h2>📁 Workspaces (Hybrid Federation)</h2>
                <div id="workspaces-list">Loading...</div>
            </div>
        </div>

        <!-- YARA Tab -->
        <div id="tab-yara" class="tab-content">
            <div class="grid-2">
                <div class="card">
                    <h2>🎯 YARA Rules</h2>
                    <div id="yara-rules">Loading...</div>
                </div>
                <div class="card">
                    <h2>🔍 YARA Scan Results</h2>
                    <div id="yara-scans">Loading...</div>
                </div>
            </div>
        </div>

        <!-- Deps Tab -->
        <div id="tab-deps" class="tab-content">
            <div class="grid-2">
                <div class="card">
                    <h2>📦 Dependencies</h2>
                    <div id="deps-list">Loading...</div>
                </div>
                <div class="card">
                    <h2>📋 SBOM</h2>
                    <div id="sbom-content">Loading...</div>
                </div>
            </div>
        </div>

        <!-- Reports Tab -->
        <div id="tab-reports" class="tab-content">
            <div class="card">
                <h2>📄 Bug Bounty Reports</h2>
                <div id="reports-content">Loading...</div>
                <div style="margin-top:15px;display:flex;gap:10px">
                    <button class="btn" onclick="exportReport('json')">Export JSON</button>
                    <button class="btn" onclick="exportReport('sarif')">Export SARIF</button>
                    <button class="btn" onclick="exportReport('markdown')">Export Markdown</button>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>r3con v6.1 PRO | Advanced Binary & Firmware Security Research Tool</p>
            <p style="margin-top:5px;font-size:0.8em">Knowledge: CVE DB 50+ patterns | YARA 5+ rules | IoC Correlator | Graph | SARIF | SBOM | CallGraph</p>
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
        renderTaintFlows(data.taint_flows||[]);
        renderKG(data.knowledge_graph||{});
        renderWorkspaces(data.workspaces||[]);
        renderYara(data.yara||{});
        renderDeps(data.deps||{});
        renderReports(data.reports||{});
        renderCallGraph(data.call_graph||{});
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
    [['Total Findings',s.total_findings||0],['Exploit Chains',s.exploit_chains||0],['Taint Flows',s.taint_flows||0],['Exploitable',s.exploitable_flows||0],['IoCs',s.ioc_count||0],['YARA Hits',s.yara_hits||0]].forEach(([l,v])=>{
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
    c.innerHTML=`<div style="text-align:center;padding:20px"><div style="font-size:3em;color:${color};font-weight:bold">${score}</div><div class="badge" style="background:${color};color:#fff;margin-top:10px">${level}</div><div style="color:#64748b;margin-top:10px;font-size:0.9em">${findings.length} findings analyzed</div><div class="progress-bar" style="margin-top:15px"><div class="progress-fill" style="width:${Math.min(100,score*2)}%;background:${color}"></div></div><div style="color:#94a3b8;margin-top:15px;font-size:0.85em">Est. Bounty: $${(findings.filter(f=>f.severity==='CRITICAL').length*2000+findings.filter(f=>f.severity==='HIGH').length*500+findings.filter(f=>f.severity==='MEDIUM').length*100).toLocaleString()}</div></div>`;
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
        if(f.file){const fileDiv=document.createElement('div');fileDiv.style.cssText='color:#64748b;font-size:0.8em;margin-top:4px';fileDiv.textContent=f.file+(f.line?':'+f.line:'');descDiv.appendChild(fileDiv);}
        item.appendChild(typeDiv);item.appendChild(descDiv);c.appendChild(item);
    });
}

function filterFindings(sev){currentFilter=sev;renderFindings(allFindings);}

function renderChains(chains){
    const c=document.getElementById('chains-container');c.innerHTML='';
    if(!chains.length){c.textContent='No exploitation chains detected';c.style.color='#64748b';return;}
    chains.slice(0,20).forEach(chain=>{
        const box=document.createElement('div');box.className='chain-box';
        const nameDiv=document.createElement('div');nameDiv.className='chain-name';nameDiv.textContent='🔗 '+(chain.name||'Chain');
        const impactDiv=document.createElement('div');impactDiv.className='chain-impact';impactDiv.textContent='Impact: '+(chain.impact||'Unknown');
        const stepsDiv=document.createElement('div');stepsDiv.className='chain-steps';stepsDiv.textContent=`Confidence: ${Math.round((chain.confidence||0)*100)}% | Steps: ${(chain.steps||[]).length} | Difficulty: ${chain.difficulty||'Unknown'}`;
        box.appendChild(nameDiv);box.appendChild(impactDiv);box.appendChild(stepsDiv);c.appendChild(box);
    });
}

function renderTaintFlows(flows){
    const c=document.getElementById('taint-flows');c.innerHTML='';
    if(!flows.length){c.textContent='No taint flows detected';c.style.color='#64748b';return;}
    flows.slice(0,50).forEach(f=>{
        const div=document.createElement('div');div.className='taint-flow';
        const srcDiv=document.createElement('div');const srcLabel=document.createElement('span');srcLabel.className='taint-source';srcLabel.textContent='SOURCE: ';srcDiv.appendChild(srcLabel);srcDiv.appendChild(document.createTextNode(`${f.source_name||''} @ ${f.source_file||''}:${f.source_line||''}`));
        const sinkDiv=document.createElement('div');const sinkLabel=document.createElement('span');sinkLabel.className='taint-sink';sinkLabel.textContent='SINK: ';sinkDiv.appendChild(sinkLabel);sinkDiv.appendChild(document.createTextNode(`${f.vulnerability_type||''} @ ${f.sink_file||''}:${f.sink_line||''}`));
        const pathDiv=document.createElement('div');pathDiv.className='taint-path';pathDiv.textContent=`Path length: ${f.path_length||0} | Exploitable: ${f.exploitable?'✓':'✗'}`;
        div.appendChild(srcDiv);div.appendChild(sinkDiv);div.appendChild(pathDiv);c.appendChild(div);
    });
}

function renderKG(kg){
    const statsEl=document.getElementById('kg-stats'); if(statsEl) statsEl.innerHTML=`<div class="stat-row"><span class="stat-label">Total Nodes</span><span class="stat-value">${kg.total_nodes||0}</span></div><div class="stat-row"><span class="stat-label">Total Edges</span><span class="stat-value">${kg.total_edges||0}</span></div><div class="stat-row"><span class="stat-label">Workspaces</span><span class="stat-value">${kg.workspaces||0}</span></div>`;
    const nodesEl=document.getElementById('kg-nodes'); if(nodesEl){nodesEl.innerHTML=''; (kg.nodes||[]).slice(0,20).forEach(n=>{const d=document.createElement('div');d.className='knowledge-node';d.innerHTML=`<span class="node-type">${safeText(n.type||'node')}</span> <strong>${safeText(n.id||'')}</strong><br><small style="color:#64748b">${safeText((n.data||{}).type||JSON.stringify(n.data||{}).slice(0,100))}</small>`;nodesEl.appendChild(d);});}
    const viz=document.getElementById('graph-viz'); if(viz && kg.total_nodes>0){viz.innerHTML=`<div style="text-align:center"><div style="color:#22d3ee;font-size:1.2em">${kg.total_nodes} nodes • ${kg.total_edges} edges</div><div style="color:#64748b;font-size:0.85em;margin-top:8px">Graph: ${(kg.edge_types||[]).join(', ')||'correlations'}</div></div>`;}
}

function renderWorkspaces(ws){
    const c=document.getElementById('workspaces-list');c.innerHTML='';
    if(!ws.length){c.textContent='No workspaces';c.style.color='#64748b';return;}
    ws.forEach(w=>{
        const d=document.createElement('div');d.className='workspace-item';
        d.innerHTML=`<strong style="color:#22d3ee">${safeText(w.name||w.id||'workspace')}</strong> <span class="badge badge-ok">${safeText(w.status||'active')}</span><br><small style="color:#64748b">${safeText(w.target||'')} • ${w.findings||0} findings • ${w.files||0} files</small>`;
        c.appendChild(d);
    });
}

function renderYara(yara){
    const rulesEl=document.getElementById('yara-rules'); if(rulesEl){rulesEl.innerHTML=''; if(!yara.rules||!yara.rules.length){rulesEl.textContent='No YARA rules';} else {yara.rules.slice(0,20).forEach(r=>{const d=document.createElement('div');d.className='knowledge-node';d.innerHTML=`<strong style="color:#22d3ee">${safeText(r.name||r)}</strong><br><small style="color:#64748b">${safeText(r.description||'')}</small> <span class="badge" style="background:#334155">${safeText(r.severity||'')}</span>`;rulesEl.appendChild(d);});}}
    const scansEl=document.getElementById('yara-scans'); if(scansEl){scansEl.innerHTML=''; if(!yara.hits||!yara.hits.length){scansEl.textContent='No YARA hits';} else {yara.hits.slice(0,20).forEach(h=>{const d=document.createElement('div');d.className='finding-item high';d.innerHTML=`<div class="finding-type">[${safeText(h.severity||'MEDIUM')}] ${safeText(h.rule||'rule')}</div><div class="finding-desc">${safeText(h.description||'')} @ ${safeText(h.file||'')}</div>`;scansEl.appendChild(d);});}}
}

function renderDeps(deps){
    const listEl=document.getElementById('deps-list'); if(listEl){listEl.innerHTML=''; if(!deps.dependencies||!deps.dependencies.length){listEl.textContent='No dependencies scanned';} else {const table=document.createElement('table');table.innerHTML='<tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Status</th></tr>';deps.dependencies.slice(0,50).forEach(d=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${safeText(d.name)}</td><td>${safeText(d.version)}</td><td>${safeText(d.ecosystem||'')}</td><td>${d.vulnerable?'<span class="badge badge-crit">VULN</span>':'<span class="badge badge-ok">OK</span>'}</td>`;table.appendChild(tr);});listEl.appendChild(table);}}
    const sbomEl=document.getElementById('sbom-content'); if(sbomEl){sbomEl.innerHTML=''; if(deps.sbom){sbomEl.innerHTML=`<div class="stat-row"><span class="stat-label">Format</span><span class="stat-value">${safeText(deps.sbom.bomFormat||'CycloneDX')}</span></div><div class="stat-row"><span class="stat-label">Components</span><span class="stat-value">${(deps.sbom.components||[]).length}</span></div><pre style="background:#0f172a;padding:10px;border-radius:4px;max-height:200px;overflow:auto;font-size:0.8em;color:#94a3b8">${safeText(JSON.stringify(deps.sbom,null,2).slice(0,2000))}</pre>`;} else {sbomEl.textContent='No SBOM generated';}}
}

function renderReports(reports){
    const c=document.getElementById('reports-content');c.innerHTML='';
    if(!reports.summary){c.innerHTML='<div style="color:#64748b">No reports generated yet. Run analysis to generate bug bounty report.</div>';return;}
    c.innerHTML=`<div class="stat-row"><span class="stat-label">Risk Level</span><span class="stat-value sev-${(reports.summary.risk_level||'low').toLowerCase()}">${safeText(reports.summary.risk_level||'LOW')}</span></div><div class="stat-row"><span class="stat-label">Risk Score</span><span class="stat-value">${reports.summary.risk_score||0}</span></div><div class="stat-row"><span class="stat-label">Est. Bounty</span><span class="stat-value" style="color:#fbbf24">$${reports.summary.estimated_bounty||0}</span></div><div style="margin-top:15px"><h3>Compliance</h3><div style="color:#94a3b8;font-size:0.9em">${(reports.summary.compliance||[]).map(c=>`<span class="badge" style="background:#334155;margin:2px">${safeText(c)}</span>`).join('')}</div></div>`;
}

function renderCallGraph(cg){
    const c=document.getElementById('callgraph-container');c.innerHTML='';
    if(!cg.functions){c.textContent='No call graph data';return;}
    c.innerHTML=`<div class="stat-row"><span class="stat-label">Functions</span><span class="stat-value">${cg.functions||0}</span></div><div class="stat-row"><span class="stat-label">Calls</span><span class="stat-value">${cg.calls||0}</span></div><div class="stat-row"><span class="stat-label">Paths to Sinks</span><span class="stat-value sev-critical">${(cg.paths_to_sinks||[]).length}</span></div>`;
    if(cg.paths_to_sinks&&cg.paths_to_sinks.length){const list=document.createElement('div');list.style.marginTop='15px';cg.paths_to_sinks.slice(0,10).forEach(p=>{const d=document.createElement('div');d.className='finding-item critical';d.innerHTML=`<div class="finding-type">${safeText(p.entry)} → ${safeText(p.sink)}()</div><div class="finding-desc">Path: ${safeText((p.path||[]).join(' → '))}</div>`;list.appendChild(d);});c.appendChild(list);}
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
    """Create Flask app PRO v6.1."""

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
                        data['findings'] = data['findings'][:200]
                    if 'exploit_chains' in data and isinstance(data['exploit_chains'], list):
                        data['exploit_chains'] = data['exploit_chains'][:20]
                    if 'taint_flows' in data and isinstance(data['taint_flows'], list):
                        data['taint_flows'] = data['taint_flows'][:50]
                return jsonify(data)
            except Exception as e:
                return jsonify({"error": str(e)[:200], "findings": [], "exploit_chains": [], "taint_flows": [],
                                "analysis": {"target": "error", "analysis_type": "error", "status": "error", "created_at": "2026-05-10T15:00:00"},
                                "stats": {"total_findings": 0, "exploit_chains": 0, "taint_flows": 0, "exploitable_flows": 0}}), 500

        return jsonify({
            "analysis": {"target": "unknown", "analysis_type": "static", "status": "in_progress", "created_at": datetime.now().isoformat()},
            "findings": [], "exploit_chains": [], "taint_flows": [],
            "stats": {"total_findings": 0, "exploit_chains": 0, "taint_flows": 0, "exploitable_flows": 0, "ioc_count": 0, "yara_hits": 0},
            "knowledge_graph": {"total_nodes": 0, "total_edges": 0, "workspaces": 0, "nodes": [], "edge_types": []},
            "workspaces": [],
            "yara": {"rules": [], "hits": []},
            "deps": {"dependencies": [], "sbom": None},
            "reports": {},
            "call_graph": {"functions": 0, "calls": 0, "paths_to_sinks": []},
        })

    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({"status": "ok", "version": "6.1.0-PRO"})

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

    @app.route('/api/iocs', methods=['GET'])
    def api_iocs():
        try:
            from modules.knowledge.ioc_correlator import IoCCorrelator
            corr = IoCCorrelator()
            # Get graph stats as proxy for IoC count
            from modules.knowledge.graph import KnowledgeGraph
            kg = KnowledgeGraph()
            stats = kg.get_stats()
            return jsonify({"stats": stats, "message": "IoC correlator active"})
        except Exception as e:
            return jsonify({"error": str(e)[:200]}), 500

    return app


if __name__ == '__main__':
    application = create_app()
    print("⚡ r3con v6.1 PRO Dashboard")
    print("⚠ Local use only - no authentication - do not expose to internet")
    print("http://127.0.0.1:5000")
    application.run(debug=False, host='127.0.0.1', port=5000, use_reloader=False)
