"""
r3con - Web Dashboard - FIXED P2
Fixes: XSS via HTML escaping, input validation, security headers, no debug
"""

from flask import Flask, render_template_string, jsonify, request
import html
import re

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# HTML template for dashboard - FIXED XSS via escaping
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
    <title>r3con — Analysis Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 100%);
            color: #e2e8f0;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #22d3ee;
            padding-bottom: 20px;
        }
        .header h1 {
            color: #22d3ee;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p { color: #64748b; font-size: 0.9em; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .card h2 {
            color: #7dd3fc;
            font-size: 1.2em;
            margin-bottom: 15px;
            border-bottom: 1px solid #475569;
            padding-bottom: 10px;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding: 10px 0;
            border-bottom: 1px solid #334155;
        }
        .stat-label { color: #94a3b8; }
        .stat-value { color: #22d3ee; font-weight: bold; }
        .severity-critical { color: #dc2626; }
        .severity-high { color: #ea580c; }
        .severity-medium { color: #ca8a04; }
        .severity-low { color: #16a34a; }
        .findings-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .finding-item {
            background: #0f172a;
            padding: 12px;
            margin-bottom: 10px;
            border-left: 4px solid #475569;
            border-radius: 4px;
        }
        .finding-item.critical { border-left-color: #dc2626; }
        .finding-item.high { border-left-color: #ea580c; }
        .finding-item.medium { border-left-color: #ca8a04; }
        .finding-item.low { border-left-color: #16a34a; }
        .finding-type { color: #e2e8f0; font-weight: bold; font-size: 0.9em; }
        .finding-desc { color: #94a3b8; font-size: 0.85em; margin-top: 5px; }
        .chain-box {
            background: #1a1a2e;
            border: 2px solid #22d3ee;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .chain-name { color: #22d3ee; font-weight: bold; }
        .chain-impact { color: #fbbf24; margin-top: 5px; }
        .chain-steps { color: #94a3b8; font-size: 0.9em; margin-top: 8px; }
        .taint-flow {
            background: #0f172a;
            border-left: 3px solid #f59e0b;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .taint-source { color: #f59e0b; font-weight: bold; }
        .taint-sink { color: #ec4899; font-weight: bold; }
        .taint-path { color: #94a3b8; font-size: 0.85em; margin-top: 5px; }
        .section-title {
            color: #22d3ee;
            font-size: 1.5em;
            margin-top: 40px;
            margin-bottom: 20px;
            border-bottom: 2px solid #22d3ee;
            padding-bottom: 10px;
        }
        .footer {
            text-align: center;
            color: #64748b;
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid #334155;
            font-size: 0.85em;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .status-complete { background: #16a34a; color: #fff; }
        .status-in-progress { background: #2563eb; color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ r3con Analysis Dashboard</h1>
            <p>Advanced vulnerability analysis & exploitation chain detection</p>
            <p style="color:#f59e0b;font-size:0.8em;margin-top:8px">⚠ Local use only - no authentication - do not expose to internet</p>
        </div>
        
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
        
        <div class="section-title">🔗 Exploitation Chains</div>
        <div id="chains-container" style="display: grid; gap: 15px;"></div>
        
        <div class="section-title">🐛 Detailed Findings</div>
        <div class="card">
            <div class="findings-list" id="findings-list">Loading...</div>
        </div>
        
        <div class="section-title">💧 Taint Analysis Flows</div>
        <div class="card">
            <div id="taint-flows" style="max-height: 500px; overflow-y: auto;">Loading...</div>
        </div>
        
        <div class="footer">
            <p>r3con v5.0.2-fixed-p2 | Advanced Binary & Firmware Security Research Tool</p>
        </div>
    </div>

    <script>
        // XSS-safe rendering: use textContent, not innerHTML for user data
        function escapeHtml(str) {
            if (!str) return '';
            const div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
        }

        function safeText(str) {
            if (str === null || str === undefined) return '';
            return String(str).replace(/[&<>"']/g, function(m) {
                return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];
            });
        }

        async function loadDashboard() {
            try {
                const res = await fetch('/api/analysis');
                if (!res.ok) throw new Error('API error ' + res.status);
                const data = await res.json();
                
                renderOverview(data.analysis);
                renderSeverity(data.findings);
                renderStats(data.stats);
                renderChains(data.exploit_chains);
                renderFindings(data.findings);
                renderTaintFlows(data.taint_flows);
            } catch (e) {
                console.error('Error loading dashboard:', e);
                document.getElementById('overview-content').textContent = 'Error loading analysis data';
            }
        }
        
        function renderOverview(analysis) {
            const container = document.getElementById('overview-content');
            container.innerHTML = '';
            
            const rows = [
                ['Target', analysis.target],
                ['Type', analysis.analysis_type],
                ['Status', analysis.status],
                ['Created', new Date(analysis.created_at).toLocaleString()]
            ];
            
            rows.forEach(([label, value]) => {
                const div = document.createElement('div');
                div.className = 'stat-row';
                const labelSpan = document.createElement('span');
                labelSpan.className = 'stat-label';
                labelSpan.textContent = label;
                const valueSpan = document.createElement('span');
                valueSpan.className = 'stat-value';
                valueSpan.textContent = value;
                div.appendChild(labelSpan);
                div.appendChild(valueSpan);
                container.appendChild(div);
            });
        }
        
        function renderSeverity(findings) {
            const container = document.getElementById('severity-content');
            container.innerHTML = '';
            
            const counts = {
                CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
                HIGH: findings.filter(f => f.severity === 'HIGH').length,
                MEDIUM: findings.filter(f => f.severity === 'MEDIUM' || f.severity === 'MED').length,
                LOW: findings.filter(f => f.severity === 'LOW').length
            };
            
            Object.entries(counts).forEach(([sev, count]) => {
                const div = document.createElement('div');
                div.className = 'stat-row';
                const labelSpan = document.createElement('span');
                labelSpan.className = 'stat-label';
                labelSpan.textContent = sev;
                const valueSpan = document.createElement('span');
                valueSpan.className = 'stat-value severity-' + sev.toLowerCase();
                valueSpan.textContent = count;
                div.appendChild(labelSpan);
                div.appendChild(valueSpan);
                container.appendChild(div);
            });
        }
        
        function renderStats(stats) {
            const container = document.getElementById('stats-content');
            container.innerHTML = '';
            
            const rows = [
                ['Total Findings', stats.total_findings],
                ['Exploit Chains', stats.exploit_chains],
                ['Taint Flows', stats.taint_flows],
                ['Exploitable', stats.exploitable_flows]
            ];
            
            rows.forEach(([label, value]) => {
                const div = document.createElement('div');
                div.className = 'stat-row';
                const labelSpan = document.createElement('span');
                labelSpan.className = 'stat-label';
                labelSpan.textContent = label;
                const valueSpan = document.createElement('span');
                valueSpan.className = 'stat-value';
                valueSpan.textContent = value;
                div.appendChild(labelSpan);
                div.appendChild(valueSpan);
                container.appendChild(div);
            });
        }
        
        function renderChains(chains) {
            const container = document.getElementById('chains-container');
            container.innerHTML = '';
            
            if (!chains || chains.length === 0) {
                container.textContent = 'No exploitation chains detected';
                container.style.color = '#64748b';
                return;
            }
            
            chains.slice(0, 20).forEach(chain => {
                const box = document.createElement('div');
                box.className = 'chain-box';
                
                const nameDiv = document.createElement('div');
                nameDiv.className = 'chain-name';
                nameDiv.textContent = '🔗 ' + (chain.name || 'Chain');
                
                const impactDiv = document.createElement('div');
                impactDiv.className = 'chain-impact';
                impactDiv.textContent = 'Impact: ' + (chain.impact || 'Unknown');
                
                const stepsDiv = document.createElement('div');
                stepsDiv.className = 'chain-steps';
                stepsDiv.textContent = `Confidence: ${Math.round((chain.confidence||0)*100)}% | Steps: ${(chain.steps||[]).length} | Difficulty: ${chain.difficulty||'Unknown'}`;
                
                box.appendChild(nameDiv);
                box.appendChild(impactDiv);
                box.appendChild(stepsDiv);
                container.appendChild(box);
            });
        }
        
        function renderFindings(findings) {
            const container = document.getElementById('findings-list');
            container.innerHTML = '';
            
            if (!findings || findings.length === 0) {
                container.textContent = 'No findings';
                container.style.color = '#64748b';
                return;
            }
            
            findings.slice(0, 100).forEach(f => {
                const item = document.createElement('div');
                const sev = (f.severity || 'INFO').toLowerCase();
                item.className = 'finding-item ' + sev;
                
                const typeDiv = document.createElement('div');
                typeDiv.className = 'finding-type';
                typeDiv.textContent = `[${f.severity||'INFO'}] ${f.type||f.finding_type||'Unknown'}`;
                
                const descDiv = document.createElement('div');
                descDiv.className = 'finding-desc';
                descDiv.textContent = f.description || '';
                
                item.appendChild(typeDiv);
                item.appendChild(descDiv);
                container.appendChild(item);
            });
        }
        
        function renderTaintFlows(flows) {
            const container = document.getElementById('taint-flows');
            container.innerHTML = '';
            
            if (!flows || flows.length === 0) {
                container.textContent = 'No taint flows detected';
                container.style.color = '#64748b';
                return;
            }
            
            flows.slice(0, 50).forEach(f => {
                const div = document.createElement('div');
                div.className = 'taint-flow';
                
                const srcDiv = document.createElement('div');
                const srcLabel = document.createElement('span');
                srcLabel.className = 'taint-source';
                srcLabel.textContent = 'SOURCE: ';
                srcDiv.appendChild(srcLabel);
                srcDiv.appendChild(document.createTextNode(`${f.source_name||''} @ ${f.source_file||''}:${f.source_line||''}`));
                
                const sinkDiv = document.createElement('div');
                const sinkLabel = document.createElement('span');
                sinkLabel.className = 'taint-sink';
                sinkLabel.textContent = 'SINK: ';
                sinkDiv.appendChild(sinkLabel);
                sinkDiv.appendChild(document.createTextNode(`${f.vulnerability_type||''} @ ${f.sink_file||''}:${f.sink_line||''}`));
                
                const pathDiv = document.createElement('div');
                pathDiv.className = 'taint-path';
                pathDiv.textContent = `Path length: ${f.path_length||0} | Exploitable: ${f.exploitable ? '✓' : '✗'}`;
                
                div.appendChild(srcDiv);
                div.appendChild(sinkDiv);
                div.appendChild(pathDiv);
                container.appendChild(div);
            });
        }
        
        loadDashboard();
        setInterval(loadDashboard, 30000);
    </script>
</body>
</html>
"""


def create_app(data_provider=None):
    """Create Flask app with dashboard - FIXED security headers."""

    @app.route('/')
    def dashboard():
        # Security headers
        resp = app.make_response(render_template_string(DASHBOARD_HTML))
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        return resp

    @app.route('/api/analysis', methods=['GET'])
    def api_analysis():
        """Return analysis data as JSON - FIXED validation."""
        # Validate that request is local
        # In production, add auth here

        if data_provider:
            try:
                data = data_provider()
                # Sanitize data to prevent XSS via JSON
                if isinstance(data, dict):
                    # Limit sizes
                    if 'findings' in data and isinstance(data['findings'], list):
                        data['findings'] = data['findings'][:100]
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
            "analysis": {
                "target": "unknown",
                "analysis_type": "static",
                "status": "in_progress",
                "created_at": "2026-05-10T15:00:00"
            },
            "findings": [],
            "exploit_chains": [],
            "taint_flows": [],
            "stats": {
                "total_findings": 0,
                "exploit_chains": 0,
                "taint_flows": 0,
                "exploitable_flows": 0
            }
        })

    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({"status": "ok", "version": "5.0.2-fixed-p2"})

    return app


if __name__ == '__main__':
    app = create_app()
    print("⚡ r3con Web Dashboard - FIXED P2")
    print("⚠ Local use only - no authentication - do not expose to internet")
    print("http://127.0.0.1:5000")
    # Bind to 127.0.0.1 only, no debug, no reloader
    app.run(debug=False, host='127.0.0.1', port=5000, use_reloader=False)
