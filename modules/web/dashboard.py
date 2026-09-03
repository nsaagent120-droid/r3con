"""
r3con - Web Dashboard
Interactive Flask web interface for viewing analyses, exploit chains, and taint flows.
"""

from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

# HTML template for dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
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
        </div>
        
        <div class="grid">
            <!-- Analysis Overview -->
            <div class="card">
                <h2>📊 Analysis Overview</h2>
                <div id="overview-content">Loading...</div>
            </div>
            
            <!-- Severity Breakdown -->
            <div class="card">
                <h2>🎯 Severity Breakdown</h2>
                <div id="severity-content">Loading...</div>
            </div>
            
            <!-- Quick Stats -->
            <div class="card">
                <h2>⚙️ Statistics</h2>
                <div id="stats-content">Loading...</div>
            </div>
        </div>
        
        <!-- Exploit Chains -->
        <div class="section-title">🔗 Exploitation Chains</div>
        <div id="chains-container" style="display: grid; gap: 15px;"></div>
        
        <!-- Findings -->
        <div class="section-title">🐛 Detailed Findings</div>
        <div class="card">
            <div class="findings-list" id="findings-list">Loading...</div>
        </div>
        
        <!-- Taint Flows -->
        <div class="section-title">💧 Taint Analysis Flows</div>
        <div class="card">
            <div id="taint-flows" style="max-height: 500px; overflow-y: auto;">Loading...</div>
        </div>
        
        <div class="footer">
            <p>r3con v5.0.2 | Advanced Binary & Firmware Security Research Tool</p>
        </div>
    </div>

    <script>
        // Load analysis data from API
        async function loadDashboard() {
            try {
                const res = await fetch('/api/analysis');
                const data = await res.json();
                
                renderOverview(data.analysis);
                renderSeverity(data.findings);
                renderStats(data.stats);
                renderChains(data.exploit_chains);
                renderFindings(data.findings);
                renderTaintFlows(data.taint_flows);
            } catch (e) {
                console.error('Error loading dashboard:', e);
                document.getElementById('overview-content').innerHTML = 
                    '<p style="color: #ef4444;">Error loading analysis data</p>';
            }
        }
        
        function renderOverview(analysis) {
            const html = `
                <div class="stat-row">
                    <span class="stat-label">Target</span>
                    <span class="stat-value">${analysis.target}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Type</span>
                    <span class="stat-value">${analysis.analysis_type}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Status</span>
                    <span class="status-badge status-${analysis.status}">${analysis.status}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Created</span>
                    <span class="stat-value">${new Date(analysis.created_at).toLocaleString()}</span>
                </div>
            `;
            document.getElementById('overview-content').innerHTML = html;
        }
        
        function renderSeverity(findings) {
            const critical = findings.filter(f => f.severity === 'CRITICAL').length;
            const high = findings.filter(f => f.severity === 'HIGH').length;
            const medium = findings.filter(f => f.severity === 'MEDIUM').length;
            const low = findings.filter(f => f.severity === 'LOW').length;
            
            const html = `
                <div class="stat-row">
                    <span class="stat-label"><span class="severity-critical">●</span> Critical</span>
                    <span class="stat-value severity-critical">${critical}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label"><span class="severity-high">●</span> High</span>
                    <span class="stat-value severity-high">${high}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label"><span class="severity-medium">●</span> Medium</span>
                    <span class="stat-value severity-medium">${medium}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label"><span class="severity-low">●</span> Low</span>
                    <span class="stat-value severity-low">${low}</span>
                </div>
            `;
            document.getElementById('severity-content').innerHTML = html;
        }
        
        function renderStats(stats) {
            const html = `
                <div class="stat-row">
                    <span class="stat-label">Total Findings</span>
                    <span class="stat-value">${stats.total_findings}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Exploit Chains</span>
                    <span class="stat-value">${stats.exploit_chains}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Taint Flows</span>
                    <span class="stat-value">${stats.taint_flows}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Exploitable</span>
                    <span class="stat-value">${stats.exploitable_flows}</span>
                </div>
            `;
            document.getElementById('stats-content').innerHTML = html;
        }
        
        function renderChains(chains) {
            const html = chains.map(chain => `
                <div class="chain-box">
                    <div class="chain-name">🔗 ${chain.name}</div>
                    <div class="chain-impact">Impact: ${chain.impact}</div>
                    <div class="chain-steps">
                        Confidence: ${(chain.confidence * 100).toFixed(0)}% | 
                        Steps: ${chain.steps.length} |
                        Difficulty: ${chain.difficulty}
                    </div>
                </div>
            `).join('');
            
            document.getElementById('chains-container').innerHTML = html || '<p style="color: #64748b;">No exploitation chains detected</p>';
        }
        
        function renderFindings(findings) {
            const html = findings.map(f => `
                <div class="finding-item ${f.severity.toLowerCase()}">
                    <div class="finding-type">[${f.severity}] ${f.type}</div>
                    <div class="finding-desc">${f.description}</div>
                </div>
            `).join('');
            
            document.getElementById('findings-list').innerHTML = html || '<p style="color: #64748b;">No findings</p>';
        }
        
        function renderTaintFlows(flows) {
            const html = flows.map(f => `
                <div class="taint-flow">
                    <div><span class="taint-source">SOURCE:</span> ${f.source_name} @ ${f.source_file}:${f.source_line}</div>
                    <div><span class="taint-sink">SINK:</span> ${f.vulnerability_type} @ ${f.sink_file}:${f.sink_line}</div>
                    <div class="taint-path">Path length: ${f.path_length} | Exploitable: ${f.exploitable ? '✓' : '✗'}</div>
                </div>
            `).join('');
            
            document.getElementById('taint-flows').innerHTML = html || '<p style="color: #64748b;">No taint flows detected</p>';
        }
        
        // Load dashboard on page load
        loadDashboard();
        // Refresh every 30 seconds
        setInterval(loadDashboard, 30000);
    </script>
</body>
</html>
"""


def create_app():
    """Create Flask app with dashboard."""

    @app.route('/')
    def dashboard():
        return render_template_string(DASHBOARD_HTML)

    @app.route('/api/analysis', methods=['GET'])
    def api_analysis():
        """Return analysis data as JSON."""
        # This would be populated from the database
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

    return app


if __name__ == '__main__':
    app = create_app()
    print("⚡ r3con Web Dashboard")
    print("http://localhost:5000")
    app.run(debug=False, host='127.0.0.1', port=5000)
