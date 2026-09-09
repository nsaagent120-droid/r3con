"""Dashboard group - v7.2 PRO Real-time + ML."""
from __future__ import annotations
from pathlib import Path
import json
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, warn, spinner
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

@click.group()
def dashboard():
    """📊 Dashboard - Real-time WebSocket + ML + All domains (v7.2)."""

@dashboard.command("start")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind")
@click.option("--port", default=5000, show_default=True, help="Port")
@click.option("--no-websocket", is_flag=True, help="Disable WebSocket, use polling")
@click.option("--debug", is_flag=True, help="Debug mode")
def dashboard_start(host, port, no_websocket, debug):
    """Start real-time dashboard."""
    section("DASHBOARD v7.2 REAL-TIME")

    try:
        if no_websocket:
            from modules.web.dashboard import create_app
            app = create_app()
            info(f"Starting dashboard (polling) on http://{host}:{port}")
            info("WebSocket disabled - using polling fallback")
            app.run(host=host, port=port, debug=debug, use_reloader=False)
        else:
            from modules.web.dashboard_v2 import create_app_v2
            app, socketio = create_app_v2()

            if socketio:
                info(f"Starting dashboard with WebSocket real-time on http://{host}:{port}")
                info("WebSocket: Flask-SocketIO available - real-time updates enabled")
                info("Features: Real-time logs, live metrics, TaskQueue, active scans, ML chart")
                socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
            else:
                warn("Flask-SocketIO not installed - falling back to polling")
                info("Install with: pip install flask-socketio")
                info(f"Starting dashboard (polling) on http://{host}:{port}")
                app.run(host=host, port=port, debug=debug, use_reloader=False)

    except ImportError as e:
        warn(f"Dashboard dependencies missing: {e}")
        info("Install with: pip install flask flask-socketio")
    except Exception as e:
        warn(f"Failed to start dashboard: {e}")
        import traceback
        traceback.print_exc()

@dashboard.command("test")
@click.option("--json-output", is_flag=True)
def dashboard_test(json_output):
    """Test dashboard components."""
    from modules.web.dashboard_v2 import SOCKETIO_AVAILABLE

    result = {
        "version": "7.2.0",
        "websocket_available": SOCKETIO_AVAILABLE,
        "dashboard_v1": False,
        "dashboard_v2": False,
    }

    try:
        from modules.web.dashboard import create_app as create_app_v1
        result["dashboard_v1"] = True
    except Exception as e:
        result["dashboard_v1_error"] = str(e)[:200]

    try:
        from modules.web.dashboard_v2 import create_app_v2
        result["dashboard_v2"] = True
    except Exception as e:
        result["dashboard_v2_error"] = str(e)[:200]

    if json_output:
        click.echo(json.dumps(result, indent=2))
        return

    section("DASHBOARD TEST")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=20)
    t.add_column(style="bold white")
    t.add_row("Version", result["version"])
    t.add_row("WebSocket", "✅ Available" if result["websocket_available"] else "❌ Need flask-socketio")
    t.add_row("Dashboard v1", "✅ OK" if result["dashboard_v1"] else f"❌ {result.get('dashboard_v1_error','')}")
    t.add_row("Dashboard v2", "✅ OK" if result["dashboard_v2"] else f"❌ {result.get('dashboard_v2_error','')}")
    console.print(Panel(t, title="[bold]Dashboard v7.2[/]", border_style="cyan"))

    if not result["websocket_available"]:
        warn("Install WebSocket: pip install flask-socketio")
        info("Fallback polling will be used (30s)")

@click.group()
def ml():
    """🧠 ML - Embeddings TF-IDF + sentence-transformers + clustering."""

@ml.command("embeddings")
@click.argument("query")
@click.option("--docs", type=click.Path(exists=True, dir_okay=False), help="JSON file with documents array")
@click.option("--top-k", default=5, show_default=True, help="Top K results")
@click.option("--method", type=click.Choice(["tfidf", "transformer", "hybrid"]), default="hybrid", show_default=True)
@click.option("--json-output", is_flag=True)
def ml_embeddings(query, docs, top_k, method, json_output):
    """Test ML embeddings search."""
    from modules.ai.embeddings import MLEmbeddingsEngine

    documents = []
    if docs:
        try:
            data = json.loads(Path(docs).read_text())
            if isinstance(data, list):
                documents = data
            elif isinstance(data, dict) and "findings" in data:
                findings = data["findings"]
                documents = [f"{f.get('type','')} {f.get('description','')} {f.get('severity','')}" for f in findings]
            else:
                documents = [str(data)]
        except Exception as e:
            raise click.ClickException(f"Failed to load docs: {e}")
    else:
        # Default test documents
        documents = [
            "Buffer overflow in strcpy function critical vulnerability",
            "SQL injection via concatenation in web application high severity",
            "Cross-site scripting XSS via innerHTML medium",
            "Server-side template injection SSTI via render_template_string critical",
            "Local file inclusion LFI via open request query high",
            "AWS Access Key ID leaked AKIA critical secret",
            "Dockerfile runs as root user high cloud misconfig",
            "Kubernetes privileged container critical",
            "Private key leaked BEGIN RSA PRIVATE KEY critical",
            "Malware ransomware behavior with C2 communication",
        ]

    with spinner(f"Building embeddings for {len(documents)} docs..."):
        engine = MLEmbeddingsEngine(use_transformers=(method in ("transformer", "hybrid")))
        engine.fit(documents)

    results = engine.search(query, top_k=top_k, method=method)

    if json_output:
        click.echo(json.dumps({"query": query, "results": results, "stats": engine.get_stats()}, indent=2, default=str))
        return

    section("ML EMBEDDINGS SEARCH")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Query", query)
    t.add_row("Method", method)
    t.add_row("Docs", str(len(documents)))
    t.add_row("Vocab", str(engine.get_stats().get("vocab_size", 0)))
    t.add_row("Transformers", "✅" if engine.get_stats().get("use_transformers") else "❌ TF-IDF only")
    console.print(Panel(t, title="[bold]ML Embeddings[/]", border_style="magenta"))

    rt = Table(box=box.SIMPLE, title="Top Results")
    rt.add_column("Score", style="cyan", width=8)
    rt.add_column("Document", style="white")
    rt.add_column("Method", style="dim")
    for res in results:
        rt.add_row(f"{res.get('score',0):.3f}", res.get("document","")[:80], res.get("method",""))
    console.print(rt)

@ml.command("cluster")
@click.option("--docs", type=click.Path(exists=True, dir_okay=False), help="JSON file with documents")
@click.option("--k", default=3, show_default=True, help="Number of clusters")
@click.option("--json-output", is_flag=True)
def ml_cluster(docs, k, json_output):
    """Cluster documents via k-means TF-IDF."""
    from modules.ai.embeddings import MLEmbeddingsEngine

    documents = []
    if docs:
        try:
            data = json.loads(Path(docs).read_text())
            if isinstance(data, list):
                documents = data
            elif isinstance(data, dict) and "findings" in data:
                findings = data["findings"]
                documents = [f"{f.get('type','')} {f.get('description','')}" for f in findings]
        except Exception as e:
            raise click.ClickException(f"Failed to load: {e}")
    else:
        documents = [
            "Buffer overflow strcpy critical",
            "Stack overflow buffer high",
            "SQL injection concat critical web",
            "SQLi in query high web",
            "XSS innerHTML medium web",
            "SSTI render_template_string critical web",
            "AWS AKIA key leaked critical secret",
            "GitHub PAT ghp_ critical secret",
            "Dockerfile root user high cloud",
            "K8s privileged critical cloud",
        ]

    engine = MLEmbeddingsEngine(use_transformers=False)
    engine.fit(documents)
    result = engine.cluster(n_clusters=k)

    if json_output:
        click.echo(json.dumps(result, indent=2, default=str))
        return

    section("ML CLUSTERING")
    if result.get("status") != "ok":
        warn(f"Clustering failed: {result.get('error')}")
        return

    info(f"Clustered {len(documents)} docs into {k} clusters")
    for cluster in result.get("clusters", []):
        ct = Table(box=box.SIMPLE, title=f"Cluster {cluster.get('cluster_id')} (size {cluster.get('size')})")
        ct.add_column("Doc", style="white")
        for doc in cluster.get("documents", [])[:5]:
            ct.add_row(doc[:80])
        console.print(ct)

@ml.command("rag")
@click.argument("query")
@click.option("--findings", type=click.Path(exists=True, dir_okay=False), help="Findings JSON file")
@click.option("--json-output", is_flag=True)
def ml_rag(query, findings, json_output):
    """Test RAG v2 with ML embeddings."""
    from modules.ai.rag_engine_v2 import RAGEngineV2

    rag = RAGEngineV2(use_embeddings=True)

    if findings:
        try:
            data = json.loads(Path(findings).read_text())
            findings_list = data.get("findings", []) if isinstance(data, dict) else data if isinstance(data, list) else []
            rag.add_findings(findings_list)
            info(f"Loaded {len(findings_list)} findings")
        except Exception as e:
            raise click.ClickException(f"Failed to load findings: {e}")
    else:
        # Test findings
        test_findings = [
            {"type": "Buffer Overflow", "severity": "CRITICAL", "description": "strcpy overflow in vuln function", "file": "vuln.c", "line": 10, "recommendation": "Use strncpy"},
            {"type": "SQL Injection", "severity": "CRITICAL", "description": "SQLi via concatenation", "file": "app.py", "line": 20, "recommendation": "Use prepared statements"},
            {"type": "XSS", "severity": "HIGH", "description": "XSS via innerHTML", "file": "web.py", "line": 30, "recommendation": "Escape output"},
            {"type": "Secret: AWS Key", "severity": "CRITICAL", "description": "AWS AKIA key leaked", "file": ".env", "line": 5, "recommendation": "Rotate key, use env var"},
        ]
        rag.add_findings(test_findings)

    result = rag.query(query)

    if json_output:
        click.echo(json.dumps(result, indent=2, default=str))
        return

    section("RAG v2 ML")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Query", query)
    t.add_row("Intent", result.get("intent",""))
    t.add_row("Findings", str(len(result.get("findings",[]))))
    t.add_row("Embeddings", "✅" if result.get("use_embeddings") else "❌")
    t.add_row("Total KG", str(result.get("total_findings",0)))
    console.print(Panel(t, title="[bold]RAG v2[/]", border_style="magenta"))

    console.print(Panel(result.get("answer","")[:1000], title="[bold]Answer[/]", border_style="green"))

    if result.get("findings"):
        ft = Table(box=box.SIMPLE, title="Relevant Findings")
        ft.add_column("Score", style="cyan", width=8)
        ft.add_column("Type", style="white")
        ft.add_column("Severity", style="red")
        ft.add_column("File", style="dim")
        for f in result.get("findings", [])[:5]:
            ft.add_row(f"{f.get('_score',0):.3f}" if "_score" in f else "-", f.get("type","")[:30], f.get("severity",""), f.get("file","")[:20])
        console.print(ft)
