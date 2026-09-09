"""AI RAG & Agent group - v7.0 PRO."""
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
def ai():
    """🧠 AI - RAG over knowledge graph, autonomous agent OODA, NL queries."""

@ai.command("query")
@click.argument("question")
@click.option("--context-file", type=click.Path(exists=True, dir_okay=False), help="JSON context file with findings")
@click.option("--json-output", is_flag=True)
def ai_query(question, context_file, json_output):
    """Natural language query over findings and knowledge graph."""
    from modules.ai.rag_engine import RAGEngine

    context = None
    if context_file:
        try:
            context = json.loads(Path(context_file).read_text())
        except Exception as e:
            warn(f"Failed to load context: {e}")

    engine = RAGEngine()
    result = engine.query(question, context=context)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("AI RAG QUERY")
    console.print(Panel(f"[bold cyan]Q:[/] {question}\n\n[bold green]A:[/] {result.get('answer','')}", title="[bold]AI Answer[/]", border_style="cyan"))

    retrieved = result.get("retrieved", {})
    findings = retrieved.get("findings", [])[:10]
    if findings:
        console.print("\n[bold]Retrieved Findings:[/]")
        for f in findings:
            console.print(f"[dim][{f.get('severity','INFO')}] {f.get('type','')} - {f.get('description','')[:80]}[/]")

@ai.command("agent")
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--iterations", default=3, show_default=True, help="Max OODA iterations")
@click.option("--json-output", is_flag=True)
def ai_agent(target_path, iterations, json_output):
    """Autonomous agent - OODA loop with tool chaining."""
    from modules.ai.agent_advanced import AdvancedAgent

    agent = AdvancedAgent(config={"max_iterations": iterations})

    with spinner(f"Agent analyzing {Path(target_path).name} autonomously..."):
        result = agent.run_autonomous(target_path, max_iterations=iterations)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("AUTONOMOUS AGENT")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Target", target_path)
    t.add_row("Iterations", str(result.get("iterations", 0)))
    t.add_row("Total Findings", str(result.get("final_summary", {}).get("total_findings", 0)))
    t.add_row("Critical", str(result.get("final_summary", {}).get("critical", 0)))
    console.print(Panel(t, title="[bold]Agent Summary[/]", border_style="magenta"))

    findings = result.get("final_findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)

@ai.command("summarize")
@click.argument("findings_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def ai_summarize(findings_file, json_output):
    """Summarize findings file via AI."""
    from modules.ai.rag_engine import RAGEngine

    try:
        data = json.loads(Path(findings_file).read_text())
        findings = data.get("findings", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    except Exception as e:
        raise click.ClickException(f"Failed to load findings: {e}")

    engine = RAGEngine()
    summary = engine.summarize_findings(findings)

    if json_output:
        click.echo(json.dumps({"summary": summary, "count": len(findings)}, ensure_ascii=False, indent=2))
        return

    section("AI SUMMARY")
    console.print(Panel(summary, title="[bold]Summary[/]", border_style="cyan"))
