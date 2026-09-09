"""
r3con v6.0 Titan-Omega - Agent CLI
Agent autonome qui enchaîne outils, décide next steps
"""
from __future__ import annotations
import json
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, ok

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.agent import AutonomousAgent

@click.group()
def agent():
    """Agent autonome PRO - boucle OODA, décide et enchaîne outils automatiquement (v6.0)."""

@agent.command("run")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--workspace", "workspace_name", default=None, help="Workspace fédéré")
@click.option("--profile", default="auto", type=click.Choice(["auto", "quick", "deep", "full", "binary", "firmware", "apk", "bugbounty", "exploit"]), help="Profil initial")
@click.option("--max-iterations", default=5, type=click.IntRange(1, 10), help="Max itérations autonomes")
@click.option("--json-output", is_flag=True)
def agent_run(target, workspace_name, profile, max_iterations, json_output):
    """Lancer agent autonome sur cible."""
    section(f"AGENT AUTONOME - {target}")

    if workspace_name:
        info(f"Workspace: {workspace_name} | Profile: {profile} | Max iter: {max_iterations}")
    else:
        info(f"Target: {target} | Profile: {profile} | Max iter: {max_iterations} | (sans workspace, utilise --workspace pour fédération)")

    agent_obj = AutonomousAgent(workspace=workspace_name, profile=profile, max_iterations=max_iterations)

    with console.status("[cyan]Agent en cours d'analyse autonome...", spinner="dots"):
        result = agent_obj.run(target)

    if json_output:
        click.echo(json.dumps(result, indent=2, ensure_ascii=False))
        return

    console.print(Panel(
        f"[cyan]Target:[/] {result['target']}\n"
        f"[cyan]Workspace:[/] {result.get('workspace') or '—'}\n"
        f"[cyan]Iterations:[/] {result['iterations']}/{max_iterations}\n"
        f"[cyan]Duration:[/] {result['duration_ms']} ms\n"
        f"[cyan]Total findings:[/] {result['total_findings']}\n"
        f"[cyan]Status:[/] {result['status']}",
        title="[bold green]Agent terminé[/]", border_style="green"
    ))

    # History
    t = Table(box=box.SIMPLE_HEAVY, title="Historique OODA")
    t.add_column("Iter", style="cyan", width=5)
    t.add_column("Action", style="white", width=16)
    t.add_column("Reasoning", style="dim", width=40)
    t.add_column("Result", style="yellow")

    for h in result["history"]:
        t.add_row(
            str(h.get("iteration","")),
            h.get("action",""),
            h.get("reasoning","")[:40],
            h.get("result_summary","")[:40],
        )
    console.print(t)

    if result["findings"]:
        console.print(f"\n[bold]Findings ({len(result['findings'])}):[/]")
        for f in result["findings"][:10]:
            console.print(f"  [{f.get('severity','INFO')}] {f.get('type','')} - {f.get('description','')[:80]}")

    ok(f"Rapport agent sauvegardé dans workspace {workspace_name}/artifacts/ si workspace spécifié")

@agent.command("plan")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", default="auto")
def agent_plan(target, profile):
    """Montrer plan que l'agent suivrait (dry-run)."""
    agent_obj = AutonomousAgent(profile=profile, max_iterations=3)
    obs = agent_obj.observe(target)
    orient = agent_obj.orient(obs)

    section(f"PLAN AGENT - {target}")
    info(f"Kind détecté: {orient['kind']} | Findings initiaux: {orient['findings_count']}")

    t = Table(box=box.SIMPLE_HEAVY, title="Actions proposées")
    t.add_column("Action", style="cyan")
    t.add_column("Profile", style="white")
    t.add_column("Raison", style="dim")
    for action in orient["next_actions"]:
        t.add_row(action["action"], action["profile"], action["reason"])
    console.print(t)
