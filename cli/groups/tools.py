"""Tools group - external tools inspection."""
from __future__ import annotations
from pathlib import Path
import json
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.integration.tool_manager import ToolManager

@click.group()
def tools():
    """Inspect optional external tools; no installation by default."""

@tools.command("status")
def tools_status():
    for row in ToolManager().inspect():
        state = "present" if row["present"] else "missing"
        console.print(f"{row['key']:10} {state:8} {row.get('version') or ''} {row.get('path') or ''}")

@tools.command("plan")
@click.argument("names", nargs=-1)
def tools_plan(names):
    plan = ToolManager().install_plan(list(names) or None)
    for item in plan:
        console.print(json.dumps(item, ensure_ascii=False))

@tools.command("summary")
def tools_summary():
    mgr = ToolManager()
    summary = mgr.summary()
    t = Table(box=box.SIMPLE_HEAVY, title=f"Tool Summary - {summary['present']}/{summary['total']} available")
    t.add_column("Category", style="cyan")
    t.add_column("Present/Total", style="white")
    t.add_column("Tools", style="dim")
    for cat, data in summary["by_category"].items():
        t.add_row(cat, f"{data['present']}/{data['total']}", ", ".join(data["tools"][:8]))
    console.print(t)
    console.print(f"\n[bold]Capabilities:[/]")
    for cap, count in summary["capabilities"].items():
        console.print(f"  {cap}: {count} tools")

@tools.command("enhanced")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", default="binary", type=click.Choice(["binary", "firmware", "apk", "full"]), help="Analysis chain")
@click.option("--json-output", is_flag=True)
def tools_enhanced(target, profile, json_output):
    try:
        from modules.integration.advanced_adapters import EnhancedToolChain
        from core.config_manager import get_config
    except ImportError as e:
        raise click.ClickException(f"Advanced adapters not available: {e}")
    cfg = get_config(profile=profile)
    chain = EnhancedToolChain(target, config=cfg.to_dict())
    if profile == "binary":
        result = chain.full_binary_analysis()
    elif profile == "firmware":
        result = chain.full_firmware_analysis()
    elif profile == "apk":
        result = chain.full_apk_analysis()
    else:
        result = chain.full_binary_analysis()
    if json_output:
        click.echo(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        section(f"ENHANCED TOOLCHAIN - {profile.upper()}")
        info(f"Target: {target}")
        for tool, res in result.get("observations", {}).items():
            status = res.get("status", "unknown") if isinstance(res, dict) else "unknown"
            console.print(f"[{status}] {tool} — {res.get('engine', '') if isinstance(res, dict) else ''}")
        console.print(f"\nFindings: {len(result.get('findings', []))}")

@tools.command("check")
@click.argument("tool_name")
def tools_check(tool_name):
    mgr = ToolManager()
    for row in mgr.inspect():
        if row["key"] == tool_name:
            console.print(Panel(
                f"[cyan]Tool:[/] {row['key']}\n"
                f"[cyan]Executables:[/] {', '.join(row['executables'])}\n"
                f"[cyan]Present:[/] {'yes' if row['present'] else 'no'}\n"
                f"[cyan]Path:[/] {row['path'] or 'not found'}\n"
                f"[cyan]Version:[/] {row['version'] or 'unknown'}\n"
                f"[cyan]Category:[/] {row['category']}\n"
                f"[cyan]Capabilities:[/] {', '.join(row['capabilities'])}\n"
                f"[cyan]Purpose:[/] {row['purpose']}",
                title=f"Tool: {tool_name}", border_style="green" if row["present"] else "red"
            ))
            return
    raise click.ClickException(f"Unknown tool: {tool_name}")
