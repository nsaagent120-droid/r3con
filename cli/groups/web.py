"""Web scanner group - v7.0 PRO."""
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
def web():
    """🌐 Web analysis - SAST + DAST (SQLi, XSS, SSTI, LFI, RCE, SSRF) + Nuclei."""

@web.command("analyze")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def web_analyze(file_path, json_output):
    """Web SAST analysis from source file."""
    from modules.web_scanner.web_analyzer import WebAnalyzer
    analyzer = WebAnalyzer()
    result = analyzer.analyze_file(file_path)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("WEB SAST ANALYSIS")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Findings", str(result.get("count", 0)))
    t.add_row("Categories", ", ".join(f"{k}:{v}" for k, v in result.get("by_category", {}).items()))
    console.print(Panel(t, title="[bold]Web Analysis[/]", border_style="cyan"))

    findings = result.get("findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)

        pocs = analyzer.generate_pocs(findings)
        if pocs:
            console.print("\n[bold yellow]Generated PoCs:[/]")
            for poc in pocs[:5]:
                console.print(f"[dim]{poc['type']}: {poc['payloads'][0][:50]}[/]")

@web.command("nuclei")
@click.argument("target_url")
@click.option("--templates", help="Comma-separated templates")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Filter by severity")
@click.option("--json-output", is_flag=True)
def web_nuclei(target_url, templates, severity, json_output):
    """Nuclei scan - requires nuclei installed."""
    from modules.web_scanner.nuclei_wrapper import NucleiWrapper
    wrapper = NucleiWrapper(target_url)
    tmpl_list = templates.split(",") if templates else None
    result = wrapper.scan(target_url, templates=tmpl_list, severity=severity)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("NUCLEI SCAN")
    if result.get("status") == "unsupported":
        warn(f"Nuclei not installed: {result.get('install')}")
        return

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Target", target_url)
    t.add_row("Findings", str(result.get("count", 0)))
    console.print(Panel(t, title="[bold]Nuclei[/]", border_style="green"))

    findings = result.get("findings", [])[:20]
    if findings:
        from .helpers import show_findings
        show_findings(findings)
