"""Reporting group - v7.1 PRO."""
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
def report():
    """📄 Reporting - JIRA, DefectDojo, GitHub Issues, MITRE ATT&CK, PDF, HTML, SARIF."""

@report.command("jira")
@click.argument("findings_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--project", default="SEC", show_default=True, help="JIRA project key")
@click.option("--output", type=click.Path(dir_okay=False), help="Output JSON file")
@click.option("--json-output", is_flag=True)
def report_jira(findings_file, project, output, json_output):
    """Export findings to JIRA format."""
    from modules.reporting.jira_exporter import JIRAExporter

    try:
        data = json.loads(Path(findings_file).read_text())
        findings = data.get("findings", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    except Exception as e:
        raise click.ClickException(f"Failed to load findings: {e}")

    exporter = JIRAExporter(project_key=project)
    result = exporter.export_json(findings, output_path=output)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("JIRA EXPORT")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Project", project)
    t.add_row("Issues", str(result.get("total_issues", 0)))
    t.add_row("Output", result.get("output_path", "preview only"))
    console.print(Panel(t, title="[bold]JIRA Export[/]", border_style="blue"))

@report.command("defectdojo")
@click.argument("findings_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def report_defectdojo(findings_file, json_output):
    """Export to DefectDojo format."""
    from modules.reporting.jira_exporter import DefectDojoExporter

    try:
        data = json.loads(Path(findings_file).read_text())
        findings = data.get("findings", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    except Exception as e:
        raise click.ClickException(f"Failed to load: {e}")

    exporter = DefectDojoExporter()
    result = exporter.export_json(findings)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("DEFECTDOJO EXPORT")
    console.print(Panel(f"Total: {result.get('total_findings',0)} findings", title="[bold]DefectDojo[/]", border_style="blue"))

@report.command("mitre")
@click.argument("findings_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", type=click.Path(dir_okay=False), help="Output layer JSON file")
@click.option("--json-output", is_flag=True)
def report_mitre(findings_file, output, json_output):
    """Generate MITRE ATT&CK Navigator layer."""
    from modules.reporting.jira_exporter import MITRENavigatorExporter

    try:
        data = json.loads(Path(findings_file).read_text())
        findings = data.get("findings", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    except Exception as e:
        raise click.ClickException(f"Failed to load: {e}")

    exporter = MITRENavigatorExporter()
    result = exporter.generate_layer(findings)

    if output:
        try:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json.dumps(result.get("layer", {}), indent=2))
            info(f"Layer written to {output} - import in https://mitre-attack.github.io/attack-navigator/")
        except Exception as e:
            warn(f"Failed to write: {e}")

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("MITRE ATT&CK NAVIGATOR")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Techniques", str(result.get("technique_count", 0)))
    t.add_row("Output", output or "No file")
    console.print(Panel(t, title="[bold]MITRE ATT&CK[/]", border_style="red"))

    layer = result.get("layer", {})
    techniques = layer.get("techniques", [])[:10]
    if techniques:
        tt = Table(box=box.SIMPLE, title="Techniques")
        tt.add_column("ID", style="cyan")
        tt.add_column("Score", style="white")
        tt.add_column("Comment", style="dim")
        for tech in techniques:
            tt.add_row(tech.get("techniqueID",""), str(tech.get("score","")), tech.get("comment","")[:60])
        console.print(tt)

@report.command("pdf")
@click.argument("findings_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--target", default="unknown", help="Target name")
@click.option("--output", type=click.Path(dir_okay=False), default="report.pdf", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["pdf", "html", "md"]), default="pdf", show_default=True)
def report_pdf(findings_file, target, output, fmt):
    """Generate PDF/HTML/Markdown report."""
    from modules.reporting.pdf_reporter import PDFReporter

    try:
        data = json.loads(Path(findings_file).read_text())
        findings = data.get("findings", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    except Exception as e:
        raise click.ClickException(f"Failed to load: {e}")

    reporter = PDFReporter()

    with spinner(f"Generating {fmt.upper()} report..."):
        if fmt == "pdf":
            result = reporter.generate_pdf(findings, target, output)
        elif fmt == "html":
            result = reporter.generate_html(findings, target, output)
        else:
            result = reporter.save_markdown(findings, target, output)

    section(f"{fmt.upper()} REPORT")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Format", result.get("format", fmt))
    t.add_row("Path", result.get("path", output))
    t.add_row("Status", result.get("status", ""))
    console.print(Panel(t, title=f"[bold]{fmt.upper()} Report[/]", border_style="green"))

    if result.get("status") == "ok":
        info(f"Report saved: {result.get('path')}")
