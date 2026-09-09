"""Cloud & Container group - v7.0 PRO."""
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
def cloud():
    """☁️ Cloud & Container - Dockerfile, K8s, Terraform, secrets, image scanning."""

@cloud.command("docker")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def cloud_docker(file_path, json_output):
    """Dockerfile analysis."""
    from modules.cloud.docker_analyzer import CloudAnalyzer
    analyzer = CloudAnalyzer()
    result = analyzer.analyze_dockerfile(file_path)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("DOCKERFILE ANALYSIS")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Findings", str(result.get("count", 0)))
    t.add_row("Score", str(result.get("score", 0)))
    console.print(Panel(t, title="[bold]Dockerfile[/]", border_style="blue"))

    findings = result.get("findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)

@cloud.command("k8s")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def cloud_k8s(file_path, json_output):
    """K8s manifest analysis."""
    from modules.cloud.docker_analyzer import CloudAnalyzer
    analyzer = CloudAnalyzer()
    result = analyzer.analyze_k8s(file_path)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("K8S ANALYSIS")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Findings", str(result.get("count", 0)))
    t.add_row("Score", str(result.get("score", 0)))
    console.print(Panel(t, title="[bold]K8s[/]", border_style="blue"))

    findings = result.get("findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)

@cloud.command("terraform")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def cloud_terraform(file_path, json_output):
    """Terraform analysis."""
    from modules.cloud.docker_analyzer import CloudAnalyzer
    analyzer = CloudAnalyzer()
    result = analyzer.analyze_terraform(file_path)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("TERRAFORM ANALYSIS")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Findings", str(result.get("count", 0)))
    t.add_row("Score", str(result.get("score", 0)))
    console.print(Panel(t, title="[bold]Terraform[/]", border_style="purple"))

    findings = result.get("findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)

@cloud.command("scan")
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--json-output", is_flag=True)
def cloud_scan(directory, json_output):
    """Scan directory for all cloud configs."""
    from modules.cloud.docker_analyzer import CloudAnalyzer
    analyzer = CloudAnalyzer()
    result = analyzer.analyze_directory(directory)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("CLOUD DIRECTORY SCAN")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Files", str(result.get("total_files", 0)))
    t.add_row("Findings", str(result.get("count", 0)))
    t.add_row("Score", str(result.get("score", 0)))
    console.print(Panel(t, title="[bold]Cloud Scan[/]", border_style="cyan"))

    findings = result.get("findings", [])[:50]
    if findings:
        from .helpers import show_findings
        show_findings(findings)

@click.group()
def container():
    """📦 Container - Image scanning, Dockerfile, secrets, layers."""

@container.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True)
def container_scan(path, json_output):
    """Container scan - Dockerfile or image tar or directory."""
    from modules.container.image_scanner import ContainerScanner
    scanner = ContainerScanner()
    p = Path(path)
    if p.is_dir():
        result = scanner.scan_directory(str(p))
    elif p.suffix == ".tar":
        result = scanner.scan_image_tar(str(p))
    else:
        result = scanner.scan_dockerfile(str(p))

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("CONTAINER SCAN")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Findings", str(result.get("count", result.get("secret_count", 0))))
    t.add_row("Score", str(result.get("score", 0)))
    console.print(Panel(t, title="[bold]Container[/]", border_style="blue"))

    findings = result.get("findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)
