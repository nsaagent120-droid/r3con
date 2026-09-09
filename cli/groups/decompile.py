"""Decompiler group - v7.1 PRO."""
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
def decompile():
    """🔧 Decompiler - Ghidra, RetDec, pseudo-code generation."""

@decompile.command("ghidra")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--function", "func_name", help="Specific function to decompile")
@click.option("--json-output", is_flag=True)
def decompile_ghidra(binary_path, func_name, json_output):
    """Decompile with Ghidra headless."""
    from modules.disasm.decompiler import GhidraDecompiler
    decompiler = GhidraDecompiler(binary_path)
    result = decompiler.decompile(function_name=func_name)

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("GHIDRA DECOMPILER")
    if result.get("status") == "unsupported":
        warn(f"Ghidra not found: {result.get('install')}")
        return

    info(f"Status: {result.get('status')}")
    if result.get("decompiled"):
        console.print(Panel(result["decompiled"][:5000], title="[bold]Decompiled Code[/]", border_style="cyan"))

@decompile.command("all")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True)
def decompile_all(binary_path, json_output):
    """Try all decompilers (Ghidra, RetDec, pseudo)."""
    from modules.disasm.decompiler import DecompilerManager
    mgr = DecompilerManager(binary_path)

    with spinner(f"Decompiling {Path(binary_path).name} with all engines..."):
        result = mgr.decompile_all()

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("DECOMPILATION - ALL ENGINES")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Best Engine", result.get("best") or "None")
    t.add_row("Ghidra", result.get("ghidra", {}).get("status", ""))
    t.add_row("RetDec", result.get("retdec", {}).get("status", ""))
    t.add_row("Pseudo", result.get("pseudo", {}).get("status", ""))
    console.print(Panel(t, title="[bold]Decompiler Status[/]", border_style="cyan"))

    decompiled = result.get("decompiled", "")
    if decompiled:
        console.print(Panel(decompiled[:5000], title=f"[bold]Decompiled via {result.get('best')}[/]", border_style="green"))

@click.group()
def secrets():
    """🔑 Secret Scanner - Trufflehog-like detection (AWS, GitHub, API keys, private keys)."""

@secrets.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True)
@click.option("--entropy", default=4.5, show_default=True, help="Min entropy for high entropy detection")
def secrets_scan(path, json_output, entropy):
    """Scan file or directory for secrets."""
    from modules.audit.secret_scanner import SecretScanner
    scanner = SecretScanner(min_entropy=entropy)

    p = Path(path)
    if p.is_dir():
        with spinner(f"Scanning directory {p.name} for secrets..."):
            result = scanner.scan_directory(str(p))
    else:
        result = scanner.scan_file(str(p))

    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return

    section("SECRET SCANNER")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Findings", str(result.get("count", 0)))
    t.add_row("Files Scanned", str(result.get("files_scanned", 1) if p.is_dir() else 1))
    console.print(Panel(t, title="[bold]Secrets[/]", border_style="red"))

    findings = result.get("findings", [])[:30]
    if findings:
        from .helpers import show_findings
        show_findings(findings)
