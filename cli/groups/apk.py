"""APK group."""
from __future__ import annotations
from pathlib import Path
import re
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, ok, warn, spinner, show_findings, hpanel
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.apk.apk_analyzer import APKAnalyzer

@click.group()
def apk():
    """Android APK security analysis."""

@apk.command("analyze")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--report", "-r", is_flag=True)
@click.pass_context
def apk_analyze(ctx, apk_path, report):
    from core.report_gen import ReportGenerator
    section("APK ANALYSIS")
    info(f"Target: {apk_path}")
    console.print()
    analyzer = APKAnalyzer(apk_path)
    with spinner("Extracting APK contents") as p:
        p.add_task("", total=None)
        ok_load = analyzer.load()
    if not ok_load:
        detail = f" ({analyzer.last_error})" if analyzer.last_error else ""
        warn(f"Could not open APK. Ensure it is a valid ZIP/APK file.{detail}")
        return
    summary = analyzer.get_file_summary()
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Total files", str(summary["total_files"]))
    t.add_row("DEX files", str(len(summary["dex_files"])))
    t.add_row("Native libs", str(len(summary["native_libs"])))
    t.add_row("Has manifest", "✓" if summary["has_manifest"] else "✗")
    console.print(Panel(t, title="[bold]APK Contents[/]", border_style="dim cyan", padding=(0,1)))
    console.print()
    components = analyzer.get_components()
    if any(components.values()):
        section("COMPONENTS")
        for ctype, items in components.items():
            if items:
                ct = Table(box=box.SIMPLE_HEAVY, title=f"[bold]{ctype.title()}[/]")
                ct.add_column("Name", style="white")
                ct.add_column("Exported", width=10)
                for item in items:
                    exp = "[red]YES[/]" if item.get("exported") else "[dim]no[/]"
                    ct.add_row(item["name"], exp)
                console.print(ct)
    section("SECURITY FINDINGS")
    with spinner("Analyzing manifest") as p:
        p.add_task("", total=None)
        manifest_f = analyzer.analyze_manifest()
    with spinner("Analyzing bytecode (Smali)") as p:
        p.add_task("", total=None)
        smali_f = analyzer.analyze_smali()
    with spinner("Scanning strings") as p:
        p.add_task("", total=None)
        strings_f = analyzer.analyze_strings()
    all_f = manifest_f + smali_f + strings_f
    show_findings(all_f)
    with spinner("AI APK deep analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].apk_analysis(manifest=analyzer.manifest, smali="\n".join([s["content"][:500] for s in analyzer.smali[:5]]), strings=[s["value"] for s in analyzer.strings[:100]])
    hpanel(ai_res, "AI APK Analysis", "high")
    if report:
        path = ReportGenerator().generate({"type":"apk","target":apk_path,"findings":all_f})
        ok(f"Report → {path}")

@apk.command("manifest")
@click.argument("manifest_path", type=click.Path(exists=True))
@click.pass_context
def apk_manifest(ctx, manifest_path):
    section("MANIFEST ANALYSIS")
    with open(manifest_path, errors="ignore") as f:
        manifest = f.read()
    analyzer = APKAnalyzer.__new__(APKAnalyzer)
    analyzer.manifest = manifest
    analyzer.smali = []
    analyzer.strings = []
    findings = analyzer.analyze_manifest()
    show_findings(findings)

@apk.command("permissions")
@click.argument("apk_path", type=click.Path(exists=True))
@click.pass_context
def apk_permissions(ctx, apk_path):
    section("PERMISSION ANALYSIS")
    analyzer = APKAnalyzer(apk_path)
    analyzer.load()
    if not analyzer.manifest:
        warn("Could not read manifest.")
        return
    from modules.apk.apk_analyzer import DANGEROUS_PERMISSIONS
    t = Table(box=box.SIMPLE_HEAVY, title="Permissions")
    t.add_column("Severity", width=10)
    t.add_column("Permission")
    t.add_column("Description")
    found = re.findall(r'android:name\s*=\s*"(android\.permission\.[^"]+)"', analyzer.manifest)
    for perm in found:
        if perm in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[perm]
            from .helpers import SEV_STYLE
            style, _ = SEV_STYLE.get(sev, ("white",""))
            t.add_row(f"[{style}]{sev}[/{style}]", perm, desc)
        else:
            t.add_row("[dim]INFO[/]", perm, "")
    console.print(t)
