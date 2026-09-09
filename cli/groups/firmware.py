"""Firmware group."""
from __future__ import annotations
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, ok, warn, spinner, show_findings, hpanel
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.firmware.firmware_analyzer import FirmwareAnalyzer

@click.group()
def firmware():
    """Firmware image analysis and extraction."""

@firmware.command("analyze")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--report", "-r", is_flag=True)
@click.pass_context
def fw_analyze(ctx, firmware_path, report):
    from core.report_gen import ReportGenerator
    section("FIRMWARE ANALYSIS")
    info(f"Target: {firmware_path}")
    console.print()
    fw = FirmwareAnalyzer(firmware_path)
    with spinner("Loading firmware image") as p:
        p.add_task("", total=None)
        fw.load()
    with spinner("Identifying components & architecture") as p:
        p.add_task("", total=None)
        id_info = fw.identify()
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=20)
    t.add_column(style="bold white")
    t.add_row("Size", id_info.get("size_human","?"))
    t.add_row("Components", str(len(id_info.get("components",[]))))
    t.add_row("Arch hints", str(len(id_info.get("arch_hints",[]))))
    console.print(Panel(t, title="[bold]Firmware Info[/]", border_style="dim cyan", padding=(0,1)))
    if id_info.get("components"):
        ct = Table(box=box.SIMPLE_HEAVY, title="Identified Components")
        ct.add_column("Offset", style="cyan", width=14)
        ct.add_column("Type", style="bold white")
        for comp in id_info["components"]:
            ct.add_row(comp["hex"], comp["type"])
        console.print(ct)
    if id_info.get("arch_hints"):
        for hint in id_info["arch_hints"]:
            info(hint)
    section("ENTROPY MAP")
    with spinner("Computing entropy map") as p:
        p.add_task("", total=None)
        high_e = fw.high_entropy_regions()
    if high_e:
        et = Table(box=box.SIMPLE_HEAVY)
        et.add_column("Offset", style="cyan", width=14)
        et.add_column("Size", style="dim", width=10)
        et.add_column("Entropy", style="yellow", width=10)
        et.add_column("Type", style="bold white")
        for r in high_e[:20]:
            et.add_row(r["hex"], f"{r['size']}B", f"{r['entropy']:.3f}", r["type"])
        console.print(et)
        info(f"Total high-entropy regions: {len(high_e)}")
    else:
        ok("No high-entropy regions found (no obvious encryption)")
    section("VULNERABILITY SCAN")
    with spinner("Extracting strings") as p:
        p.add_task("", total=None)
        fw.extract_strings()
    with spinner("Scanning for vulnerabilities") as p:
        p.add_task("", total=None)
        findings = fw.scan_vulns()
    show_findings(findings)
    paths = fw.find_interesting_paths()
    if paths:
        section("INTERESTING PATHS")
        pt = Table(box=box.SIMPLE_HEAVY)
        pt.add_column("Offset", style="cyan", width=12)
        pt.add_column("Path", style="bold white")
        pt.add_column("Match", style="yellow")
        for p_entry in paths[:30]:
            pt.add_row(p_entry["offset"], p_entry["path"][:60], p_entry["match"])
        console.print(pt)
    section("AI ANALYSIS")
    with spinner("AI firmware deep analysis") as p:
        p.add_task("", total=None)
        fw.get_summary()
        ai_res = ctx.obj["ai"].firmware_analysis(file_list=[c["type"] for c in id_info.get("components",[])], strings=[s["value"] for s in (fw.strings or [])[:100]], entropy_map={"high_entropy_regions": len(high_e)}, context=f"File: {firmware_path}")
    hpanel(ai_res, "AI Firmware Analysis", "high")
    if report:
        path = ReportGenerator().generate({"type":"firmware","target":firmware_path,"findings":findings})
        ok(f"Report → {path}")

@firmware.command("extract")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="./fw_extracted")
@click.pass_context
def fw_extract(ctx, firmware_path, output):
    section("FIRMWARE EXTRACTION")
    info(f"Target    : {firmware_path}")
    info(f"Output dir: {output}")
    fw = FirmwareAnalyzer(firmware_path)
    fw.load()
    with spinner("Extracting filesystem") as p:
        p.add_task("", total=None)
        result = fw.extract_filesystem(output)
    if result["success"]:
        ok(f"Extraction complete via {result['method']} → {output}")
    else:
        warn("Extraction failed or binwalk not available.")
        if result.get("error"):
            hpanel(result["error"], "Extraction Info", "medium")

@firmware.command("strings")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--min-len", default=6)
@click.option("--category", "-c", type=click.Choice(["all","credential","url","path","debug","ip_addr","cve_ref"]), default="all")
@click.pass_context
def fw_strings(ctx, firmware_path, min_len, category):
    section("FIRMWARE STRINGS")
    fw = FirmwareAnalyzer(firmware_path)
    fw.load()
    with spinner("Extracting strings") as p:
        p.add_task("", total=None)
        strings = fw.extract_strings(min_len=min_len)
    if category != "all":
        strings = [s for s in strings if s.get("category") == category]
    COLORS = {"credential":"red","url":"cyan","path":"yellow","debug":"orange3","ip_addr":"red","cve_ref":"red","log":"dim","":"dim white"}
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Offset", style="dim cyan", width=12)
    t.add_column("Category", width=12)
    t.add_column("String")
    for s in strings[:200]:
        cat = s.get("category","")
        color = COLORS.get(cat, "white")
        t.add_row(s["hex"], f"[{color}]{cat or '—'}[/{color}]", f"[{color}]{s['value'][:80]}[/{color}]")
    console.print(t)
    info(f"Total: {len(strings)} strings")

@firmware.command("entropy")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--block-size", default=4096)
@click.pass_context
def fw_entropy(ctx, firmware_path, block_size):
    section("ENTROPY MAP")
    info(f"Target: {firmware_path}  |  Block: {block_size}B")
    fw = FirmwareAnalyzer(firmware_path)
    fw.load()
    with spinner("Computing entropy") as p:
        p.add_task("", total=None)
        regions = fw.entropy_map(block_size=block_size)
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Offset", style="cyan", width=14)
    t.add_column("Entropy", style="yellow", width=10)
    t.add_column("Type", style="bold white")
    t.add_column("Visual")
    for r in regions:
        e = r["entropy"]
        bar = "█" * int(e) + "░" * (8 - int(e))
        color = "red" if e >= 7.5 else "yellow" if e >= 6.5 else "green"
        t.add_row(r["hex"], f"{e:.3f}", r["type"], f"[{color}]{bar}[/{color}]")
    console.print(t)
