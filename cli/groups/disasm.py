"""Disasm group - binary analysis."""
from __future__ import annotations
import re
import json
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich import box

from .helpers import console, section, info, ok, warn, hpanel, spinner, THEME

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.disasm.capstone_engine import DisasmEngine
from modules.disasm.binary_parser import BinaryParser
from modules.integration.reverse_adapters import R2Adapter

@click.group()
def disasm():
    """Disassembly & binary analysis (ELF / PE / Mach-O)."""

@disasm.command("file")
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--arch", "-a", default="auto", type=click.Choice(["auto","x86","x86_64","arm","arm64","mips","riscv"]))
@click.option("--output", "-o", default="pseudocode", type=click.Choice(["asm","pseudocode","c","cfg"]))
@click.option("--function", "-f", default=None, help="Disassemble specific function")
@click.option("--ai", is_flag=True, help="AI pseudo-code generation")
@click.option("--report", is_flag=True)
@click.pass_context
def disasm_file(ctx, binary_path, arch, output, function, ai, report):
    from core.report_gen import ReportGenerator
    section("BINARY ANALYSIS")
    info(f"Target   : {binary_path}")
    parser = BinaryParser(binary_path)
    binfo = parser.parse()
    if binfo.get("format") == "unknown":
        raise click.ClickException("Format binaire non reconnu; utilisez un format ELF/PE/Mach-O valide ou un mode raw explicite.")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=14)
    t.add_column(style="bold white")
    for k,v in [("Format", binfo.get("format","?")),("Arch", binfo.get("arch","?")),("Entry", hex(binfo.get("entry",0))),("Sections", str(len(binfo.get("sections",[])))),("Symbols", str(len(binfo.get("symbols",[]))))]:
        t.add_row(k, v)
    console.print(Panel(t, title="[bold]Binary Info[/]", border_style="dim cyan", padding=(0,1)))
    r2_result = R2Adapter(binary_path).analyze(function=function or "main")
    r2_obs = r2_result.get("observations", {})
    if r2_result.get("status") in ("ok", "partial"):
        if output == "cfg":
            content = "Use r2 interactively: agf @ {}".format(function or "main")
            syntax = "text"
        elif output in ("pseudocode", "c"):
            content = r2_obs.get("pseudocode") or "No pseudo-code was produced for this function."
            syntax = "c"
        else:
            content = json.dumps(r2_obs.get("disassembly", []), ensure_ascii=False, indent=2)
            syntax = "json"
        console.print(Panel(Syntax(content, syntax, theme="monokai", line_numbers=True), title=f"[bold]radare2 — {function or 'main'}[/]", border_style="green"))
        asm_out = content
    else:
        warn("radare2/rizin unavailable; using internal disassembly fallback")
        engine = DisasmEngine(binary_path, arch=arch)
        asm_out = engine.disasm_function(function) if function else engine.disasm_main()
        console.print(Panel(Syntax(asm_out, "nasm", theme="monokai", line_numbers=True), title="[bold]Internal fallback assembly[/]", border_style="yellow"))
    if report:
        path = ReportGenerator().generate({"type":"disasm","binary":binary_path,"output":asm_out,"engine": r2_result.get("engine", "internal")})
        ok(f"Report → {path}")

@disasm.command("strings")
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--min-len", default=4)
@click.option("--filter", "-f", default=None)
@click.option("--ai", is_flag=True)
@click.pass_context
def disasm_strings(ctx, binary_path, min_len, filter, ai):
    section("STRING EXTRACTION")
    parser = BinaryParser(binary_path)
    strings = parser.extract_strings(min_len=min_len, pattern=filter)
    COLORS = {"credential":"red","command":"red","url":"cyan","path":"yellow","crypto":"magenta","debug":"orange3","ip_addr":"red","":"dim white"}
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Offset", style="dim cyan", width=12)
    t.add_column("Category", width=12)
    t.add_column("String")
    for s in strings[:150]:
        cat = s.get("category","")
        color = COLORS.get(cat, "white")
        t.add_row(hex(s["offset"]), f"[{color}]{cat or '—'}[/{color}]", f"[{color}]{s['value'][:80]}[/{color}]")
    console.print(t)
    info(f"Total: {len(strings)} strings")
    if ai and strings:
        with spinner("AI analyzing strings for intel") as p:
            p.add_task("", total=None)
            analysis = ctx.obj["ai"].analyze_strings([s["value"] for s in strings])
        hpanel(analysis, "String Intel", "info")

@disasm.command("imports")
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--vuln-check", is_flag=True)
@click.pass_context
def disasm_imports(ctx, binary_path, vuln_check):
    section("IMPORT ANALYSIS")
    DANGEROUS = {"gets": ("CRITICAL","No bounds check — stack BOF"),"strcpy": ("HIGH","No bounds check — use strncpy"),"strcat": ("HIGH","No bounds check — use strncat"),"sprintf": ("MED","Use snprintf with explicit size"),"system": ("HIGH","Command injection risk"),"rand": ("LOW","Weak PRNG — not crypto-safe")}
    def match_import(name, dangerous):
        return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(dangerous)}(?![A-Za-z0-9_])", name.lower()))
    parser = BinaryParser(binary_path)
    imports = parser.get_imports()
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Library", style="dim", width=20)
    t.add_column("Function", style="bold white")
    t.add_column("Warning")
    for imp in imports:
        name = imp.get("name","")
        warn_str = ""
        if vuln_check:
            for d, (sev, msg) in DANGEROUS.items():
                if match_import(name, d):
                    from .helpers import SEV_STYLE
                    style, _ = SEV_STYLE.get(sev, ("white",""))
                    warn_str = f"[{style}][{sev}] {msg}[/{style}]"
                    break
        t.add_row(imp.get("library",""), name, warn_str)
    console.print(t)
    ok(f"{len(imports)} imports analyzed")
