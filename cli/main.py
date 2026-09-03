#!/usr/bin/env python3
"""
r3con v5.0.0 - Advanced Security Research Tool
Hacker-style CLI Interface
"""

import sys
import os
import re
import json
# sys est déjà importé ci-dessus; aucun module externe supplémentaire n’est requis ici.
import time
import subprocess
from pathlib import Path

# Graceful dependency check
_missing = []
try:
    import click
except ImportError:
    _missing.append("click")
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich import box
    from rich.theme import Theme
except ImportError:
    _missing.append("rich")

if _missing:
    print(f"[r3con] Missing dependencies: {', '.join(_missing)}")
    print(f"[r3con] Install with: pip install {' '.join(_missing)}")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ai_engine import AIEngine
from core.session import SessionManager
from core.report_gen import ReportGenerator
from core.plugin_system import default_registry, save_run
from modules.disasm.capstone_engine import DisasmEngine
from modules.disasm.binary_parser import BinaryParser
from modules.audit.static_analyzer import StaticAnalyzer
from modules.advanced.heap_analyzer import HeapAnalyzer
from modules.advanced.crypto_checker import CryptoChecker
from modules.advanced.kernel_patterns import KernelPatternScanner
from modules.research.research import HypothesisEngine, CVEMatcher, VariantFinder
from modules.apk.apk_analyzer import APKAnalyzer
from modules.firmware.firmware_analyzer import FirmwareAnalyzer
from modules.network.protocol_analyzer import ProtocolAnalyzer
from modules.network.external_analyzers import ExternalNetworkAnalyzer
from modules.network.live_capture import LiveCaptureAnalyzer
from modules.integration.tool_manager import ToolManager
from modules.integration.reverse_adapters import R2Adapter
from modules.dynamic.gdb_analyzer import DynamicAnalyzer
from modules.orchestration.orchestrator import Orchestrator

# ── Theme ─────────────────────────────────────────────────────
THEME_PRESETS = {
    "matrix": {"banner": "bold green", "accent": "bold green", "success": "bold green", "warning": "bold yellow", "critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "green", "muted": "dim green", "label": "green", "border": "green", "table_header": "bold green", "prompt": "bold green"},
    "cyber": {"banner": "bold magenta", "accent": "bold cyan", "success": "bold green", "warning": "bold yellow", "critical": "bold red", "high": "bright_red", "medium": "bright_yellow", "low": "bright_cyan", "info": "cyan", "muted": "dim cyan", "label": "bright_cyan", "border": "cyan", "table_header": "bold cyan", "prompt": "bold magenta"},
    "amber": {"banner": "bold yellow", "accent": "bold yellow", "success": "bold green", "warning": "yellow", "critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "yellow", "muted": "dim yellow", "label": "yellow", "border": "yellow", "table_header": "bold yellow", "prompt": "bold yellow"},
    "mono": {"banner": "bold white", "accent": "bold white", "success": "bold white", "warning": "bold white", "critical": "bold white", "high": "white", "medium": "white", "low": "white", "info": "white", "muted": "dim white", "label": "white", "border": "white", "table_header": "bold white", "prompt": "bold white"},
}

def _make_theme(name=None):
    selected = (name or os.environ.get("R3CON_THEME", "cyber")).lower()
    return selected if selected in THEME_PRESETS else "cyber"

THEME_NAME = _make_theme()
THEME = Theme(THEME_PRESETS[THEME_NAME])

def _no_color() -> bool:
    return os.environ.get("R3CON_NO_COLOR", "").lower() in {"1", "true", "yes", "on"}

console = Console(theme=THEME, no_color=_no_color())

def apply_theme(name):
    global THEME_NAME, THEME, console
    THEME_NAME = _make_theme(name)
    THEME = Theme(THEME_PRESETS[THEME_NAME])
    console = Console(theme=THEME, no_color=_no_color())

VERSION  = "5.0.2"
BANNER   = """\
 ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗ ██║
 ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝\
 """

SEV_STYLE = {
    "CRITICAL": ("bold red",    "██"),
    "HIGH":     ("red",         "▓▓"),
    "MED":      ("yellow",      "░░"),
    "MEDIUM":   ("yellow",      "░░"),
    "LOW":      ("green",       "--"),
    "INFO":     ("cyan",        "··"),
}
SEV_ORDER = ["CRITICAL","HIGH","MED","MEDIUM","LOW","INFO"]


# ── Helpers ───────────────────────────────────────────────────

def _animations_enabled() -> bool:
    """Enable motion only on a real terminal and allow CI/users to disable it."""
    disabled = os.environ.get("R3CON_NO_ANIMATION", "").lower() in {"1", "true", "yes", "on"}
    return bool(getattr(console, "is_terminal", False)) and not disabled and not os.environ.get("CI")


def print_banner(boot: bool = True):
    console.print()
    title = Text(BANNER, style="banner")
    subtitle = Text(f"v{VERSION}  ·  Binary  ·  APK  ·  Firmware  ·  Kernel  ·  Network", style="muted")
    console.print(Panel(title, subtitle=subtitle, border_style="border", padding=(0, 2)))
    ai_engine = AIEngine()
    mode_str = "[green]ONLINE[/]" if ai_engine.is_online() else "[yellow]OFFLINE[/]"
    console.print("  [bold cyan]R3CON[/]  [dim]local analysis orchestrator[/]  ·  AI: " + mode_str)
    console.print("  [dim]r2 reverse[/] · [dim]GDB/pwndbg dynamic[/] · [dim]Ghidra opt-in[/]")
    console.print()
    if boot:
        _boot(ai_engine.is_online())


def _boot(online: bool):
    steps = [
        ("Loading pattern database", 0.18),
        ("Mounting analysis modules", 0.18),
        ("Preparing external engines", 0.18),
        ("Connecting AI engine" if online else "AI offline — local mode", 0.18),
    ]
    if not _animations_enabled():
        for desc, _ in steps:
            console.print(f"  [green]✓[/] {desc}")
        console.print("  [green]✓[/] Ready.\n")
        return
    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=24, style="dim cyan", complete_style="cyan"),
        TextColumn("[dim]{task.percentage:>3.0f}%"),
        console=console, transient=True,
    ) as prog:
        for desc, dur in steps:
            task = prog.add_task(desc, total=100)
            for _ in range(20):
                time.sleep(dur / 20)
                prog.advance(task, 5)
    status = "[green]✓[/] Ready." if online else "[yellow]✓[/] Ready (offline mode)."
    console.print(f"  {status}\n")

def section(title: str):
    console.print()
    console.print(Rule(f"[accent] {title} [/accent]", style="muted"))
    console.print()


def ok(msg: str):
    console.print(f"  [success]✓[/]  {msg}")


def info(msg: str):
    console.print(f"  [info]→[/info]  [muted]{msg}[/muted]")


def warn(msg: str):
    console.print(f"  [warning]![/warning]  {msg}")


def hpanel(content: str, title: str = "", sev: str = "info"):
    borders = {"critical":"critical", "high":"high", "medium":"medium",
               "low":"low", "info":"info", "success":"success"}
    border = borders.get(sev.lower(), "border")
    console.print(Panel(content, title=f"[bold]{title}[/bold]" if title else None,
                         border_style=border, padding=(0, 2)))


def spinner(label: str):
    return Progress(
        SpinnerColumn(spinner_name="dots2", style="cyan"),
        TextColumn(f"[cyan]{label}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    )


def show_findings(findings: list):
    if not findings:
        ok("No findings detected.")
        return

    counts = {}
    for f in findings:
        s = f.get("severity","INFO")
        counts[s] = counts.get(s, 0) + 1

    parts = []
    for sev in SEV_ORDER:
        if sev in counts:
            style, _ = SEV_STYLE.get(sev, ("white","  "))
            parts.append(f"[{style}]{counts[sev]} {sev}[/{style}]")
    console.print(f"  [muted]Findings:[/muted] {' · '.join(parts)}")
    console.print()

    sorted_f = sorted(findings,
        key=lambda x: SEV_ORDER.index(x.get("severity","INFO"))
        if x.get("severity","INFO") in SEV_ORDER else 99)

    for f in sorted_f:
        sev         = f.get("severity","INFO")
        style, icon = SEV_STYLE.get(sev, ("white","  "))
        loc = ""
        if f.get("file"):   loc += f"[dim]{Path(f['file']).name}[/] "
        if f.get("line"):   loc += f"[dim cyan]L{f['line']}[/]"
        if f.get("offset"): loc += f"[dim cyan]@{f['offset']}[/]"

        console.print(f"  [{style}][{sev}][/{style}] [{style}]{icon}[/{style}]"
                      f"  [bold]{f.get('type', f.get('finding_type', ''))}[/bold]  {loc}")
        console.print(f"       [muted]{f.get('description','')[:110]}[/muted]")
        if f.get("recommendation"):
            console.print(f"       [success]↳  {f['recommendation'][:100]}[/success]")
        console.print()


# ── CLI root ──────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version=VERSION)
@click.option("--no-banner", is_flag=True)
@click.option("--theme", type=click.Choice(["matrix", "cyber", "amber", "mono"]), default=None, help="Terminal color theme")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors for logs and CI")
@click.pass_context
def cli(ctx, no_banner, theme, no_color):
    """r3con — Binary · APK · Firmware · Kernel Security Research Tool"""
    ctx.ensure_object(dict)
    if no_color:
        os.environ["R3CON_NO_COLOR"] = "1"
    if theme or no_color:
        apply_theme(theme)
    ctx.obj["ai"]      = AIEngine()
    ctx.obj["session"] = SessionManager()
    if not no_banner and ctx.invoked_subcommand not in ("interactive", None):
        print_banner(boot=False)
    elif ctx.invoked_subcommand is None:
        print_banner(boot=False)
        console.print("  Run [cyan]r3con --help[/] to see all commands.\n"
                      "  Run [cyan]r3con interactive[/] for AI shell.\n")


# ═════════════════════════════════════════════════════════════
# DISASM
# ═════════════════════════════════════════════════════════════

@cli.group()
def disasm():
    """Disassembly & binary analysis (ELF / PE / Mach-O)."""


@disasm.command("file")
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--arch", "-a", default="auto",
              type=click.Choice(["auto","x86","x86_64","arm","arm64","mips","riscv"]))
@click.option("--output", "-o", default="pseudocode",
              type=click.Choice(["asm","pseudocode","c","cfg"]))
@click.option("--function", "-f", default=None, help="Disassemble specific function")
@click.option("--ai",    is_flag=True, help="AI pseudo-code generation")
@click.option("--report",is_flag=True)
@click.pass_context
def disasm_file(ctx, binary_path, arch, output, function, ai, report):
    """Disassemble a binary file."""
    section("BINARY ANALYSIS")
    info(f"Target   : {binary_path}")

    parser = BinaryParser(binary_path)
    binfo  = parser.parse()
    if binfo.get("format") == "unknown":
        raise click.ClickException(
            "Format binaire non reconnu; utilisez un format ELF/PE/Mach-O "
            "valide ou un mode raw explicite.")

    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=14)
    t.add_column(style="bold white")
    for k,v in [("Format", binfo.get("format","?")),
                ("Arch",   binfo.get("arch","?")),
                ("Entry",  hex(binfo.get("entry",0))),
                ("Sections", str(len(binfo.get("sections",[])))),
                ("Symbols",  str(len(binfo.get("symbols",[]))))]:
        t.add_row(k, v)
    console.print(Panel(t, title="[bold]Binary Info[/]",
                        border_style="dim cyan", padding=(0,1)))

    # The external reverse engine owns disassembly/decompilation. The internal
    # engine is used only as an explicit fallback when r2/rizin is unavailable.
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
        console.print(Panel(Syntax(content, syntax, theme="monokai", line_numbers=True),
                            title=f"[bold]radare2 — {function or 'main'}[/]", border_style="green"))
        asm_out = content
    else:
        warn("radare2/rizin unavailable; using internal disassembly fallback")
        engine = DisasmEngine(binary_path, arch=arch)
        asm_out = engine.disasm_function(function) if function else engine.disasm_main()
        console.print(Panel(Syntax(asm_out, "nasm", theme="monokai", line_numbers=True),
                            title="[bold]Internal fallback assembly[/]", border_style="yellow"))

    if report:
        path = ReportGenerator().generate(
            {"type":"disasm","binary":binary_path,"output":asm_out,
             "engine": r2_result.get("engine", "internal")})
        ok(f"Report → {path}")


@disasm.command("strings")
@click.argument("binary_path", type=click.Path(exists=True))
@click.option("--min-len", default=4)
@click.option("--filter", "-f", default=None)
@click.option("--ai", is_flag=True)
@click.pass_context
def disasm_strings(ctx, binary_path, min_len, filter, ai):
    """Extract and categorize strings from a binary."""
    section("STRING EXTRACTION")
    parser  = BinaryParser(binary_path)
    strings = parser.extract_strings(min_len=min_len, pattern=filter)

    COLORS = {"credential":"red","command":"red","url":"cyan",
              "path":"yellow","crypto":"magenta","debug":"orange3","ip_addr":"red","":"dim white"}
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Offset",   style="dim cyan", width=12)
    t.add_column("Category", width=12)
    t.add_column("String")
    for s in strings[:150]:
        cat   = s.get("category","")
        color = COLORS.get(cat, "white")
        t.add_row(hex(s["offset"]),
                  f"[{color}]{cat or '—'}[/{color}]",
                  f"[{color}]{s['value'][:80]}[/{color}]")
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
    """List imports and flag dangerous functions."""
    section("IMPORT ANALYSIS")
    DANGEROUS = {
        "gets":    ("CRITICAL","No bounds check — stack BOF"),
        "strcpy":  ("HIGH",    "No bounds check — use strncpy"),
        "strcat":  ("HIGH",    "No bounds check — use strncat"),
        "sprintf": ("MED",     "Use snprintf with explicit size"),
        "system":  ("HIGH",    "Command injection risk"),
        "rand":    ("LOW",     "Weak PRNG — not crypto-safe"),
    }
    def match_import(name, dangerous):
        # Ne jamais utiliser `dangerous in name`: cela confond `gets` et
        # `fgets`. Les noms r2 peuvent contenir des préfixes comme sym.imp.
        return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(dangerous)}(?![A-Za-z0-9_])", name.lower()))

    parser  = BinaryParser(binary_path)
    imports = parser.get_imports()
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Library",  style="dim", width=20)
    t.add_column("Function", style="bold white")
    t.add_column("Warning")
    for imp in imports:
        name = imp.get("name","")
        warn_str = ""
        if vuln_check:
            for d, (sev, msg) in DANGEROUS.items():
                if match_import(name, d):
                    style, _ = SEV_STYLE.get(sev, ("white",""))
                    warn_str = f"[{style}][{sev}] {msg}[/{style}]"
                    break
        t.add_row(imp.get("library",""), name, warn_str)
    console.print(t)
    ok(f"{len(imports)} imports analyzed")


# ═════════════════════════════════════════════════════════════
# DIRECT EXTERNAL ENGINES / DYNAMIC ANALYSIS
# ═════════════════════════════════════════════════════════════

@cli.command("r2")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--no-analysis", is_flag=True, help="Open r2 without automatic analysis")
def r2_command(binary_path, no_analysis):
    """Open radare2 directly on a local binary."""
    import shutil
    executable = shutil.which("r2") or shutil.which("radare2")
    if not executable:
        raise click.ClickException("radare2/r2 is not installed")
    command = [executable]
    if not no_analysis:
        command += ["-AA"]
    command.append(binary_path)
    console.print(f"[cyan]Launching {executable} directly. Type q to quit.[/]")
    raise SystemExit(subprocess.call(command))


@cli.command("workspace")
@click.argument("binary_path", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--session", default="r3con-lab", show_default=True, help="tmux session name")
@click.option("--dry-run", is_flag=True, help="Print the four-pane plan without launching it")
def workspace_command(binary_path, session, dry_run):
    """Open a four-pane local analysis workspace using tmux."""
    import shutil
    tmux = shutil.which("tmux")
    target = binary_path or ""
    commands = [
        "r3con interactive",
        (f"r2 -AA {target}" if target else "echo 'r2 pane: use r2 -AA ./binary'"),
        (f"gdb {target}" if target else "echo 'GDB pane: use gdb ./binary'"),
        "bash",
    ]
    if dry_run:
        console.print(Panel("\n".join(f"Pane {i + 1}: {cmd}" for i, cmd in enumerate(commands)), title="[bold cyan] r3con workspace [/bold cyan]", border_style="cyan"))
        return
    if not tmux:
        raise click.ClickException("tmux is required for the four-pane workspace. Install it with your distribution package manager, or use r3con interactive directly.")
    if subprocess.call([tmux, "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        raise click.ClickException(f"tmux session '{session}' already exists; use tmux attach -t {session} or choose --session NAME")
    subprocess.run([tmux, "new-session", "-d", "-s", session, "bash"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.0", commands[0].replace("\\n", " && "), "C-m"], check=True)
    subprocess.run([tmux, "split-window", "-h", "-t", f"{session}:0.0"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.1", commands[1], "C-m"], check=True)
    subprocess.run([tmux, "split-window", "-v", "-t", f"{session}:0.1"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.2", commands[2], "C-m"], check=True)
    subprocess.run([tmux, "select-pane", "-t", f"{session}:0.0"], check=True)
    subprocess.run([tmux, "split-window", "-v", "-t", f"{session}:0.0"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.3", commands[3], "C-m"], check=True)
    subprocess.run([tmux, "select-layout", "-t", f"{session}:0", "tiled"], check=True)
    console.print(f"[green]✓[/] Four-pane workspace created: [cyan]{session}[/]")
    raise SystemExit(subprocess.call([tmux, "attach-session", "-t", session]))


@cli.command("gdb")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("gdb_args", nargs=-1)
def gdb_command(binary_path, gdb_args):
    """Open GDB directly; the user's pwndbg/GEF/ peda config is preserved."""
    import shutil
    executable = shutil.which("gdb")
    if not executable:
        raise click.ClickException("gdb is not installed")
    console.print("[cyan]Launching GDB directly; your ~/.gdbinit configuration is preserved.[/]")
    raise SystemExit(subprocess.call([executable, binary_path, *gdb_args]))


@cli.group("dynamic")
def dynamic_group():
    """Local dynamic analysis helpers using GDB and optional pwndbg."""


@dynamic_group.command("status")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
def dynamic_status(binary_path):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).status(), ensure_ascii=False))


@dynamic_group.command("function")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("function_name")
def dynamic_function(binary_path, function_name):
    result = DynamicAnalyzer(binary_path).analyze_function(function_name)
    console.print_json(json.dumps(result, ensure_ascii=False))


@dynamic_group.command("crash")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--input", "input_data", default="A" * 128, show_default=False)
def dynamic_crash(binary_path, input_data):
    result = DynamicAnalyzer(binary_path).analyze_crash(input_data)
    console.print_json(json.dumps(result, ensure_ascii=False))


@dynamic_group.command("heap")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
def dynamic_heap(binary_path):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).analyze_heap(), ensure_ascii=False))


@dynamic_group.command("offset")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--length", default=300, type=click.IntRange(32, 10000), show_default=True)
def dynamic_offset(binary_path, length):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).find_bof_offset(length), ensure_ascii=False))


@dynamic_group.command("rop")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
def dynamic_rop(binary_path):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).find_rop_gadgets_live(), ensure_ascii=False))


@dynamic_group.command("trace")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("function_name", required=False, default="main")
@click.option("--steps", default=20, type=click.IntRange(1, 500), show_default=True)
def dynamic_trace(binary_path, function_name, steps):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).trace_execution(function_name, steps), ensure_ascii=False))


@dynamic_group.command("maps")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
def dynamic_maps(binary_path):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).get_memory_maps(), ensure_ascii=False))


@dynamic_group.command("core")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("core_path", type=click.Path(exists=True, dir_okay=False))
def dynamic_core(binary_path, core_path):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).analyze_core_dump(core_path), ensure_ascii=False))


@dynamic_group.command("watchpoint")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("address")
@click.option("--type", "watch_type", type=click.Choice(["write", "read", "access"]), default="write", show_default=True)
def dynamic_watchpoint(binary_path, address, watch_type):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).set_watchpoint(address, watch_type), ensure_ascii=False))


@cli.command("benchmark")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", type=click.Choice(["quick", "binary", "network", "firmware", "source", "apk", "full"]), default="quick", show_default=True)
@click.option("--runs", default=3, type=click.IntRange(1, 20), show_default=True)
@click.option("--no-cache", is_flag=True, help="Benchmark without the local cache")
def benchmark_command(target, profile, runs, no_cache):
    """Benchmark a non-dynamic local analysis without executing the target."""
    import contextlib
    import io
    durations = []
    for _ in range(runs):
        started = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = Orchestrator(target, profile=profile, cache=not no_cache).run()
        durations.append(round((time.perf_counter() - started) * 1000, 2))
    payload = {"target": target, "profile": profile, "runs": runs, "durations_ms": durations, "min_ms": min(durations), "max_ms": max(durations), "avg_ms": round(sum(durations) / len(durations), 2), "cache": not no_cache, "last_status": result.get("status")}
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@cli.command("correlate")
@click.argument("firmware_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("pcap_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write correlation JSON")
def correlate_command(firmware_path, pcap_path, max_mb, json_output):
    """Correlate firmware strings with passive PCAP IOCs."""
    from modules.integration.firmware_pcap_correlation import correlate
    result = correlate(firmware_path, pcap_path, max_mb=max_mb)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
        return
    console.print_json(payload)


@cli.command("diff")
@click.argument("old_binary", type=click.Path(exists=True, dir_okay=False))
@click.argument("new_binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write comparison JSON")
def diff_command(old_binary, new_binary, json_output):
    """Compare functions and protections between two local binaries."""
    from modules.integration.binary_diff import compare_binaries
    result = compare_binaries(old_binary, new_binary)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
        return
    console.print_json(payload)


# ═════════════════════════════════════════════════════════════
# CENTRAL ORCHESTRATION
# ═════════════════════════════════════════════════════════════

@cli.command("analyze")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", type=click.Choice(["auto", "quick", "binary", "network", "firmware", "apk", "dynamic", "full"]), default="auto", show_default=True)
@click.option("--timeout", default=120, show_default=True, type=click.IntRange(1, 3600))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--workers", default=3, show_default=True, type=click.IntRange(1, 8))
@click.option("--reverse-engine", type=click.Choice(["radare2", "rizin"]), default="radare2", show_default=True, help="Reverse-engineering engine")
@click.option("--with-ghidra", is_flag=True, default=None, help="Run Ghidra in addition to radare2 (opt-in)")
@click.option("--no-cache", is_flag=True, help="Do not read or write the local analysis cache")
@click.option("--cache-dir", type=click.Path(file_okay=False), help="Cache directory")
@click.option("--workspace", "workspace_mode", type=click.Choice(["never", "always", "auto"]), default="never", show_default=True, help="Open the four-pane workspace")
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write unified JSON report")
def analyze_command(target, profile, timeout, max_mb, workers, reverse_engine, with_ghidra, no_cache, cache_dir, workspace_mode, json_output):
    """Run the adaptive local orchestration pipeline."""
    result = Orchestrator(target, profile=profile, timeout=timeout, max_mb=max_mb,
                          max_workers=workers, reverse_engine=reverse_engine,
                          with_ghidra=with_ghidra, cache=not no_cache,
                          cache_dir=cache_dir).run()
    if json_output:
        Path(json_output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"Report written: {json_output}")
    section("R3CON ORCHESTRATION")
    info(f"Target: {target}")
    info(f"Profile: {result.get('profile', profile)}")
    for name, value in result.get("results", {}).items():
        console.print(f"[{value.get('status', 'unknown')}] {name} — {value.get('engine', '')}")
    console.print(f"Findings: {len(result.get('findings', []))} | Duration: {result.get('duration_ms', 0)} ms")
    if result.get("status") != "ok":
        warn(f"Overall status: {result.get('status')}")
    selected_profile = result.get("profile", profile)
    auto_profiles = {"binary", "dynamic", "firmware", "network"}
    if workspace_mode == "always" or (workspace_mode == "auto" and selected_profile in auto_profiles):
        workspace_command.callback(target, f"r3con-{selected_profile}", False)


# ═════════════════════════════════════════════════════════════
# EXTERNAL TOOLS
# ═════════════════════════════════════════════════════════════

@cli.group()
def tools():
    """Inspect optional external tools; no installation by default."""


@tools.command("status")
def tools_status():
    """Show detected tools, versions and paths."""
    for row in ToolManager().inspect():
        state = "present" if row["present"] else "missing"
        console.print(f"{row['key']:10} {state:8} {row.get('version') or ''} {row.get('path') or ''}")


@tools.command("plan")
@click.argument("names", nargs=-1)
def tools_plan(names):
    """Show an installation plan; never installs anything."""
    plan = ToolManager().install_plan(list(names) or None)
    for item in plan:
        console.print(json.dumps(item, ensure_ascii=False))


# ═════════════════════════════════════════════════════════════
# NETWORK / PROTOCOLS (PASSIVE)
# ═════════════════════════════════════════════════════════════

@cli.group()
def network():
    """Passive offline/live network and protocol analysis; no scanning or injection."""


@network.command("live")
@click.option("--interface", "interface_name", default="any", show_default=True,
              help="Local capture interface; use 'any' on Linux when supported")
@click.option("--duration", default=30, show_default=True, type=click.IntRange(1, 3600),
              help="Maximum capture duration in seconds")
@click.option("--max-packets", default=10000, show_default=True, type=click.IntRange(1, 1000000),
              help="Maximum number of packets to inspect")
@click.option("--filter", "display_filter", default=None,
              help="Optional TShark display filter, for example 'dns or tcp'")
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False),
              help="Write the aggregated result to a JSON file")
def network_live(interface_name, duration, max_packets, display_filter, json_output):
    """Capture and analyze local traffic passively; never injects packets."""
    analyzer = LiveCaptureAnalyzer(interface=interface_name, duration=duration,
                                   max_packets=max_packets, display_filter=display_filter)
    result = analyzer.capture()
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
    else:
        if result.get("status") == "error":
            raise click.ClickException(result.get("error", "live capture failed"))
        section("LIVE PASSIVE NETWORK ANALYSIS")
        info(f"Interface: {result.get('interface')} | Duration: {result.get('duration_actual', 0)} s")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
        t.add_column(style="dim cyan", width=18)
        t.add_column(style="bold white")
        t.add_row("Packets", str(result.get("packets", 0)))
        t.add_row("Bytes", str(result.get("bytes", 0)))
        t.add_row("Protocols", ", ".join(f"{k}: {v}" for k, v in result.get("protocols", {}).items()) or "none")
        iocs = result.get("iocs", {})
        t.add_row("DNS / HTTP / TLS", f"{len(iocs.get('dns', []))} / {len(iocs.get('http_hosts', []))} / {len(iocs.get('tls_sni', []))}")
        t.add_row("Flows", str(len(result.get("flows", []))))
        console.print(Panel(t, title="[bold]Live Capture Summary[/]", border_style="green"))
        if result.get("stderr"):
            warn("TShark reported a partial capture; inspect the JSON report for details.")
        if result.get("iocs"):
            hpanel(json.dumps(result["iocs"], ensure_ascii=False, indent=2), "Observed Network IOCs", "info")


@network.command("analyze")
@click.argument("pcap_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-packets", default=100000, show_default=True, type=click.IntRange(1, 1000000))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--json-output", "json_output", is_flag=True, help="Print machine-readable JSON")
@click.option("--engine", type=click.Choice(["internal", "tshark", "zeek", "all"]), default="internal", show_default=True)
def network_analyze(pcap_path, max_packets, max_mb, json_output, engine):
    """Analyze an offline PCAP file without transmitting packets."""
    result = ProtocolAnalyzer(pcap_path, max_packets=max_packets,
                               max_bytes=max_mb * 1024 * 1024).analyze()
    external = ExternalNetworkAnalyzer(pcap_path)
    if engine in ("tshark", "all"):
        result["tshark"] = external.tshark_fields(["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "dns.qry.name", "http.host"])
    if engine in ("zeek", "all"):
        result["zeek"] = external.zeek_offline()
    if engine == "tshark":
        result = result["tshark"]
    elif engine == "zeek":
        result = result["zeek"]
    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("status") in ("ok", "partial") else 3)
    section("PASSIVE NETWORK ANALYSIS")
    info(f"Target: {pcap_path}")
    if result.get("status") != "ok":
        raise click.ClickException(result.get("error", "network analysis failed"))
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Packets", str(result["packets_read"]))
    t.add_row("Link type", str(result["linktype"]))
    t.add_row("Protocols", ", ".join(f"{k}: {v}" for k, v in result["protocols"].items()) or "none")
    ioc_count = sum(len(values) for values in result.get("iocs", {}).values())
    t.add_row("Findings", str(len(result["findings"])))
    t.add_row("IOCs", str(ioc_count))
    console.print(Panel(t, title="[bold]Capture Summary[/]", border_style="dim cyan"))
    show_findings(result["findings"])
    if result.get("packets_truncated"):
        warn("Packet limit reached; result is partial.")


# ═════════════════════════════════════════════════════════════
# AUDIT
# ═════════════════════════════════════════════════════════════

@cli.group()
def audit():
    """Static source code audit."""


@audit.command("file")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--lang",  "-l", default="auto",
              type=click.Choice(["auto","c","cpp","python","java","go","rust"]))
@click.option("--focus", "-f", default="all",
              type=click.Choice(["all","memory","crypto","race","kernel","proto"]))
@click.option("--depth", "-d", default="deep",
              type=click.Choice(["quick","deep","full"]))
@click.option("--report", "-r", is_flag=True)
@click.pass_context
def audit_file(ctx, source_path, lang, focus, depth, report):
    """Audit a source file for vulnerabilities."""
    section("CODE AUDIT")
    info(f"Target : {source_path}  |  Focus: {focus}  |  Depth: {depth}")
    console.print()
    with open(source_path) as f:
        code = f.read()

    with spinner("Static pattern analysis") as p:
        p.add_task("", total=None)
        static = StaticAnalyzer(lang=lang).analyze(code, focus=focus)

    with spinner("AI deep analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].audit_code(code, lang=lang, focus=focus, depth=depth)

    all_f = static + (ai_res if isinstance(ai_res, list) else [])
    show_findings(all_f)
    if report:
        path = ReportGenerator().generate(
            {"type":"audit","source":source_path,"findings":all_f})
        ok(f"Report → {path}")


@audit.command("dir")
@click.argument("directory", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, default=True)
@click.option("--lang", "-l", default="auto")
@click.option("--report", is_flag=True)
@click.pass_context
def audit_dir(ctx, directory, recursive, lang, report):
    """Recursive directory audit."""
    section("DIRECTORY AUDIT")
    exts  = [".c",".h",".cpp",".py",".java",".go",".rs"]
    base  = Path(directory)
    files = []
    for ext in exts:
        files.extend(base.rglob(f"*{ext}") if recursive else base.glob(f"*{ext}"))
    info(f"Found {len(files)} files")
    console.print()

    analyzer = StaticAnalyzer(lang=lang)
    all_f    = []
    with Progress(SpinnerColumn(spinner_name="dots", style="cyan"),
                  TextColumn("[cyan]{task.description}"),
                  BarColumn(bar_width=30, style="dim cyan", complete_style="cyan"),
                  TextColumn("[dim]{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task("Auditing", total=len(files))
        for f in files:
            prog.update(task, description=f"[cyan]{f.name[:28]}")
            try:
                code = f.read_text(errors="ignore")
                res  = analyzer.analyze(code)
                for fi in res: fi["file"] = str(f)
                all_f.extend(res)
            except Exception:
                pass
            prog.advance(task)
    console.print()
    show_findings(all_f)
    if report:
        path = ReportGenerator().generate(
            {"type":"audit_dir","directory":directory,"findings":all_f})
        ok(f"Report → {path}")


# ═════════════════════════════════════════════════════════════
# ADVANCED
# ═════════════════════════════════════════════════════════════

@cli.group()
def advanced():
    """Advanced vulnerability analysis modules."""


@advanced.command("heap")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--allocator", default="glibc",
              type=click.Choice(["glibc","jemalloc","tcmalloc"]))
@click.pass_context
def adv_heap(ctx, source_path, allocator):
    """Heap exploitation primitives analysis."""
    section("HEAP ANALYSIS")
    info(f"Target: {source_path}  |  Allocator: {allocator}")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Analyzing heap patterns") as p:
        p.add_task("", total=None)
        findings = HeapAnalyzer(allocator=allocator).analyze(code)
    with spinner("AI identifying exploitation primitives") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].heap_exploitation_analysis(code, allocator=allocator)
    show_findings(findings)
    hpanel(ai_res, "Exploitation Primitives", "high")


@advanced.command("crypto")
@click.argument("source_path", type=click.Path(exists=True))
@click.pass_context
def adv_crypto(ctx, source_path):
    """Deep cryptographic vulnerability audit."""
    section("CRYPTO AUDIT")
    info(f"Target: {source_path}")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Scanning cryptographic patterns") as p:
        p.add_task("", total=None)
        findings = CryptoChecker().analyze(code)
    with spinner("AI deep crypto analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].crypto_analysis(code)
    show_findings(findings)
    if ai_res: hpanel(ai_res, "AI Crypto Analysis", "medium")


@advanced.command("kernel")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--type","ktype",
              type=click.Choice(["driver","module","syscall","auto"]), default="auto")
@click.pass_context
def adv_kernel(ctx, source_path, ktype):
    """Kernel vulnerability scanner."""
    section("KERNEL ANALYSIS")
    info(f"Target: {source_path}  |  Type: {ktype}")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Scanning kernel patterns") as p:
        p.add_task("", total=None)
        findings = KernelPatternScanner().analyze(code, ktype=ktype)
    with spinner("AI kernel analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].kernel_analysis(code, ktype=ktype)
    show_findings(findings)
    if ai_res: hpanel(ai_res, "Kernel Vuln Analysis", "critical")


@advanced.command("toctou")
@click.argument("source_path", type=click.Path(exists=True))
@click.pass_context
def adv_toctou(ctx, source_path):
    """TOCTOU race condition detection."""
    section("TOCTOU ANALYSIS")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Analyzing TOCTOU patterns") as p:
        p.add_task("", total=None)
        result = ctx.obj["ai"].toctou_analysis(code)
    hpanel(result, "TOCTOU Race Conditions", "high")


@advanced.command("proto")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--protocol", "-p",
              type=click.Choice(["auto","tls","ssh","smb","custom"]), default="auto")
@click.pass_context
def adv_proto(ctx, source_path, protocol):
    """Protocol state machine analysis."""
    section("PROTOCOL ANALYSIS")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner(f"Analyzing {protocol.upper()} implementation") as p:
        p.add_task("", total=None)
        result = ctx.obj["ai"].protocol_analysis(code, protocol=protocol)
    hpanel(result, f"Protocol Analysis ({protocol.upper()})", "medium")


# ═════════════════════════════════════════════════════════════
# APK
# ═════════════════════════════════════════════════════════════

@cli.group()
def apk():
    """Android APK security analysis."""


@apk.command("analyze")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--report", "-r", is_flag=True)
@click.pass_context
def apk_analyze(ctx, apk_path, report):
    """Full APK security analysis (manifest + bytecode + strings)."""
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
    t.add_row("Total files",   str(summary["total_files"]))
    t.add_row("DEX files",     str(len(summary["dex_files"])))
    t.add_row("Native libs",   str(len(summary["native_libs"])))
    t.add_row("Has manifest",  "✓" if summary["has_manifest"] else "✗")
    console.print(Panel(t, title="[bold]APK Contents[/]",
                        border_style="dim cyan", padding=(0,1)))
    console.print()

    # Components
    components = analyzer.get_components()
    if any(components.values()):
        section("COMPONENTS")
        for ctype, items in components.items():
            if items:
                ct = Table(box=box.SIMPLE_HEAVY, title=f"[bold]{ctype.title()}[/]")
                ct.add_column("Name",     style="white")
                ct.add_column("Exported", width=10)
                for item in items:
                    exp = "[red]YES[/]" if item.get("exported") else "[dim]no[/]"
                    ct.add_row(item["name"], exp)
                console.print(ct)

    # Findings
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
        ai_res = ctx.obj["ai"].apk_analysis(
            manifest  = analyzer.manifest,
            smali     = "\n".join([s["content"][:500] for s in analyzer.smali[:5]]),
            strings   = [s["value"] for s in analyzer.strings[:100]],
        )
    hpanel(ai_res, "AI APK Analysis", "high")

    if report:
        path = ReportGenerator().generate(
            {"type":"apk","target":apk_path,"findings":all_f})
        ok(f"Report → {path}")


@apk.command("manifest")
@click.argument("manifest_path", type=click.Path(exists=True))
@click.pass_context
def apk_manifest(ctx, manifest_path):
    """Analyze a decoded AndroidManifest.xml."""
    section("MANIFEST ANALYSIS")
    with open(manifest_path, errors="ignore") as f:
        manifest = f.read()
    analyzer          = APKAnalyzer.__new__(APKAnalyzer)
    analyzer.manifest = manifest
    analyzer.smali    = []
    analyzer.strings  = []
    findings          = analyzer.analyze_manifest()
    show_findings(findings)


@apk.command("permissions")
@click.argument("apk_path", type=click.Path(exists=True))
@click.pass_context
def apk_permissions(ctx, apk_path):
    """List all permissions with risk assessment."""
    section("PERMISSION ANALYSIS")
    analyzer = APKAnalyzer(apk_path)
    analyzer.load()
    if not analyzer.manifest:
        warn("Could not read manifest.")
        return

    import re
    from modules.apk.apk_analyzer import DANGEROUS_PERMISSIONS
    t = Table(box=box.SIMPLE_HEAVY, title="Permissions")
    t.add_column("Severity", width=10)
    t.add_column("Permission")
    t.add_column("Description")

    found = re.findall(
        r'android:name\s*=\s*"(android\.permission\.[^"]+)"',
        analyzer.manifest)
    for perm in found:
        if perm in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[perm]
            style, _  = SEV_STYLE.get(sev, ("white",""))
            t.add_row(f"[{style}]{sev}[/{style}]", perm, desc)
        else:
            t.add_row("[dim]INFO[/]", perm, "")
    console.print(t)


# ═════════════════════════════════════════════════════════════
# FIRMWARE
# ═════════════════════════════════════════════════════════════

@cli.group()
def firmware():
    """Firmware image analysis and extraction."""


@firmware.command("analyze")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--report", "-r", is_flag=True)
@click.pass_context
def fw_analyze(ctx, firmware_path, report):
    """Full firmware security analysis."""
    section("FIRMWARE ANALYSIS")
    info(f"Target: {firmware_path}")
    console.print()

    fw = FirmwareAnalyzer(firmware_path)
    with spinner("Loading firmware image") as p:
        p.add_task("", total=None)
        fw.load()

    # Identify
    with spinner("Identifying components & architecture") as p:
        p.add_task("", total=None)
        id_info = fw.identify()

    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=20)
    t.add_column(style="bold white")
    t.add_row("Size",       id_info.get("size_human","?"))
    t.add_row("Components", str(len(id_info.get("components",[]))))
    t.add_row("Arch hints", str(len(id_info.get("arch_hints",[]))))
    console.print(Panel(t, title="[bold]Firmware Info[/]",
                        border_style="dim cyan", padding=(0,1)))

    if id_info.get("components"):
        ct = Table(box=box.SIMPLE_HEAVY, title="Identified Components")
        ct.add_column("Offset", style="cyan", width=14)
        ct.add_column("Type",   style="bold white")
        for comp in id_info["components"]:
            ct.add_row(comp["hex"], comp["type"])
        console.print(ct)

    if id_info.get("arch_hints"):
        for hint in id_info["arch_hints"]:
            info(hint)

    # Entropy
    section("ENTROPY MAP")
    with spinner("Computing entropy map") as p:
        p.add_task("", total=None)
        high_e = fw.high_entropy_regions()

    if high_e:
        et = Table(box=box.SIMPLE_HEAVY)
        et.add_column("Offset",  style="cyan",  width=14)
        et.add_column("Size",    style="dim",    width=10)
        et.add_column("Entropy", style="yellow", width=10)
        et.add_column("Type",    style="bold white")
        for r in high_e[:20]:
            et.add_row(r["hex"], f"{r['size']}B",
                       f"{r['entropy']:.3f}", r["type"])
        console.print(et)
        info(f"Total high-entropy regions: {len(high_e)}")
    else:
        ok("No high-entropy regions found (no obvious encryption)")

    # Strings & vulns
    section("VULNERABILITY SCAN")
    with spinner("Extracting strings") as p:
        p.add_task("", total=None)
        fw.extract_strings()

    with spinner("Scanning for vulnerabilities") as p:
        p.add_task("", total=None)
        findings = fw.scan_vulns()

    show_findings(findings)

    # Interesting paths
    paths = fw.find_interesting_paths()
    if paths:
        section("INTERESTING PATHS")
        pt = Table(box=box.SIMPLE_HEAVY)
        pt.add_column("Offset", style="cyan", width=12)
        pt.add_column("Path",   style="bold white")
        pt.add_column("Match",  style="yellow")
        for p_entry in paths[:30]:
            pt.add_row(p_entry["offset"], p_entry["path"][:60], p_entry["match"])
        console.print(pt)

    # AI analysis
    section("AI ANALYSIS")
    with spinner("AI firmware deep analysis") as p:
        p.add_task("", total=None)
        fw.get_summary()
        ai_res   = ctx.obj["ai"].firmware_analysis(
            file_list   = [c["type"] for c in id_info.get("components",[])],
            strings     = [s["value"] for s in (fw.strings or [])[:100]],
            entropy_map = {"high_entropy_regions": len(high_e)},
            context     = f"File: {firmware_path}",
        )
    hpanel(ai_res, "AI Firmware Analysis", "high")

    if report:
        path = ReportGenerator().generate(
            {"type":"firmware","target":firmware_path,"findings":findings})
        ok(f"Report → {path}")


@firmware.command("extract")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="./fw_extracted")
@click.pass_context
def fw_extract(ctx, firmware_path, output):
    """Extract filesystem from firmware image (requires binwalk)."""
    section("FIRMWARE EXTRACTION")
    info(f"Target    : {firmware_path}")
    info(f"Output dir: {output}")
    fw     = FirmwareAnalyzer(firmware_path)
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
@click.option("--category", "-c",
              type=click.Choice(["all","credential","url","path","debug","ip_addr","cve_ref"]),
              default="all")
@click.pass_context
def fw_strings(ctx, firmware_path, min_len, category):
    """Extract and categorize strings from firmware."""
    section("FIRMWARE STRINGS")
    fw = FirmwareAnalyzer(firmware_path)
    fw.load()
    with spinner("Extracting strings") as p:
        p.add_task("", total=None)
        strings = fw.extract_strings(min_len=min_len)

    if category != "all":
        strings = [s for s in strings if s.get("category") == category]

    COLORS = {"credential":"red","url":"cyan","path":"yellow",
              "debug":"orange3","ip_addr":"red","cve_ref":"red","log":"dim","":"dim white"}
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Offset",   style="dim cyan", width=12)
    t.add_column("Category", width=12)
    t.add_column("String")
    for s in strings[:200]:
        cat   = s.get("category","")
        color = COLORS.get(cat, "white")
        t.add_row(s["hex"], f"[{color}]{cat or '—'}[/{color}]",
                  f"[{color}]{s['value'][:80]}[/{color}]")
    console.print(t)
    info(f"Total: {len(strings)} strings")


@firmware.command("entropy")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--block-size", default=4096)
@click.pass_context
def fw_entropy(ctx, firmware_path, block_size):
    """Compute entropy map to find encrypted/compressed regions."""
    section("ENTROPY MAP")
    info(f"Target: {firmware_path}  |  Block: {block_size}B")
    fw = FirmwareAnalyzer(firmware_path)
    fw.load()
    with spinner("Computing entropy") as p:
        p.add_task("", total=None)
        regions = fw.entropy_map(block_size=block_size)

    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Offset",  style="cyan",   width=14)
    t.add_column("Entropy", style="yellow", width=10)
    t.add_column("Type",    style="bold white")
    t.add_column("Visual")
    for r in regions:
        e   = r["entropy"]
        bar = "█" * int(e) + "░" * (8 - int(e))
        color = "red" if e >= 7.5 else "yellow" if e >= 6.5 else "green"
        t.add_row(r["hex"], f"{e:.3f}", r["type"],
                  f"[{color}]{bar}[/{color}]")
    console.print(t)


# ═════════════════════════════════════════════════════════════
# RESEARCH
# ═════════════════════════════════════════════════════════════

@cli.group()
def research():
    """0day research, CVE matching, hypothesis engine."""


@research.command("hypothesis")
@click.argument("target", type=click.Path(exists=True))
@click.option("--context", "-c", default=None)
@click.option("--depth", type=click.Choice(["quick","deep"]), default="deep")
@click.pass_context
def res_hypothesis(ctx, target, context, depth):
    """AI 0day hypothesis engine — attack surface modeling."""
    section("0DAY HYPOTHESIS ENGINE")
    info(f"Target  : {target}  |  Context: {context or 'auto'}")
    console.print()
    with open(target, errors="ignore") as f: content = f.read()

    engine  = HypothesisEngine()
    surface = engine.build_attack_surface(content)

    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=22)
    t.add_column(style="bold white")
    t.add_row("Entry points",    str(len(surface["entry_points"])))
    t.add_row("Dangerous sinks", str(len(surface["dangerous_sinks"])))
    console.print(Panel(t, title="[bold]Attack Surface[/]",
                        border_style="dim cyan", padding=(0,1)))

    if surface["entry_points"]:
        et = Table(box=box.SIMPLE_HEAVY, title="Entry Points")
        et.add_column("Line", style="cyan",  width=6)
        et.add_column("Type", style="white", width=20)
        et.add_column("Code", style="dim")
        for e in surface["entry_points"][:10]:
            et.add_row(str(e["line"]), e["type"], e["code"][:60])
        console.print(et)
    console.print()

    with spinner("AI formulating 0day hypotheses") as p:
        p.add_task("", total=None)
        hypotheses = ctx.obj["ai"].generate_hypotheses(
            content, context=context, depth=depth)
    hpanel(hypotheses, "0day Hypotheses", "critical")
    ctx.obj["session"].save("hypothesis", target, hypotheses)


@research.command("cve-match")
@click.argument("target", type=click.Path(exists=True))
@click.option("--limit", default=10)
@click.pass_context
def res_cve(ctx, target, limit):
    """Match code patterns against known CVEs (works offline)."""
    section("CVE PATTERN MATCHING")
    info(f"Target: {target}")
    with open(target, errors="ignore") as f: content = f.read()

    matcher = CVEMatcher()
    with spinner("Matching vulnerability patterns") as p:
        p.add_task("", total=None)
        matches = matcher.extract_patterns(content)

    if matches:
        t = Table(box=box.SIMPLE_HEAVY)
        t.add_column("Line",      style="dim cyan", width=6)
        t.add_column("CVE Class", style="bold white")
        t.add_column("CWE",       style="dim",      width=10)
        t.add_column("Example CVEs")
        for m in matches[:15]:
            t.add_row(str(m.get("line","")), m.get("finding_class",""),
                      m.get("cwe",""),
                      ", ".join(m.get("reference_cves",[])[:1]))
        console.print(t)

    with spinner("AI CVE analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].cve_match(content, patterns=matches, limit=limit)
    hpanel(ai_res, "CVE Analysis", "high")


@research.command("variant")
@click.argument("cve_id")
@click.argument("target_dir", type=click.Path(exists=True))
@click.pass_context
def res_variant(ctx, cve_id, target_dir):
    """Find variants of a known CVE in a codebase."""
    section(f"VARIANT FINDER — {cve_id}")
    finder = VariantFinder()
    with spinner(f"Fetching {cve_id} from NVD") as p:
        p.add_task("", total=None)
        cve_info = finder.fetch_cve(cve_id)

    info(f"CVSS : {cve_info.get('cvss','N/A')}")
    info(f"Desc : {cve_info.get('description','N/A')[:80]}")
    console.print()

    files = (list(Path(target_dir).rglob("*.c")) +
             list(Path(target_dir).rglob("*.cpp")) +
             list(Path(target_dir).rglob("*.py")))[:50]
    info(f"Scanning {len(files)} files...")

    results = []
    with Progress(SpinnerColumn(spinner_name="dots", style="cyan"),
                  TextColumn("[cyan]{task.description}"),
                  BarColumn(bar_width=30, style="dim cyan", complete_style="cyan"),
                  console=console) as prog:
        task = prog.add_task("Scanning", total=len(files))
        for f in files:
            prog.update(task, description=f"[cyan]{f.name[:28]}")
            try:
                code  = f.read_text(errors="ignore")
                match = finder.find_in_code(code, cve_info)
                if match:
                    results.append({"file": str(f), "match": match})
            except Exception:
                pass
            prog.advance(task)

    console.print()
    if results:
        for r in results:
            hpanel(f"[bold]File:[/] {r['file']}\n\n{r['match']}",
                   f"Potential Variant of {cve_id}", "critical")
    else:
        ok(f"No obvious variants of {cve_id} found.")


@research.command("patch-diff")
@click.argument("binary_before", type=click.Path(exists=True))
@click.argument("binary_after",  type=click.Path(exists=True))
@click.pass_context
def res_patch_diff(ctx, binary_before, binary_after):
    """Reverse-engineer a security patch by diffing two binary versions."""
    section("PATCH DIFF ANALYSIS")
    info(f"Before : {binary_before}")
    info(f"After  : {binary_after}")

    with spinner("Extracting function lists") as p:
        p.add_task("", total=None)
        f_before = set(BinaryParser(binary_before).get_function_list())
        f_after  = set(BinaryParser(binary_after).get_function_list())

    added   = sorted(f_after  - f_before)
    removed = sorted(f_before - f_after)

    t = Table(box=box.SIMPLE_HEAVY, title="Function Diff")
    t.add_column("Status",   width=12)
    t.add_column("Function", style="white")
    for f in added:   t.add_row("[green]+ ADDED[/]",   f)
    for f in removed: t.add_row("[red]- REMOVED[/]", f)
    console.print(t)
    info(f"{len(f_before & f_after)} functions unchanged")

    with spinner("AI patch security analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].patch_diff_analysis(
            added, removed, binary_before, binary_after)
    hpanel(ai_res, "Patch Security Analysis", "high")


@research.command("fuzz-hints")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--function", "-f", default=None)
@click.option("--format", "fmt",
              type=click.Choice(["afl","libfuzzer","manual"]), default="manual")
@click.pass_context
def res_fuzz(ctx, source_path, function, fmt):
    """AI-guided fuzzing strategy and test case generation."""
    section("AI FUZZING HINTS")
    info(f"Target: {source_path}  |  Format: {fmt}")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Generating fuzzing strategy") as p:
        p.add_task("", total=None)
        result = ctx.obj["ai"].fuzz_hints(code, function=function, fmt=fmt)
    hpanel(result, "Fuzzing Strategy & Test Cases", "medium")
    ctx.obj["session"].save("fuzz_hints", source_path, result)


# ═════════════════════════════════════════════════════════════
# SESSION
# ═════════════════════════════════════════════════════════════

@cli.command("session")
@click.option("--list",  "list_s",  is_flag=True)
@click.option("--clear", is_flag=True)
@click.option("--show",  default=None)
@click.pass_context
def session_cmd(ctx, list_s, clear, show):
    """Manage analysis sessions and history."""
    sm = ctx.obj["session"]
    if list_s:
        section("SESSIONS")
        sessions = sm.list_sessions()
        if not sessions:
            info("No sessions recorded yet.")
            return
        t = Table(box=box.SIMPLE_HEAVY)
        t.add_column("ID",     style="cyan",  width=10)
        t.add_column("Type",   style="white", width=16)
        t.add_column("Target", style="dim",   width=32)
        t.add_column("Time",   style="dim cyan")
        for s in sessions:
            t.add_row(s["id"],s["type"],s["target"][:32],s["time"])
        console.print(t)
    elif clear:
        sm.clear(); ok("All sessions cleared.")
    elif show:
        data = sm.get(show)
        if data: hpanel(data["output"][:3000], f"Session {show}", "info")
        else:    warn(f"Session {show} not found.")


# ═════════════════════════════════════════════════════════════
# PLUGINS / ORCHESTRATION
# ═════════════════════════════════════════════════════════════

@cli.group("plugins")
def plugins_group():
    """List and run local tool adapters without installing anything."""


@plugins_group.command("list")
def plugins_list():
    """Show registered plugins and whether their executable is available."""
    registry = default_registry()
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Plugin", style="cyan")
    table.add_column("Executable", style="white")
    table.add_column("Available", style="green")
    table.add_column("Capabilities", style="dim")
    for item in registry.list():
        table.add_row(item["name"], item["executable"], "yes" if item["available"] else "no", ", ".join(item["capabilities"]))
    console.print(table)


@plugins_group.command("run")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--plugin", "plugin_names", multiple=True, help="Plugin name; repeat for several plugins.")
@click.option("--timeout", default=60, show_default=True)
@click.option("--output", default="./r3con-runs")
def plugins_run(target, plugin_names, timeout, output):
    """Run selected local adapters and save a reproducible JSON run."""
    registry = default_registry()
    names = list(plugin_names) or ["file", "strings"]
    unknown = [name for name in names if name not in {item["name"] for item in registry.list()}]
    if unknown:
        raise click.ClickException("Unknown plugin(s): " + ", ".join(unknown))
    result = registry.run(names, target, timeout=timeout)
    path = save_run(result, output)
    console.print(json.dumps(result, indent=2, ensure_ascii=False))
    ok(f"Run saved → {path}")


# ═════════════════════════════════════════════════════════════
# INTERACTIVE
# ═════════════════════════════════════════════════════════════

_CONSOLE_COMMANDS = [
    "help", "set", "show", "analyze", "r2", "gdb", "disasm", "dynamic",
    "audit", "advanced", "apk", "firmware", "research", "network", "tools", "plugins",
    "history", "sessions", "theme", "clear", "exit", "quit",
]


def _setup_readline():
    """Configure native terminal editing without leaking escape sequences."""
    try:
        import readline
        import glob
        history_file = Path(os.environ.get("R3CON_HISTORY", str(Path.home() / ".r3con_history")))
        try:
            readline.read_history_file(str(history_file))
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)
        readline.parse_and_bind("tab: complete")

        def complete(text, state):
            line = readline.get_line_buffer()
            before = line[:readline.get_endidx()]
            if not before.strip() or (len(before.split()) <= 1 and not before.endswith(" ")):
                matches = [c for c in _CONSOLE_COMMANDS if c.startswith(text)]
            else:
                expanded = os.path.expanduser(text)
                pattern = expanded + "*"
                matches = glob.glob(pattern)
                if text.startswith("~"):
                    matches = [m.replace(str(Path.home()), "~", 1) for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer(complete)
        return readline, history_file
    except (ImportError, OSError):
        return None, None


def _save_readline(readline, history_file):
    if readline is not None and history_file is not None:
        try:
            readline.write_history_file(str(history_file))
        except OSError:
            pass


@cli.command("interactive")
@click.pass_context
def interactive_mode(ctx):
    """Persistent Metasploit-style r3con command console."""
    import shlex
    readline, history_file = _setup_readline()
    ai_engine = ctx.obj["ai"]
    session = ctx.obj["session"]
    chat_history = []
    print_banner(boot=True)
    console.print(Panel(
        "Type [cyan]help[/] for commands. Execute [cyan]r2[/], [cyan]gdb[/], "
        "[cyan]analyze[/] and [cyan]dynamic[/] without restarting r3con.",
        title="[bold cyan] r3con console [/bold cyan]", border_style="cyan"))
    history = []
    state = {"target": None}

    while True:
        try:
            prompt = "r3con" + (f"({Path(state['target']).name})" if state["target"] else "") + "> "
            user_input = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [dim]Goodbye.[/]")
            _save_readline(readline, history_file)
            break
        if not user_input:
            continue
        history.append(user_input)
        lowered = user_input.lower()
        if lowered in ("exit", "quit", "q"):
            console.print("  [dim]Goodbye.[/]")
            _save_readline(readline, history_file)
            break
        if lowered in ("help", "?"):
            _help(); continue
        if lowered == "theme" or lowered.startswith("theme "):
            parts = user_input.split(maxsplit=1)
            requested = parts[1].strip() if len(parts) > 1 else None
            if requested:
                if requested.lower() not in THEME_PRESETS:
                    warn("Unknown theme. Available: matrix, cyber, amber, mono")
                else:
                    apply_theme(requested)
                    ok(f"Theme changed to {THEME_NAME}")
            else:
                info(f"Active theme: {THEME_NAME} | Available: matrix, cyber, amber, mono")
            continue
        if lowered == "clear":
            chat_history = []
            console.clear(); print_banner(boot=False); continue
        if lowered == "history":
            for n, item in enumerate(history[-20:], 1):
                console.print(f"  [dim]{n:>2}[/]  {item}")
            continue
        if lowered == "sessions":
            for s in ctx.obj["session"].list_sessions()[:10]:
                console.print(f"  [cyan]{s['id']}[/]  {s['type']:<16} {s['time']}  [dim]{s['target'][:36]}[/]")
            continue
        if lowered.startswith("set target "):
            state["target"] = user_input[11:].strip()
            ok(f"Target set to {state['target']}")
            continue
        if lowered in ("show options", "options"):
            console.print(f"  [cyan]TARGET[/]  {state['target'] or '(not set)'}")
            console.print("  [cyan]ENGINE[/]  radare2 by default; Ghidra with --with-ghidra")
            continue
        try:
            args = shlex.split(user_input)
            command_names = {"analyze", "r2", "gdb", "disasm", "dynamic", "audit", "advanced", "apk", "firmware", "research", "network", "tools", "plugins", "session"}
            if not args:
                continue
            if args[0] not in command_names:
                chat_history.append({"role": "user", "content": user_input})
                with spinner("AI thinking") as progress:
                    progress.add_task("", total=None)
                    response = ai_engine.chat(chat_history)
                chat_history.append({"role": "assistant", "content": response})
                session.save("interactive", "chat", response)
                console.print(Panel(response, title="[bold cyan] AI [/bold cyan]", border_style="dim cyan", padding=(0, 2)))
                continue
            if args[0] in {"analyze", "r2", "gdb", "disasm", "dynamic"} and state["target"] and len(args) == 1:
                args.append(state["target"])
            cli.main(args=["--no-banner", *args], prog_name="r3con", obj=ctx.obj, standalone_mode=False)
        except SystemExit:
            # Direct r2/gdb sessions return here after the user types q/quit.
            continue
        except click.ClickException as exc:
            console.print(f"  [bold red]Error:[/] {exc}")
        except (click.UsageError, ValueError) as exc:
            console.print(f"  [bold yellow]Usage:[/] {exc}")


def _help():
    console.print()
    console.print(Panel(
        "  [bold cyan]DISASM[/]\n"
        "    [cyan]disasm file <bin>[/]            Disassemble binary (ELF/PE/MachO)\n"
        "    [cyan]disasm strings <bin> --ai[/]    Extract & analyze strings\n"
        "    [cyan]disasm imports <bin> --vuln-check[/]  Flag dangerous imports\n\n"
        "  [bold cyan]AUDIT[/]\n"
        "    [cyan]audit file <src> --depth full[/]  Source code audit\n"
        "    [cyan]audit dir <dir> --report[/]        Recursive audit\n\n"
        "  [bold cyan]ADVANCED[/]\n"
        "    [cyan]advanced heap <file>[/]           Heap exploitation analysis\n"
        "    [cyan]advanced crypto <file>[/]         Cryptographic audit\n"
        "    [cyan]advanced kernel <file>[/]         Kernel vulnerability scan\n"
        "    [cyan]advanced toctou <file>[/]         TOCTOU race detection\n"
        "    [cyan]advanced proto <file>[/]          Protocol analysis\n\n"
        "  [bold cyan]APK[/]\n"
        "    [cyan]apk analyze <apk>[/]             Full Android APK analysis\n"
        "    [cyan]apk manifest <xml>[/]            Analyze decoded manifest\n"
        "    [cyan]apk permissions <apk>[/]         Permission risk assessment\n\n"
        "  [bold cyan]FIRMWARE[/]\n"
        "    [cyan]firmware analyze <img>[/]         Full firmware analysis\n"
        "    [cyan]firmware extract <img>[/]         Extract filesystem\n"
        "    [cyan]firmware strings <img>[/]         String extraction\n"
        "    [cyan]firmware entropy <img>[/]         Entropy map\n\n"
        "  [bold cyan]RESEARCH[/]\n"
        "    [cyan]research hypothesis <file>[/]    0day hypothesis engine\n"
        "    [cyan]research cve-match <file>[/]     CVE pattern matching\n"
        "    [cyan]research variant <CVE> <dir>[/]  CVE variant search\n"
        "    [cyan]research patch-diff <v1> <v2>[/] Reverse security patch\n"
        "    [cyan]research fuzz-hints <file>[/]    AI fuzzing strategy\n\n"
        "  [bold cyan]CONSOLE[/]\n"
        "    [cyan]theme [matrix|cyber|amber|mono][/]  Change terminal palette\n"
        "    [cyan]set target <file>[/]  Set the current target\n"
        "    [cyan]show options[/]       Show current context\n"
        "    [cyan]history[/]            Show command history\n"
        "    [cyan]r2 <file>[/]          Open radare2 directly\n"
        "    [cyan]gdb <file>[/]         Open GDB/pwndbg directly\n\n"
        "  [bold cyan]DYNAMIC[/]\n"
        "    [cyan]dynamic status <file>[/]   GDB/framework status\n"
        "    [cyan]dynamic function <file> <fn>[/]  Analyze function\n"
        "    [cyan]dynamic crash <file>[/]    Local crash check\n"
        "    [cyan]dynamic heap|rop|core|watchpoint[/]  Dynamic helpers\n\n"
        "  [bold cyan]UTILS[/]\n"
        "    [cyan]sessions[/]         Show saved sessions\n"
        "    [cyan]clear[/]            Clear screen\n"
        "    [cyan]exit[/]             Quit console\n\n"
        "  [dim]Commands are executed locally; use only authorized targets.[/]",
        title="[bold] r3con Commands [/]", border_style="dim cyan", padding=(0,2)
    ))
    console.print()


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
