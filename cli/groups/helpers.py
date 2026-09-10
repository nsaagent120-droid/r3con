"""Shared UI helpers, theme, console - extracted from monolith for reusability."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box
from rich.theme import Theme

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.ai_engine import AIEngine

try:
    from core.__version__ import __version__ as VERSION
except ImportError:
    VERSION = "7.3.0"

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

BANNER = """\
 ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗ ██║
 ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝\
 """

SEV_STYLE = {
    "CRITICAL": ("bold red", "██"),
    "HIGH": ("red", "▓▓"),
    "MED": ("yellow", "░░"),
    "MEDIUM": ("yellow", "░░"),
    "LOW": ("green", "--"),
    "INFO": ("cyan", "··"),
}
SEV_ORDER = ["CRITICAL", "HIGH", "MED", "MEDIUM", "LOW", "INFO"]

def _animations_enabled() -> bool:
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
    borders = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "info": "info", "success": "success"}
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
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    parts = []
    for sev in SEV_ORDER:
        if sev in counts:
            style, _ = SEV_STYLE.get(sev, ("white", "  "))
            parts.append(f"[{style}]{counts[sev]} {sev}[/{style}]")
    console.print(f"  [muted]Findings:[/muted] {' · '.join(parts)}")
    console.print()
    sorted_f = sorted(findings,
                      key=lambda x: SEV_ORDER.index(x.get("severity", "INFO"))
                      if x.get("severity", "INFO") in SEV_ORDER else 99)
    for f in sorted_f:
        sev = f.get("severity", "INFO")
        style, icon = SEV_STYLE.get(sev, ("white", "  "))
        loc = ""
        if f.get("file"):
            loc += f"[dim]{Path(f['file']).name}[/] "
        if f.get("line"):
            loc += f"[dim cyan]L{f['line']}[/]"
        if f.get("offset"):
            loc += f"[dim cyan]@{f['offset']}[/]"
        console.print(f"  [{style}][{sev}][/{style}] [{style}]{icon}[/{style}]"
                      f"  [bold]{f.get('type', f.get('finding_type', ''))}[/bold]  {loc}")
        console.print(f"       [muted]{f.get('description', '')[:110]}[/muted]")
        if f.get("recommendation"):
            console.print(f"       [success]↳  {f['recommendation'][:100]}[/success]")
        console.print()
