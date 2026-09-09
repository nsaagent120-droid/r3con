#!/usr/bin/env python3
"""
r3con v5.1.1 PRO - Modular CLI
Lean main.py that imports groups - efficace et utile
Structure:
  cli/groups/helpers.py      -> UI shared (banner, theme, console, spinner...)
  cli/groups/disasm.py       -> binary disassembly
  cli/groups/audit.py        -> source audit
  cli/groups/advanced.py     -> heap/crypto/kernel/toctou/proto
  cli/groups/apk.py          -> APK analysis
  cli/groups/firmware.py     -> firmware
  cli/groups/research.py     -> 0day/CVE/variant/patch-diff/fuzz
  cli/groups/network.py      -> passive network
  cli/groups/tools.py        -> external tools
  cli/groups/dynamic.py      -> GDB/pwndbg dynamic
  cli/groups/analyze.py      -> analyze / analyze-pro / benchmark / correlate / diff
  cli/groups/config.py       -> PRO config management
  cli/groups/interactive.py  -> r2/gdb/workspace/plugins/session/interactive

Efficacité:
  - Before: 1986L monolithe, tout chargé à chaque fois
  - After:  ~250L main + lazy groups, chargement modulaire
  - Unified orchestrator avec pipeline + cache
"""
from __future__ import annotations
import sys
import os
from pathlib import Path

_missing = []
try:
    import click
except ImportError:
    _missing.append("click")
try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    _missing.append("rich")

if _missing:
    print(f"[r3con] Missing dependencies: {', '.join(_missing)}")
    print(f"[r3con] Install with: pip install {' '.join(_missing)}")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent.parent))

# Import helpers (theme, console, banner)
from cli.groups.helpers import (
    console, print_banner, apply_theme, THEME_PRESETS,
    VERSION, BANNER, SEV_STYLE, SEV_ORDER,
    _make_theme, _no_color
)
# Re-export for backward compat tests
from cli.groups.helpers import THEME_PRESETS as THEME_PRESETS
from modules.disasm.binary_parser import BinaryParser

# Keep helpers accessible via cli.main for legacy tests
# (tests import cli.main and expect these symbols)


# Import AI/Session for context
from core.ai_engine import AIEngine
from core.session import SessionManager

# Import groups
from cli.groups.disasm import disasm
from cli.groups.audit import audit
from cli.groups.advanced import advanced
from cli.groups.apk import apk
from cli.groups.firmware import firmware
from cli.groups.research import research
from cli.groups.network import network
from cli.groups.tools import tools
from cli.groups.dynamic import dynamic_group
from cli.groups.analyze import (
    analyze_command, analyze_pro_command,
    benchmark_command, correlate_command, diff_command
)
from cli.groups.config import config
from cli.groups.interactive import (
    r2_command, workspace_command, gdb_command,
    session_cmd, plugins_group, interactive_mode
)

# ── CLI root ──────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version=VERSION)
@click.option("--no-banner", is_flag=True)
@click.option("--theme", type=click.Choice(["matrix", "cyber", "amber", "mono"]), default=None, help="Terminal color theme")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors for logs and CI")
@click.pass_context
def cli(ctx, no_banner, theme, no_color):
    """r3con — Binary · APK · Firmware · Kernel Security Research Tool (PRO modular)"""
    ctx.ensure_object(dict)
    if no_color:
        os.environ["R3CON_NO_COLOR"] = "1"
    if theme or no_color:
        apply_theme(theme)
    ctx.obj["ai"] = AIEngine()
    ctx.obj["session"] = SessionManager()
    if not no_banner and ctx.invoked_subcommand not in ("interactive", None):
        print_banner(boot=False)
    elif ctx.invoked_subcommand is None:
        print_banner(boot=False)
        console.print("  Run [cyan]r3con --help[/] to see all commands.\n"
                      "  Run [cyan]r3con interactive[/] for AI shell.\n"
                      "  [dim]PRO: r3con analyze-pro --profile full ./binary --chain[/]\n")

# ── Register groups (modular, efficace) ───────────────────────

# Core analysis groups
cli.add_command(disasm)
cli.add_command(audit)
cli.add_command(advanced)
cli.add_command(apk)
cli.add_command(firmware)
cli.add_command(research)
cli.add_command(network)
cli.add_command(tools)
cli.add_command(dynamic_group)
cli.add_command(config)
cli.add_command(plugins_group)

# Direct commands
cli.add_command(analyze_command)
cli.add_command(analyze_pro_command)
cli.add_command(benchmark_command)
cli.add_command(correlate_command)
cli.add_command(diff_command)

# Interactive / external
cli.add_command(r2_command)
cli.add_command(workspace_command)
cli.add_command(gdb_command)
cli.add_command(session_cmd)
cli.add_command(interactive_mode)

# ── Legacy compatibility: keep old command names ──────────────

def main():
    cli(obj={})

if __name__ == "__main__":
    main()
