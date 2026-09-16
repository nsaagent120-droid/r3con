#!/usr/bin/env python3
"""
r3con v7.x Titan-Omega - Modular CLI PRO
Lean main.py that imports groups - efficace, utile, puissant

Structure v6.0 (clean):
  cli/groups/
    disasm.py      -> binary disassembly
    audit.py       -> source audit
    advanced.py    -> heap/crypto/kernel/toctou/proto
    apk.py         -> APK analysis
    firmware.py    -> firmware
    research.py    -> 0day/CVE/variant/patch-diff/fuzz
    network.py     -> passive network
    tools.py       -> external tools 35+
    dynamic.py     -> GDB/pwndbg dynamic
    analyze.py      -> analyze / analyze-pro / federated workspaces auto
    config.py      -> PRO config 300+ opts
    workspace.py   -> workspaces fédérés cloisonnés + liens + partage
    fuzzing.py      -> fuzzing lab AFL++/honggfuzz/Radamsa + triage
    agent.py       -> agent autonome OODA
    exploit.py      -> ROP + templates
    interactive.py  -> r2/gdb/session/plugins/interactive

Core analysis, reporting, cache and runtime groups are imported below to keep
command registration explicit and backwards compatible.
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

from cli.groups.helpers import (
    console, print_banner, apply_theme, THEME_PRESETS,
    VERSION, BANNER, SEV_STYLE, SEV_ORDER,
    _make_theme, _no_color
)
from cli.groups.helpers import THEME_PRESETS as THEME_PRESETS
from modules.disasm.binary_parser import BinaryParser
from core.ai_engine import AIEngine
from core.session import SessionManager

from cli.groups.disasm import disasm
from cli.groups.audit import audit
from cli.groups.advanced import advanced
from cli.groups.apk import apk
from cli.groups.firmware import firmware
from cli.groups.research import research
from cli.groups.network import network
from cli.groups.tools import tools
from cli.groups.dynamic import dynamic_group
from cli.groups.malware import malware
from cli.groups.web import web
from cli.groups.cloud import cloud, container
from cli.groups.ai import ai
from cli.groups.decompile import decompile, secrets
from cli.groups.report import report
from cli.groups.dashboard import dashboard, ml
from cli.groups.analyze import analyze_command, analyze_pro_command, benchmark_command, correlate_command, diff_command
from cli.groups.config import config
from cli.groups.workspace import workspace as workspace_group
from cli.groups.fuzzing import fuzzing as fuzzing_group
from cli.groups.agent import agent as agent_group
from cli.groups.exploit import exploit as exploit_group
from cli.groups.supply import supply_chain_group
from cli.groups.power import scan_command, doctor_command, reports_group, compare_command, explain_command, summarize_command, ask_command
from cli.groups.interactive import r2_command, gdb_command, session_cmd, plugins_group, interactive_mode
from cli.groups.runtime import runtime_group
from cli.groups.cache import cache_group


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


for command in (
    disasm, audit, advanced, apk, firmware, research, network, malware, web,
    cloud, container, ai, decompile, secrets, report, dashboard, ml, tools,
    dynamic_group, config, plugins_group, workspace_group, fuzzing_group,
    agent_group, exploit_group, scan_command, supply_chain_group,
    reports_group, compare_command, explain_command, summarize_command,
    ask_command, analyze_command, analyze_pro_command, benchmark_command,
    correlate_command, diff_command, r2_command, gdb_command, session_cmd,
    interactive_mode, runtime_group, cache_group,
):
    cli.add_command(command)

# Compatibility alias used by existing scripts.
cli.add_command(doctor_command, name="tools-doctor")
tools.add_command(doctor_command)


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
