"""Analyze commands - classic + PRO unified."""
from __future__ import annotations
import json
import time
import contextlib
import io
import subprocess
from pathlib import Path
import click
from .helpers import console, section, info, warn
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

@click.command("analyze")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", type=click.Choice(["auto", "quick", "binary", "network", "firmware", "apk", "dynamic", "full"]), default="auto", show_default=True)
@click.option("--timeout", default=120, show_default=True, type=click.IntRange(1, 3600))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--workers", default=3, show_default=True, type=click.IntRange(1, 8))
@click.option("--reverse-engine", type=click.Choice(["radare2", "rizin"]), default="radare2", show_default=True, help="Reverse engine")
@click.option("--with-ghidra", is_flag=True, default=None, help="Run Ghidra in addition to radare2 (opt-in)")
@click.option("--no-cache", is_flag=True, help="Do not read or write local cache")
@click.option("--cache-dir", type=click.Path(file_okay=False), help="Cache directory")
@click.option("--workspace", "workspace_mode", type=click.Choice(["never", "always", "auto"]), default="never", show_default=True, help="Open four-pane workspace")
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write unified JSON")
def analyze_command(target, profile, timeout, max_mb, workers, reverse_engine, with_ghidra, no_cache, cache_dir, workspace_mode, json_output):
    from modules.orchestration.orchestrator import Orchestrator
    result = Orchestrator(target, profile=profile, timeout=timeout, max_mb=max_mb, max_workers=workers, reverse_engine=reverse_engine, with_ghidra=with_ghidra, cache=not no_cache, cache_dir=cache_dir).run()
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
    if workspace_mode == "always" or (workspace_mode == "auto" and result.get("profile", profile) in {"binary", "dynamic", "firmware", "network"}):
        from .interactive import workspace_command
        workspace_command.callback(target, f"r3con-{result.get('profile', profile)}", False)

@click.command("analyze-pro")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", default="auto", type=click.Choice(["auto", "quick", "deep", "full", "binary", "firmware", "apk", "network", "bugbounty", "exploit", "stealth"]), help="Profil puissant")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True), help="Fichier config YAML")
@click.option("--timeout", default=None, type=int, help="Timeout override")
@click.option("--workers", default=None, type=int, help="Workers override")
@click.option("--max-mb", default=None, type=int, help="Max file size MB override")
@click.option("--with-ghidra", is_flag=True, help="Activer Ghidra (lourd)")
@click.option("--with-angr", is_flag=True, help="Activer angr symbolic")
@click.option("--with-jadx", is_flag=True, help="Activer JADX")
@click.option("--chain/--no-chain", default=True, help="Chaînage outils externes")
@click.option("--use-pipeline/--no-pipeline", default=True, help="Use pipeline efficace")
@click.option("--json-output", type=click.Path(dir_okay=False), help="Rapport JSON")
def analyze_pro_command(target, profile, config_path, timeout, workers, max_mb, with_ghidra, with_angr, with_jadx, chain, use_pipeline, json_output):
    try:
        from modules.orchestration.unified import UnifiedOrchestrator
        UNIFIED = True
    except ImportError:
        UNIFIED = False
        try:
            from modules.orchestration.enhanced_orchestrator import EnhancedOrchestrator
        except ImportError:
            from modules.orchestration.orchestrator import Orchestrator as EnhancedOrchestrator

    if not UNIFIED:
        console.print("[yellow]Unified orchestrator non disponible, fallback[/]")
        from modules.orchestration.orchestrator import Orchestrator
        result = Orchestrator(target, profile=profile, timeout=timeout or 120).run()
    else:
        overrides = {}
        if timeout: overrides["analysis.timeout"] = timeout
        if workers: overrides["analysis.max_workers"] = workers
        if max_mb: overrides["analysis.max_file_size_mb"] = max_mb
        if with_ghidra: overrides["external_tools.enabled.ghidra"] = True
        if with_angr: overrides["external_tools.enabled.angr"] = True
        if with_jadx: overrides["external_tools.enabled.jadx"] = True
        overrides["external_tools.chaining.enabled"] = chain
        result = UnifiedOrchestrator(target, profile=profile, config_path=config_path, use_pipeline=use_pipeline, **overrides).run()

    if json_output:
        Path(json_output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"Report written: {json_output}")

    section(f"R3CON PRO ORCHESTRATION - {profile.upper()}")
    target_info = result.get("target", {})
    if isinstance(target_info, dict):
        info(f"Target: {target_info.get('path', target)} | Kind: {target_info.get('kind')} | Confidence: {target_info.get('confidence')}")
    info(f"Profile: {result.get('profile', profile)} | Chain: {'enabled' if chain else 'disabled'} | Pipeline: {'yes' if use_pipeline else 'no'}")
    for name, value in result.get("results", {}).items():
        if isinstance(value, dict):
            status = value.get("status", "unknown")
            engine = value.get("engine", "")
            color = "green" if status == "ok" else "yellow" if status == "partial" else "red"
            console.print(f"[{color}][{status}][/{color}] {name:20} — {engine}")
    console.print(f"\n[bold]Findings:[/] {len(result.get('findings', []))} | [bold]Duration:[/] {result.get('duration_ms', 0)} ms | [bold]Status:[/] {result.get('status')}")
    tool_summary = result.get("tool_summary", {})
    if tool_summary:
        console.print(f"[dim]Tools: {tool_summary.get('present', 0)}/{tool_summary.get('total', 0)} available[/]")
    from .helpers import show_findings
    show_findings(result.get("findings", [])[:20])

@click.command("benchmark")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", type=click.Choice(["quick", "binary", "network", "firmware", "source", "apk", "full"]), default="quick", show_default=True)
@click.option("--runs", default=3, type=click.IntRange(1, 20), show_default=True)
@click.option("--no-cache", is_flag=True, help="Benchmark without cache")
def benchmark_command(target, profile, runs, no_cache):
    from modules.orchestration.orchestrator import Orchestrator
    durations = []
    for _ in range(runs):
        started = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = Orchestrator(target, profile=profile, cache=not no_cache).run()
        durations.append(round((time.perf_counter() - started) * 1000, 2))
    payload = {"target": target, "profile": profile, "runs": runs, "durations_ms": durations, "min_ms": min(durations), "max_ms": max(durations), "avg_ms": round(sum(durations) / len(durations), 2), "cache": not no_cache, "last_status": result.get("status")}
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))

@click.command("correlate")
@click.argument("firmware_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("pcap_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write correlation JSON")
def correlate_command(firmware_path, pcap_path, max_mb, json_output):
    from modules.integration.firmware_pcap_correlation import correlate
    result = correlate(firmware_path, pcap_path, max_mb=max_mb)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
        return
    console.print_json(payload)

@click.command("diff")
@click.argument("old_binary", type=click.Path(exists=True, dir_okay=False))
@click.argument("new_binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write comparison JSON")
def diff_command(old_binary, new_binary, json_output):
    from modules.integration.binary_diff import compare_binaries
    result = compare_binaries(old_binary, new_binary)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
        return
    console.print_json(payload)
