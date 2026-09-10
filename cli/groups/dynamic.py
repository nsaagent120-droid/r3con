"""Dynamic group - GDB/pwndbg helpers."""
from __future__ import annotations
from pathlib import Path
import json
import click
from .helpers import console
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.dynamic.gdb_analyzer import DynamicAnalyzer

@click.group("dynamic")
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
@click.option("--input", "input_data", default=None, help="Texte envoyé sur stdin; rien n’est injecté par défaut")
@click.option("--arg", "args", multiple=True, help="Argument du programme; répétable")
@click.option("--prompt", is_flag=True, help="Demander l’entrée stdin dans le terminal avant le lancement")
@click.option("--breakpoint", help="Fonction où arrêter avant l’exécution")
@click.option("--address", "breakpoint_address", help="Adresse où arrêter, par exemple 0x401176")
@click.option("--stop-at-breakpoint", is_flag=True, help="S’arrêter au breakpoint au lieu de continuer")
@click.option("--timeout", default=15, type=click.IntRange(1, 300), show_default=True)
def dynamic_crash(binary_path, input_data, args, prompt, breakpoint, breakpoint_address,
                  stop_at_breakpoint, timeout):
    if prompt and input_data is None:
        input_data = click.prompt("Entrée stdin", default="", show_default=False)
    result = DynamicAnalyzer(binary_path).analyze_crash(
        input_data, timeout=timeout, args=list(args), breakpoint=breakpoint,
        breakpoint_address=breakpoint_address, stop_at_breakpoint=stop_at_breakpoint,
    )
    console.print_json(json.dumps(result, ensure_ascii=False))

@dynamic_group.command("heap")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
def dynamic_heap(binary_path):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).analyze_heap(), ensure_ascii=False))

@dynamic_group.command("offset")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--length", default=300, type=click.IntRange(32, 10000), show_default=True)
@click.option("--prefix-length", default=0, type=click.IntRange(0, 9999), show_default=True)
@click.option("--arg", "args", multiple=True, help="Argument du programme; répétable")
@click.option("--breakpoint", help="Fonction où arrêter avant l’entrée du motif")
@click.option("--address", "breakpoint_address", help="Adresse où arrêter, par exemple 0x401176")
@click.option("--stop-at-breakpoint", is_flag=True, help="S’arrêter au breakpoint au lieu de continuer")
@click.option("--input-mode", type=click.Choice(["stdin", "argument"]), default="stdin", show_default=True)
@click.option("--pattern-arg-index", type=click.IntRange(0, 100), help="Position de l’argument cyclique")
@click.option("--plan", is_flag=True, help="Construire le payload sans lancer la cible")
def dynamic_offset(binary_path, length, prefix_length, args, breakpoint, breakpoint_address,
                   stop_at_breakpoint, input_mode, pattern_arg_index, plan):
    result = DynamicAnalyzer(binary_path).find_bof_offset(
        length, prefix_length=prefix_length, args=list(args), breakpoint=breakpoint,
        breakpoint_address=breakpoint_address, input_mode=input_mode,
        pattern_arg_index=pattern_arg_index, stop_at_breakpoint=stop_at_breakpoint,
        execute=not plan,
    )
    console.print_json(json.dumps(result, ensure_ascii=False))

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

@dynamic_group.command("sandbox")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--arg", "args", multiple=True, help="Argument passé à la cible; répétable")
@click.option("--input-file", type=click.Path(exists=True, dir_okay=False), help="Données envoyées sur stdin")
@click.option("--stdin", "stdin_text", default=None, help="Texte envoyé sur stdin")
@click.option("--timeout", default=10, type=click.IntRange(1, 300), show_default=True, help="Timeout mural (s)")
@click.option("--cpu-sec", default=5, type=click.IntRange(1, 600), show_default=True)
@click.option("--mem-mb", default=256, type=click.IntRange(16, 8192), show_default=True)
@click.option("--max-procs", default=32, type=click.IntRange(1, 512), show_default=True)
@click.option("--allow-network", is_flag=True, help="Autorise le réseau (laboratoire contrôlé uniquement)")
@click.option("--lenient-network", is_flag=True, help="Exécute même si unshare -n est indisponible (averti)")
@click.option("--strace", is_flag=True, help="Profil de syscalls si strace est installé")
@click.option("--execute", is_flag=True, help="Exécuter réellement; sans ce drapeau, seul le plan est affiché")
@click.option("--json-output", type=click.Path(dir_okay=False), help="Écrire le résultat JSON")
def dynamic_sandbox(target, args, input_file, stdin_text, timeout, cpu_sec, mem_mb,
                    max_procs, allow_network, lenient_network, strace, execute, json_output):
    """Runner local isolé : réseau coupé, rlimits, tmp privé. Par défaut : PLAN uniquement."""
    from modules.dynamic.sandboxed_runner import SandboxedRunner, SandboxLimits

    limits = SandboxLimits(cpu_seconds=cpu_sec, memory_mb=mem_mb, wall_timeout_s=timeout,
                           max_processes=max_procs, allow_network=allow_network,
                           strict_network=not lenient_network, strace=strace)
    runner = SandboxedRunner(target, args=list(args),
                             stdin_data=stdin_text.encode() if stdin_text is not None else None,
                             input_file=input_file, limits=limits)
    result = runner.execute() if execute else runner.plan()
    text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if json_output:
        Path(json_output).parent.mkdir(parents=True, exist_ok=True)
        Path(json_output).write_text(text, encoding="utf-8")
    if not execute:
        console.print("[yellow]Mode simulation : aucun processus lancé. Relancez avec --execute.[/yellow]")
    console.print_json(text)


@dynamic_group.command("watchpoint")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("address")
@click.option("--type", "watch_type", type=click.Choice(["write", "read", "access"]), default="write", show_default=True)
def dynamic_watchpoint(binary_path, address, watch_type):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).set_watchpoint(address, watch_type), ensure_ascii=False))
