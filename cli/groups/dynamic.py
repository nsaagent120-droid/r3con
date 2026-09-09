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

@dynamic_group.command("watchpoint")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("address")
@click.option("--type", "watch_type", type=click.Choice(["write", "read", "access"]), default="write", show_default=True)
def dynamic_watchpoint(binary_path, address, watch_type):
    console.print_json(json.dumps(DynamicAnalyzer(binary_path).set_watchpoint(address, watch_type), ensure_ascii=False))
