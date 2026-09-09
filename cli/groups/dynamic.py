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
