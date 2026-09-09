"""Advanced group - heap, crypto, kernel, toctou, proto."""
from __future__ import annotations
from pathlib import Path
import click
from .helpers import console, section, info, show_findings, hpanel, spinner
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.advanced.heap_analyzer import HeapAnalyzer
from modules.advanced.crypto_checker import CryptoChecker
from modules.advanced.kernel_patterns import KernelPatternScanner

@click.group()
def advanced():
    """Advanced vulnerability analysis modules."""

@advanced.command("heap")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--allocator", default="glibc", type=click.Choice(["glibc","jemalloc","tcmalloc"]))
@click.pass_context
def adv_heap(ctx, source_path, allocator):
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
@click.option("--type","ktype", type=click.Choice(["driver","module","syscall","auto"]), default="auto")
@click.pass_context
def adv_kernel(ctx, source_path, ktype):
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
    section("TOCTOU ANALYSIS")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Analyzing TOCTOU patterns") as p:
        p.add_task("", total=None)
        result = ctx.obj["ai"].toctou_analysis(code)
    hpanel(result, "TOCTOU Race Conditions", "high")

@advanced.command("proto")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--protocol", "-p", type=click.Choice(["auto","tls","ssh","smb","custom"]), default="auto")
@click.pass_context
def adv_proto(ctx, source_path, protocol):
    section("PROTOCOL ANALYSIS")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner(f"Analyzing {protocol.upper()} implementation") as p:
        p.add_task("", total=None)
        result = ctx.obj["ai"].protocol_analysis(code, protocol=protocol)
    hpanel(result, f"Protocol Analysis ({protocol.upper()})", "medium")
