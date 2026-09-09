"""Research group."""
from __future__ import annotations
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, ok, spinner, hpanel
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.disasm.binary_parser import BinaryParser
from modules.research.research import HypothesisEngine, CVEMatcher, VariantFinder

@click.group()
def research():
    """0day research, CVE matching, hypothesis engine."""

@research.command("hypothesis")
@click.argument("target", type=click.Path(exists=True))
@click.option("--context", "-c", default=None)
@click.option("--depth", type=click.Choice(["quick","deep"]), default="deep")
@click.pass_context
def res_hypothesis(ctx, target, context, depth):
    section("0DAY HYPOTHESIS ENGINE")
    info(f"Target  : {target}  |  Context: {context or 'auto'}")
    console.print()
    with open(target, errors="ignore") as f: content = f.read()
    engine = HypothesisEngine()
    surface = engine.build_attack_surface(content)
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column(style="dim cyan", width=22)
    t.add_column(style="bold white")
    t.add_row("Entry points", str(len(surface["entry_points"])))
    t.add_row("Dangerous sinks", str(len(surface["dangerous_sinks"])))
    console.print(Panel(t, title="[bold]Attack Surface[/]", border_style="dim cyan", padding=(0,1)))
    if surface["entry_points"]:
        et = Table(box=box.SIMPLE_HEAVY, title="Entry Points")
        et.add_column("Line", style="cyan", width=6)
        et.add_column("Type", style="white", width=20)
        et.add_column("Code", style="dim")
        for e in surface["entry_points"][:10]:
            et.add_row(str(e["line"]), e["type"], e["code"][:60])
        console.print(et)
    console.print()
    with spinner("AI formulating 0day hypotheses") as p:
        p.add_task("", total=None)
        hypotheses = ctx.obj["ai"].generate_hypotheses(content, context=context, depth=depth)
    hpanel(hypotheses, "0day Hypotheses", "critical")
    ctx.obj["session"].save("hypothesis", target, hypotheses)

@research.command("cve-match")
@click.argument("target", type=click.Path(exists=True))
@click.option("--limit", default=10)
@click.pass_context
def res_cve(ctx, target, limit):
    section("CVE PATTERN MATCHING")
    info(f"Target: {target}")
    with open(target, errors="ignore") as f: content = f.read()
    matcher = CVEMatcher()
    with spinner("Matching vulnerability patterns") as p:
        p.add_task("", total=None)
        matches = matcher.extract_patterns(content)
    if matches:
        t = Table(box=box.SIMPLE_HEAVY)
        t.add_column("Line", style="dim cyan", width=6)
        t.add_column("CVE Class", style="bold white")
        t.add_column("CWE", style="dim", width=10)
        t.add_column("Example CVEs")
        for m in matches[:15]:
            t.add_row(str(m.get("line","")), m.get("finding_class",""), m.get("cwe",""), ", ".join(m.get("reference_cves",[])[:1]))
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
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    section(f"VARIANT FINDER — {cve_id}")
    finder = VariantFinder()
    with spinner(f"Fetching {cve_id} from NVD") as p:
        p.add_task("", total=None)
        cve_info = finder.fetch_cve(cve_id)
    info(f"CVSS : {cve_info.get('cvss','N/A')}")
    info(f"Desc : {cve_info.get('description','N/A')[:80]}")
    console.print()
    files = (list(Path(target_dir).rglob("*.c")) + list(Path(target_dir).rglob("*.cpp")) + list(Path(target_dir).rglob("*.py")))[:50]
    info(f"Scanning {len(files)} files...")
    results = []
    with Progress(SpinnerColumn(spinner_name="dots", style="cyan"), TextColumn("[cyan]{task.description}"), BarColumn(bar_width=30, style="dim cyan", complete_style="cyan"), console=console) as prog:
        task = prog.add_task("Scanning", total=len(files))
        for f in files:
            prog.update(task, description=f"[cyan]{f.name[:28]}")
            try:
                code = f.read_text(errors="ignore")
                match = finder.find_in_code(code, cve_info)
                if match:
                    results.append({"file": str(f), "match": match})
            except Exception:
                pass
            prog.advance(task)
    console.print()
    if results:
        for r in results:
            hpanel(f"[bold]File:[/] {r['file']}\n\n{r['match']}", f"Potential Variant of {cve_id}", "critical")
    else:
        ok(f"No obvious variants of {cve_id} found.")

@research.command("patch-diff")
@click.argument("binary_before", type=click.Path(exists=True))
@click.argument("binary_after", type=click.Path(exists=True))
@click.pass_context
def res_patch_diff(ctx, binary_before, binary_after):
    section("PATCH DIFF ANALYSIS")
    info(f"Before : {binary_before}")
    info(f"After  : {binary_after}")
    with spinner("Extracting function lists") as p:
        p.add_task("", total=None)
        f_before = set(BinaryParser(binary_before).get_function_list())
        f_after = set(BinaryParser(binary_after).get_function_list())
    added = sorted(f_after - f_before)
    removed = sorted(f_before - f_after)
    t = Table(box=box.SIMPLE_HEAVY, title="Function Diff")
    t.add_column("Status", width=12)
    t.add_column("Function", style="white")
    for f in added: t.add_row("[green]+ ADDED[/]", f)
    for f in removed: t.add_row("[red]- REMOVED[/]", f)
    console.print(t)
    info(f"{len(f_before & f_after)} functions unchanged")
    with spinner("AI patch security analysis") as p:
        p.add_task("", total=None)
        ai_res = ctx.obj["ai"].patch_diff_analysis(added, removed, binary_before, binary_after)
    hpanel(ai_res, "Patch Security Analysis", "high")

@research.command("fuzz-hints")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--function", "-f", default=None)
@click.option("--format", "fmt", type=click.Choice(["afl","libfuzzer","manual"]), default="manual")
@click.pass_context
def res_fuzz(ctx, source_path, function, fmt):
    section("AI FUZZING HINTS")
    info(f"Target: {source_path}  |  Format: {fmt}")
    with open(source_path, errors="ignore") as f: code = f.read()
    with spinner("Generating fuzzing strategy") as p:
        p.add_task("", total=None)
        result = ctx.obj["ai"].fuzz_hints(code, function=function, fmt=fmt)
    hpanel(result, "Fuzzing Strategy & Test Cases", "medium")
    ctx.obj["session"].save("fuzz_hints", source_path, result)
