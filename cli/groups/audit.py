"""Audit group - static source analysis."""
from __future__ import annotations
from pathlib import Path
import click
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from .helpers import console, section, info, ok, spinner, show_findings, hpanel
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.audit.static_analyzer import StaticAnalyzer

@click.group()
def audit():
    """Static source code audit."""

@audit.command("file")
@click.argument("source_path", type=click.Path(exists=True))
@click.option("--lang", "-l", default="auto", type=click.Choice(["auto","c","cpp","python","java","go","rust"]))
@click.option("--focus", "-f", default="all", type=click.Choice(["all","memory","crypto","race","kernel","proto"]))
@click.option("--depth", "-d", default="deep", type=click.Choice(["quick","deep","full"]))
@click.option("--report", "-r", is_flag=True)
@click.pass_context
def audit_file(ctx, source_path, lang, focus, depth, report):
    from core.report_gen import ReportGenerator
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
        path = ReportGenerator().generate({"type":"audit","source":source_path,"findings":all_f})
        ok(f"Report → {path}")

@audit.command("dir")
@click.argument("directory", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, default=True)
@click.option("--lang", "-l", default="auto")
@click.option("--report", is_flag=True)
@click.pass_context
def audit_dir(ctx, directory, recursive, lang, report):
    from core.report_gen import ReportGenerator
    section("DIRECTORY AUDIT")
    exts = [".c",".h",".cpp",".py",".java",".go",".rs"]
    base = Path(directory)
    files = []
    for ext in exts:
        files.extend(base.rglob(f"*{ext}") if recursive else base.glob(f"*{ext}"))
    info(f"Found {len(files)} files")
    console.print()
    analyzer = StaticAnalyzer(lang=lang)
    all_f = []
    with Progress(SpinnerColumn(spinner_name="dots", style="cyan"), TextColumn("[cyan]{task.description}"), BarColumn(bar_width=30, style="dim cyan", complete_style="cyan"), TextColumn("[dim]{task.completed}/{task.total}"), console=console) as prog:
        task = prog.add_task("Auditing", total=len(files))
        for f in files:
            prog.update(task, description=f"[cyan]{f.name[:28]}")
            try:
                code = f.read_text(errors="ignore")
                res = analyzer.analyze(code)
                for fi in res: fi["file"] = str(f)
                all_f.extend(res)
            except Exception:
                pass
            prog.advance(task)
    console.print()
    show_findings(all_f)
    if report:
        path = ReportGenerator().generate({"type":"audit_dir","directory":directory,"findings":all_f})
        ok(f"Report → {path}")
