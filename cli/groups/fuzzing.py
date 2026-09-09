"""
r3con v6.0 Titan-Omega - Fuzzing CLI
Lab de fuzzing complet avec workspaces fédérés

Commands:
  fuzzing engines - list engines availability
  fuzzing create <name> <target> --engine afl --workspace <ws> --corpus ./corpus
  fuzzing list [--workspace <ws>]
  fuzzing show <name> [--workspace <ws>]
  fuzzing stats <name> [--workspace <ws>]
  fuzzing triage <name> [--workspace <ws>]
  fuzzing corpus <name> --generate 100 --strategy radamsa
  fuzzing corpus <name> --minimize
  fuzzing delete <name> [--workspace <ws>]
"""
from __future__ import annotations
import json
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, ok, warn

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.fuzzing_manager import FuzzingManager, FUZZING_ENGINES

@click.group()
def fuzzing():
    """Lab de fuzzing complet - AFL++, libFuzzer, honggfuzz, Radamsa, crash triage (PRO v6.0)."""

@fuzzing.command("engines")
@click.option("--json-output", is_flag=True)
def fuzz_engines(json_output):
    """Lister engines de fuzzing disponibles."""
    mgr = FuzzingManager()
    engines = mgr.list_engines()

    if json_output:
        click.echo(json.dumps(engines, indent=2, ensure_ascii=False))
        return

    t = Table(box=box.SIMPLE_HEAVY, title="Fuzzing Engines")
    t.add_column("Engine", style="bold cyan", width=12)
    t.add_column("Name", style="white", width=16)
    t.add_column("Present", style="green", width=8)
    t.add_column("Path", style="dim", width=20)
    t.add_column("QEMU", style="yellow", width=6)
    t.add_column("Coverage", style="magenta", width=8)
    t.add_column("Description", style="dim")

    for eng in engines:
        t.add_row(
            eng["key"],
            eng["name"],
            "✓" if eng["present"] else "✗",
            Path(eng["path"]).name if eng["path"] else "—",
            "yes" if eng["supports_qemu"] else "no",
            "yes" if eng["supports_coverage"] else "no",
            eng["description"][:40],
        )
    console.print(t)
    present = sum(1 for e in engines if e["present"])
    console.print(f"\n[bold]Total: {present}/{len(engines)} engines disponibles[/]")
    console.print("[dim]Installe AFL++: apt install afl++ | honggfuzz: apt install honggfuzz | radamsa: apt install radamsa[/]")

@fuzzing.command("create")
@click.argument("name")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--engine", type=click.Choice(list(FUZZING_ENGINES.keys())), default="afl", help="Engine de fuzzing")
@click.option("--workspace", "workspace_name", default=None, help="Workspace fédéré (recommandé)")
@click.option("--corpus", "corpus_dir", type=click.Path(exists=True), default=None, help="Corpus initial")
@click.option("--output", "output_dir", type=click.Path(file_okay=False), default=None, help="Output dir (si pas workspace)")
@click.option("--tags", default="", help="Tags séparés par virgule")
def fuzz_create(name, target, engine, workspace_name, corpus_dir, output_dir, tags):
    """Créer une campagne de fuzzing."""
    mgr = FuzzingManager()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    try:
        campaign = mgr.create_campaign(
            name=name,
            target=target,
            engine=engine,
            workspace=workspace_name,
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            tags=tag_list,
        )
        console.print(Panel(
            f"[cyan]Name:[/] {name}\n"
            f"[cyan]Target:[/] {target}\n"
            f"[cyan]Engine:[/] {engine} ({FUZZING_ENGINES[engine]['name']})\n"
            f"[cyan]Workspace:[/] {workspace_name or 'global'}\n"
            f"[cyan]Output:[/] {campaign.output_dir}\n"
            f"[cyan]Corpus:[/] {campaign.corpus_dir}\n"
            f"[cyan]Tags:[/] {','.join(tag_list) or '—'}",
            title=f"[bold green]Campagne créée: {name}[/]", border_style="green"
        ))
        ok(f"Corpus initial: {len(list(Path(campaign.corpus_dir).glob('*')))} fichiers")
        info(f"Prochaines étapes:")
        info(f"  r3con fuzzing stats {name}" + (f" --workspace {workspace_name}" if workspace_name else ""))
        info(f"  r3con fuzzing corpus {name} --generate 100 --strategy radamsa")
        info(f"  r3con fuzzing triage {name} (après fuzzing)")
        if engine == "afl":
            info(f"  Pour lancer AFL++: afl-fuzz -i {campaign.corpus_dir} -o {campaign.output_dir} -- {target} @@")
    except Exception as e:
        raise click.ClickException(str(e))

@fuzzing.command("list")
@click.option("--workspace", "workspace_name", default=None, help="Filtrer par workspace")
@click.option("--json-output", is_flag=True)
def fuzz_list(workspace_name, json_output):
    """Lister campagnes de fuzzing."""
    mgr = FuzzingManager()
    campaigns = mgr.list_campaigns(workspace=workspace_name)

    if json_output:
        click.echo(json.dumps(campaigns, indent=2, ensure_ascii=False))
        return

    if not campaigns:
        info("Aucune campagne. Crée avec: r3con fuzzing create my-camp ./binary --engine afl --workspace my-ws")
        return

    t = Table(box=box.SIMPLE_HEAVY, title=f"Campagnes Fuzzing ({len(campaigns)})")
    t.add_column("Name", style="bold cyan", width=20)
    t.add_column("Engine", style="white", width=10)
    t.add_column("Workspace", style="dim", width=15)
    t.add_column("Target", style="dim", width=20)
    t.add_column("Status", style="yellow", width=10)
    t.add_column("Crashes", style="red", width=8)
    t.add_column("Created", style="dim cyan", width=16)

    for camp in campaigns:
        t.add_row(
            camp.get("name",""),
            camp.get("engine",""),
            camp.get("workspace") or "global",
            Path(camp.get("target","")).name[:20],
            camp.get("status",""),
            str(camp.get("stats", {}).get("crashes", 0)),
            camp.get("created_at","")[:16].replace("T", " "),
        )
    console.print(t)

@fuzzing.command("show")
@click.argument("name")
@click.option("--workspace", "workspace_name", default=None)
@click.option("--json-output", is_flag=True)
def fuzz_show(name, workspace_name, json_output):
    """Afficher détails campagne."""
    mgr = FuzzingManager()
    try:
        camp = mgr.get_campaign(name, workspace=workspace_name)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    data = camp.to_dict()

    if json_output:
        click.echo(json.dumps(data, indent=2, ensure_ascii=False))
        return

    section(f"FUZZING CAMPAIGN: {name}")
    console.print(Panel(
        f"[cyan]Target:[/] {data['target']}\n"
        f"[cyan]Engine:[/] {data['engine']} ({FUZZING_ENGINES[data['engine']]['name']})\n"
        f"[cyan]Workspace:[/] {data.get('workspace') or 'global'}\n"
        f"[cyan]Output:[/] {data['output_dir']}\n"
        f"[cyan]Corpus:[/] {data['corpus_dir']}\n"
        f"[cyan]Status:[/] {data['status']} | [cyan]PID:[/] {data.get('pid') or '—'}\n"
        f"[cyan]Created:[/] {data['created_at'][:19]} | [cyan]Updated:[/] {data['updated_at'][:19]}\n"
        f"[cyan]Tags:[/] {','.join(data.get('tags', [])) or '—'}",
        title=f"[bold cyan]{name}[/]", border_style="cyan"
    ))

    stats = data.get("stats", {})
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    t.add_column(style="dim cyan", width=14)
    t.add_column(style="bold white")
    t.add_row("Execs", str(stats.get("execs", 0)))
    t.add_row("Crashes", str(stats.get("crashes", 0)))
    t.add_row("Hangs", str(stats.get("hangs", 0)))
    t.add_row("Coverage", str(stats.get("coverage", 0)))
    console.print(Panel(t, title="[bold]Stats[/]", border_style="dim cyan"))

    # List files
    out_dir = Path(data["output_dir"])
    for sub in ["corpus", "crashes", "hangs", "queue"]:
        sub_path = out_dir / sub
        if sub_path.is_dir():
            count = len(list(sub_path.glob("*")))
            info(f"{sub}: {count} fichiers dans {sub_path}")

@fuzzing.command("stats")
@click.argument("name")
@click.option("--workspace", "workspace_name", default=None)
@click.option("--json-output", is_flag=True)
def fuzz_stats(name, workspace_name, json_output):
    """Stats détaillées campagne."""
    mgr = FuzzingManager()
    try:
        stats = mgr.get_stats(name, workspace=workspace_name)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    if json_output:
        click.echo(json.dumps(stats, indent=2, ensure_ascii=False))
        return

    section(f"STATS: {name}")
    console.print(Panel(
        f"[cyan]Target:[/] {stats['target']}\n"
        f"[cyan]Engine:[/] {stats['engine']} | [cyan]Status:[/] {stats['status']}\n"
        f"[cyan]Workspace:[/] {stats.get('workspace') or 'global'}\n"
        f"[cyan]Corpus:[/] {stats['corpus']} | [cyan]Crashes:[/] {stats['crashes']} | [cyan]Hangs:[/] {stats['hangs']} | [cyan]Queue:[/] {stats['queue']}",
        title=f"[bold]{name} stats[/]", border_style="cyan"
    ))

@fuzzing.command("triage")
@click.argument("name")
@click.option("--workspace", "workspace_name", default=None)
@click.option("--json-output", is_flag=True)
def fuzz_triage(name, workspace_name, json_output):
    """Triage crashes: déduplication, classification, exploitabilité."""
    mgr = FuzzingManager()
    try:
        report = mgr.triage_crashes(name, workspace=workspace_name)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    if json_output:
        click.echo(json.dumps(report, indent=2, ensure_ascii=False))
        return

    section(f"TRIAGE: {name} - {report['unique_crashes']} crashes uniques / {report['total_files']} fichiers")

    # By severity
    t = Table(box=box.SIMPLE_HEAVY, title="Par Sévérité")
    t.add_column("Severity", style="bold")
    t.add_column("Count", style="white")
    for sev, count in report.get("by_severity", {}).items():
        style = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "white"
        t.add_row(f"[{style}]{sev}[/{style}]", str(count))
    console.print(t)

    # By type
    t2 = Table(box=box.SIMPLE_HEAVY, title="Par Type")
    t2.add_column("Type", style="cyan")
    t2.add_column("Count", style="white")
    for ctype, count in report.get("by_type", {}).items():
        t2.add_row(ctype, str(count))
    console.print(t2)

    # Crashes list
    if report["crashes"]:
        ct = Table(box=box.SIMPLE_HEAVY, title=f"Crashes uniques ({len(report['crashes'])})")
        ct.add_column("ID", style="dim", width=20)
        ct.add_column("Type", style="yellow", width=20)
        ct.add_column("Severity", style="red", width=10)
        ct.add_column("Size", style="white", width=8)
        ct.add_column("Stack Hash", style="dim", width=16)
        ct.add_column("Count", style="cyan", width=6)
        for crash in report["crashes"][:20]:
            ct.add_row(
                crash["id"][:20],
                crash["crash_type"],
                crash["severity"],
                str(crash["size"]),
                crash["stack_hash"],
                str(crash["count"]),
            )
        console.print(ct)

    ok(f"Triage sauvegardé: {Path(report['crashes'][0]['file_path']).parent.parent / 'triage.json' if report['crashes'] else 'triage.json'}")

@fuzzing.command("corpus")
@click.argument("name")
@click.option("--workspace", "workspace_name", default=None)
@click.option("--generate", type=int, default=None, help="Générer N samples avec Radamsa/mutation")
@click.option("--strategy", type=click.Choice(["radamsa", "mutate"]), default="radamsa", help="Stratégie génération")
@click.option("--minimize", is_flag=True, help="Minimiser corpus (déduplication)")
def fuzz_corpus(name, workspace_name, generate, strategy, minimize):
    """Gérer corpus: génération et minimisation."""
    mgr = FuzzingManager()

    if generate:
        try:
            result = mgr.generate_corpus(name, workspace=workspace_name, num_samples=generate, strategy=strategy)
            ok(f"Corpus généré: {result['generated']} nouveaux | Total: {result['total_corpus']} dans {result['corpus_dir']}")
        except Exception as e:
            raise click.ClickException(str(e))
        return

    if minimize:
        try:
            result = mgr.minimize_corpus(name, workspace=workspace_name)
            ok(f"Corpus minimisé: {result['removed']} supprimés, {result['kept']} conservés")
        except Exception as e:
            raise click.ClickException(str(e))
        return

    # Show corpus stats
    try:
        stats = mgr.get_stats(name, workspace=workspace_name)
        console.print(f"Corpus: {stats['corpus']} fichiers | Crashes: {stats['crashes']} | Hangs: {stats['hangs']}")
        info(f"Utilise --generate 100 --strategy radamsa pour générer")
        info(f"Utilise --minimize pour dédupliquer")
    except Exception as e:
        raise click.ClickException(str(e))

@fuzzing.command("delete")
@click.argument("name")
@click.option("--workspace", "workspace_name", default=None)
@click.option("--force", is_flag=True)
def fuzz_delete(name, workspace_name, force):
    """Supprimer campagne."""
    mgr = FuzzingManager()
    try:
        camp = mgr.get_campaign(name, workspace=workspace_name)
        if not force:
            if not click.confirm(f"Supprimer campagne {name} dans {camp.output_dir} ?"):
                info("Annulé")
                return
        import shutil
        shutil.rmtree(camp.output_dir, ignore_errors=True)
        ok(f"Campagne supprimée: {name}")
    except Exception as e:
        raise click.ClickException(str(e))
