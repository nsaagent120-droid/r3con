"""
r3con v5.2.0 PRO - Workspace CLI
Espaces de travail intelligents, cloisonnés, fédérés et connectés

Chaque workspace:
- Type + profil → outils prioritaires mais tous accessibles
- Cloisonnement hybride: isolation par défaut, import/link/share explicite
- Fédération: fork, merge, liens typés, partage sélectif
- Graphe de workspaces

Commands:
  workspace create <name> --type binary --profile exploit --tags bof,rop
  workspace list
  workspace show <name>
  workspace info <name> --tools  (montre tous outils dispo pour ce workspace)
  workspace add-target <workspace> <target_file>
  workspace fork <source> <new_name>
  workspace merge <ws1> <ws2> ... --target <new_ws>
  workspace link <source> <target> --relation shares_target_with --shared findings,targets
  workspace unlink <source> <target>
  workspace share <source> <target> --items findings,targets,artifacts,notes
  workspace import <source> <target> --items findings
  workspace graph --json
  workspace related <name> --depth 2
  workspace delete <name> --force
  workspace tmux <binary> (ancien workspace four-pane)
  workspace notes <name> --edit
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from typing import List
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.tree import Tree
from rich.syntax import Syntax

from .helpers import console, section, info, ok, warn, hpanel, spinner, VERSION

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.workspace_manager import WorkspaceManager, Workspace, WORKSPACE_TYPES, RELATION_TYPES

@click.group()
def workspace():
    """Espaces de travail intelligents, cloisonnés et fédérés (PRO)."""

@workspace.command("create")
@click.argument("name")
@click.option("--type", "ws_type", type=click.Choice(list(WORKSPACE_TYPES.keys())), default="custom", help="Type d'espace")
@click.option("--profile", default=None, help="Profil (auto si non spécifié, basé sur type)")
@click.option("--description", "-d", default="", help="Description")
@click.option("--parent", default=None, help="Workspace parent (fork)")
@click.option("--tags", default="", help="Tags séparés par virgule")
@click.option("--isolation", type=click.Choice(["private", "shared", "public"]), default="private", help="Niveau isolation")
@click.option("--config", "config_overrides", multiple=True, help="Override config: key=value (ex: analysis.timeout=300)")
def ws_create(name, ws_type, profile, description, parent, tags, isolation, config_overrides):
    """Créer un nouvel espace de travail."""
    mgr = WorkspaceManager()

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    overrides = {}
    for ov in config_overrides:
        if "=" in ov:
            k, v = ov.split("=", 1)
            # Try to parse value
            if v.lower() in ("true", "false"):
                overrides[k] = v.lower() == "true"
            elif v.isdigit():
                overrides[k] = int(v)
            else:
                try:
                    overrides[k] = float(v)
                except ValueError:
                    overrides[k] = v

    try:
        ws = mgr.create_workspace(
            name,
            ws_type=ws_type,
            profile=profile,
            description=description,
            parent=parent,
            tags=tag_list,
            config_overrides=overrides,
            isolation=isolation,
        )
        console.print(Panel(
            f"[cyan]Name:[/] {name}\n"
            f"[cyan]Type:[/] {ws_type} ({WORKSPACE_TYPES[ws_type]['description']})\n"
            f"[cyan]Profile:[/] {ws.load_meta().get('profile')}\n"
            f"[cyan]Priority tools:[/] {', '.join(WORKSPACE_TYPES[ws_type]['priority_tools'][:5])}\n"
            f"[cyan]Isolation:[/] {isolation}\n"
            f"[cyan]Path:[/] {ws.path}\n"
            f"[cyan]Description:[/] {description or '—'}",
            title=f"[bold green]Workspace créé: {name}[/]", border_style="green"
        ))
        info(f"Tous les 35+ outils restent accessibles, profil {ws.load_meta().get('profile')} prioritaire")
        info(f"Utilise: r3con workspace info {name} --tools pour voir tous les outils dispo")
    except FileExistsError as e:
        raise click.ClickException(str(e))
    except Exception as e:
        raise click.ClickException(f"Erreur création workspace: {e}")

@workspace.command("list")
@click.option("--type", "filter_type", type=click.Choice(list(WORKSPACE_TYPES.keys())), default=None, help="Filtrer par type")
@click.option("--tag", default=None, help="Filtrer par tag")
@click.option("--json-output", is_flag=True, help="Sortie JSON")
def ws_list(filter_type, tag, json_output):
    """Lister tous les espaces de travail."""
    mgr = WorkspaceManager()
    workspaces = mgr.list_workspaces()

    if filter_type:
        workspaces = [w for w in workspaces if w["type"] == filter_type]
    if tag:
        workspaces = [w for w in workspaces if tag in w.get("tags", [])]

    if json_output:
        click.echo(json.dumps(workspaces, indent=2, ensure_ascii=False))
        return

    if not workspaces:
        info("Aucun workspace trouvé. Crée avec: r3con workspace create my-ws --type binary")
        return

    t = Table(box=box.SIMPLE_HEAVY, title=f"Workspaces ({len(workspaces)})")
    t.add_column("Name", style="bold cyan", width=20)
    t.add_column("Type", style="white", width=10)
    t.add_column("Profile", style="dim", width=10)
    t.add_column("Targets", style="yellow", width=8)
    t.add_column("Findings", style="red", width=8)
    t.add_column("Links", style="magenta", width=6)
    t.add_column("Tags", style="dim")
    t.add_column("Updated", style="dim cyan", width=16)

    for ws in workspaces:
        t.add_row(
            ws["name"],
            ws["type"],
            ws["profile"],
            str(ws["stats"]["targets"]),
            str(ws["stats"]["findings"]),
            str(ws["stats"]["links"]),
            ",".join(ws.get("tags", [])[:3]),
            ws.get("updated_at", "")[:16].replace("T", " "),
        )
    console.print(t)
    console.print(f"\n[dim]Total: {len(workspaces)} workspaces | Types: {', '.join(WORKSPACE_TYPES.keys())}[/]")

@workspace.command("show")
@click.argument("name")
@click.option("--json-output", is_flag=True)
def ws_show(name, json_output):
    """Afficher détails d'un workspace."""
    mgr = WorkspaceManager()
    try:
        ws = mgr.get_workspace(name)
        data = ws.to_dict()
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    if json_output:
        click.echo(json.dumps(data, indent=2, ensure_ascii=False))
        return

    meta = ws.load_meta()
    section(f"WORKSPACE: {name}")

    console.print(Panel(
        f"[cyan]Type:[/] {meta.get('type')} - {meta.get('type_description')}\n"
        f"[cyan]Profile:[/] {meta.get('profile')} | [cyan]Isolation:[/] {meta.get('isolation')}\n"
        f"[cyan]Created:[/] {meta.get('created_at','')[:19]} | [cyan]Updated:[/] {meta.get('updated_at','')[:19]}\n"
        f"[cyan]Parent:[/] {meta.get('parent') or '—'} | [cyan]Children:[/] {', '.join(meta.get('children', [])) or '—'}\n"
        f"[cyan]Tags:[/] {', '.join(meta.get('tags', [])) or '—'}\n"
        f"[cyan]Path:[/] {data.get('path')}\n"
        f"[cyan]Description:[/] {meta.get('description') or '—'}",
        title=f"[bold cyan]{name}[/]", border_style="cyan"
    ))

    # Stats
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    t.add_column(style="dim cyan", width=14)
    t.add_column(style="bold white")
    t.add_row("Targets", str(meta.get("stats", {}).get("targets", 0)))
    t.add_row("Findings", str(data.get("findings_count", 0)))
    t.add_row("Artifacts", str(data.get("artifacts_count", 0)))
    t.add_row("Links", str(len(data.get("links", []))))
    t.add_row("Priority tools", ", ".join(meta.get("priority_tools", [])[:6]) or "—")
    console.print(Panel(t, title="[bold]Stats & Tools[/]", border_style="dim cyan"))

    # Targets
    targets = ws.get_targets()
    if targets:
        tt = Table(box=box.SIMPLE_HEAVY, title=f"Targets ({len(targets)})")
        tt.add_column("SHA256", style="dim", width=16)
        tt.add_column("Kind", style="cyan", width=10)
        tt.add_column("Size", style="white", width=10)
        tt.add_column("Path", style="dim")
        for tgt in targets[:10]:
            tt.add_row(tgt.get("sha256","")[:16], tgt.get("kind",""), str(tgt.get("size","")), Path(tgt.get("path","")).name[:40])
        console.print(tt)

    # Links
    links = data.get("links", [])
    if links:
        lt = Table(box=box.SIMPLE_HEAVY, title=f"Links / Connexions ({len(links)})")
        lt.add_column("Target", style="bold cyan")
        lt.add_column("Relation", style="yellow")
        lt.add_column("Shared", style="dim")
        lt.add_column("Description", style="white")
        for link in links[:20]:
            lt.add_row(link.get("target",""), link.get("relation",""), ",".join(link.get("shared_items", [])), link.get("description","")[:40])
        console.print(lt)

    # Config overrides
    if meta.get("config_overrides"):
        console.print(Panel(json.dumps(meta.get("config_overrides"), indent=2, ensure_ascii=False), title="[bold]Config Overrides (custom)[/]", border_style="yellow"))

@workspace.command("info")
@click.argument("name")
@click.option("--tools", "show_tools", is_flag=True, help="Afficher tous les outils disponibles pour ce workspace")
@click.option("--json-output", is_flag=True)
def ws_info(name, show_tools, json_output):
    """Infos détaillées + outils disponibles par tâche (PRO)."""
    mgr = WorkspaceManager()
    try:
        ws = mgr.get_workspace(name)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    if not show_tools:
        # Alias to show
        ctx = click.get_current_context()
        ctx.invoke(ws_show, name=name, json_output=json_output)
        return

    tools_info = ws.get_tools_info()

    if json_output:
        click.echo(json.dumps(tools_info, indent=2, ensure_ascii=False))
        return

    section(f"OUTILS DISPONIBLES - Workspace {name} (type={tools_info['type']}, profile={tools_info['profile']})")

    meta = ws.load_meta()
    console.print(Panel(
        f"[cyan]Workspace:[/] {name} | [cyan]Type:[/] {tools_info['type']} | [cyan]Profile:[/] {tools_info['profile']}\n"
        f"[cyan]Priority tools:[/] {', '.join(tools_info['priority_tools']) or '—'}\n"
        f"[cyan]Config overrides:[/] {len(tools_info['config_overrides'])} | [cyan]Isolation:[/] {meta.get('isolation')}\n"
        f"[cyan]Total tools:[/] {tools_info['total_tools']} | [cyan]Present:[/] {tools_info['present_tools']} | [cyan]Missing:[/] {tools_info['total_tools'] - tools_info['present_tools']}",
        title=f"[bold green]Capacités pour tâche {tools_info['type']}[/]", border_style="green"
    ))

    # Summary by category
    t = Table(box=box.SIMPLE_HEAVY, title="Outils par catégorie (priorité + tous)")
    t.add_column("Catégorie", style="bold cyan", width=12)
    t.add_column("Prioritaires (pour cette tâche)", style="bold yellow")
    t.add_column("Tous disponibles", style="dim")
    t.add_column("Present/Total", style="white", width=12)

    for cat, data in tools_info["by_category"].items():
        prio_names = ", ".join([f"[yellow]{x['key']}[/]" + ("✓" if x["present"] else "✗") for x in data["priority"][:5]])
        all_names = ", ".join([x["key"] for x in data["all"][:8]])
        present = sum(1 for x in data["all"] if x["present"])
        total = len(data["all"])
        t.add_row(cat, prio_names or "—", all_names, f"{present}/{total}")

    console.print(t)

    # Capabilities
    console.print(f"\n[bold]Capacités (toutes tâches confondues):[/]")
    for cap, count in tools_info["capabilities"].items():
        console.print(f"  [cyan]{cap}:[/] {count} outils")

    # Detailed priority tools
    if tools_info["priority_tools"]:
        console.print(f"\n[bold yellow]Outils prioritaires pour {tools_info['type']} ({tools_info['profile']}):[/]")
        for tool_key in tools_info["priority_tools"]:
            # Find tool
            found = next((x for x in tools_info["all_tools"] if x["key"] == tool_key), None)
            if found:
                status = "[green]✓ présent[/]" if found["present"] else "[red]✗ manquant[/]"
                console.print(f"  [yellow]{found['key']}[/] {status} - {found.get('purpose','')[:60]} | {found.get('path') or 'non trouvé'}")

    console.print(f"\n[dim]Tous les 35+ outils restent accessibles via config override:[/]")
    console.print(f"[dim]  r3con workspace create my-ws --type custom --config external_tools.enabled.ghidra=true[/]")
    console.print(f"[dim]  r3con analyze-pro --workspace {name} ./binary --with-ghidra --chain[/]")

@workspace.command("add-target")
@click.argument("workspace_name")
@click.argument("target_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--kind", default="auto", type=click.Choice(["auto", "binary", "firmware", "apk", "network", "source"]), help="Type de cible")
@click.option("--tags", default="", help="Tags séparés par virgule")
@click.option("--notes", default="", help="Notes")
def ws_add_target(workspace_name, target_path, kind, tags, notes):
    """Ajouter une cible à un workspace."""
    mgr = WorkspaceManager()
    try:
        ws = mgr.get_workspace(workspace_name)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    try:
        result = ws.add_target(target_path, kind=kind, tags=tag_list, notes=notes)
        ok(f"Cible ajoutée à {workspace_name}: {Path(target_path).name} ({result['kind']}, {result['sha256'][:16]}...)")
        console.print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("fork")
@click.argument("source")
@click.argument("new_name")
@click.option("--description", "-d", default="", help="Description du fork")
def ws_fork(source, new_name, description):
    """Fork un workspace (crée dérivé avec lien derived_from)."""
    mgr = WorkspaceManager()
    try:
        src_ws = mgr.get_workspace(source)
        new_ws = src_ws.fork(new_name, description=description)
        ok(f"Workspace forked: {source} → {new_name}")
        console.print(f"Path: {new_ws.path}")
        info(f"Lien créé: {new_name} derived_from {source}")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("merge")
@click.argument("sources", nargs=-1, required=True)
@click.option("--target", required=True, help="Nom du workspace cible (nouveau)")
@click.option("--description", "-d", default="", help="Description")
def ws_merge(sources, target, description):
    """Fusionner plusieurs workspaces en un nouveau."""
    mgr = WorkspaceManager()
    try:
        merged = mgr.merge_workspaces(list(sources), target, description=description)
        ok(f"Workspaces mergés: {', '.join(sources)} → {target}")
        console.print(f"Targets: {len(merged.get_targets())} | Findings: {len(merged.get_findings())} | Path: {merged.path}")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("link")
@click.argument("source")
@click.argument("target")
@click.option("--relation", type=click.Choice(list(RELATION_TYPES.keys())), default="references", help="Type de relation")
@click.option("--description", "-d", default="", help="Description du lien")
@click.option("--shared", default="", help="Items partagés: targets,findings,artifacts,notes")
@click.option("--bidirectional", is_flag=True, help="Lien bidirectionnel")
def ws_link(source, target, relation, description, shared, bidirectional):
    """Créer un lien entre deux workspaces."""
    mgr = WorkspaceManager()
    try:
        src_ws = mgr.get_workspace(source)
        shared_items = [s.strip() for s in shared.split(",") if s.strip()] if shared else []
        link = src_ws.add_link(target, relation=relation, description=description, shared_items=shared_items, bidirectional=bidirectional)
        ok(f"Lien créé: {source} --[{relation}]--> {target}")
        if shared_items:
            info(f"Shared items: {','.join(shared_items)}")
        if bidirectional:
            info(f"Bidirectionnel: lien inverse créé")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("unlink")
@click.argument("source")
@click.argument("target")
@click.option("--relation", default=None, help="Relation spécifique à supprimer (optionnel)")
def ws_unlink(source, target, relation):
    """Supprimer un lien entre workspaces."""
    mgr = WorkspaceManager()
    try:
        src_ws = mgr.get_workspace(source)
        removed = src_ws.remove_link(target, relation=relation)
        if removed:
            ok(f"{removed} lien(s) supprimé(s): {source} -X-> {target}" + (f" [{relation}]" if relation else ""))
        else:
            warn(f"Aucun lien trouvé: {source} -> {target}")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("share")
@click.argument("source")
@click.argument("target")
@click.option("--items", default="findings", help="Items à partager: targets,findings,artifacts,notes (virgule)")
@click.option("--relation", type=click.Choice(list(RELATION_TYPES.keys())), default="shares_target_with")
def ws_share(source, target, items, relation):
    """Partager sélectivement des infos entre workspaces (fédération)."""
    mgr = WorkspaceManager()
    try:
        src_ws = mgr.get_workspace(source)
        item_list = [i.strip() for i in items.split(",") if i.strip()]
        result = src_ws.share_with(target, items=item_list, relation=relation)
        ok(f"Partage: {source} → {target} | {', '.join(f'{k}:{v}' for k,v in result.items())}")
        console.print(f"Relation: {relation} | Items: {','.join(item_list)}")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("import")
@click.argument("source")
@click.argument("target")
@click.option("--items", default="findings", help="Items à importer")
def ws_import(source, target, items):
    """Importer depuis un autre workspace (alias de share inversé)."""
    mgr = WorkspaceManager()
    try:
        src_ws = mgr.get_workspace(source)
        item_list = [i.strip() for i in items.split(",") if i.strip()]
        result = src_ws.share_with(target, items=item_list, relation="references")
        ok(f"Import: {target} ← {source} | {', '.join(f'{k}:{v}' for k,v in result.items())}")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("graph")
@click.option("--json-output", is_flag=True, help="Sortie JSON")
@click.option("--depth", default=2, type=int, help="Profondeur pour related (si --related)")
@click.option("--related", default=None, help="Workspace source pour graphe lié (BFS)")
def ws_graph(json_output, depth, related):
    """Afficher graphe des workspaces et connexions."""
    mgr = WorkspaceManager()

    if related:
        try:
            data = mgr.find_related(related, depth=depth)
            if json_output:
                click.echo(json.dumps(data, indent=2, ensure_ascii=False))
                return
            section(f"GRAPH LIÉ - {related} (depth={depth})")
            console.print(f"Source: {related} | Related: {data['total_related']}")
            t = Table(box=box.SIMPLE_HEAVY, title=f"Workspaces liés à {related}")
            t.add_column("Name", style="cyan")
            t.add_column("Depth", style="yellow", width=6)
            t.add_column("Type", style="white")
            t.add_column("Targets", style="dim")
            t.add_column("Findings", style="dim")
            for r in data["related"]:
                t.add_row(r["name"], str(r["depth"]), r["meta"].get("type",""), str(r["targets_count"]), str(r["findings_count"]))
            console.print(t)
            return
        except Exception as e:
            raise click.ClickException(str(e))

    graph = mgr.get_graph()

    if json_output:
        click.echo(json.dumps(graph, indent=2, ensure_ascii=False))
        return

    section(f"GRAPH WORKSPACES - {graph['total_workspaces']} nodes, {graph['total_links']} edges")

    # Nodes
    nt = Table(box=box.SIMPLE_HEAVY, title="Nodes")
    nt.add_column("Name", style="bold cyan")
    nt.add_column("Type", style="white", width=10)
    nt.add_column("Profile", style="dim", width=10)
    nt.add_column("Targets", style="yellow", width=8)
    nt.add_column("Findings", style="red", width=8)
    nt.add_column("Tags", style="dim")
    for node in graph["nodes"]:
        nt.add_row(node["id"], node["type"], node["profile"], str(node["stats"]["targets"]), str(node["stats"]["findings"]), ",".join(node.get("tags", [])[:3]))
    console.print(nt)

    # Edges
    if graph["edges"]:
        et = Table(box=box.SIMPLE_HEAVY, title="Edges / Connexions")
        et.add_column("Source", style="cyan")
        et.add_column("Relation", style="bold yellow", width=20)
        et.add_column("Target", style="green")
        et.add_column("Shared", style="dim")
        for edge in graph["edges"][:30]:
            et.add_row(edge["source"], edge["relation"], edge["target"], ",".join(edge.get("shared_items", [])))
        console.print(et)

    console.print(f"\n[dim]Visualisation: chaque workspace est un espace cloisonné, les edges sont les liens fédérés[/]")
    console.print(f"[dim]Utilise --related <name> pour voir graphe lié à un workspace[/]")

@workspace.command("delete")
@click.argument("name")
@click.option("--force", is_flag=True, help="Forcer suppression même avec enfants")
def ws_delete(name, force):
    """Supprimer un workspace."""
    mgr = WorkspaceManager()
    try:
        # Confirm
        if not force:
            ws = mgr.get_workspace(name)
            meta = ws.load_meta()
            if meta.get("children"):
                warn(f"Workspace {name} a des enfants: {meta['children']}")
                if not click.confirm(f"Supprimer {name} et détacher enfants ?"):
                    info("Annulé")
                    return
        mgr.delete_workspace(name, force=force)
        ok(f"Workspace supprimé: {name}")
    except Exception as e:
        raise click.ClickException(str(e))

@workspace.command("notes")
@click.argument("name")
@click.option("--edit", is_flag=True, help="Ouvrir éditeur")
@click.option("--add", "add_text", default=None, help="Ajouter texte aux notes")
def ws_notes(name, edit, add_text):
    """Gérer notes d'un workspace."""
    mgr = WorkspaceManager()
    try:
        ws = mgr.get_workspace(name)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    if add_text:
        current = ws.notes_path.read_text(encoding="utf-8") if ws.notes_path.is_file() else ""
        new = current + f"\n\n## {__import__('datetime').datetime.now().isoformat()}\n\n{add_text}\n"
        ws.notes_path.write_text(new, encoding="utf-8")
        ok(f"Note ajoutée à {name}")
        return

    if edit:
        editor = shutil.which("nano") or shutil.which("vim") or shutil.which("vi") or "cat"
        subprocess.call([editor, str(ws.notes_path)])
        return

    # Show notes
    if ws.notes_path.is_file():
        content = ws.notes_path.read_text(encoding="utf-8")
        console.print(Panel(Syntax(content, "markdown", theme="monokai"), title=f"Notes: {name}", border_style="cyan"))
    else:
        info(f"Pas de notes pour {name}")

@workspace.command("tmux")
@click.argument("binary_path", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--session", default="r3con-lab", show_default=True, help="tmux session name")
@click.option("--dry-run", is_flag=True, help="Print plan without launching")
def workspace_tmux(binary_path, session, dry_run):
    """Ancien workspace four-pane tmux (lab)."""
    tmux = shutil.which("tmux")
    target = binary_path or ""
    commands = ["r3con interactive", (f"r2 -AA {target}" if target else "echo 'r2 pane: use r2 -AA ./binary'"), (f"gdb {target}" if target else "echo 'GDB pane: use gdb ./binary'"), "bash"]
    if dry_run:
        console.print(Panel("\n".join(f"Pane {i + 1}: {cmd}" for i, cmd in enumerate(commands)), title="[bold cyan] r3con workspace tmux [/bold cyan]", border_style="cyan"))
        return
    if not tmux:
        raise click.ClickException("tmux requis pour four-pane workspace")
    if subprocess.call([tmux, "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        raise click.ClickException(f"tmux session '{session}' existe déjà; use tmux attach -t {session}")
    subprocess.run([tmux, "new-session", "-d", "-s", session, "bash"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.0", commands[0].replace("\\n", " && "), "C-m"], check=True)
    subprocess.run([tmux, "split-window", "-h", "-t", f"{session}:0.0"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.1", commands[1], "C-m"], check=True)
    subprocess.run([tmux, "split-window", "-v", "-t", f"{session}:0.1"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.2", commands[2], "C-m"], check=True)
    subprocess.run([tmux, "select-pane", "-t", f"{session}:0.0"], check=True)
    subprocess.run([tmux, "split-window", "-v", "-t", f"{session}:0.0"], check=True)
    subprocess.run([tmux, "send-keys", "-t", f"{session}:0.3", commands[3], "C-m"], check=True)
    subprocess.run([tmux, "select-layout", "-t", f"{session}:0", "tiled"], check=True)
    console.print(f"[green]✓[/] Four-pane workspace: [cyan]{session}[/]")
    raise SystemExit(subprocess.call([tmux, "attach-session", "-t", session]))
