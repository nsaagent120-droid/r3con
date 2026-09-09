"""Interactive console, r2, gdb, workspace, plugins, session."""
from __future__ import annotations
import os
import sys
import json
import subprocess
import shlex
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, print_banner, apply_theme, THEME_PRESETS, THEME_NAME, ok, warn, info, spinner
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.plugin_system import default_registry, save_run

_CONSOLE_COMMANDS = ["help", "set", "show", "analyze", "analyze-pro", "r2", "gdb", "disasm", "dynamic", "audit", "advanced", "apk", "firmware", "research", "network", "tools", "plugins", "history", "sessions", "theme", "clear", "exit", "quit"]

def _setup_readline():
    try:
        import readline
        import glob
        history_file = Path(os.environ.get("R3CON_HISTORY", str(Path.home() / ".r3con_history")))
        try:
            readline.read_history_file(str(history_file))
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)
        readline.parse_and_bind("tab: complete")
        def complete(text, state):
            line = readline.get_line_buffer()
            before = line[:readline.get_endidx()]
            if not before.strip() or (len(before.split()) <= 1 and not before.endswith(" ")):
                matches = [c for c in _CONSOLE_COMMANDS if c.startswith(text)]
            else:
                expanded = os.path.expanduser(text)
                pattern = expanded + "*"
                matches = glob.glob(pattern)
                if text.startswith("~"):
                    matches = [m.replace(str(Path.home()), "~", 1) for m in matches]
            return matches[state] if state < len(matches) else None
        readline.set_completer(complete)
        return readline, history_file
    except (ImportError, OSError):
        return None, None

def _save_readline(readline, history_file):
    if readline is not None and history_file is not None:
        try:
            readline.write_history_file(str(history_file))
        except OSError:
            pass

@click.command("r2")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--no-analysis", is_flag=True, help="Open r2 without automatic analysis")
def r2_command(binary_path, no_analysis):
    import shutil
    executable = shutil.which("r2") or shutil.which("radare2")
    if not executable:
        raise click.ClickException("radare2/r2 is not installed")
    command = [executable]
    if not no_analysis:
        command += ["-AA"]
    command.append(binary_path)
    console.print(f"[cyan]Launching {executable} directly. Type q to quit.[/]")
    raise SystemExit(subprocess.call(command))

@click.command("workspace")
@click.argument("binary_path", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--session", default="r3con-lab", show_default=True, help="tmux session name")
@click.option("--dry-run", is_flag=True, help="Print the four-pane plan without launching it")
def workspace_command(binary_path, session, dry_run):
    import shutil
    tmux = shutil.which("tmux")
    target = binary_path or ""
    commands = ["r3con interactive", (f"r2 -AA {target}" if target else "echo 'r2 pane: use r2 -AA ./binary'"), (f"gdb {target}" if target else "echo 'GDB pane: use gdb ./binary'"), "bash"]
    if dry_run:
        console.print(Panel("\n".join(f"Pane {i + 1}: {cmd}" for i, cmd in enumerate(commands)), title="[bold cyan] r3con workspace [/bold cyan]", border_style="cyan"))
        return
    if not tmux:
        raise click.ClickException("tmux is required for the four-pane workspace.")
    if subprocess.call([tmux, "has-session", "-t", session], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        raise click.ClickException(f"tmux session '{session}' already exists; use tmux attach -t {session} or choose --session NAME")
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
    console.print(f"[green]✓[/] Four-pane workspace created: [cyan]{session}[/]")
    raise SystemExit(subprocess.call([tmux, "attach-session", "-t", session]))

@click.command("gdb")
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("gdb_args", nargs=-1)
def gdb_command(binary_path, gdb_args):
    import shutil
    executable = shutil.which("gdb")
    if not executable:
        raise click.ClickException("gdb is not installed")
    console.print("[cyan]Launching GDB directly; your ~/.gdbinit configuration is preserved.[/]")
    raise SystemExit(subprocess.call([executable, binary_path, *gdb_args]))

@click.command("session")
@click.option("--list", "list_s", is_flag=True)
@click.option("--clear", is_flag=True)
@click.option("--show", default=None)
@click.pass_context
def session_cmd(ctx, list_s, clear, show):
    from .helpers import section
    sm = ctx.obj["session"]
    if list_s:
        section("SESSIONS")
        sessions = sm.list_sessions()
        if not sessions:
            info("No sessions recorded yet.")
            return
        t = Table(box=box.SIMPLE_HEAVY)
        t.add_column("ID", style="cyan", width=10)
        t.add_column("Type", style="white", width=16)
        t.add_column("Target", style="dim", width=32)
        t.add_column("Time", style="dim cyan")
        for s in sessions:
            t.add_row(s["id"],s["type"],s["target"][:32],s["time"])
        console.print(t)
    elif clear:
        sm.clear(); ok("All sessions cleared.")
    elif show:
        data = sm.get(show)
        if data:
            from .helpers import hpanel
            hpanel(data["output"][:3000], f"Session {show}", "info")
        else:
            warn(f"Session {show} not found.")

@click.group("plugins")
def plugins_group():
    """List and run local tool adapters without installing anything."""

@plugins_group.command("list")
def plugins_list():
    registry = default_registry()
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Plugin", style="cyan")
    table.add_column("Executable", style="white")
    table.add_column("Available", style="green")
    table.add_column("Capabilities", style="dim")
    for item in registry.list():
        table.add_row(item["name"], item["executable"], "yes" if item["available"] else "no", ", ".join(item["capabilities"]))
    console.print(table)

@plugins_group.command("run")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--plugin", "plugin_names", multiple=True, help="Plugin name; repeat for several plugins.")
@click.option("--timeout", default=60, show_default=True)
@click.option("--output", default="./r3con-runs")
def plugins_run(target, plugin_names, timeout, output):
    registry = default_registry()
    names = list(plugin_names) or ["file", "strings"]
    unknown = [name for name in names if name not in {item["name"] for item in registry.list()}]
    if unknown:
        raise click.ClickException("Unknown plugin(s): " + ", ".join(unknown))
    result = registry.run(names, target, timeout=timeout)
    path = save_run(result, output)
    console.print(json.dumps(result, indent=2, ensure_ascii=False))
    ok(f"Run saved → {path}")

def _help():
    console.print()
    console.print(Panel(
        "  [bold cyan]DISASM[/]\n"
        "    [cyan]disasm file <bin>[/]            Disassemble binary (ELF/PE/MachO)\n"
        "    [cyan]disasm strings <bin> --ai[/]    Extract & analyze strings\n"
        "    [cyan]disasm imports <bin> --vuln-check[/]  Flag dangerous imports\n\n"
        "  [bold cyan]AUDIT[/]\n"
        "    [cyan]audit file <src> --depth full[/]  Source code audit\n"
        "    [cyan]audit dir <dir> --report[/]        Recursive audit\n\n"
        "  [bold cyan]ADVANCED[/]\n"
        "    [cyan]advanced heap <file>[/]           Heap exploitation analysis\n"
        "    [cyan]advanced crypto <file>[/]         Cryptographic audit\n"
        "    [cyan]advanced kernel <file>[/]         Kernel vulnerability scan\n"
        "    [cyan]advanced toctou <file>[/]         TOCTOU race detection\n"
        "    [cyan]advanced proto <file>[/]          Protocol analysis\n\n"
        "  [bold cyan]APK[/]\n"
        "    [cyan]apk analyze <apk>[/]             Full Android APK analysis\n"
        "    [cyan]apk manifest <xml>[/]            Analyze decoded manifest\n"
        "    [cyan]apk permissions <apk>[/]         Permission risk assessment\n\n"
        "  [bold cyan]FIRMWARE[/]\n"
        "    [cyan]firmware analyze <img>[/]         Full firmware analysis\n"
        "    [cyan]firmware extract <img>[/]         Extract filesystem\n"
        "    [cyan]firmware strings <img>[/]         String extraction\n"
        "    [cyan]firmware entropy <img>[/]         Entropy map\n\n"
        "  [bold cyan]RESEARCH[/]\n"
        "    [cyan]research hypothesis <file>[/]    0day hypothesis engine\n"
        "    [cyan]research cve-match <file>[/]     CVE pattern matching\n"
        "    [cyan]research variant <CVE> <dir>[/]  CVE variant search\n"
        "    [cyan]research patch-diff <v1> <v2>[/] Reverse security patch\n"
        "    [cyan]research fuzz-hints <file>[/]    AI fuzzing strategy\n\n"
        "  [bold cyan]ANALYZE PRO[/]\n"
        "    [cyan]analyze-pro <target> --profile full --chain[/]  Pipeline efficace\n"
        "    [cyan]config show / profiles / init[/]               Config puissante\n\n"
        "  [bold cyan]CONSOLE[/]\n"
        "    [cyan]theme [matrix|cyber|amber|mono][/]  Change terminal palette\n"
        "    [cyan]set target <file>[/]  Set the current target\n"
        "    [cyan]show options[/]       Show current context\n"
        "    [cyan]history[/]            Show command history\n"
        "    [cyan]r2 <file>[/]          Open radare2 directly\n"
        "    [cyan]gdb <file>[/]         Open GDB/pwndbg directly\n\n"
        "  [bold cyan]DYNAMIC[/]\n"
        "    [cyan]dynamic status <file>[/]   GDB/framework status\n"
        "    [cyan]dynamic function <file> <fn>[/]  Analyze function\n"
        "    [cyan]dynamic crash <file>[/]    Local crash check\n\n"
        "  [dim]Commands are executed locally; use only authorized targets.[/]",
        title="[bold] r3con Commands [/]", border_style="dim cyan", padding=(0,2)
    ))
    console.print()

@click.command("interactive")
@click.pass_context
def interactive_mode(ctx):
    readline, history_file = _setup_readline()
    ai_engine = ctx.obj["ai"]
    session = ctx.obj["session"]
    chat_history = []
    print_banner(boot=True)
    console.print(Panel("Type [cyan]help[/] for commands. Execute [cyan]r2[/], [cyan]gdb[/], [cyan]analyze[/] and [cyan]dynamic[/] without restarting r3con.", title="[bold cyan] r3con console [/bold cyan]", border_style="cyan"))
    history = []
    state = {"target": None}
    while True:
        try:
            prompt = "r3con" + (f"({Path(state['target']).name})" if state["target"] else "") + "> "
            user_input = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [dim]Goodbye.[/]")
            _save_readline(readline, history_file)
            break
        if not user_input:
            continue
        history.append(user_input)
        lowered = user_input.lower()
        if lowered in ("exit", "quit", "q"):
            console.print("  [dim]Goodbye.[/]")
            _save_readline(readline, history_file)
            break
        if lowered in ("help", "?"):
            _help(); continue
        if lowered == "theme" or lowered.startswith("theme "):
            parts = user_input.split(maxsplit=1)
            requested = parts[1].strip() if len(parts) > 1 else None
            if requested:
                if requested.lower() not in THEME_PRESETS:
                    warn("Unknown theme. Available: matrix, cyber, amber, mono")
                else:
                    apply_theme(requested)
                    ok(f"Theme changed to {THEME_NAME}")
            else:
                info(f"Active theme: {THEME_NAME} | Available: matrix, cyber, amber, mono")
            continue
        if lowered == "clear":
            chat_history = []
            console.clear(); print_banner(boot=False); continue
        if lowered == "history":
            for n, item in enumerate(history[-20:], 1):
                console.print(f"  [dim]{n:>2}[/]  {item}")
            continue
        if lowered == "sessions":
            for s in ctx.obj["session"].list_sessions()[:10]:
                console.print(f"  [cyan]{s['id']}[/]  {s['type']:<16} {s['time']}  [dim]{s['target'][:36]}[/]")
            continue
        if lowered.startswith("set target "):
            state["target"] = user_input[11:].strip()
            ok(f"Target set to {state['target']}")
            continue
        if lowered in ("show options", "options"):
            console.print(f"  [cyan]TARGET[/]  {state['target'] or '(not set)'}")
            console.print("  [cyan]ENGINE[/]  radare2 by default; Ghidra with --with-ghidra")
            continue
        try:
            args = shlex.split(user_input)
            command_names = {"analyze", "analyze-pro", "r2", "gdb", "disasm", "dynamic", "audit", "advanced", "apk", "firmware", "research", "network", "tools", "plugins", "session", "config", "benchmark", "correlate", "diff"}
            if not args:
                continue
            if args[0] not in command_names:
                chat_history.append({"role": "user", "content": user_input})
                with spinner("AI thinking") as progress:
                    progress.add_task("", total=None)
                    response = ai_engine.chat(chat_history)
                chat_history.append({"role": "assistant", "content": response})
                session.save("interactive", "chat", response)
                console.print(Panel(response, title="[bold cyan] AI [/bold cyan]", border_style="dim cyan", padding=(0, 2)))
                continue
            if args[0] in {"analyze", "analyze-pro", "r2", "gdb", "disasm", "dynamic"} and state["target"] and len(args) == 1:
                args.append(state["target"])
            # Import cli dynamically to avoid circular
            from cli.main import cli as root_cli
            root_cli.main(args=["--no-banner", *args], prog_name="r3con", obj=ctx.obj, standalone_mode=False)
        except SystemExit:
            continue
        except click.ClickException as exc:
            console.print(f"  [bold red]Error:[/] {exc}")
        except (click.UsageError, ValueError) as exc:
            console.print(f"  [bold yellow]Usage:[/] {exc}")
