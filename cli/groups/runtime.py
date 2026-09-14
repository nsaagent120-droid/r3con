"""Commandes CLI pour lancer des outils externes dans un workspace borné."""
from __future__ import annotations

import json
import shlex
import click

from .helpers import console, ok, warn
from modules.integration.execution_workspace import ExecutionWorkspace, WorkspaceLimits


@click.group("runtime")
def runtime_group():
    """Exécution contrôlée d'outils externes dans un workspace privé."""


@runtime_group.command("run")
@click.argument("command", nargs=-1, required=True)
@click.option("--timeout", type=click.IntRange(1, 86400), default=300, show_default=True)
@click.option("--allow-network", is_flag=True, help="Autoriser le réseau; à utiliser uniquement en laboratoire contrôlé.")
@click.option("--lenient-network", is_flag=True, help="Continuer même si l'isolation réseau n'est pas disponible.")
@click.option("--json-output", is_flag=True, help="Afficher uniquement le résultat JSON.")
def runtime_run(command, timeout, allow_network, lenient_network, json_output):
    """Lancer COMMAND dans un répertoire privé avec limites."""
    limits = WorkspaceLimits(
        wall_timeout_s=timeout,
        allow_network=allow_network,
        strict_network=not lenient_network,
    )
    try:
        with ExecutionWorkspace(limits=limits) as workspace:
            job_id = workspace.start(list(command))
            result = workspace.status(job_id)
            while result["status"] == "running":
                result = workspace.status(job_id)
            if json_output:
                console.print_json(json.dumps(result, ensure_ascii=False))
            else:
                console.print(f"[cyan]Job[/] {job_id} · [bold]{result['status']}[/]")
                if result["stdout"]:
                    console.print(result["stdout"], end="")
                if result["stderr"]:
                    warn(result["stderr"][:4000])
            if result["status"] not in {"ok"}:
                raise click.exceptions.Exit(1)
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


@runtime_group.command("parse")
@click.argument("command_line")
def runtime_parse(command_line):
    """Afficher la séparation argv appliquée à une ligne de commande."""
    try:
        console.print_json(json.dumps({"argv": shlex.split(command_line)}, ensure_ascii=False))
    except ValueError as exc:
        raise click.ClickException(f"ligne invalide: {exc}") from exc
