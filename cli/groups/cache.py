"""Commandes de diagnostic et de maintenance des caches r3con."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import click

from core.cache import CACHE_FILE, CACHE_DIR, IncrementalCache, TaskCache
from .helpers import console, ok, warn


@click.group("cache")
def cache_group():
    """Inspecter et administrer les caches locaux de r3con."""


@cache_group.command("status")
@click.option("--json-output", is_flag=True, help="Afficher uniquement le JSON.")
def cache_status(json_output: bool):
    """Afficher les entrées, la taille et les versions des caches."""
    file_cache = IncrementalCache()
    task_cache = TaskCache()
    payload = {
        "file_cache": file_cache.stats(),
        "task_cache": task_cache.stats(),
    }
    if json_output:
        console.print_json(json.dumps(payload, ensure_ascii=False))
        return
    console.print(f"[cyan]Cache fichiers[/] : {payload['file_cache']['total_entries']} entrées, "
                  f"{payload['file_cache']['cache_size_kb']} KiB, "
                  f"TTL {payload['file_cache']['ttl_days']} jours")
    console.print(f"[cyan]Cache tâches[/]  : {payload['task_cache']['dir']} "
                  f"(hits {payload['task_cache']['hits']}, misses {payload['task_cache']['misses']})")
    if file_cache.last_error or task_cache.last_error:
        warn(f"Erreur cache : {file_cache.last_error or task_cache.last_error}")


@cache_group.command("clear")
@click.option("--yes", is_flag=True, help="Confirmer la suppression sans question interactive.")
def cache_clear(yes: bool):
    """Supprimer les résultats de cache locaux (action destructive mais réversible par un nouveau scan)."""
    if not yes and not click.confirm("Supprimer les caches locaux r3con ?"):
        click.echo("Annulé.")
        return
    IncrementalCache().clear()
    task_dir = CACHE_DIR / "tasks"
    if task_dir.exists():
        shutil.rmtree(task_dir)
    ok("Caches r3con supprimés.")


@cache_group.command("verify")
@click.option("--json-output", is_flag=True, help="Afficher uniquement le JSON.")
def cache_verify(json_output: bool):
    """Vérifier que les fichiers de cache sont lisibles et cohérents."""
    file_cache = IncrementalCache()
    task_cache = TaskCache()
    task_files = list(task_cache.dir.rglob("*.json")) if task_cache.dir.exists() else []
    payload = {
        "ok": not file_cache.last_error and not task_cache.last_error,
        "file_cache": file_cache.stats(),
        "task_files": len(task_files),
    }
    if json_output:
        console.print_json(json.dumps(payload, ensure_ascii=False))
    elif payload["ok"]:
        ok(f"Cache valide : {payload['file_cache']['total_entries']} entrées fichiers, {len(task_files)} tâches.")
    else:
        warn("Le cache présente une erreur ; consultez `r3con cache status`.")
        raise click.exceptions.Exit(1)
