"""Config group - PRO configuration management."""
from __future__ import annotations
from pathlib import Path
import json
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, VERSION
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.config_manager import get_config, ConfigManager

@click.group()
def config():
    """Gestion de la configuration puissante et profils PRO."""

@config.command("show")
@click.option("--profile", default=None, help="Profil à afficher")
@click.option("--json-output", is_flag=True, help="Sortie JSON")
def config_show(profile, json_output):
    cfg = get_config(profile=profile, force_reload=True)
    if json_output:
        click.echo(json.dumps(cfg.to_dict(), indent=2, ensure_ascii=False))
        return
    console.print(Panel(f"[bold cyan]r3con v{cfg.get('version')} - Profile: {cfg.profile_name}[/]\nConfig: {cfg.config_path or 'defaults only'}", title="Configuration", border_style="cyan"))
    t = Table(box=box.SIMPLE_HEAVY, title="Analyse")
    t.add_column("Paramètre", style="cyan")
    t.add_column("Valeur", style="white")
    t.add_row("Timeout", str(cfg.get("analysis.timeout")))
    t.add_row("Max workers", str(cfg.get("analysis.max_workers")))
    t.add_row("Max file size", f"{cfg.get('analysis.max_file_size_mb')} MB")
    t.add_row("Cache", "enabled" if cfg.get_bool("analysis.cache_enabled") else "disabled")
    console.print(t)
    t2 = Table(box=box.SIMPLE_HEAVY, title="Limites")
    t2.add_column("Limite", style="cyan")
    t2.add_column("Valeur", style="white")
    t2.add_row("Max strings", str(cfg.get("limits.max_strings")))
    t2.add_row("Max findings", str(cfg.get("limits.max_findings")))
    t2.add_row("Max functions", str(cfg.get("limits.max_functions")))
    console.print(t2)

@config.command("profiles")
def config_profiles():
    cfg = get_config(force_reload=True)
    profiles = cfg.get("profiles", {})
    t = Table(box=box.SIMPLE_HEAVY, title="Profils disponibles")
    t.add_column("Profil", style="bold cyan", width=12)
    t.add_column("Description", style="white")
    t.add_column("Workers", style="dim", width=8)
    t.add_column("Timeout", style="dim", width=8)
    for name, data in profiles.items():
        desc = data.get("description", "")[:50]
        workers = str(data.get("analysis", {}).get("max_workers", cfg.get("analysis.max_workers")))
        timeout = str(data.get("analysis", {}).get("timeout", cfg.get("analysis.timeout")))
        style = "bold green" if name == cfg.profile_name else "white"
        t.add_row(f"[{style}]{name}[/{style}]", desc, workers, timeout)
    console.print(t)
    console.print("\n[dim]Usage: r3con analyze --profile full ./binary[/]")

@config.command("init")
@click.option("--output", default="~/.r3con/config.yaml", help="Fichier de sortie")
@click.option("--profile", default="deep", type=click.Choice(["quick", "deep", "full", "binary", "firmware", "apk", "network", "bugbounty"]), help="Profil de base")
def config_init(output, profile):
    import shutil
    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pro_config = Path(__file__).parent.parent.parent / "config.pro.yaml"
    if pro_config.is_file():
        shutil.copy(pro_config, output_path)
        console.print(f"[green]✓[/] Config PRO copiée vers {output_path}")
    else:
        cfg = ConfigManager(profile=profile)
        cfg.save(str(output_path))
        console.print(f"[green]✓[/] Config créée vers {output_path}")

@config.command("env")
def config_env():
    t = Table(box=box.SIMPLE_HEAVY, title="Variables d'environnement R3CON_*")
    t.add_column("Variable", style="cyan", width=32)
    t.add_column("Description", style="white")
    t.add_column("Exemple", style="dim")
    env_vars = [("R3CON_CONFIG", "Chemin config YAML", "~/.r3con/config.yaml"),("R3CON_PROFILE", "Profil actif", "full, deep, quick..."),("R3CON_TIMEOUT", "Timeout global", "300"),("R3CON_TOOL_GHIDRA", "Chemin Ghidra", "/opt/ghidra/..."),("R3CON_TOOL_JADX", "Chemin JADX", "/opt/jadx/bin/jadx"),("R3CON_EXPERT_MODE", "Mode expert", "true/false"),("R3CON_ANALYSIS_MAX_FILE_SIZE_MB", "Taille max", "1024")]
    for var, desc, ex in env_vars:
        t.add_row(var, desc, ex)
    console.print(t)
