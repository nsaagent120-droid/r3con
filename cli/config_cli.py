"""
r3con v5.0.3 PRO - Config CLI
Gestion de la configuration puissante
"""
import click
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.config_manager import get_config, ConfigManager

console = Console()

@click.group()
def config():
    """Gestion de la configuration puissante et profils."""


@config.command("show")
@click.option("--profile", default=None, help="Profil à afficher")
@click.option("--json-output", is_flag=True, help="Sortie JSON")
def config_show(profile, json_output):
    """Afficher la configuration actuelle."""
    cfg = get_config(profile=profile, force_reload=True)

    if json_output:
        click.echo(json.dumps(cfg.to_dict(), indent=2, ensure_ascii=False))
        return

    # Show summary
    console.print(Panel(f"[bold cyan]r3con v{cfg.get('version')} - Profile: {cfg.profile_name}[/]\n"
                        f"Config: {cfg.config_path or 'defaults only'}",
                        title="Configuration", border_style="cyan"))

    # Main settings
    t = Table(box=box.SIMPLE_HEAVY, title="Analyse")
    t.add_column("Paramètre", style="cyan")
    t.add_column("Valeur", style="white")
    t.add_row("Timeout", str(cfg.get("analysis.timeout")))
    t.add_row("Max workers", str(cfg.get("analysis.max_workers")))
    t.add_row("Max file size", f"{cfg.get('analysis.max_file_size_mb')} MB")
    t.add_row("Cache", "enabled" if cfg.get_bool("analysis.cache_enabled") else "disabled")
    t.add_row("Parallel", "yes" if cfg.get_bool("analysis.parallel") else "no")
    console.print(t)

    # Limits
    t2 = Table(box=box.SIMPLE_HEAVY, title="Limites")
    t2.add_column("Limite", style="cyan")
    t2.add_column("Valeur", style="white")
    t2.add_row("Max strings", str(cfg.get("limits.max_strings")))
    t2.add_row("Max findings", str(cfg.get("limits.max_findings")))
    t2.add_row("Max functions", str(cfg.get("limits.max_functions")))
    t2.add_row("Max depth", str(cfg.get("limits.max_depth")))
    console.print(t2)

    # External tools
    t3 = Table(box=box.SIMPLE_HEAVY, title="Outils externes")
    t3.add_column("Catégorie", style="cyan")
    t3.add_column("Préféré", style="white")
    t3.add_column("Enabled", style="green")
    for cat in ["disasm", "decompiler", "firmware", "apk", "network", "dynamic"]:
        pref = cfg.get(f"external_tools.prefer.{cat}", "auto")
        enabled = []
        for tool, en in cfg.get("external_tools.enabled", {}).items():
            if en:
                enabled.append(tool)
        t3.add_row(cat, pref, ", ".join(enabled[:5]) + ("..." if len(enabled) > 5 else ""))
    console.print(t3)


@config.command("profiles")
def config_profiles():
    """Lister tous les profils disponibles."""
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
    console.print("\n[dim]Usage: r3con analyze --profile full ./binary[/] ou [cyan]export R3CON_PROFILE=full[/]")


@config.command("path")
def config_path():
    """Afficher les chemins de configuration."""
    cfg = get_config(force_reload=True)

    console.print(Panel(
        f"[cyan]Config actuelle:[/] {cfg.config_path or 'defaults (aucun fichier)'}\n"
        f"[cyan]Profile:[/] {cfg.profile_name}\n"
        f"[cyan]Recherche dans:[/]\n"
        f"  - ./config.yaml\n"
        f"  - ./r3con.yaml\n"
        f"  - ~/.r3con/config.yaml\n"
        f"  - ~/.config/r3con/config.yaml\n"
        f"  - /etc/r3con/config.yaml\n"
        f"  - $R3CON_CONFIG\n",
        title="Chemins de configuration", border_style="cyan"
    ))


@config.command("init")
@click.option("--output", default="~/.r3con/config.yaml", help="Fichier de sortie")
@click.option("--profile", default="deep", type=click.Choice(["quick", "deep", "full", "binary", "firmware", "apk", "network", "bugbounty"]), help="Profil de base")
def config_init(output, profile):
    """Créer un fichier de configuration personnalisé."""
    from pathlib import Path
    import shutil

    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Copy pro config as template
    pro_config = Path(__file__).parent.parent / "config.pro.yaml"
    if pro_config.is_file():
        shutil.copy(pro_config, output_path)
        console.print(f"[green]✓[/] Config PRO copiée vers {output_path}")
    else:
        # Create minimal
        cfg = ConfigManager(profile=profile)
        cfg.save(str(output_path))
        console.print(f"[green]✓[/] Config créée vers {output_path}")

    console.print(f"[cyan]Profile de base:[/] {profile}")
    console.print(f"[dim]Éditez {output_path} puis: r3con config show[/]")


@config.command("validate")
@click.option("--file", "config_file", default=None, help="Fichier à valider")
def config_validate(config_file):
    """Valider un fichier de configuration."""
    try:
        cfg = ConfigManager(config_path=config_file, profile="auto")
        console.print(f"[green]✓[/] Configuration valide")
        console.print(f"  Version: {cfg.get('version')}")
        console.print(f"  Profile: {cfg.profile_name}")
        console.print(f"  Path: {cfg.config_path}")
        console.print(f"  Workers: {cfg.get('analysis.max_workers')}")
        console.print(f"  Timeout: {cfg.get('analysis.timeout')}s")
    except Exception as e:
        console.print(f"[red]✗[/] Erreur de validation: {e}")
        raise click.ClickException(str(e))


@config.command("env")
def config_env():
    """Afficher les variables d'environnement supportées."""
    t = Table(box=box.SIMPLE_HEAVY, title="Variables d'environnement R3CON_*")
    t.add_column("Variable", style="cyan", width=30)
    t.add_column("Description", style="white")
    t.add_column("Exemple", style="dim")

    env_vars = [
        ("R3CON_CONFIG", "Chemin config YAML", "/home/user/.r3con/config.yaml"),
        ("R3CON_PROFILE", "Profil actif", "full, deep, quick, binary..."),
        ("R3CON_TIMEOUT", "Timeout global", "300"),
        ("R3CON_MAX_WORKERS", "Workers parallèles", "8"),
        ("R3CON_CACHE_DIR", "Dossier cache", "~/.cache/r3con"),
        ("R3CON_TOOL_GHIDRA", "Chemin Ghidra", "/opt/ghidra/support/analyzeHeadless"),
        ("R3CON_TOOL_JADX", "Chemin JADX", "/opt/jadx/bin/jadx"),
        ("R3CON_EXPERT_MODE", "Mode expert", "true/false"),
        ("R3CON_MULTI_AI", "Multi-AI", "true/false"),
        ("R3CON_THEME", "Thème CLI", "cyber, matrix, amber, mono"),
        ("R3CON_NO_COLOR", "Sans couleur", "1"),
        ("R3CON_ANALYSIS_MAX_FILE_SIZE_MB", "Taille max", "1024"),
        ("R3CON_LIMITS_MAX_FINDINGS", "Max findings", "50000"),
        ("R3CON_EXTERNAL_TOOLS_ENABLED_GHIDRA", "Activer Ghidra", "true"),
    ]

    for var, desc, example in env_vars:
        t.add_row(var, desc, example)

    console.print(t)
    console.print("\n[dim]Toutes les options YAML sont surchargeables via R3CON_<SECTION>_<OPTION>[/]")
    console.print("[dim]Exemple: R3CON_ANALYSIS_TIMEOUT=300, R3CON_FIRMWARE_EXTRACT=true[/]")
