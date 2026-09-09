"""
r3con v6.0 Titan-Omega - Analyze commands
Classic + PRO unified with federated workspaces support

Supports:
- r3con analyze <target> --profile auto --workspace never/always/auto (legacy tmux)
- r3con analyze <target> --ws <name|auto> --workspace-tags tag1,tag2 (new federated)
- r3con analyze-pro <target> --profile auto --workspace auto|name --workspace-tags
- Directory targets: /home/pentagone/phase_1/lundi -> auto workspace + multi-file analysis
"""
from __future__ import annotations
import json
import time
import contextlib
import io
import re
from pathlib import Path
import click
from .helpers import console, section, info, warn, ok
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _sanitize_workspace_name(name: str) -> str:
    """Sanitize workspace name from path."""
    name = name.replace(".", "-").replace("/", "-").replace("\\", "-").replace(" ", "-").lower()
    name = "".join(c for c in name if c.isalnum() or c in "-_")
    return name[:50] or f"auto-{int(time.time())}"


def _detect_kind_from_path(path: Path) -> str:
    """Detect kind from file content."""
    try:
        if not path.is_file():
            return "custom"
        data = path.read_bytes()[:8192]
        if data.startswith(b"\x7fELF") or data.startswith(b"MZ"):
            return "binary"
        if data.startswith(b"PK\x03\x04"):
            return "apk" if b"AndroidManifest" in data or b"classes.dex" in data else "archive"
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return "network"
        if path.suffix.lower() in {".c", ".h", ".cpp", ".py", ".go", ".rs", ".java", ".js"}:
            return "source"
        return "binary" if len(data) > 100 else "custom"
    except Exception:
        return "custom"


def _get_or_create_workspace(workspace_arg: str, target: str, profile: str, tags: str, description_prefix: str = "Auto-créé"):
    """Get or create workspace, handling auto."""
    from core.workspace_manager import WorkspaceManager, WORKSPACE_TYPES

    mgr = WorkspaceManager()
    target_path = Path(target)

    # Auto: generate name from target path
    if workspace_arg == "auto":
        parts = target_path.parts
        if len(parts) > 3:
            name_parts = parts[-3:]
        else:
            name_parts = parts[-2:] if len(parts) > 1 else [target_path.name]
        ws_auto_name = "-".join(name_parts)
        ws_auto_name = _sanitize_workspace_name(ws_auto_name)
        workspace_arg = ws_auto_name
        info(f"Workspace auto: {workspace_arg} (généré depuis {target})")

    # Get or create
    try:
        ws_obj = mgr.get_workspace(workspace_arg)
        info(f"Workspace existant: {workspace_arg} | Type: {ws_obj.load_meta().get('type')} | Profile: {ws_obj.load_meta().get('profile')}")
    except FileNotFoundError:
        kind = _detect_kind_from_path(target_path) if target_path.is_file() else "custom"
        # Special handling for pentagone paths
        if "pentagone" in str(target_path).lower() or "phase" in str(target_path).lower():
            ws_type = "bugbounty"
        else:
            ws_type = kind if kind in WORKSPACE_TYPES else "custom"

        try:
            ws_obj = mgr.create_workspace(
                workspace_arg,
                ws_type=ws_type,
                profile=profile if profile != "auto" else None,
                description=f"{description_prefix} depuis {target} via r3con analyze",
                tags=[t.strip() for t in tags.split(",") if t.strip()] if tags else [],
            )
            ok(f"Workspace auto-créé: {workspace_arg} | Type: {ws_type} | Profile: {ws_obj.load_meta().get('profile')}")
            info(f"Tous les 35+ outils disponibles, priorité: {', '.join(ws_obj.load_meta().get('priority_tools', [])[:5])}")
        except Exception as e:
            warn(f"Impossible de créer workspace {workspace_arg}: {e}")
            return None, workspace_arg

    return ws_obj, workspace_arg


@click.command("analyze")
@click.argument("target", type=click.Path(exists=True), required=True)
@click.option("--profile", type=click.Choice(["auto", "quick", "binary", "network", "firmware", "apk", "dynamic", "full"]), default="auto", show_default=True)
@click.option("--timeout", default=120, show_default=True, type=click.IntRange(1, 3600))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--workers", default=3, show_default=True, type=click.IntRange(1, 8))
@click.option("--reverse-engine", type=click.Choice(["radare2", "rizin"]), default="radare2", show_default=True)
@click.option("--with-ghidra", is_flag=True, default=None, help="Run Ghidra opt-in")
@click.option("--no-cache", is_flag=True, help="Do not read/write cache")
@click.option("--cache-dir", type=click.Path(file_okay=False), help="Cache directory")
@click.option("--workspace", "workspace_mode", type=click.Choice(["never", "always", "auto"]), default="never", show_default=True, help="[LEGACY tmux] Open four-pane workspace")
@click.option("--ws", "federated_workspace", default=None, help="Workspace fédéré (nom ou auto) - NOUVEAU v5.2+ : cloisonnement + partage")
@click.option("--workspace-tags", default="", help="Tags pour cible dans workspace fédéré")
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write JSON")
def analyze_command(target, profile, timeout, max_mb, workers, reverse_engine, with_ghidra, no_cache, cache_dir, workspace_mode, federated_workspace, workspace_tags, json_output):
    """Run adaptive local orchestration pipeline (classic + federated workspaces)."""
    from modules.orchestration.orchestrator import Orchestrator

    # Federated workspace handling (new)
    ws_obj = None
    ws_name_for_save = None
    target_path = Path(target)

    if federated_workspace:
        ws_obj, ws_name_for_save = _get_or_create_workspace(
            federated_workspace, target, profile, workspace_tags, description_prefix="Auto-créé depuis"
        )

    # Backward compat: if --workspace auto used without --ws and target is dir, treat as federated auto
    if not federated_workspace and workspace_mode == "auto" and target_path.is_dir():
        info(f"Target dossier + --workspace auto → création workspace fédéré auto (nouveau comportement)")
        ws_obj, ws_name_for_save = _get_or_create_workspace(
            "auto", target, profile, workspace_tags, description_prefix="Auto-créé depuis dossier"
        )

    # Directory handling: /home/pentagone/phase_1/lundi
    targets_to_analyze = []
    if target_path.is_dir():
        info(f"Target est un dossier: {target} → analyse de tous les fichiers")
        for f in target_path.rglob("*"):
            if f.is_file() and 0 < f.stat().st_size < 500*1024*1024:
                # Filter interesting files
                if f.suffix.lower() in {".elf", ".bin", ".apk", ".pcap", ".c", ".h", ".py", ".js", ".so", ".exe", ""} or f.stat().st_size < 10*1024*1024:
                    targets_to_analyze.append(str(f))
        if len(targets_to_analyze) > 20:
            info(f"Dossier contient {len(targets_to_analyze)} fichiers, limité à 20 premiers")
            targets_to_analyze = targets_to_analyze[:20]
        if not targets_to_analyze:
            raise click.ClickException(f"Aucun fichier analysable dans dossier {target}")
        info(f"Fichiers à analyser: {len(targets_to_analyze)}")
        primary_target = targets_to_analyze[0]
    else:
        primary_target = target
        targets_to_analyze = [target]

    result = Orchestrator(primary_target, profile=profile, timeout=timeout, max_mb=max_mb, max_workers=workers, reverse_engine=reverse_engine, with_ghidra=with_ghidra, cache=not no_cache, cache_dir=cache_dir).run()

    all_findings = result.get("findings", [])[:]
    all_results = {primary_target: result}
    if len(targets_to_analyze) > 1:
        for extra_target in targets_to_analyze[1:]:
            try:
                extra_result = Orchestrator(extra_target, profile=profile, timeout=timeout, max_mb=max_mb, max_workers=workers, reverse_engine=reverse_engine, with_ghidra=with_ghidra, cache=not no_cache, cache_dir=cache_dir).run()
                all_findings.extend(extra_result.get("findings", []))
                all_results[extra_target] = extra_result
            except Exception:
                continue

    if json_output:
        Path(json_output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"Report written: {json_output}")

    section("R3CON ORCHESTRATION")
    info(f"Target: {target} ({'dossier' if target_path.is_dir() else 'fichier'})")
    info(f"Profile: {result.get('profile', profile)}" + (f" | Workspace fédéré: {ws_name_for_save}" if ws_name_for_save else ""))
    for name, value in result.get("results", {}).items():
        console.print(f"[{value.get('status', 'unknown')}] {name} — {value.get('engine', '')}")
    console.print(f"Findings: {len(all_findings)} | Duration: {result.get('duration_ms', 0)} ms" + (f" | Fichiers: {len(targets_to_analyze)}" if len(targets_to_analyze) > 1 else ""))
    if result.get("status") != "ok":
        warn(f"Overall status: {result.get('status')}")

    if ws_obj and ws_name_for_save:
        try:
            for t_path in targets_to_analyze:
                ws_obj.add_target(t_path, tags=[t.strip() for t in workspace_tags.split(",") if t.strip()] if workspace_tags else [], notes=f"Analyzed via r3con analyze --profile {profile}")
            added = ws_obj.add_findings(all_findings, source=f"analyze:{profile}")
            for t_path, res in all_results.items():
                artifact_path = ws_obj.artifacts_dir / f"{Path(t_path).name}_{int(time.time())}.json"
                try:
                    artifact_path.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
                except Exception:
                    pass
            ok(f"Résultats sauvegardés dans workspace {ws_name_for_save}: {len(targets_to_analyze)} targets, +{added} findings")
            info(f"Voir: r3con workspace show {ws_name_for_save} | Outils: r3con workspace info {ws_name_for_save} --tools")
        except Exception as e:
            warn(f"Erreur sauvegarde workspace: {e}")

    # Legacy tmux
    if workspace_mode == "always" or (workspace_mode == "auto" and result.get("profile", profile) in {"binary", "dynamic", "firmware", "network"}):
        try:
            from cli.groups.workspace import workspace_tmux
            workspace_tmux.callback(primary_target, f"r3con-{result.get('profile', profile)}", False)
        except Exception:
            pass


@click.command("analyze-pro")
@click.argument("target", type=click.Path(exists=True), required=True)
@click.option("--profile", default="auto", type=click.Choice(["auto", "quick", "deep", "full", "binary", "firmware", "apk", "network", "bugbounty", "exploit", "stealth"]), help="Profil puissant")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True), help="Fichier config YAML")
@click.option("--timeout", default=None, type=int, help="Timeout override")
@click.option("--workers", default=None, type=int, help="Workers override")
@click.option("--max-mb", default=None, type=int, help="Max file size MB override")
@click.option("--with-ghidra", is_flag=True, help="Activer Ghidra (lourd)")
@click.option("--with-angr", is_flag=True, help="Activer angr symbolic")
@click.option("--with-jadx", is_flag=True, help="Activer JADX")
@click.option("--chain/--no-chain", default=True, help="Chaînage outils externes")
@click.option("--use-pipeline/--no-pipeline", default=True, help="Use pipeline efficace")
@click.option("--workspace", "workspace_name", default=None, help="Workspace fédéré (nom ou auto) - PRO: cloisonnement + partage + tous outils par tâche")
@click.option("--ws", "workspace_alias", default=None, help="Alias pour --workspace")
@click.option("--workspace-tags", default="", help="Tags pour cible dans workspace")
@click.option("--json-output", type=click.Path(dir_okay=False), help="Rapport JSON")
def analyze_pro_command(target, profile, config_path, timeout, workers, max_mb, with_ghidra, with_angr, with_jadx, chain, use_pipeline, workspace_name, workspace_alias, workspace_tags, json_output):
    """Analyse PRO avec config puissante, 35+ outils, chaînage, pipeline, workspaces fédérés."""

    # Alias handling: --ws same as --workspace
    if workspace_alias and not workspace_name:
        workspace_name = workspace_alias

    try:
        from modules.orchestration.unified import UnifiedOrchestrator
        UNIFIED = True
    except ImportError:
        UNIFIED = False

    ws_config_overrides = {}
    ws_obj = None
    ws_name_for_save = None
    target_path = Path(target)

    # Handle directory target like /home/pentagone/phase_1/lundi
    targets_to_analyze = []
    if target_path.is_dir():
        info(f"Target dossier: {target} → analyse multi-fichiers + workspace auto si --workspace auto")
        for f in target_path.rglob("*"):
            if f.is_file() and 0 < f.stat().st_size < 500*1024*1024:
                if f.suffix.lower() in {".elf", ".bin", ".apk", ".pcap", ".c", ".h", ".py", ".js", ".so", ".exe", ""} or f.stat().st_size < 10*1024*1024:
                    targets_to_analyze.append(str(f))
        if len(targets_to_analyze) > 20:
            targets_to_analyze = targets_to_analyze[:20]
        if not targets_to_analyze:
            raise click.ClickException(f"Aucun fichier dans dossier {target}")
        primary_target = targets_to_analyze[0]
    else:
        primary_target = target
        targets_to_analyze = [target]

    if workspace_name:
        # Use original target (dossier) for workspace name if dossier, sinon primary_target
        ws_target_for_name = target if target_path.is_dir() else primary_target
        ws_obj, ws_name_for_save = _get_or_create_workspace(
            workspace_name, ws_target_for_name, profile, workspace_tags, description_prefix="Auto-créé via analyze-pro"
        )
        if ws_obj:
            ws_config_overrides = ws_obj.load_meta().get("config_overrides", {})
            if profile == "auto":
                profile = ws_obj.load_meta().get("profile", "full")
            info(f"Workspace: {ws_name_for_save} | Type: {ws_obj.load_meta().get('type')} | Profile: {profile} | Isolation: {ws_obj.load_meta().get('isolation')}")
            prio = ws_obj.load_meta().get("priority_tools", [])[:5]
            if prio:
                info(f"Priority tools pour cette tâche: {', '.join(prio)} (tous les 35+ restent accessibles)")

    if not UNIFIED:
        console.print("[yellow]Unified orchestrator non disponible, fallback[/]")
        from modules.orchestration.orchestrator import Orchestrator
        result = Orchestrator(primary_target, profile=profile, timeout=timeout or 120).run()
    else:
        overrides = {}
        overrides.update(ws_config_overrides)
        if timeout:
            overrides["analysis.timeout"] = timeout
        if workers:
            overrides["analysis.max_workers"] = workers
        if max_mb:
            overrides["analysis.max_file_size_mb"] = max_mb
        if with_ghidra:
            overrides["external_tools.enabled.ghidra"] = True
        if with_angr:
            overrides["external_tools.enabled.angr"] = True
        if with_jadx:
            overrides["external_tools.enabled.jadx"] = True
        overrides["external_tools.chaining.enabled"] = chain
        result = UnifiedOrchestrator(primary_target, profile=profile, config_path=config_path, use_pipeline=use_pipeline, **overrides).run()

    # If directory, analyze others and aggregate
    all_findings = result.get("findings", [])[:]
    all_results = {primary_target: result}
    if len(targets_to_analyze) > 1:
        for extra_target in targets_to_analyze[1:]:
            try:
                if UNIFIED:
                    extra_result = UnifiedOrchestrator(extra_target, profile=profile, config_path=config_path, use_pipeline=use_pipeline, **overrides).run()
                else:
                    from modules.orchestration.orchestrator import Orchestrator
                    extra_result = Orchestrator(extra_target, profile=profile, timeout=timeout or 120).run()
                all_findings.extend(extra_result.get("findings", []))
                all_results[extra_target] = extra_result
            except Exception:
                continue

    if json_output:
        Path(json_output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"Report written: {json_output}")

    section(f"R3CON PRO ORCHESTRATION - {profile.upper()}")
    target_info = result.get("target", {})
    if isinstance(target_info, dict):
        info(f"Target: {target_info.get('path', primary_target)} | Kind: {target_info.get('kind')} | Confidence: {target_info.get('confidence')}")
    info(f"Profile: {result.get('profile', profile)} | Chain: {'enabled' if chain else 'disabled'} | Pipeline: {'yes' if use_pipeline else 'no'}" + (f" | Workspace: {ws_name_for_save}" if ws_name_for_save else "") + (f" | Fichiers: {len(targets_to_analyze)}" if len(targets_to_analyze) > 1 else ""))

    for name, value in result.get("results", {}).items():
        if isinstance(value, dict):
            status = value.get("status", "unknown")
            engine = value.get("engine", "")
            color = "green" if status == "ok" else "yellow" if status == "partial" else "red"
            console.print(f"[{color}][{status}][/{color}] {name:20} — {engine}")

    console.print(f"\n[bold]Findings:[/] {len(all_findings)} | [bold]Duration:[/] {result.get('duration_ms', 0)} ms | [bold]Status:[/] {result.get('status')}")
    tool_summary = result.get("tool_summary", {})
    if tool_summary:
        console.print(f"[dim]Tools: {tool_summary.get('present', 0)}/{tool_summary.get('total', 0)} available[/]")

    if ws_obj and ws_name_for_save:
        try:
            for t_path in targets_to_analyze:
                ws_obj.add_target(t_path, kind=_detect_kind_from_path(Path(t_path)), tags=[t.strip() for t in workspace_tags.split(",") if t.strip()] if workspace_tags else [], notes=f"Analyzed with profile {profile}")
            added = ws_obj.add_findings(all_findings, source=f"analyze-pro:{profile}")
            for t_path, res in all_results.items():
                artifact_path = ws_obj.artifacts_dir / f"{Path(t_path).name}_{int(time.time())}.json"
                try:
                    artifact_path.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
                except Exception:
                    pass
            ok(f"Résultats sauvegardés dans workspace {ws_name_for_save}: {len(targets_to_analyze)} targets, +{added} findings")
            info(f"Voir: r3con workspace show {ws_name_for_save} | Outils: r3con workspace info {ws_name_for_save} --tools")
            info(f"Partage: r3con workspace share {ws_name_for_save} <other_ws> --items findings,targets")
        except Exception as e:
            warn(f"Erreur sauvegarde workspace: {e}")

    from .helpers import show_findings
    show_findings(all_findings[:20])


@click.command("benchmark")
@click.argument("target", type=click.Path(exists=True), required=True)
@click.option("--profile", type=click.Choice(["quick", "binary", "network", "firmware", "source", "apk", "full"]), default="quick", show_default=True)
@click.option("--runs", default=3, type=click.IntRange(1, 20), show_default=True)
@click.option("--no-cache", is_flag=True, help="Benchmark without cache")
def benchmark_command(target, profile, runs, no_cache):
    from modules.orchestration.orchestrator import Orchestrator
    durations = []
    for _ in range(runs):
        started = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = Orchestrator(target, profile=profile, cache=not no_cache).run()
        durations.append(round((time.perf_counter() - started) * 1000, 2))
    payload = {"target": target, "profile": profile, "runs": runs, "durations_ms": durations, "min_ms": min(durations), "max_ms": max(durations), "avg_ms": round(sum(durations) / len(durations), 2), "cache": not no_cache, "last_status": result.get("status")}
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@click.command("correlate")
@click.argument("firmware_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("pcap_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write correlation JSON")
def correlate_command(firmware_path, pcap_path, max_mb, json_output):
    from modules.integration.firmware_pcap_correlation import correlate
    result = correlate(firmware_path, pcap_path, max_mb=max_mb)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
        return
    console.print_json(payload)


@click.command("diff")
@click.argument("old_binary", type=click.Path(exists=True, dir_okay=False))
@click.argument("new_binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write comparison JSON")
def diff_command(old_binary, new_binary, json_output):
    from modules.integration.binary_diff import compare_binaries
    result = compare_binaries(old_binary, new_binary)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
        return
    console.print_json(payload)
