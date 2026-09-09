"""High-level commands for repeatable, explainable security workflows."""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

import click

from .helpers import console, info, ok, section, warn


def _target_kind(path: Path) -> str:
    if path.is_dir():
        return "directory"
    try:
        head = path.read_bytes()[:8192]
    except OSError:
        return "unknown"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"PK\x03\x04"):
        return "archive/apk"
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return "pcap"
    if path.suffix.lower() in {".py", ".c", ".h", ".cpp", ".go", ".rs", ".js", ".java"}:
        return "source"
    return "file"


def _profile_for(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    kind = _target_kind(path)
    return {"elf": "binary", "pe": "binary", "archive/apk": "apk", "pcap": "network", "source": "source"}.get(kind, "quick")


def _write_json(path: str | None, payload: dict) -> None:
    if path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        ok(f"Rapport écrit : {output}")


@click.command("scan")
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--profile", type=click.Choice(["auto", "quick", "binary", "network", "firmware", "apk", "dynamic", "full", "source"]), default="auto", show_default=True)
@click.option("--timeout", default=120, type=click.IntRange(1, 3600), show_default=True)
@click.option("--workers", default=3, type=click.IntRange(1, 16), show_default=True)
@click.option("--max-mb", default=256, type=click.IntRange(1, 4096), show_default=True)
@click.option("--no-cache", is_flag=True, help="Désactiver le cache")
@click.option("--explain-plan", is_flag=True, help="Afficher le type de cible et le profil choisi")
@click.option("--json-output", type=click.Path(dir_okay=False), help="Écrire le rapport JSON")
def scan_command(target, profile, timeout, workers, max_mb, no_cache, explain_plan, json_output):
    """Lancer une analyse adaptative reproductible sur un fichier ou un dossier."""
    from modules.orchestration.orchestrator import Orchestrator

    selected = _profile_for(target, profile)
    if explain_plan:
        info(f"Cible : {_target_kind(target)} | Profil sélectionné : {selected}")
        info(f"Mode : {'avec cache' if not no_cache else 'sans cache'} | Workers : {workers} | Timeout : {timeout}s")
    started = time.perf_counter()
    targets = [target]
    if target.is_dir():
        targets = [p for p in sorted(target.rglob("*")) if p.is_file() and p.stat().st_size <= max_mb * 1024 * 1024][:20]
        if not targets:
            raise click.ClickException("Aucun fichier analysable dans le dossier")
    reports = []
    for item in targets:
        try:
            reports.append(Orchestrator(str(item), profile=selected, timeout=timeout, max_mb=max_mb, max_workers=workers, cache=not no_cache).run())
        except Exception as exc:
            reports.append({"schema_version": "2.0", "status": "error", "target": str(item), "error": str(exc), "findings": []})
    findings = [f for report in reports for f in report.get("findings", [])]
    payload = reports[0] if len(reports) == 1 else {"schema_version": "2.0", "status": "ok", "profile": selected, "target": str(target), "reports": reports, "findings": findings}
    payload["scan_meta"] = {"target_kind": _target_kind(target), "targets_count": len(targets), "duration_ms": round((time.perf_counter() - started) * 1000, 2), "profile_selected": selected}
    _write_json(json_output, payload)
    section("R3CON SCAN")
    info(f"Cible : {target} | Profil : {selected}")
    console.print(f"Findings : {len(findings)} | Durée : {payload['scan_meta']['duration_ms']} ms | Fichiers : {len(targets)}")
    if any(r.get("status") == "error" for r in reports):
        warn("Une ou plusieurs analyses ont échoué ; consultez le rapport JSON.")
    return payload


@click.command("doctor")
def doctor_command():
    """Diagnostiquer les moteurs locaux et indiquer les fallbacks actifs."""
    tools = [
        ("file", "Détection de format"), ("strings", "Chaînes embarquées"), ("readelf", "Métadonnées ELF"),
        ("objdump", "Désassemblage"), ("checksec", "Protections binaires"), ("r2", "Reverse engineering"),
        ("rizin", "Reverse engineering alternatif"), ("gdb", "Analyse dynamique"), ("binwalk", "Firmware"),
        ("tshark", "PCAP/réseau"), ("nuclei", "Scanner web"), ("ghidra", "Décompilation avancée"),
    ]
    available = []
    for command, purpose in tools:
        found = shutil.which(command)
        entry = {"tool": command, "purpose": purpose, "available": bool(found), "path": found or ""}
        available.append(entry)
        state = "green" if found else "yellow"
        label = "available" if found else "fallback"
        console.print(f"[{state}]{command:10} {label:8}[/{state}] {purpose}")
    payload = {"schema_version": "1.0", "tools": available, "available": sum(x["available"] for x in available), "total": len(available)}
    console.print(f"\nDisponibles : {payload['available']}/{payload['total']}")
    return payload


@click.group("reports")
def reports_group():
    """Comparer et inspecter les rapports r3con."""


@reports_group.command("compare")
@click.argument("old_report", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new_report", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json-output", type=click.Path(dir_okay=False), help="Écrire la comparaison JSON")
def compare_reports_command(old_report, new_report, json_output):
    """Comparer les findings de deux rapports JSON."""
    try:
        old = json.loads(old_report.read_text(encoding="utf-8"))
        new = json.loads(new_report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"Rapport JSON invalide : {exc}") from exc

    def key(finding):
        if finding.get("id"):
            return str(finding["id"])
        raw = "|".join(str(finding.get(k, "")) for k in ("type", "finding_type", "target", "description", "file", "line"))
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    old_map = {key(f): f for f in old.get("findings", [])}
    new_map = {key(f): f for f in new.get("findings", [])}
    result = {"schema_version": "1.0", "old": str(old_report), "new": str(new_report), "added": [new_map[k] for k in new_map.keys() - old_map.keys()], "removed": [old_map[k] for k in old_map.keys() - new_map.keys()], "unchanged": len(old_map.keys() & new_map.keys())}
    _write_json(json_output, result)
    console.print(f"Ajoutés : {len(result['added'])} | Supprimés : {len(result['removed'])} | Inchangés : {result['unchanged']}")
    return result
