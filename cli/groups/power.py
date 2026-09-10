"""High-level commands for repeatable, explainable security workflows.

- ``r3con scan``            : analyse adaptative avec plan explicable, reprise,
                              cache versionné et porte de sévérité.
- ``r3con tools doctor``    : diagnostic des outils externes + versions.
- ``r3con reports compare`` : comparaison de deux rapports (ajoutés/supprimés/modifiés).
- ``r3con compare``         : analyse différentielle de deux cibles (binaire/APK/…).
- ``r3con explain``         : explication citée d'un finding, incertitudes incluses.
- ``r3con summarize``       : résumé de risque d'un rapport.
- ``r3con ask``             : questions/réponses corrélées, 100 % locales.
"""
from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import click

from .helpers import console, info, ok, section, warn

FAIL_ON_LEVELS = {"critical": ["CRITICAL"],
                  "high": ["CRITICAL", "HIGH"],
                  "medium": ["CRITICAL", "HIGH", "MEDIUM"]}


def _target_kind(path: Path) -> str:
    """Classification lisible de cible ; valeurs historiques préservées."""
    if path.is_dir():
        return "directory"
    from core.target_types import (
        KIND_APK,
        KIND_BINARY,
        KIND_FIRMWARE,
        KIND_NETWORK,
        KIND_SOURCE,
        detect_target,
    )
    t = detect_target(path)
    if "pe" in t.types:
        return "pe"
    if t.kind == KIND_BINARY:
        return "elf" if "elf64" in t.types or "elf32" in t.types else t.types[0] if t.types else "binary"
    if t.kind in (KIND_APK,):
        return "archive/apk"
    if t.kind == KIND_NETWORK:
        return "pcap"
    if t.kind == KIND_SOURCE:
        return "source"
    if t.kind == KIND_FIRMWARE:
        return "firmware"
    return "file"


def _profile_for(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    kind = _target_kind(path)
    return {"elf": "binary", "pe": "binary", "archive/apk": "apk", "pcap": "network",
            "source": "source", "firmware": "firmware"}.get(kind, "quick")


def _write_json(path: str | None, payload: dict) -> None:
    if path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        ok(f"Rapport écrit : {output}")


def apply_fail_on(ctx: click.Context, findings: list[dict], level: str | None) -> None:
    """Interrompt avec le code 2 si un finding non-exclu atteint le seuil.

    Le code 2 distingue explicitement un « gate de sévérité » d'une erreur
    d'exécution (code 1). Les faux positifs marqués par revue ne bloquent pas.
    """
    if not level:
        return
    wanted = FAIL_ON_LEVELS.get(str(level).lower(), [])
    blocking = [f for f in findings
                if str(f.get("severity", "")).upper() in wanted
                and str(f.get("status", "")).lower().replace("_", "-") != "false-positive"]
    if blocking:
        worst = min(blocking, key=lambda f: wanted.index(str(f.get("severity", "")).upper()))
        warn(f"--fail-on {level} : {len(blocking)} finding(s) au moins {level.upper()} "
             f"(exemple : {worst.get('type') or worst.get('finding_type')})")
        ctx.exit(2)


def _report_meta(reports: list[dict], started: float, targets_count: int, selected: str,
                 kind: str, resume_dir: str | None) -> dict:
    """Métadonnées de reporting : reproductibilité et limites appliquées."""
    from core.__version__ import __version__
    from core.result_schema import SCHEMA_VERSION
    fallbacks = sorted({t for r in reports for t in (r.get("fallbacks_used") or [])})
    tool_versions: dict[str, str] = {}
    for r in reports:
        for row in r.get("tool_inventory") or []:
            if isinstance(row, dict) and row.get("present"):
                tool_versions[str(row.get("key"))] = str(row.get("version") or "installed")
    limits = (reports[0].get("config_snapshot") or {}) if reports else {}
    durations = [r.get("duration_ms") for r in reports if isinstance(r.get("duration_ms"), (int, float))]
    return {
        "r3con_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "profile": selected,
        "target_kind": kind,
        "targets_count": targets_count,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "total_analysis_ms": int(sum(durations)) if durations else None,
        "fallbacks_used": fallbacks,
        "tool_versions": dict(sorted(tool_versions.items())),
        "limits_applied": limits.get("limits") or {},
        "cache_enabled": bool(limits.get("cache", True)),
        "resumed_from": resume_dir,
        "offline": all((r.get("config_snapshot") or {}).get("offline", False) for r in reports) if reports else False,
    }


def _print_plan(target: Path, report: dict) -> None:
    """Affiche le plan explicable produit par l'orchestrateur."""
    tgt = report.get("target") or {}
    info(f"Détection : {tgt.get('description', _target_kind(target))}")
    plan_details = report.get("plan_details") or []
    if plan_details:
        console.print("  Plan :")
        for entry in plan_details:
            state = "⏭  ignoré (outil absent)" if entry.get("skipped") else \
                ("↩ repli interne" if entry.get("fallback") else "✓ disponible")
            tool = entry.get("tool", "r3con")
            reason = entry.get("reason", "")
            console.print(f"    - {entry.get('task'):<18} [{tool}] {state} — {reason}")
            if entry.get("install_hint") and entry.get("skipped"):
                console.print(f"      ↳ conseil : {entry['install_hint']}")
    for w in report.get("warnings") or []:
        warn(f"Limite : tâche '{w}' ignorée, outil externe non installé")


@click.command("scan")
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--profile", type=click.Choice(["auto", "quick", "binary", "network", "firmware", "apk", "dynamic", "full", "source"]), default="auto", show_default=True)
@click.option("--timeout", default=120, type=click.IntRange(1, 3600), show_default=True)
@click.option("--workers", default=3, type=click.IntRange(1, 16), show_default=True)
@click.option("--max-mb", default=256, type=click.IntRange(1, 4096), show_default=True)
@click.option("--no-cache", is_flag=True, help="Désactiver le cache")
@click.option("--explain-plan", is_flag=True, help="Afficher le type de cible et le profil choisi")
@click.option("--plan-only", "--dry-run", "plan_only", is_flag=True, help="Afficher le plan détaillé sans exécuter de module")
@click.option("--resume", type=click.Path(exists=True, file_okay=False, path_type=Path), default=None, help="Reprendre un run interrompu (répertoire d'artefacts)")
@click.option("--offline", is_flag=True, help="Désactive toute intégration distante pendant l'analyse")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium"]), default=None, help="Code de sortie 2 si un finding atteint ce seuil")
@click.option("--json-output", type=click.Path(dir_okay=False), help="Écrire le rapport JSON")
@click.pass_context
def scan_command(ctx, target, profile, timeout, workers, max_mb, no_cache, explain_plan,
                 plan_only, resume, offline, fail_on, json_output):
    """Lancer une analyse adaptative reproductible sur un fichier ou un dossier."""
    from modules.orchestration.orchestrator import Orchestrator

    selected = _profile_for(target, profile)
    if explain_plan:
        info(f"Cible : {_target_kind(target)} | Profil sélectionné : {selected}")
        info(f"Mode : {'avec cache' if not no_cache else 'sans cache'} | Workers : {workers} | Timeout : {timeout}s")
        if resume:
            info(f"Reprise depuis : {resume}")
    started = time.perf_counter()
    targets = [target]
    if target.is_dir():
        targets = [p for p in sorted(target.rglob("*")) if p.is_file() and p.stat().st_size <= max_mb * 1024 * 1024][:20]
        if not targets:
            raise click.ClickException("Aucun fichier analysable dans le dossier")
    reports = []
    for item in targets:
        kwargs = {"profile": selected, "timeout": timeout, "max_mb": max_mb,
                  "max_workers": workers, "cache": not no_cache}
        if offline:
            kwargs["analysis.offline"] = True
        if resume and len(targets) == 1:
            kwargs["resume_dir"] = str(resume)
        try:
            if plan_only:
                orchestrator = Orchestrator(str(item), **kwargs)
                orchestrator.explain_only = True
                reports.append(orchestrator.run())
            else:
                reports.append(Orchestrator(str(item), **kwargs).run())
        except Exception as exc:
            from core.result_schema import SCHEMA_VERSION
            reports.append({"schema_version": SCHEMA_VERSION, "status": "error",
                            "target": str(item), "error": str(exc), "findings": []})
    if plan_only:
        if explain_plan or True:
            section("R3CON SCAN — PLAN")
            for report in reports:
                tgt = report.get("target") or {}
                console.print(f"[cyan]{tgt.get('path', target)}[/cyan] — profil {report.get('profile')}")
                _print_plan(Path(tgt.get("path", target)), report)
            info("Aucun module exécuté (--plan-only).")
        return reports[0] if len(reports) == 1 else {"reports": reports}
    findings = [f for report in reports for f in report.get("findings", [])]
    payload = reports[0] if len(reports) == 1 else {"schema_version": "2.0", "status": "ok", "profile": selected, "target": str(target), "reports": reports, "findings": findings}
    payload["scan_meta"] = {"target_kind": _target_kind(target), "targets_count": len(targets), "duration_ms": round((time.perf_counter() - started) * 1000, 2), "profile_selected": selected}
    payload["report_meta"] = _report_meta(reports, started, len(targets), selected, _target_kind(target), str(resume) if resume else None)
    _write_json(json_output, payload)
    section("R3CON SCAN")
    info(f"Cible : {target} | Profil : {selected}")
    if explain_plan:
        _print_plan(target, payload if len(reports) == 1 else reports[0])
    cache_hits = (payload.get("cache_stats") or {}).get("hits")
    hits_line = f" | Cache : {cache_hits} tâche(s) réutilisée(s)" if cache_hits else ""
    console.print(f"Findings : {len(findings)} | Durée : {payload['scan_meta']['duration_ms']} ms | Fichiers : {len(targets)}{hits_line}")
    if any(r.get("status") == "error" for r in reports):
        warn("Une ou plusieurs analyses ont échoué ; consultez le rapport JSON.")
    apply_fail_on(ctx, findings, fail_on)
    return payload


@click.command("doctor")
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Écrire le diagnostic JSON")
def doctor_command(json_output):
    """Diagnostiquer les moteurs locaux et indiquer les fallbacks actifs."""
    tools = [
        ("file", "Détection de format"), ("strings", "Chaînes embarquées"), ("readelf", "Métadonnées ELF"),
        ("objdump", "Désassemblage"), ("checksec", "Protections binaires"), ("r2", "Reverse engineering"),
        ("rizin", "Reverse engineering alternatif"), ("gdb", "Analyse dynamique"), ("binwalk", "Firmware"),
        ("tshark", "PCAP/réseau"), ("nuclei", "Scanner web"), ("ghidra", "Décompilation avancée"),
    ]
    versions: dict[str, str] = {}
    try:
        from modules.integration.tool_manager import ToolManager
        for row in ToolManager().inspect():
            if row.get("present"):
                versions[str(row.get("key"))] = str(row.get("version") or "installed")
    except Exception:
        pass
    available = []
    for command, purpose in tools:
        found = shutil.which(command)
        version = versions.get(command) or versions.get({"r2": "r2", "rizin": "rizin"}.get(command, ""))
        entry = {"tool": command, "purpose": purpose, "available": bool(found),
                 "path": found or "", "version": version or ("inconnue" if found else None)}
        available.append(entry)
        state = "green" if found else "yellow"
        label = "available" if found else "fallback"
        suffix = f" — {entry['version']}" if entry.get("version") else ""
        console.print(f"[{state}]{command:10} {label:8}[/{state}] {purpose}{suffix}")
    python_features = {
        "capstone": bool(shutil.which("r2")) or _module_available("capstone"),
        "lief": _module_available("lief"),
        "yara-python": _module_available("yara"),
        "z3": _module_available("z3"),
    }
    console.print("\n[bold]Bibliothèques Python optionnelles :[/bold]")
    for name, present in python_features.items():
        state = "green" if present else "yellow"
        console.print(f"[{state}]{name:12} {'available' if present else 'fallback'}[/{state}]")
    payload = {"schema_version": "1.1", "tools": available,
               "available": sum(x["available"] for x in available), "total": len(tools),
               "python_features": python_features,
               "generated_utc": datetime.now(timezone.utc).isoformat()}
    console.print(f"\nDisponibles : {payload['available']}/{payload['total']}")
    if payload["available"] < payload["total"]:
        info("r3con reste fonctionnel sans ces outils : les tâches concernées sont marquées "
             "« fallback » ou ignorées explicitement dans le plan.")
    _write_json(json_output, payload)
    return payload


def _module_available(name: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


@click.group("reports")
def reports_group():
    """Comparer et inspecter les rapports r3con."""


@reports_group.command("compare")
@click.argument("old_report", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new_report", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json-output", type=click.Path(dir_okay=False), help="Écrire la comparaison JSON")
@click.option("--format", "fmt", type=click.Choice(["json", "md", "sarif"]), default="json", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False), help="Fichier de sortie (md/sarif)")
def compare_reports_command(old_report, new_report, json_output, fmt, output):
    """Comparer les findings de deux rapports JSON (ajoutés, supprimés, modifiés)."""
    try:
        old = json.loads(old_report.read_text(encoding="utf-8"))
        new = json.loads(new_report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"Rapport JSON invalide : {exc}") from exc

    from modules.diff import compare_reports, render_markdown, to_sarif
    envelope = compare_reports(old, new)
    result = envelope["comparison"]
    # Compat v7.2 : clés added/removed/unchanged au niveau racine.
    payload = {"schema_version": "1.1", "old": str(old_report), "new": str(new_report),
               "added": result["added"], "removed": result["removed"],
               "changed": result["changed"], "unchanged": result["counts"]["unchanged"],
               "risk_trend": result["risk_trend"]}
    _write_json(json_output, payload)
    console.print(f"Ajoutés : {len(result['added'])} | Supprimés : {len(result['removed'])} | Inchangés : {result['counts']['unchanged']}")
    if result["changed"]:
        console.print(f"Modifiés : {len(result['changed'])} | Tendance : {result['risk_trend']}")
    if fmt == "md":
        text = render_markdown(envelope)
    elif fmt == "sarif":
        from modules.diff import to_sarif
        text = to_sarif({"findings": payload["added"]})
    else:
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    if fmt in {"md", "sarif"}:
        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(text, encoding="utf-8")
            ok(f"Sortie {fmt} écrite : {output}")
        else:
            console.print(text)
    return payload


@click.command("compare")
@click.argument("old_target", type=click.Path(exists=True, path_type=Path))
@click.argument("new_target", type=click.Path(exists=True, path_type=Path))
@click.option("--kind", type=click.Choice(["auto", "binary", "apk", "firmware", "source", "report"]),
              default="auto", show_default=True, help="Type de comparaison")
@click.option("--format", "fmt", type=click.Choice(["json", "md", "sarif"]), default="json", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False), help="Écrire le résultat dans un fichier")
def compare_command(old_target, new_target, kind, fmt, output):
    """Analyse différentielle de deux cibles (binaires, APK, firmwares, rapports)."""
    from modules.diff import compare_reports, compare_targets, render_markdown, to_sarif

    if kind == "report" or (kind == "auto" and old_target.suffix == ".json" and new_target.suffix == ".json"):
        try:
            old = json.loads(old_target.read_text(encoding="utf-8"))
            new = json.loads(new_target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise click.ClickException(f"Rapport JSON invalide : {exc}") from exc
        envelope = compare_reports(old, new)
    else:
        envelope = compare_targets(old_target, new_target, kind=kind)

    if fmt == "md":
        text = render_markdown(envelope)
    elif fmt == "sarif":
        text = to_sarif(envelope)
    else:
        text = json.dumps(envelope, ensure_ascii=False, indent=2, default=str)
    if output:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        ok(f"Comparaison écrite : {out}")
    elif fmt == "json":
        console.print_json(text)
    else:
        console.print(text)
    counts = (envelope.get("comparison") or {}).get("counts") or {}
    if counts:
        console.print(f"[bold]Écarts[/bold] : +{counts.get('added', 0)} trouvé(s), "
                      f"-{counts.get('removed', 0)} retiré(s), ~{counts.get('changed', 0)} modifié(s)")
    return envelope


@click.command("explain")
@click.argument("finding_id")
@click.option("--report", "report_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Rapport JSON r3con à interroger")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
@click.option("--ai", is_flag=True, help="Ajouter un commentaire IA (fournisseur configuré uniquement)")
def explain_command(finding_id, report_path, fmt, ai):
    """Expliquer un finding par son id, en citant les preuves du rapport."""
    from core.explainer import explain_finding, find_finding, load_report

    payload = load_report(report_path)
    finding, ambiguity = find_finding(payload, finding_id)
    if finding is None:
        raise click.ClickException("; ".join(ambiguity) or "finding introuvable")
    explanation = explain_finding(payload, finding, ai=ai)
    if ambiguity:
        explanation["notes"] = ambiguity
    if fmt == "json":
        click.echo(json.dumps(explanation, ensure_ascii=False, indent=2, default=str))
        return explanation
    section(f"FINDING {explanation['finding_id']}")
    console.print(f"[bold]{explanation['severity']}[/bold] · {payload.get('profile', '')}"
                  f" · statut {explanation['kind_label']}")
    console.print(explanation["explanation"])
    if explanation["location"]:
        console.print(f"Emplacement : {explanation['location']}")
    console.print("\n[bold]Preuves citées[/bold] :")
    for citation in explanation["citations"][:14]:
        console.print(f"  · [{citation['kind']}] {citation['value']}")
    console.print("\n[bold]Incertitudes[/bold] :")
    for u in explanation["uncertainty"]:
        console.print(f"  ⚠ {u}")
    if explanation["recommendation"]:
        console.print(f"\n[bold]Recommandation[/bold] : {explanation['recommendation']}")
    commentary = explanation.get("ai_commentary") or {}
    if commentary.get("status") == "generated":
        console.print(f"\n[dim]Commentaire IA (non probant) : {commentary['text'][:800]}[/dim]")
    elif commentary.get("status") in {"skipped", "error"}:
        info(f"IA indisponible ({commentary.get('reason', 'skipped')}) — réponse 100 % locale conservée.")
    if ambiguity:
        for note in ambiguity:
            warn(note)
    return explanation


@click.command("summarize")
@click.argument("report_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Sortie JSON")
def summarize_command(report_path, as_json):
    """Résumer un rapport : score de risque, corroboration, fallbacks."""
    from core.explainer import load_report, summarize_report
    summary = summarize_report(load_report(report_path))
    if as_json:
        click.echo(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
        return summary
    section("R3CON SUMMARIZE")
    risk = summary["risk"]
    console.print(f"Score de risque : [bold]{risk['score']}/100[/bold] ({risk['rating']}) · "
                  f"{summary['total_findings']} finding(s) · confirmés {risk['confirmed']} · "
                  f"corroborés {risk['corroborated']} · fallbacks {risk['fallback']}")
    if summary.get("by_tool"):
        console.print("Par outil : " + ", ".join(f"{k}={v}" for k, v in summary["by_tool"].items()))
    if summary["top_findings"]:
        console.print("\nTop findings :")
        for f in summary["top_findings"][:10]:
            console.print(f"  {f['severity']:<8} {f['type']!s:<28} conf {f['confidence']} · id {str(f['id'])[:8]}")
    return summary


@click.command("ask")
@click.argument("report_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("question")
@click.option("--ai", is_flag=True, help="Ajouter un commentaire IA (fournisseur configuré uniquement)")
@click.option("--json", "as_json", is_flag=True, help="Sortie JSON")
def ask_command(report_path, question, ai, as_json):
    """Poser une question corrélée à un rapport (réponse locale, preuves citées)."""
    from core.explainer import ask_report, load_report
    answer = ask_report(load_report(report_path), question, ai=ai)
    if as_json:
        click.echo(json.dumps(answer, ensure_ascii=False, indent=2, default=str))
        return answer
    section("R3CON ASK")
    console.print(f"[dim]Q:[/] {answer['question']}")
    console.print(f"[bold]R:[/] {answer['answer']}")
    if answer["citations"]:
        console.print("\nPreuves citées :")
        for c in answer["citations"][:12]:
            console.print(f"  · {c['finding_id'][:8] if c.get('finding_id') else '?'} [{c.get('severity')}] {c.get('type')} ({c.get('tool')})")
    console.print(f"\n[dim]{answer['note']}[/dim]")
    return answer
