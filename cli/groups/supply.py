"""r3con supply-chain — analyse de chaîne d'approvisionnement, 100 % locale.

Par défaut, aucun fichier du projet n'est transmis à un service distant : la
détection s'appuie sur les manifestes/lockfiles locaux et une politique
offline (amorces intégrées + fichier d'avis optionnel).
"""
from __future__ import annotations

import json
from pathlib import Path

import click

from .helpers import console, info, ok, section, warn


@click.group("supply-chain")
def supply_chain_group():
    """Analyse offline des dépendances, SBOM et politique locale."""


@supply_chain_group.command("scan")
@click.argument("project", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--sbom", "sbom_format", type=click.Choice(["cyclonedx", "spdx", "both", "none"]),
              default="cyclonedx", show_default=True, help="Format(s) de SBOM à générer")
@click.option("--dependencies", is_flag=True, help="Inclure la liste complète des composants dans le rapport")
@click.option("--secrets", is_flag=True, help="Chercher aussi des secrets dans les sources du projet")
@click.option("--policy", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Fichier JSON/YAML de politique locale (avis + liste noire)")
@click.option("--report", "report_path", type=click.Path(dir_okay=False), default=None,
              help="Écrire le rapport JSON complet")
@click.option("--sbom-output", type=click.Path(dir_okay=False), default=None,
              help="Écrire le SBOM séparément (format choisi)")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium"]), default=None,
              help="Code de sortie 2 si un finding atteint ce seuil")
@click.pass_context
def supply_chain_scan(ctx, project, sbom_format, dependencies, secrets, policy, report_path,
                      sbom_output, fail_on):
    """Scanner PROJECT : dépendances, vulnérabilités locales, SBOM, secrets."""
    from modules.supply_chain import SupplyChainScanner

    scanner = SupplyChainScanner(
        project,
        policy_path=str(policy) if policy else None,
        scan_secrets=secrets,
        sbom_format=sbom_format,
    )
    result = scanner.scan()
    findings = result.get("findings") or []
    summary = result.get("finding_summary") or {}

    if not dependencies and "components" in result:
        result = {**result, "components_omitted": len(result["components"]),
                  "components": []}

    if report_path:
        out = Path(report_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        ok(f"Rapport écrit : {out}")
    if sbom_output and result.get("sbom"):
        payload = result["sbom"]
        if sbom_format == "both":
            out = Path(sbom_output)
            for fmt, blob in payload.items():
                target = out.with_name(f"{out.stem}.{fmt}{out.suffix or '.json'}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(blob, ensure_ascii=False, indent=2), encoding="utf-8")
                ok(f"SBOM {fmt} écrit : {target}")
        else:
            blob = payload.get(sbom_format if sbom_format in payload else next(iter(payload)))
            out = Path(sbom_output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(blob, ensure_ascii=False, indent=2), encoding="utf-8")
            ok(f"SBOM écrit : {out}")

    section("SUPPLY CHAIN — ANALYSE OFFLINE")
    cons = result.get("components_summary") or {}
    info(f"Projet : {project} | Composants : {cons.get('total', 0)} | "
         f"Politique : {result.get('policy', {}).get('source')}")
    if cons.get("by_ecosystem"):
        console.print("Écosystèmes : " + ", ".join(f"{k}={v}" for k, v in cons["by_ecosystem"].items()))
    console.print(f"Findings : {len(findings)} | Score de risque : {summary.get('score', 0)}/100 "
                  f"({summary.get('rating', 'none')})")
    by_type: dict[str, int] = {}
    for finding in findings:
        t = str(finding.get("type") or finding.get("finding_type"))
        by_type[t] = by_type.get(t, 0) + 1
    for t, n in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))[:12]:
        console.print(f"  · {t}: {n}")
    for w in result.get("warnings") or []:
        warn(w)
    if result.get("policy", {}).get("builtin_only"):
        info("Aucun fichier de politique fourni : seuls les avis intégrés (exemples) sont appliqués. "
             "Alimentez --policy avec un export OSV/vex-local pour une base complète.")
    if fail_on:
        from cli.groups.power import apply_fail_on
        apply_fail_on(ctx, findings, fail_on)
    return result
