"""Politique offline pour la chaîne d'approvisionnement.

Aucun service distant n'est interrogé. La base d'avis est un simple fichier
JSON (ou YAML si pyyaml est présent) fourni par l'utilisateur ; un jeu
d'amorces intégré couvre quelques CVE célèbres pour la démonstration et le
mode hors-ligne strict. Les correspondances de versions utilisent une
heuristique numérique bornée et les findings sont marqués ``hypothesis`` :
ils signalent un RISQUE À VÉRIFIER, jamais une preuve d'exploitation.

Format du fichier de politique ::

    {
      "advisories": [
        {"id": "R3CON-0001", "cve": "CVE-2021-44228", "ecosystem": "maven",
         "package": "org.apache.logging.log4j:log4j-core",
         "affected": "<2.17.1", "severity": "CRITICAL",
         "description": "Log4Shell : JNDI injection via Log4j2"}
      ],
      "deny_packages": [{"ecosystem": "npm", "package": "event-stream"}]
    }
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Amorces intégrées : identifiants publics vérifiables, comparisons heuristiques.
BUILTIN_ADVISORIES: list[dict[str, Any]] = [
    {"id": "r3con-seed-log4shell", "cve": "CVE-2021-44228", "ecosystem": "maven",
     "package": "org.apache.logging.log4j:log4j-core", "affected": "<2.17.1",
     "severity": "CRITICAL", "description": "Log4Shell : injection JNDI via Log4j2"},
    {"id": "r3con-seed-log4shell-artifact", "cve": "CVE-2021-44228", "ecosystem": "maven",
     "package": "log4j-core", "affected": "<2.17.1",
     "severity": "CRITICAL", "description": "Log4Shell : injection JNDI via Log4j2"},
    {"id": "r3con-seed-lodash-proto", "cve": "CVE-2021-23337", "ecosystem": "npm",
     "package": "lodash", "affected": "<4.17.21", "severity": "HIGH",
     "description": "Command injection via template() de lodash"},
    {"id": "r3con-seed-requests-cred", "cve": "CVE-2018-18074", "ecosystem": "pip",
     "package": "requests", "affected": "<2.20.0", "severity": "MEDIUM",
     "description": "Fuite de credentials netrc vers un proxy redirigé"},
    {"id": "r3con-seed-openssl-loop", "cve": "CVE-2022-0778", "ecosystem": "cargo",
     "package": "openssl", "affected": "<0.10.38", "severity": "HIGH",
     "description": "Boucle infinie BN_mod_sqrt (openssl-sys)"},
]

BUILTIN_DENY: list[dict[str, str]] = [
    {"ecosystem": "npm", "package": "event-stream", "reason": "paquet compromis (malveillant) en 2018"},
    {"ecosystem": "pypi", "package": "python-dateutil2", "reason": "typosquatting connu"},
    {"ecosystem": "pip", "package": "colour-sss", "reason": "typosquatting connu"},
]

_UNPINNED_RE = re.compile(r"^(\*|latest|x|>=?\s*0)?$", re.I)


def _version_tuple(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", str(value or ""))
    return tuple(int(n) for n in nums[:4]) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _version_tuple(a), _version_tuple(b)
    width = max(len(ta), len(tb))
    ta += (0,) * (width - len(ta))
    tb += (0,) * (width - len(tb))
    return (ta > tb) - (ta < tb)


def version_matches(version: str, affected: str) -> bool:
    """Heuristique de plage : '<2.17.1', '>=1.0,<1.5', '=1.2.3', '*'.

    ``unknown`` ne correspond jamais (pas de faux positif sur les versions
    non résolues ; l'absence d'épingle est traitée par une règle dédiée).
    """
    if not affected or affected.strip() == "*":
        return False
    if str(version).lower() in {"", "unknown", "unpinned"}:
        return False
    for clause in affected.split(","):
        clause = clause.strip()
        m = re.match(r"^(<=|>=|<|>|=|~)\s*([\w.\-+]+)$", clause)
        if not m:
            return False
        op, bound = m.group(1), m.group(2)
        c = _cmp(version, bound)
        ok = {
            "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0,
            "=": c == 0, "~": c >= 0,  # compatibilité '~>' borne basse inclusive
        }[op]
        if not ok:
            return False
    return True


def load_policy(path: str | Path | None) -> tuple[list[dict], list[dict], list[str]]:
    """Charge (advisories, deny_packages, warnings). En l'absence de fichier,
    retombe sur les amorces intégrées."""
    warnings: list[str] = []
    advisories = list(BUILTIN_ADVISORIES)
    deny = list(BUILTIN_DENY)
    if not path:
        return advisories, deny, warnings
    p = Path(path)
    if not p.is_file():
        warnings.append(f"fichier de politique introuvable : {p} (amorces intégrées utilisées)")
        return advisories, deny, warnings
    try:
        raw = p.read_text(encoding="utf-8")
        if p.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml
                data = yaml.safe_load(raw) or {}
            except ImportError:
                warnings.append("pyyaml absent : impossible de lire la politique YAML, amorces intégrées")
                return advisories, deny, warnings
        else:
            data = json.loads(raw)
    except (OSError, ValueError) as exc:
        warnings.append(f"politique illisible ({exc}) ; amorces intégrées utilisées")
        return advisories, deny, warnings
    if isinstance(data, dict):
        advisories.extend(x for x in data.get("advisories", []) if isinstance(x, dict))
        deny.extend(x for x in data.get("deny_packages", []) if isinstance(x, dict))
    elif isinstance(data, list):
        advisories.extend(x for x in data if isinstance(x, dict))
    return advisories, deny, warnings


def check_component(component: dict[str, Any], advisories: list[dict], deny: list[dict]) -> list[dict]:
    """Renvoie les findings de politique pour un composant (contrat Finding)."""
    findings: list[dict] = []
    name = str(component.get("name", ""))
    eco = str(component.get("ecosystem", ""))
    version = str(component.get("version", "unknown"))

    def base(finding_type: str, severity: str, description: str, recommendation: str,
              refs: dict | None = None, confidence: float = 0.6) -> dict:
        return {
            "finding_type": finding_type,
            "severity": severity,
            "confidence": confidence,
            "status": "hypothesis",
            "exploitability": "unknown",
            "tool": "r3con-supply-chain",
            "description": description,
            "recommendation": recommendation,
            "location": {"file": component.get("manifest", ""), "function": None},
            "evidence": {"component": {"name": name, "version": version, "ecosystem": eco,
                                        "source": component.get("source"),
                                        "scope": component.get("scope")}},
            "references": refs or {},
            "tags": ["supply-chain"],
            "provenance": {"policy": "offline-local"},
        }

    for adv in advisories:
        if str(adv.get("ecosystem", "")) not in {eco, "", "*"}:
            continue
        target = str(adv.get("package", ""))
        if not target:
            continue
        matched = name.lower() == target.lower() or name.lower().endswith(":" + target.lower()) \
            or (":" in target and target.lower() == name.lower())
        if not matched:
            continue
        if version_matches(version, str(adv.get("affected", ""))):
            refs = {"cve": [adv["cve"]]} if adv.get("cve") else {}
            findings.append(base(
                "vulnerable-dependency", adv.get("severity", "MEDIUM"),
                f"Dépendance vulnérable ({adv.get('id', 'advisory')}) : {name}@{version} — "
                f"{adv.get('description', '')} ; politique locale hors-ligne, à confirmer avec une base d'avis à jour",
                f"Mettre à jour {name} hors de la plage « {adv.get('affected', '?')} ».",
                refs, 0.65))
    for entry in deny:
        if str(entry.get("ecosystem", "")) not in {eco, "", "*"}:
            continue
        if name.lower() == str(entry.get("package", "")).lower():
            findings.append(base(
                "denied-package", "HIGH",
                f"Paquet sur liste noire locale : {name}@{version} — {entry.get('reason', '')}",
                "Retirer ce paquet et choisir un alternative maintenue.", {}, 0.9))

    spec = str(component.get("version_spec", ""))
    if spec.lower() in {"unpinned", "*", "latest", ""} or _UNPINNED_RE.match(spec or "unpinned"):
        findings.append(base(
            "unpinned-dependency", "LOW",
            f"Dépendance non épinglée : {name} [{spec or 'unpinned'}] — la résolution peut changer à chaque build",
            f"Épingler une version exacte pour {name} (et committer le lockfile).", {}, 0.85))
    if "git" in spec or spec.startswith(("http://", "https://")) or re.search(r"\bgit\+", spec or ""):
        findings.append(base(
            "untrusted-source-dependency", "MEDIUM",
            f"Dépendance issue d'une source non vérifiable hors-ligne : {name} ({spec[:80]})",
            "Préférer un paquet publié avec version épinglée et intégrité vérifiable.", {}, 0.8))
    if eco in {"docker", "k8s"} and version == "latest":
        findings.append(base(
            "floating-container-tag", "MEDIUM",
            f"Image conteneur au tag mutable : {name}:latest",
            "Épingler l'image par digest (name@sha256:…) pour la reproductibilité.", {}, 0.9))
    if eco == "terraform" and version == "unpinned":
        findings.append(base(
            "unpinned-terraform-module", "MEDIUM",
            f"Module Terraform sans version épinglée : {name}",
            "Ajouter un attribut version = \"…\" au module.", {}, 0.9))
    return findings
