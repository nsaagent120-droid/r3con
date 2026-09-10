"""Analyse différentielle entre deux rapports ou deux cibles locales.

Tout est calculé localement, sans réseau : comparaison des findings par
empreinte stable, des fonctions/protections pour les binaires, des
permissions pour les APK, et des secrets pour les sources. Les sorties sont
déterministes et sérialisables (JSON, Markdown, SARIF).
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.result_schema import SEVERITY_ORDER, Status, make_result

COMPARED_FIELDS = ("severity", "confidence", "status", "exploitability",
                   "description", "recommendation", "location")

_PERM_RE = re.compile(r"(?:android\.permission\.)[A-Z_][A-Z0-9_]+")


def _finding_key(finding: dict) -> str:
    """Même convention que v7.2 : id stable sinon empreinte des champs clés."""
    if finding.get("id"):
        return str(finding["id"])
    raw = "|".join(str(finding.get(k, "")) for k in
                   ("type", "finding_type", "target", "description", "file", "line"))
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _index(payload: Any) -> dict[str, dict]:
    findings = []
    if isinstance(payload, dict):
        findings = payload.get("findings") or []
        if not findings and isinstance(payload.get("reports"), list):
            for sub in payload["reports"]:
                findings.extend((sub or {}).get("findings") or [])
    elif isinstance(payload, list):
        findings = payload
    out: dict[str, dict] = {}
    for finding in findings:
        if isinstance(finding, dict):
            out[_finding_key(finding)] = finding
    return out


def _iter_findings(payload: Any) -> list[dict]:
    if isinstance(payload, dict):
        items = payload.get("findings")
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
        reports = payload.get("reports")
        if isinstance(reports, list):
            flat: list[dict] = []
            for sub in reports:
                if isinstance(sub, dict):
                    flat.extend(x for x in (sub.get("findings") or []) if isinstance(x, dict))
            return flat
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    return []


def compare_reports(old: Any, new: Any) -> dict[str, Any]:
    """Comparer deux payloads de rapport (dicts ou fichiers JSON déjà chargés).

    Retourne ``added`` / ``removed`` / ``changed`` (avec le détail des champs
    modifiés) / ``unchanged`` et une enveloppe de statut déterministe.
    """
    old_map, new_map = _index(old), _index(new)
    added = [new_map[k] for k in sorted(new_map.keys() - old_map.keys())]
    removed = [old_map[k] for k in sorted(old_map.keys() - new_map.keys())]
    changed = []
    unchanged = 0
    for key in sorted(old_map.keys() & new_map.keys()):
        before, after = old_map[key], new_map[key]
        diffs = {}
        for field in COMPARED_FIELDS:
            b, a = before.get(field), after.get(field)
            if b != a:
                diffs[field] = {"old": b, "new": a}
        if diffs:
            changed.append({"id": key, "type": after.get("type", after.get("finding_type")),
                            "target": after.get("target"), "fields": diffs})
        else:
            unchanged += 1
    risk_delta = _risk_shift(added, removed, changed)
    result = {
        "schema_version": "1.1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "counts": {"added": len(added), "removed": len(removed),
                   "changed": len(changed), "unchanged": unchanged},
        "added": added,
        "removed": removed,
        "changed": changed,
        "risk_trend": risk_delta,
    }
    return make_result(Status.OK, comparison=result)


def _sev_points(severity: str) -> int:
    """CRITICAL=5 … INFO=1 ; toute valeur inconnue vaut 0 (neutre)."""
    sev = str(severity or "INFO").upper()
    if sev not in SEVERITY_ORDER:
        return 0
    return len(SEVERITY_ORDER) - SEVERITY_ORDER.index(sev)


def _risk_shift(added: list[dict], removed: list[dict], changed: list[dict]) -> str:
    weight = 0
    for finding in added:                       # un nouveau finding aggrave
        weight += _sev_points(finding.get("severity"))
    for finding in removed:                     # un finding retiré améliore
        weight -= _sev_points(finding.get("severity"))
    for change in changed:
        sev_field = change["fields"].get("severity")
        if sev_field:
            weight += _sev_points(sev_field.get("new")) - _sev_points(sev_field.get("old"))
    if weight > 0:
        return "degrading"
    if weight < 0:
        return "improving"
    return "stable"


# ── Diff de cibles (binaires / APK / firmware / source) ─────────────


def _binary_profile(path: Path) -> dict[str, Any]:
    """Profil statique léger d'un binaire, sans outil externe requis."""
    profile: dict[str, Any] = {"sha256": _sha256(path), "size": path.stat().st_size}
    try:
        from modules.disasm.binary_parser import BinaryParser
        info = BinaryParser(str(path)).parse()
        if isinstance(info, dict):
            profile["protections"] = info.get("protections") or {}
            profile["sections"] = sorted(s.get("name", "") for s in info.get("sections", []) if isinstance(s, dict))
            profile["arch"] = info.get("arch") or info.get("machine")
            profile["entrypoint"] = info.get("entrypoint") or info.get("entry")
            functions = info.get("functions") or info.get("symbols") or []
            profile["functions"] = {}
            for fn in functions[:2000]:
                if isinstance(fn, dict) and fn.get("name"):
                    profile["functions"][str(fn["name"])] = {
                        "address": fn.get("address") or fn.get("offset"),
                        "size": fn.get("size"),
                    }
    except Exception as exc:  # noqa: BLE001 - un parseur fragile ne doit pas casser le diff
        profile["parse_error"] = str(exc)[:300]
    return profile


def _strings_of(path: Path, limit: int = 20000) -> list[str]:
    """Liste plate de chaînes; tolère les formes dict/str du parseur."""
    raw: list = []
    try:
        from modules.disasm.binary_parser import BinaryParser
        raw = list(BinaryParser(str(path)).extract_strings())
    except Exception:  # noqa: BLE001
        data = path.read_bytes()
        raw = [x.decode("ascii", "ignore") for x in re.findall(rb"[\x20-\x7e]{6,}", data)]
    out: list[str] = []
    for item in raw[:limit]:
        if isinstance(item, dict):
            value = item.get("string") or item.get("value") or item.get("text") or ""
            out.append(str(value))
        else:
            out.append(str(item))
    return out


def _permissions_of(path: Path) -> set[str]:
    if path.suffix.lower() != ".apk" and not _zip_is_android(path):
        return set()
    perms: set[str] = set()
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if "AndroidManifest.xml" in names:
                blob = zf.read("AndroidManifest.xml")
                text = blob.decode("utf-8", "ignore") if b"<manifest" in blob else \
                    blob.decode("latin-1", "ignore")
                perms.update(_PERM_RE.findall(text))
    except (OSError, zipfile.BadZipFile):
        pass
    return perms


def _zip_is_android(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
        return any(n in names for n in ("AndroidManifest.xml", "classes.dex"))
    except (OSError, zipfile.BadZipFile):
        return False


def _secrets_of(path: Path) -> set[str]:
    try:
        from modules.audit.secret_scanner import SecretScanner
        scanner = SecretScanner()
        result = scanner.scan_file(str(path))
        return {f"{x.get('rule', x.get('name', 'secret'))}@{x.get('line', '?')}"
                for x in (result.get("findings") or []) if isinstance(x, dict)}
    except Exception:  # noqa: BLE001
        return set()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compare_targets(old_path: str | Path, new_path: str | Path,
                    kind: str = "auto") -> dict[str, Any]:
    """Comparer deux fichiers locaux (binaires, APK, firmware, sources).

    Détecte : changements de protections, fonctions ajoutées/retirées/modifiées,
    permissions Android, nouveaux secrets et findings d'une analyse légère de
    chaque cible. Aucune donnée n'est envoyée à l'extérieur.
    """
    old, new = Path(old_path), Path(new_path)
    missing = [str(p) for p in (old, new) if not p.is_file()]
    if missing:
        return make_result(Status.INVALID, error="target_not_found", missing=missing)

    from core.target_types import KIND_APK, KIND_SOURCE, detect_target

    detected = detect_target(new)
    if kind == "auto":
        effective = detected.kind
    else:
        effective = kind

    comparison: dict[str, Any] = {
        "old": {"path": str(old), "sha256": _sha256(old), "size": old.stat().st_size},
        "new": {"path": str(new), "sha256": _sha256(new), "size": new.stat().st_size},
        "kind": effective,
    }

    old_profile, new_profile = _binary_profile(old), _binary_profile(new)
    protection_changes = _diff_dicts(old_profile.get("protections", {}),
                                     new_profile.get("protections", {}))
    comparison["protections"] = protection_changes or {"changed": False}
    comparison["size_delta_bytes"] = new_profile["size"] - old_profile["size"]

    funcs: dict[str, Any] = {"added": [], "removed": [], "modified": []}
    old_f, new_f = old_profile.get("functions", {}), new_profile.get("functions", {})
    if old_f or new_f:
        funcs["added"] = sorted(set(new_f) - set(old_f))[:200]
        funcs["removed"] = sorted(set(old_f) - set(new_f))[:200]
        for name in sorted(set(old_f) & set(new_f))[:2000]:
            if old_f[name] != new_f[name]:
                funcs["modified"].append({"name": name, "old": old_f[name], "new": new_f[name]})
        funcs["modified"] = funcs["modified"][:200]
    comparison["functions"] = funcs

    old_strings, new_strings = _strings_of(old), _strings_of(new)
    added_strings = sorted(set(new_strings) - set(old_strings))
    comparison["strings"] = {"added": len(added_strings), "removed": len(set(old_strings) - set(new_strings)),
                             "added_sample": added_strings[:50]}

    if effective in {KIND_APK, "apk"}:
        old_perms, new_perms = _permissions_of(old), _permissions_of(new)
        comparison["permissions"] = {"added": sorted(new_perms - old_perms),
                                     "removed": sorted(old_perms - new_perms)}

    if effective == KIND_SOURCE:
        old_secrets, new_secrets = _secrets_of(old), _secrets_of(new)
        comparison["secrets"] = {"added": sorted(new_secrets - old_secrets),
                                 "removed": sorted(old_secrets - new_secrets)}

    # Findings différentiels via analyses légères des deux cibles.
    old_scan, new_scan = _light_scan(old), _light_scan(new)
    report_diff = compare_reports(old_scan, new_scan)
    comparison["findings"] = report_diff
    diff_findings = build_diff_findings(old_scan, new_scan)
    return make_result(Status.OK, kind=effective, target=str(old), comparison=comparison,
                       findings=diff_findings)


def _diff_dicts(old: dict, new: dict) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for key in sorted(set(old) | set(new)):
        before, after = old.get(key), new.get(key)
        if before != after:
            changes[key] = {"old": before, "new": after}
    if changes:
        changes["changed"] = True
    return changes


def _light_scan(path: Path) -> dict[str, Any]:
    """Analyse minimale hors cache, sans outils externes."""
    try:
        from modules.orchestration.unified import UnifiedOrchestrator
        o = UnifiedOrchestrator(str(path), profile="quick",
                                **{"analysis.cache_enabled": False, "analysis.timeout": 30})
        return o.run()
    except Exception as exc:  # noqa: BLE001
        return make_result(Status.ERROR, target=str(path), error=str(exc)[:300], findings=[])


def build_diff_findings(old_scan: dict, new_scan: dict) -> list[dict]:
    """Matérialise les écarts de findings en contrat Finding v2.1."""
    from core.result_schema import deduplicate_findings, normalize_findings
    old_map, new_map = _index(old_scan), _index(new_scan)
    findings: list[dict] = []
    for key in sorted(new_map.keys() - old_map.keys()):
        base = new_map[key]
        findings.append({**base,
                         "finding_type": "diff-added-finding",
                         "severity": base.get("severity", "INFO"),
                         "tags": sorted(set(base.get("tags") or []) | {"diff"}),
                         "description": f"Finding apparu dans la nouvelle version : {base.get('description', base.get('type', ''))}"[:500],
                         "recommendation": "Vérifier ce changement avant publication.",
                         "provenance": {"source_task": "diff", "diff_key": key}})
    for key in sorted(old_map.keys() - new_map.keys()):
        base = old_map[key]
        findings.append({**base,
                         "finding_type": "diff-removed-finding",
                         "severity": "INFO",
                         "status": "observation",
                         "tags": sorted(set(base.get("tags") or []) | {"diff"}),
                         "description": f"Finding disparu dans la nouvelle version : {base.get('description', base.get('type', ''))}"[:500],
                         "recommendation": "Confirmer que la disparition est volontaire.",
                         "provenance": {"source_task": "diff", "diff_key": key}})
    for key in sorted(old_map.keys() & new_map.keys()):
        before, after = old_map[key], new_map[key]
        fields = {f for f in COMPARED_FIELDS if before.get(f) != after.get(f)}
        if fields:
            escalated = False
            sev_before = str(before.get("severity", "INFO")).upper()
            sev_after = str(after.get("severity", "INFO")).upper()
            if sev_after in SEVERITY_ORDER and sev_before in SEVERITY_ORDER:
                escalated = SEVERITY_ORDER.index(sev_after) < SEVERITY_ORDER.index(sev_before)
            findings.append({**after,
                             "finding_type": "diff-changed-finding",
                             "severity": after.get("severity") if escalated else "LOW",
                             "tags": sorted(set(after.get("tags") or []) | {"diff"}),
                             "description": f"Finding modifié ({', '.join(sorted(fields))}) : {after.get('description', '')}"[:500],
                             "recommendation": "Relire le finding : ses attributs ont changé entre les deux versions.",
                             "provenance": {"source_task": "diff", "diff_key": key,
                                            "changed_fields": sorted(fields)}})
    return deduplicate_findings(normalize_findings(findings, tool="r3con-diff", tool_version="unknown"))


# ── Exports ────────────────────────────────────────────────────────


def render_markdown(diff_payload: dict) -> str:
    comparison = diff_payload.get("comparison") or diff_payload
    counts = comparison.get("counts")
    lines = [
        "# r3con — Analyse différentielle",
        f"_Généré : {comparison.get('generated_utc', 'n/a')} · version r3con locale, aucune donnée envoyée_",
        "",
    ]
    if counts:
        lines += [f"- Ajoutés : **{counts.get('added', 0)}**",
                  f"- Supprimés : **{counts.get('removed', 0)}**",
                  f"- Modifiés : **{counts.get('changed', 0)}**",
                  f"- Inchangés : {counts.get('unchanged', 0)}",
                  f"- Tendance de risque : {comparison.get('risk_trend', 'n/a')}", ""]
        for label, key in (("Ajoutés", "added"), ("Supprimés", "removed")):
            items = comparison.get(key) or []
            if items:
                lines.append(f"## {label}")
                for f in items[:100]:
                    lines.append(f"- `[{f.get('severity', 'INFO')}]` {f.get('type') or f.get('finding_type')} — {f.get('description', '')}")
                lines.append("")
        if comparison.get("changed"):
            lines.append("## Modifiés")
            for change in comparison["changed"][:100]:
                fields = ", ".join(f"{k}: `{v.get('old')}` → `{v.get('new')}`"
                                   for k, v in change["fields"].items())
                lines.append(f"- `{change.get('id', '')[:8]}` {change.get('type')} — {fields}")
            lines.append("")
    if comparison.get("protections") or comparison.get("permissions") or comparison.get("functions"):
        lines.append("## Cibles")
        prot = comparison.get("protections") or {}
        if prot and prot.get("changed"):
            prot.pop("changed", None)
            lines.append("- Protections :")
            for key, delta in prot.items():
                lines.append(f"  - `{key}` : `{delta.get('old')}` → `{delta.get('new')}`")
        perms = comparison.get("permissions") or {}
        if perms.get("added") or perms.get("removed"):
            lines.append(f"- Permissions ajoutées : {', '.join(perms['added']) or 'aucune'}")
            lines.append(f"- Permissions retirées : {', '.join(perms['removed']) or 'aucune'}")
        funcs = comparison.get("functions") or {}
        if any(funcs.get(k) for k in ("added", "removed", "modified")):
            lines.append(f"- Fonctions : +{len(funcs.get('added', []))} "
                         f"-{len(funcs.get('removed', []))} "
                         f"~{len(funcs.get('modified', []))}")
        secrets = comparison.get("secrets") or {}
        if secrets.get("added"):
            lines.append(f"- Nouveaux secrets : {', '.join(secrets['added'])}")
        lines.append("")
    return "\n".join(lines)


def to_sarif(diff_payload: dict) -> str:
    """Export SARIF 2.1.0 des écarts (findings ajoutés/modifiés)."""
    from core.__version__ import __version__ as version
    sarif_findings = diff_payload.get("findings") or []
    results = []
    rules: dict[str, dict] = {}
    for finding in sarif_findings:
        rule_id = f"r3con-diff/{finding.get('finding_type', 'change')}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": str(finding.get("description", ""))[:200]},
            "defaultConfiguration": {"level": "warning"},
        })
        location = finding.get("location") or {}
        physical = {}
        if location.get("file"):
            physical = {"artifactLocation": {"uri": str(location["file"])},
                        "region": {"startLine": int(location["line"]) if str(location.get("line", "")).isdigit() else 1}}
        results.append({
            "ruleId": rule_id,
            "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                      "LOW": "note"}.get(str(finding.get("severity", "INFO")).upper(), "note"),
            "message": {"text": str(finding.get("description", ""))[:1000]},
            "locations": [{"physicalLocation": physical}] if physical else [],
            "partialFingerprints": {"primaryLocationLineHash": finding.get("id", "")},
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "r3con diff", "version": version, "rules": list(rules.values())}},
            "results": results,
            "automationDetails": {"description": {"text": "r3con differential analysis (offline)"}},
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
