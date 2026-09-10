"""Couche d'explication et de corrélation au-dessus des rapports r3con.

Principes (contraintes de sécurité du projet) :

- offline-first : ``explain`` et ``ask`` fonctionnent sans IA ni réseau ;
- chaque affirmation cite une preuve présente dans le rapport (``citations``) ;
- les incertitudes sont listées explicitement (``uncertainty``) ;
- l'IA, si ``ai=True`` et un fournisseur est configuré, n'ajoute qu'un
  commentaire étiqueté ``ai_commentary`` : elle ne produit jamais de preuve
  et une hypothèse n'est jamais présentée comme une confirmation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.result_schema import finding_kind, summarize_findings

KIND_LABELS = {
    "observation": "observation factuelle (aucune vérification d'exploitabilité)",
    "hypothese": "hypothèse à confirmer — ne doit PAS être traitée comme une preuve",
    "confirme": "finding confirmé par un vérificateur explicite",
    "faux_positif": "faux positif marqué par revue humaine",
    "fallback": "résultat issu d'un repli local (outil spécialisé absent)",
}

CONFIRMED_STATUSES = {"confirmed", "needs-review", "observation"}


def load_report(path: str | Path) -> dict[str, Any]:
    """Charge un rapport JSON r3con en tolérant les enveloppes multiples."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"rapport introuvable : {p}")
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"rapport JSON invalide : {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("le rapport JSON doit être un objet")
    return payload


def collect_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Retrouve les findings où qu'ils soient (racine, reports[], results{})."""
    findings: list[dict[str, Any]] = []
    if isinstance(payload.get("findings"), list):
        findings.extend(x for x in payload["findings"] if isinstance(x, dict))
    reports = payload.get("reports")
    if isinstance(reports, list):
        for sub in reports:
            if isinstance(sub, dict):
                findings.extend(collect_findings(sub))
    results = payload.get("results")
    if isinstance(results, dict) and not findings:
        for task, result in results.items():
            if isinstance(result, dict) and isinstance(result.get("findings"), list):
                for item in result["findings"]:
                    if isinstance(item, dict):
                        item = {**item, "provenance": {**(item.get("provenance") or {}),
                                                       "source_task": task}}
                        findings.append(item)
    return findings


def find_finding(payload: dict[str, Any], finding_id: str) -> tuple[dict[str, Any] | None, list[str]]:
    """Résout un id (exact ou préfixe >= 4 caractères) ; renvoie (finding, ambiguïtés)."""
    wanted = finding_id.strip().lower()
    findings = collect_findings(payload)
    exact = [f for f in findings if str(f.get("id", "")).lower() == wanted]
    if len(exact) == 1:
        return exact[0], []
    if len(exact) > 1:
        return exact[0], [f"{len(exact)} findings portent exactement cet id"]
    if len(wanted) < 4:
        return None, ["l'id doit faire au moins 4 caractères (ou correspondre exactement)"]
    prefix = [f for f in findings if str(f.get("id", "")).lower().startswith(wanted)]
    if len(prefix) == 1:
        return prefix[0], []
    if prefix:
        return None, [f"préfixe ambigu : {len(prefix)} correspondances -> {[str(x.get('id'))[:8] for x in prefix[:8]]}"]
    return None, [f"aucun finding avec l'id '{finding_id}' dans ce rapport"]


def _evidence_lines(finding: dict[str, Any], limit: int = 6) -> list[str]:
    evidence = finding.get("evidence")
    lines: list[str] = []
    if isinstance(evidence, dict):
        for key in ("file", "file_line", "line", "offset", "rule", "excerpt", "snippet", "location", "description"):
            value = evidence.get(key)
            if value not in (None, ""):
                lines.append(f"evidence.{key} = {str(value)[:200]}")
        for key, value in list(evidence.items())[:limit]:
            entry = f"evidence.{key} = {str(value)[:200]}"
            if entry not in lines and len(lines) < limit * 2:
                lines.append(entry)
    elif isinstance(evidence, list):
        for item in evidence[:limit * 2]:
            lines.append(f"evidence = {str(item)[:200]}")
    elif evidence not in (None, ""):
        lines.append(f"evidence = {str(evidence)[:250]}")
    if not lines and finding.get("description"):
        lines.append(f"description = {str(finding['description'])[:250]}")
    return lines[:limit * 2]


def explain_finding(payload: dict[str, Any], finding: dict[str, Any], *, ai: bool = False) -> dict[str, Any]:
    """Explication déterministe d'un finding, avec citations et incertitudes."""
    kind = finding_kind(finding)
    confidence = float(finding.get("confidence", 0.5) or 0.5)
    references = finding.get("references") or {}
    corroboration = finding.get("corroboration") or {}
    corroborating = corroboration.get("tools") or (
        sorted({t.strip() for t in str((finding.get("provenance") or {}).get("corroborating_tools", "")).split(",") if t.strip()})
    )

    citations: list[dict[str, str]] = []
    for line in _evidence_lines(finding):
        citations.append({"kind": "evidence", "value": line})
    if finding.get("tool"):
        citations.append({"kind": "tool",
                          "value": f"{finding['tool']} {finding.get('tool_version', 'unknown')}"})
    if finding.get("target_hash"):
        citations.append({"kind": "target", "value": f"sha256:{str(finding['target_hash'])[:16]}…"})
    for bucket in ("cwe", "cve", "attack"):
        for ref in references.get(bucket, []) or []:
            citations.append({"kind": "reference", "value": ref})

    uncertainty: list[str] = []
    uncertainty.append(KIND_LABELS.get(kind, f"statut '{finding.get('status')}'"))
    if confidence < 0.7 and kind != "confirme":
        uncertainty.append(f"confiance faible ({confidence:.2f} < 0.70) : résultat à recouper")
    if finding.get("fallback"):
        uncertainty.append("repli interne utilisé : l'outil spécialisé recommandé n'était pas disponible")
    if len(corroborating or []) <= 1 and kind != "confirme":
        uncertainty.append("aucune corroboration par un second outil indépendant")
    if str(finding.get("exploitability", "unknown")) in {"unknown", "theoretical"}:
        uncertainty.append("exploitabilité non établie : ne pas présenter comme prouvé")

    location = finding.get("location") or {}
    location_bits = [str(location.get(k)) for k in ("file", "function", "line", "offset", "address")
                     if location.get(k) not in (None, "")]

    explanation = (
        f"Le finding '{finding.get('type') or finding.get('finding_type')}' a été produit par "
        f"{finding.get('tool', 'r3con')} sur la cible {finding.get('target', 'inconnue')}. "
        f"Statut : {KIND_LABELS.get(kind, kind)}. "
        f"Sévérité {finding.get('severity', 'INFO')} (confiance {confidence:.2f}, "
        f"exploitabilité {finding.get('exploitability', 'unknown')})."
    )
    if len(corroborating or []) > 1:
        explanation += f" Indépendamment corroboré par : {', '.join(corroborating)}."

    out: dict[str, Any] = {
        "finding_id": finding.get("id"),
        "kind": kind,
        "kind_label": KIND_LABELS.get(kind, kind),
        "explanation": explanation,
        "severity": finding.get("severity", "INFO"),
        "confidence": confidence,
        "status": finding.get("status", "needs-review"),
        "exploitability": finding.get("exploitability", "unknown"),
        "target": finding.get("target", ""),
        "location": ", ".join(location_bits) or None,
        "tool": f"{finding.get('tool', 'r3con')} {finding.get('tool_version', '')}".strip(),
        "references": references,
        "corroborated_by": list(corroborating or []),
        "recommendation": finding.get("recommendation") or "Aucune recommandation fournie par l'outil.",
        "citations": citations,
        "uncertainty": [u for u in uncertainty if u],
        "ai_commentary": None,
    }
    if ai:
        out["ai_commentary"] = _ai_commentary(finding, out)
    return out


def _ai_commentary(finding: dict[str, Any], explanation: dict[str, Any]) -> dict[str, Any]:
    """Commentaire IA OPTIONNEL, explicitement séparé des preuves.

    N'enverra que les champs déjà présents dans le rapport (aucun contenu
    fichier arbitraire) et seulement si un fournisseur est configuré et en
    ligne. En cas d'absence, renvoie un motif d'inexécution plutôt qu'un
    échec.
    """
    try:
        from core.ai_engine import AIEngine
        engine = AIEngine()
        if not engine.is_online():
            return {"status": "skipped", "reason": "aucun fournisseur IA configuré ; l'analyse reste offline-first"}
        prompt = (
            "Tu es un analyste sécurité. Commente ce finding r3con SANS inventer de fait. "
            "Cite uniquement les éléments fournis, signale les incertitudes.\n"
            + json.dumps({k: explanation.get(k) for k in
                          ("severity", "confidence", "kind_label", "tool", "citations", "uncertainty")},
                         ensure_ascii=False)[:6000]
        )
        text = engine.chat([{"role": "user", "content": prompt}])
        return {"status": "generated", "note": "commentaire IA — ne constitue pas une preuve", "text": str(text)[:4000]}
    except Exception as exc:  # noqa: BLE001 - l'IA ne doit jamais casser explain
        return {"status": "error", "reason": str(exc)[:200]}


def summarize_report(payload: dict[str, Any]) -> dict[str, Any]:
    """Résumé global déterministe d'un rapport."""
    findings = collect_findings(payload)
    summary = summarize_findings(findings)
    by_tool: dict[str, int] = {}
    for finding in findings:
        tool = str(finding.get("tool", "r3con"))
        by_tool[tool] = by_tool.get(tool, 0) + 1
    corroborated = [f for f in findings
                    if "corroborated" in (f.get("tags") or []) or len((f.get("corroboration") or {}).get("tools") or []) > 1]
    fallbacks = [f for f in findings if f.get("fallback") or (f.get("provenance") or {}).get("fallback")]
    top = sorted(
        [f for f in findings if str(f.get("status", "")).lower() not in {"false-positive", "false_positive"}],
        key=lambda f: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(str(f.get("severity", "INFO"))
                                       if str(f.get("severity", "INFO")) in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else 4),
                       -float(f.get("confidence", 0) or 0)),
    )[:10]
    return {
        "schema_version": "1.0",
        "total_findings": len(findings),
        "risk": {k: summary[k] for k in ("score", "rating", "counts", "confirmed", "corroborated", "fallback")},
        "by_kind": summary["by_kind"],
        "by_tool": dict(sorted(by_tool.items(), key=lambda kv: (-kv[1], kv[0]))),
        "corroborated_ids": [f.get("id") for f in corroborated],
        "fallback_ids": [f.get("id") for f in fallbacks],
        "top_findings": [{"id": f.get("id"), "severity": f.get("severity"),
                          "type": f.get("type") or f.get("finding_type"),
                          "confidence": f.get("confidence"), "tool": f.get("tool")} for f in top],
        "plan": payload.get("plan"),
        "fallbacks_used": payload.get("fallbacks_used"),
        "profile": payload.get("profile"),
        "target": (payload.get("target") or {}).get("path") if isinstance(payload.get("target"), dict) else payload.get("target"),
    }


_QUESTION_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("corroborated", re.compile(r"corrobor|plusieurs outils|ind[ée]pendant|more than one tool|several tools", re.I)),
    ("fallback", re.compile(r"fallback|repli|outil absent|indisponible", re.I)),
    ("critical", re.compile(r"\bcrit|\bhigh|grave|haute|s[ée]v[èe]re|top risk", re.I)),
    ("false_positive", re.compile(r"faux[ -]?positif|false[ -]?positive", re.I)),
    ("exploitable", re.compile(r"exploit|rce|corrompre|overflow", re.I)),
    ("secrets", re.compile(r"secret|token|cl[ée]|password|credential", re.I)),
    ("cve", re.compile(r"\bcve\b|advisory|vuln[ée]rabilit", re.I)),
    ("tools", re.compile(r"outil|tool|quel moteur|which tool", re.I)),
]


def ask_report(payload: dict[str, Any], question: str, *, ai: bool = False) -> dict[str, Any]:
    """Répond localement à une question en filtrant/corrélatant le rapport."""
    findings = collect_findings(payload)
    lowered = question.lower()
    topic = "general"
    for name, pattern in _QUESTION_RULES:
        if pattern.search(lowered) or pattern.search(question):
            topic = name
            break

    def sev_rank(finding: dict[str, Any]) -> int:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev = str(finding.get("severity", "INFO")).upper()
        return order.index(sev) if sev in order else 4

    matched: list[dict[str, Any]] = []
    answer = ""
    if topic == "corroborated":
        matched = [f for f in findings if len((f.get("corroboration") or {}).get("tools") or []) > 1
                   or "corroborated" in (f.get("tags") or [])]
        answer = (f"{len(matched)} finding(s) corroboré(s) par plusieurs outils indépendants"
                  if matched else "Aucun finding corroboré par plusieurs outils dans ce rapport.")
    elif topic == "fallback":
        matched = [f for f in findings if f.get("fallback") or (f.get("provenance") or {}).get("fallback")]
        answer = (f"{len(matched)} résultat(s) issus de replis internes : à considérer comme des "
                  f"observations locales, pas comme la sortie de l'outil spécialisé.")
    elif topic == "false_positive":
        matched = [f for f in findings if str(f.get("status", "")).lower().replace("_", "-") == "false-positive"]
        answer = f"{len(matched)} finding(s) marqué(s) faux positif par revue."
    elif topic == "critical":
        matched = [f for f in findings if sev_rank(f) <= 1 and str(f.get("status", "")).lower() != "false-positive"]
        answer = f"{len(matched)} finding(s) CRITICAL/HIGH non exclus par revue ; détail par ids cités."
    elif topic == "exploitable":
        matched = [f for f in findings if str(f.get("exploitability", "")).lower()
                   in {"likely", "confirmed", "possible"}]
        answer = (f"{len(matched)} finding(s) avec exploitabilité évaluée. Rappel : 'theoretical' "
                  f"ou 'unknown' = hypothèse, jamais une preuve.")
    elif topic == "secrets":
        matched = [f for f in findings if re.search(r"secret|token|password|key", str(f.get("type", "")).lower())]
        answer = f"{len(matched)} finding(s) lié(s) aux secrets."
    elif topic == "cve":
        matched = [f for f in findings if ((f.get("references") or {}).get("cve"))]
        answer = f"{len(matched)} finding(s) référencent un identifiant CVE vérifiable."
    elif topic == "tools":
        tools = sorted({str(f.get("tool", "r3con")) for f in findings})
        answer = f"Outils ayant produit des findings : {', '.join(tools) or 'aucun'}."
    else:
        answer = ("Question sans filtre local correspondant. Filtres disponibles : corroborés, "
                  "fallbacks, critiques/high, faux positifs, exploitabilité, secrets, CVE, outils. "
                  "Exemple : « Quels risques sont corroborés par plusieurs outils ? »")

    matched = sorted(matched, key=lambda f: (sev_rank(f), -float(f.get("confidence", 0) or 0)))[:25]
    out: dict[str, Any] = {
        "schema_version": "1.0",
        "question": question,
        "topic": topic,
        "method": "offline-correlation",
        "answer": answer,
        "citations": [{"finding_id": f.get("id"), "type": f.get("type") or f.get("finding_type"),
                       "severity": f.get("severity"), "tool": f.get("tool")} for f in matched],
        "note": "Réponse construite uniquement à partir des données du rapport ; aucune donnée n'a quitté la machine.",
    }
    if ai:
        out["ai_commentary"] = _ai_commentary({}, {**out, "citations": out["citations"][:12]})
    return out
