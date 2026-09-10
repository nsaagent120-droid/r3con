"""Contrats communs de résultats pour les analyseurs r3con.

Le module conserve les statuts d'exécution historiques et fournit un contrat
Finding unique pour les observations de sécurité. Les helpers de normalisation
permettent une migration progressive des modules qui renvoient encore des
 dictionnaires historiques.

Contrat v2.1 (rétro-compatible v2.0) — un finding expose désormais :

- ``id``            : empreinte stable et déterministe (revient identique
  entre deux exécutions sur la même cible et le même outil) ;
- ``finding_type``  : type d'observation (alias historique ``type``) ;
- ``target`` / ``target_hash`` : cible analysée ;
- ``location``      : dictionnaire ``{file, function, offset, line, address}``
  normalisé depuis l'évidence ou les clés historiques ``file``/``line``/... ;
- ``severity``      : CRITICAL|HIGH|MEDIUM|LOW|INFO (alias anciens normalisés) ;
- ``confidence``    : flottant borné 0..1 ;
- ``exploitability``: unknown|theoretical|possible|likely|confirmed ;
- ``status``        : observation|hypothesis|needs-review|confirmed|false-positive ;
- ``evidence``      : preuves brutes produites par l'analyseur ;
- ``tool`` / ``tool_version`` : outil producteur et version ;
- ``fallback``      : True quand le résultat provient d'un repli local
  (l'outil spécialisé est absent) ; signalé explicitement pour ne jamais
  confondre un fallback avec une preuve issue de l'outil canonique ;
- ``provenance``    : origine fine (tâche, adaptateur, outils corroborants) ;
- ``recommendation``: remédiation proposée ;
- ``references``    : ``{cwe: [...], cve: [...], attack: [...], ref: [...]}`` ;
- ``corroboration`` : ``{tools: [...], count: n}`` rempli par la déduplication
  multi-outils.

Classification en cinq classes de résultat — voir :func:`finding_kind` :
``observation``, ``hypothese``, ``confirme``, ``faux_positif``, ``fallback``.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

SCHEMA_VERSION = "2.1"


class Status(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"
    ERROR = "error"
    TIMEOUT = "timeout"


class FindingStatus(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    NEEDS_REVIEW = "needs-review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false-positive"


class Exploitability(str, Enum):
    UNKNOWN = "unknown"
    THEORETICAL = "theoretical"
    POSSIBLE = "possible"
    LIKELY = "likely"
    CONFIRMED = "confirmed"


EXPLOITABILITY_ALIASES = {
    "": Exploitability.UNKNOWN.value,
    "NONE": Exploitability.UNKNOWN.value,
    "UNVERIFIED": Exploitability.THEORETICAL.value,
    "SUSPECTED": Exploitability.POSSIBLE.value,
    "PROBABLE": Exploitability.LIKELY.value,
    "PROVEN": Exploitability.CONFIRMED.value,
    "VERIFIED": Exploitability.CONFIRMED.value,
    "POC": Exploitability.CONFIRMED.value,
}

SEVERITY_ALIASES = {
    "CRIT": "CRITICAL",
    "SEVERE": "CRITICAL",
    "FATAL": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "MODERATE": "MEDIUM",
    "MED": "MEDIUM",
    "MINOR": "LOW",
    "TRIVIAL": "LOW",
    "NOTE": "INFO",
    "INFORMATION": "INFO",
    "INFORMATIONAL": "INFO",
}
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

LOCATION_KEYS = ("file", "function", "offset", "line", "address")

FINDING_FIELDS = {
    "severity": {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
    "confidence": (0.0, 1.0),
    "exploitability": {x.value for x in Exploitability},
    "status": {x.value for x in FindingStatus},
}


def normalize_severity(value: Any) -> str:
    """Return one of the canonical severities while accepting legacy aliases."""
    severity = str(value or "INFO").strip().upper().replace("-", "_").replace(" ", "_")
    severity = SEVERITY_ALIASES.get(severity, severity)
    return severity if severity in SEVERITY_WEIGHTS else "INFO"


def normalize_exploitability(value: Any) -> str:
    """Return one of the canonical exploitability levels."""
    raw = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    if raw in {x.value.upper() for x in Exploitability}:
        return Exploitability(raw.lower()).value
    return EXPLOITABILITY_ALIASES.get(raw, Exploitability.UNKNOWN.value)


def normalize_status(value: Any) -> str:
    """Return a canonical finding status, tolerating legacy underscore spellings."""
    raw = str(value or "").strip().lower().replace("_", "-")
    if raw in {x.value for x in FindingStatus}:
        return raw
    return FindingStatus.NEEDS_REVIEW.value


@dataclass
class Evidence:
    source: str = ""
    location: str | None = None
    excerpt: str | None = None
    rule: str | None = None


_CWE_RE = re.compile(r"^CWE-(\d{1,4})$")
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _clean_ref(value: Any, bucket: str = "ref") -> str:
    """Validate an advisory reference (CWE/CVE/ATT&CK) before storing it.

    Malformed identifiers are dropped instead of propagated so that a report
    never advertises a reference that cannot be verified.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if bucket in {"cwe", "cve", "attack"}:
        text = text.upper()
    if bucket == "cve" and re.match(r"^\d{4}-\d{4,7}$", text):
        text = f"CVE-{text}"
    if bucket == "cwe" and re.match(r"^\d{1,4}$", text):
        text = f"CWE-{text}"
    if bucket == "cve":
        match = _CVE_RE.match(text)
        return f"CVE-{match.group(1)}-{match.group(2)}" if match else ""
    if bucket == "cwe":
        match = _CWE_RE.match(text)
        return f"CWE-{int(match.group(1))}" if match else ""
    if bucket == "attack":
        return text if _ATTACK_RE.match(text) else ""
    return text if len(text) <= 200 else ""


def normalize_references(value: Any) -> dict[str, list[str]]:
    """Build a canonical ``{cwe, cve, attack, ref}`` reference map."""
    refs: dict[str, list[str]] = {"cwe": [], "cve": [], "attack": [], "ref": []}
    if not value:
        return refs
    if isinstance(value, (str, int)):
        value = [value]
    items: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, val in value.items():
            key = str(key).strip().lower()
            bucket = ("attack" if key in {"attack", "mitre", "mitre_attack", "tactic", "technique"}
                      else "ref" if key in {"ref", "refs", "reference", "references", "url", "links", "advisory"}
                      else key if key in refs else "ref")
            vals = val if isinstance(val, (list, tuple, set)) else [val]
            for v in vals:
                items.append((bucket, v))
    else:
        items = [("ref", v) for v in value]
    # Bare strings placed in "ref" still land in the right bucket by shape.
    redirected: list[tuple[str, Any]] = []
    for bucket, v in items:
        text = str(v or "").strip().upper()
        if bucket == "ref":
            if _CVE_RE.match(text):
                bucket = "cve"
            elif _CWE_RE.match(text):
                bucket = "cwe"
            elif _ATTACK_RE.match(text):
                bucket = "attack"
        redirected.append((bucket, v))
    for bucket, v in redirected:
        clean = _clean_ref(v, bucket)
        if clean and clean not in refs[bucket]:
            refs[bucket].append(clean)
    for bucket in refs:
        refs[bucket].sort()
    return refs


def _coerce_location(raw: Any, evidence: Any = None) -> dict[str, Any]:
    """Merge explicit location data and legacy evidence hints into one dict."""
    location: dict[str, Any] = {}
    if isinstance(raw, dict):
        for key in LOCATION_KEYS:
            if raw.get(key) not in (None, ""):
                location[key] = raw[key]
    elif isinstance(raw, str) and raw.strip():
        location["file"] = raw.strip()
    if isinstance(evidence, dict):
        if "file" not in location and evidence.get("file"):
            location["file"] = evidence["file"]
        if "line" not in location and evidence.get("line"):
            location["line"] = evidence["line"]
        if "line" not in location and evidence.get("file_line") not in (None, ""):
            file_line = evidence.get("file_line")
            if isinstance(file_line, int):
                location["line"] = file_line
            else:
                parts = str(file_line).rsplit(":", 1)
                location["file"] = location.get("file") or parts[0]
                if len(parts) == 2 and parts[1].isdigit():
                    location["line"] = int(parts[1])
        if "offset" not in location and evidence.get("offset") not in (None, ""):
            location["offset"] = evidence["offset"]
        if "address" not in location and evidence.get("address") not in (None, ""):
            location["address"] = evidence["address"]
    return location


def _location(location: dict[str, Any]) -> str:
    if not location:
        return ""
    parts = []
    if location.get("file"):
        parts.append(str(location["file"]))
    if location.get("function"):
        parts.append(f"fn:{location['function']}")
    if location.get("line") not in (None, ""):
        parts.append(f"line:{location['line']}")
    if location.get("offset") not in (None, ""):
        parts.append(f"off:{location['offset']}")
    if location.get("address") not in (None, ""):
        parts.append(f"addr:{location['address']}")
    return "|".join(parts)


@dataclass
class Finding:
    """Observation normalisée et sérialisable produite par un analyseur."""

    finding_type: str = "observation"
    severity: str = "INFO"
    confidence: float = 0.5
    status: str = FindingStatus.NEEDS_REVIEW.value
    exploitability: str = Exploitability.UNKNOWN.value
    target: str = ""
    target_hash: str = ""
    tool: str = "r3con"
    tool_version: str = "unknown"
    fallback: bool = False
    description: str = ""
    recommendation: str = ""
    evidence: Any = field(default_factory=dict)
    location: dict[str, Any] = field(default_factory=dict)
    references: dict[str, Any] = field(default_factory=dict)
    source_ref: str = ""
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    corroboration: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        self.finding_type = str(self.finding_type or "observation")
        self.severity = normalize_severity(self.severity)
        self.status = normalize_status(self.status)
        self.exploitability = normalize_exploitability(self.exploitability)
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.5
        self.fallback = bool(self.fallback) or bool(
            isinstance(self.provenance, dict) and self.provenance.get("fallback")
        )
        if not isinstance(self.provenance, dict):
            self.provenance = {"raw": self.provenance}
        if not isinstance(self.tags, list):
            self.tags = list(self.tags) if self.tags else []
        self.location = _coerce_location(self.location, self.evidence)
        self.references = normalize_references(self.references)
        if not isinstance(self.corroboration, dict):
            self.corroboration = {"tools": [str(self.corroboration)], "count": 1}
        self.corroboration.setdefault("tools", [self.tool] if self.tool else [])
        self.corroboration.setdefault("count", len(self.corroboration["tools"]) or 1)
        if not self.id:
            self.id = self.stable_id()

    @property
    def type(self) -> str:
        """Alias historique conservé pour les consommateurs v4."""
        return self.finding_type

    @property
    def kind(self) -> str:
        return finding_kind(self)

    def stable_id(self) -> str:
        location = self.location or _legacy_location(self.evidence)
        key = "|".join((self.target_hash or self.target, self.finding_type,
                         self.source_ref or _location(location), self.tool))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["type"] = self.finding_type
        data["schema_version"] = SCHEMA_VERSION
        return data

    @classmethod
    def from_mapping(cls, value: Any, *, target: str = "", target_hash: str = "",
                     tool: str = "r3con", tool_version: str = "unknown",
                     source_task: str = "", provenance: dict[str, Any] | None = None) -> Finding:
        if isinstance(value, cls):
            return value
        raw = dict(value) if isinstance(value, dict) else {"description": str(value)}
        finding_type = raw.pop("finding_type", raw.pop("type", "observation"))
        evidence = raw.pop("evidence", {})

        # Legacy flat keys fold into the structured location.
        legacy_location = {k: raw.pop(k) for k in LOCATION_KEYS if k in raw}

        merged_provenance = dict(provenance or {})
        raw_provenance = raw.pop("provenance", None)
        if isinstance(raw_provenance, dict):
            merged_provenance.update(raw_provenance)
        elif raw_provenance is not None:
            merged_provenance["raw"] = raw_provenance
        if source_task:
            merged_provenance.setdefault("source_task", source_task)

        # Corroborating tool list previously lived in provenance as a string.
        corroboration: dict[str, Any] = {}
        raw_corroborating = merged_provenance.get("corroborating_tools")
        if isinstance(raw_corroborating, str):
            corroboration = {"tools": sorted({x.strip() for x in raw_corroborating.split(",") if x.strip()}),
                             "count": 0}
            corroboration["count"] = len(corroboration["tools"])

        references = raw.pop("references", None)
        for ref_key in ("cwe", "cve"):
            if ref_key in raw:
                references = references or {}
                if isinstance(references, dict):
                    value = str(raw[ref_key] or "").strip()
                    if value:
                        if ref_key == "cwe" and value.isdigit():
                            value = f"CWE-{int(value)}"
                        elif ref_key == "cve" and re.match(r"^\d{4}-\d+$", value):
                            value = f"CVE-{value}"
                        references.setdefault(ref_key, []).append(value)

        allowed = {"severity", "confidence", "status", "exploitability", "target", "target_hash",
                   "tool", "tool_version", "fallback", "description", "recommendation",
                   "source_ref", "timestamp_utc", "tags", "id", "location", "corroboration"}
        values = {k: raw[k] for k in allowed if k in raw}
        values.update({"finding_type": finding_type, "evidence": evidence,
                       "target": values.get("target", target),
                       "target_hash": values.get("target_hash", target_hash),
                       "tool": values.get("tool", tool),
                       "tool_version": values.get("tool_version", tool_version),
                       "references": references,
                       "provenance": merged_provenance})
        merged_location = values.get("location") or {}
        if not isinstance(merged_location, dict):
            merged_location = _coerce_location(merged_location)
        merged_location = {**legacy_location, **merged_location}
        if merged_location:
            values["location"] = merged_location
        if corroboration.get("tools") and not values.get("corroboration"):
            values["corroboration"] = corroboration
        return cls(**values)


def _legacy_location(evidence: Any) -> dict[str, Any]:
    return _coerce_location(None, evidence)


def _location_of(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("location") or value.get("file_line") or value.get("offset") or "")
    if isinstance(value, Finding):
        return _location(value.location)
    return str(value or "")


# Back-compatible private alias (some in-repo code/tests may reference it).
_location_dict = _legacy_location


def finding_kind(finding: Any) -> str:
    """Classify a finding into one of the five result classes.

    ``fallback`` wins over the review status: a result produced by a generic
    local engine must never be mistaken for evidence from the specialized
    tool. ``observation`` and ``hypothesis`` stay clearly separated from
    ``confirmed``, and false positives are excluded from risk by consumers.
    """
    item = finding if isinstance(finding, Finding) else Finding.from_mapping(finding)
    if item.status == FindingStatus.FALSE_POSITIVE.value:
        return "faux_positif"
    if item.fallback:
        return "fallback"
    if item.status == FindingStatus.CONFIRMED.value:
        return "confirme"
    if item.status == FindingStatus.HYPOTHESIS.value:
        return "hypothese"
    return "observation"


def normalize_findings(findings: Iterable[Any], **context: Any) -> list[dict[str, Any]]:
    return [Finding.from_mapping(item, **context).to_dict() for item in findings]


def summarize_findings(findings: Iterable[Any]) -> dict[str, Any]:
    """Build a deterministic risk summary without changing the findings list.

    Le score est borné à 0..100 et combine sévérité, confiance, exploitabilité
    et corroboration ; il sert d'indicateur de triage, pas de certitude.
    """
    normalized = [Finding.from_mapping(item) for item in findings]
    counts = dict.fromkeys(SEVERITY_WEIGHTS, 0)
    kind_counts = {"observation": 0, "hypothese": 0, "confirme": 0, "faux_positif": 0, "fallback": 0}
    weighted_score = 0.0
    confirmed = 0
    corroborated = 0
    exploitable = 0
    for finding in normalized:
        kind_counts[finding_kind(finding)] += 1
        if finding.status == FindingStatus.FALSE_POSITIVE.value:
            continue
        counts[finding.severity] += 1
        weight = SEVERITY_WEIGHTS[finding.severity] * finding.confidence
        if finding.exploitability in {Exploitability.LIKELY.value, Exploitability.CONFIRMED.value}:
            weight *= 1.2
        elif finding.exploitability == Exploitability.POSSIBLE.value:
            weight *= 1.1
        corroborating = finding.corroboration.get("tools") or []
        if len(corroborating) > 1:
            weight *= 1.1
            corroborated += 1
        if finding.exploitability == Exploitability.CONFIRMED.value:
            exploitable += 1
        weighted_score += weight
        if finding.status == FindingStatus.CONFIRMED.value:
            confirmed += 1
    # A bounded score is easier to compare between reports of different sizes.
    score = min(100.0, round(weighted_score * 10, 2))
    rating = "critical" if score >= 75 else "high" if score >= 45 else "medium" if score >= 20 else "low" if score else "none"
    return {"counts": counts, "total": len(normalized), "confirmed": confirmed,
            "corroborated": corroborated, "exploitable": exploitable,
            "fallback": kind_counts["fallback"], "by_kind": kind_counts,
            "score": score, "rating": rating}


def _dedup_key(item: Finding) -> str:
    location_key = _location(item.location)
    return "|".join((item.target_hash or item.target, item.finding_type,
                     location_key or item.source_ref))


def deduplicate_findings(findings: Iterable[Any]) -> list[dict[str, Any]]:
    """Dédupliquer sans perdre les outils indépendants qui corroborent."""
    grouped: dict[str, Finding] = {}
    order: list[str] = []
    for raw in findings:
        item = Finding.from_mapping(raw)
        key = _dedup_key(item)
        if key not in grouped:
            grouped[key] = item
            order.append(key)
            continue
        current = grouped[key]
        current.confidence = min(0.99, max(current.confidence, item.confidence) + 0.05)
        current.tags = sorted(set(current.tags + item.tags + ["corroborated"]))
        tools = set(current.corroboration.get("tools") or [])
        tools.update(item.corroboration.get("tools") or [])
        if current.tool:
            tools.add(current.tool)
        if item.tool:
            tools.add(item.tool)
        current.corroboration = {"tools": sorted(tools), "count": len(tools)}
        # Keep the historical string form in provenance for v2.0 consumers.
        current.provenance["corroborating_tools"] = ",".join(sorted(tools))
        if current.severity == "INFO" and item.severity != "INFO":
            current.severity = item.severity
        for bucket, values in (item.references or {}).items():
            merged = current.references.setdefault(bucket, [])
            for value in values or []:
                if value not in merged:
                    merged.append(value)
            merged.sort()
        for lkey in LOCATION_KEYS:
            if lkey not in current.location and item.location.get(lkey) not in (None, ""):
                current.location[lkey] = item.location[lkey]
        if not current.description and item.description:
            current.description = item.description
        if not current.recommendation and item.recommendation:
            current.recommendation = item.recommendation
        # A finding corroborated by a real tool is no longer a fallback-only
        # observation when at least one non-fallback tool confirmed it.
        if current.fallback and not item.fallback:
            current.fallback = False
        # Re-derive nothing else; id stays the one of the first observation.
    return [grouped[k].to_dict() for k in order]


def make_result(status: Status | str, *, findings=None, error=None, **data) -> dict[str, Any]:
    """Construire une enveloppe stable et sérialisable pour chaque analyse."""
    value = status.value if isinstance(status, Status) else str(status)
    result = {"schema_version": SCHEMA_VERSION, "status": value, **data}
    if findings is not None:
        result["findings"] = [x.to_dict() if isinstance(x, Finding) else x for x in findings]
        result["finding_summary"] = summarize_findings(result["findings"])
    if error is not None:
        result["error"] = error
    return result


def json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def dumps(value: Any, **kwargs: Any) -> str:
    return json.dumps(value, default=json_default, ensure_ascii=False, **kwargs)
