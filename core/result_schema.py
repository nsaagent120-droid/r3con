"""Contrats communs de résultats pour les analyseurs r3con.

Le module conserve les statuts d'exécution historiques et fournit un contrat
Finding unique pour les observations de sécurité. Les helpers de normalisation
permettent une migration progressive des modules qui renvoient encore des
 dictionnaires historiques.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


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


@dataclass
class Evidence:
    source: str = ""
    location: Optional[str] = None
    excerpt: Optional[str] = None
    rule: Optional[str] = None


@dataclass
class Finding:
    """Observation normalisée et sérialisable produite par un analyseur."""

    finding_type: str = "observation"
    severity: str = "INFO"
    confidence: float = 0.5
    status: str = FindingStatus.NEEDS_REVIEW.value
    target: str = ""
    target_hash: str = ""
    tool: str = "r3con"
    tool_version: str = "unknown"
    description: str = ""
    recommendation: str = ""
    evidence: Any = field(default_factory=dict)
    source_ref: str = ""
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        self.finding_type = str(self.finding_type or "observation")
        self.severity = str(self.severity or "INFO").upper()
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.5
        if self.status not in {x.value for x in FindingStatus}:
            self.status = FindingStatus.NEEDS_REVIEW.value
        if not isinstance(self.provenance, dict):
            self.provenance = {"raw": self.provenance}
        if not isinstance(self.tags, list):
            self.tags = list(self.tags) if self.tags else []
        if not self.id:
            self.id = self.stable_id()

    @property
    def type(self) -> str:
        """Alias historique conservé pour les consommateurs v4."""
        return self.finding_type

    def stable_id(self) -> str:
        key = "|".join((self.target_hash or self.target, self.finding_type,
                         self.source_ref, _location(self.evidence), self.tool))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["type"] = self.finding_type
        return data

    @classmethod
    def from_mapping(cls, value: Any, *, target: str = "", target_hash: str = "",
                     tool: str = "r3con", tool_version: str = "unknown",
                     source_task: str = "", provenance: Optional[Dict[str, Any]] = None) -> "Finding":
        if isinstance(value, cls):
            return value
        raw = dict(value) if isinstance(value, dict) else {"description": str(value)}
        finding_type = raw.pop("finding_type", raw.pop("type", "observation"))
        evidence = raw.pop("evidence", {})
        merged_provenance = dict(provenance or {})
        raw_provenance = raw.pop("provenance", None)
        if isinstance(raw_provenance, dict):
            merged_provenance.update(raw_provenance)
        elif raw_provenance is not None:
            merged_provenance["raw"] = raw_provenance
        if source_task:
            merged_provenance.setdefault("source_task", source_task)
        allowed = {"severity", "confidence", "status", "target", "target_hash",
                   "tool", "tool_version", "description", "recommendation",
                   "source_ref", "timestamp_utc", "tags", "id"}
        values = {k: raw[k] for k in allowed if k in raw}
        values.update({"finding_type": finding_type, "evidence": evidence,
                       "target": values.get("target", target),
                       "target_hash": values.get("target_hash", target_hash),
                       "tool": values.get("tool", tool),
                       "tool_version": values.get("tool_version", tool_version),
                       "provenance": merged_provenance})
        return cls(**values)


def _location(evidence: Any) -> str:
    if isinstance(evidence, dict):
        return str(evidence.get("location") or evidence.get("file_line") or evidence.get("offset") or "")
    return str(evidence or "")


def normalize_findings(findings: Iterable[Any], **context: Any) -> List[Dict[str, Any]]:
    return [Finding.from_mapping(item, **context).to_dict() for item in findings]


def deduplicate_findings(findings: Iterable[Any]) -> List[Dict[str, Any]]:
    """Dédupliquer sans perdre les outils indépendants qui corroborent."""
    grouped: Dict[str, Finding] = {}
    for raw in findings:
        item = Finding.from_mapping(raw)
        key = "|".join((item.target_hash or item.target, item.finding_type,
                         _location(item.evidence)))
        if key not in grouped:
            grouped[key] = item
            continue
        current = grouped[key]
        current.confidence = min(0.99, max(current.confidence, item.confidence) + 0.05)
        current.tags = sorted(set(current.tags + item.tags + ["corroborated"]))
        tools = set(str(current.provenance.get("corroborating_tools", current.tool)).split(","))
        tools.add(item.tool)
        current.provenance["corroborating_tools"] = ",".join(sorted(x for x in tools if x))
        if current.severity == "INFO" and item.severity != "INFO":
            current.severity = item.severity
    return [item.to_dict() for item in grouped.values()]


def make_result(status: Status | str, *, findings=None, error=None, **data) -> Dict[str, Any]:
    """Construire une enveloppe stable et sérialisable pour chaque analyse."""
    value = status.value if isinstance(status, Status) else str(status)
    result = {"schema_version": "2.0", "status": value, **data}
    if findings is not None:
        result["findings"] = [x.to_dict() if isinstance(x, Finding) else x for x in findings]
    if error is not None:
        result["error"] = error
    return result


def json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def dumps(value: Any, **kwargs: Any) -> str:
    return json.dumps(value, default=json_default, ensure_ascii=False, **kwargs)
