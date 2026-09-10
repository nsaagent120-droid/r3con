"""
r3con - SARIF Export Module - FIXED P2
Fixes: version, path normalization, deduplication, size limits
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

# Mapping severity r3con → SARIF
SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MED": "warning",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

# Mapping severity → security-severity score (pour GitHub)
SECURITY_SEVERITY_MAP = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MED": "5.0",
    "MEDIUM": "5.0",
    "LOW": "3.0",
    "INFO": "1.0",
}

TOOL_VERSION = "5.0.2-fixed-p2"


class SARIFExporter:
    """Export r3con findings to SARIF format - FIXED.

    v7.3 : la version du driver suit ``core.__version__`` (fini le numéro
    codé en dur) et un bloc ``metadata`` optionnel (hash de cible, profil,
    fallbacks, durées) est publié dans les propriétés SARIF pour
    l'horodatage d'audit.
    """

    def __init__(self, metadata: Optional[Dict] = None):
        self.tool_name = "r3con"
        try:
            from core.__version__ import __version__ as _ver
            self.tool_version = _ver
        except ImportError:
            self.tool_version = TOOL_VERSION
        self.tool_url = "https://github.com/nsaagent120-droid/r3con"
        self.metadata = metadata or {}

    def export(self, findings: List[Dict],
               target: str = "unknown",
               output_path: Optional[str] = None,
               metadata: Optional[Dict] = None) -> str:
        if metadata:
            self.metadata = {**self.metadata, **metadata}
        """Export findings to SARIF format."""
        # Deduplicate and limit
        findings = self._deduplicate(findings)
        findings = findings[:1000]  # Limit to 1000

        sarif = self._build_sarif(findings, target)

        # Determine output path with validation
        if not output_path:
            reports_dir = Path.home() / ".r3con" / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize target for filename
            safe_target = "".join(c if c.isalnum() or c in "-_" else "_" for c in Path(target).name)[:50]
            output_path = str(reports_dir / f"r3con_{safe_target}_{ts}.sarif")
        else:
            # Validate output path
            if len(output_path) > 1024 or ".." in output_path:
                raise ValueError("Invalid output path")

        # Atomic write
        import tempfile, os
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sarif", dir=str(Path(output_path).parent) if Path(output_path).parent.exists() else None)
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(sarif, f, indent=2)
            os.rename(tmp_path, output_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            # Fallback direct write
            with open(output_path, "w") as f:
                json.dump(sarif, f, indent=2)

        return output_path

    def export_string(self, findings: List[Dict], target: str = "unknown",
                      metadata: Optional[Dict] = None) -> str:
        """Export findings to SARIF as a JSON string."""
        if metadata:
            self.metadata = {**self.metadata, **metadata}
        findings = self._deduplicate(findings)[:1000]
        sarif = self._build_sarif(findings, target)
        return json.dumps(sarif, indent=2)

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings by type+file+line."""
        seen = {}
        result = []
        for f in findings:
            key = f"{f.get('type','')}|{f.get('file','')}|{f.get('line','')}|{f.get('description','')[:50]}"
            h = hashlib.sha256(key.encode()).hexdigest()[:16]
            if h not in seen:
                seen[h] = True
                result.append(f)
        return result

    def _build_sarif(self, findings: List[Dict], target: str) -> Dict:
        """Build the complete SARIF document."""
        rules = self._build_rules(findings)
        results = [self._build_result(f, i) for i, f in enumerate(findings)]

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": self.tool_url,
                            "rules": rules,
                            "properties": {
                                "tags": ["security", "binary-analysis", "apk", "firmware", "static-analysis"]
                            }
                        }
                    },
                    "results": results,
                    "artifacts": self._build_artifacts(findings, target),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": f"r3con audit {target}",
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "properties": {
                        "r3con_version": self.tool_version,
                        "total_findings": len(findings),
                        **{k: v for k, v in self.metadata.items()
                           if k in {"target_hash", "sha256", "profile", "duration_ms",
                                    "fallbacks_used", "limits_applied", "generated_utc",
                                    "tool_versions", "resumed_from", "offline"}},
                    }
                }
            ]
        }

    def _build_rules(self, findings: List[Dict]) -> List[Dict]:
        """Build unique rules list from findings."""
        seen = set()
        rules = []

        for f in findings:
            rule_id = self._rule_id(f.get("type", "UNKNOWN"))
            if rule_id in seen:
                continue
            seen.add(rule_id)

            sev = f.get("severity", "INFO")
            cwe = f.get("cwe", "")
            if not cwe:
                refs = f.get("references") or {}
                cwes = refs.get("cwe") if isinstance(refs, dict) else None
                if cwes:
                    cwe = cwes[0]
            cvss = f.get("cvss", SECURITY_SEVERITY_MAP.get(sev, "5.0"))

            rule = {
                "id": rule_id,
                "name": f.get("type", "Unknown").replace(" ", "")[:50],
                "shortDescription": {
                    "text": f.get("type", "Unknown vulnerability")[:200]
                },
                "fullDescription": {
                    "text": f.get("description", "")[:500]
                },
                "help": {
                    "text": f.get("fix", f.get("recommendation", "Review and fix the identified issue."))[:500],
                },
                "properties": {
                    "tags": ["security", sev.lower()],
                    "security-severity": str(cvss)[:10],
                    "precision": "medium",
                    "problem.severity": SEVERITY_MAP.get(sev, "warning"),
                },
                "defaultConfiguration": {
                    "level": SEVERITY_MAP.get(sev, "warning")
                }
            }

            if cwe and isinstance(cwe, str) and cwe.startswith("CWE-"):
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html"
                rule["properties"]["tags"].append(cwe)
            elif cwe:
                rule["properties"]["tags"].append(str(cwe)[:20])

            rules.append(rule)

        return rules

    def _build_result(self, finding: Dict, index: int) -> Dict:
        """Build a single SARIF result from a finding."""
        sev = finding.get("severity", "INFO")
        rule_id = self._rule_id(finding.get("type", "UNKNOWN"))
        location = finding.get("location") or {}
        file = finding.get("file") or (location.get("file") if isinstance(location, dict) else "") or "unknown"
        line = finding.get("line") or (location.get("line") if isinstance(location, dict) else None) or 1

        # Validate line
        try:
            line = int(line)
            if line < 1 or line > 1000000:
                line = 1
        except (ValueError, TypeError):
            line = 1

        result = {
            "ruleId": rule_id,
            "ruleIndex": index,
            "level": SEVERITY_MAP.get(sev, "warning"),
            "message": {
                "text": finding.get("description", "")[:500]
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": self._normalize_path(file),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": 1,
                        }
                    },
                    "logicalLocations": [
                        {
                            "kind": "function",
                            "name": finding.get("function", "unknown")[:100]
                        }
                    ] if finding.get("function") else []
                }
            ],
            "properties": {
                "severity": sev,
                "cwe": str(finding.get("cwe", ""))[:20],
                "cvss": str(finding.get("cvss", ""))[:10],
                "fix": str(finding.get("fix", finding.get("recommendation", "")))[:500],
                "confidence": str(finding.get("confidence", ""))[:10],
            }
        }

        fix = finding.get("fix", finding.get("recommendation", ""))
        if fix:
            result["fixes"] = [
                {
                    "description": {"text": str(fix)[:500]},
                }
            ]

        if finding.get("taint_source"):
            result["relatedLocations"] = [
                {
                    "id": 1,
                    "message": {"text": "Taint source"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": self._normalize_path(finding.get("taint_source_file", file))
                        },
                        "region": {
                            "startLine": finding.get("taint_source_line", 1)
                        }
                    }
                }
            ]

        return result

    def _build_artifacts(self, findings: List[Dict], target: str) -> List[Dict]:
        """Build artifacts list."""
        files = set()
        # Sanitize target
        if target and len(target) < 1024:
            files.add(target)
        for f in findings:
            if f.get("file") and len(f["file"]) < 1024:
                files.add(f["file"])

        return [
            {
                "location": {
                    "uri": self._normalize_path(f),
                    "uriBaseId": "%SRCROOT%",
                },
                "roles": ["analysisTarget"]
            }
            for f in list(files)[:100]  # Limit to 100 artifacts
        ]

    def _rule_id(self, vuln_type: str) -> str:
        """Convert vulnerability type to rule ID."""
        # Sanitize
        clean = "".join(c if c.isalnum() or c in "-_ " else "" for c in vuln_type)
        return "R3CON-" + clean.upper().replace(" ", "-").replace("/", "-")[:30]

    def _normalize_path(self, path: str) -> str:
        """Normalize file path for SARIF - FIXED to not break absolute paths."""
        if not path or not isinstance(path, str):
            return "unknown"
        if len(path) > 500:
            path = path[:500]

        # Remove null bytes and control chars
        path = "".join(c for c in path if c.isprintable() or c in "/\\.-_")

        # Normalize separators
        normalized = path.replace("\\", "/")

        # For SARIF, we want relative paths from SRCROOT
        # If absolute, make it relative-like but preserve info
        # Don't lstrip("/") blindly - instead, handle properly
        try:
            p = Path(normalized)
            # If absolute, try to make relative or keep as is with uriBaseId handling
            if p.is_absolute():
                # Keep only last 3 parts for readability, but preserve full in uri
                # SARIF spec allows absolute URIs, but we use uriBaseId
                # So we return relative path
                try:
                    # Try to make it relative to home or cwd
                    rel = p.relative_to(Path.home())
                    return str(rel).replace("\\", "/")
                except ValueError:
                    # Return with leading slash removed for uriBaseId, but not blindly
                    # Keep it as relative by removing leading slash only
                    return normalized.lstrip("/")[:200]
            return normalized[:200]
        except Exception:
            return normalized[:200].lstrip("/") or "unknown"
