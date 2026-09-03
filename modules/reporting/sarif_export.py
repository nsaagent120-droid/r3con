"""
r3con - SARIF Export Module
Static Analysis Results Interchange Format (SARIF) v2.1.0
Compatible avec: GitHub Actions, GitLab CI, VS Code, Azure DevOps
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

# Mapping severity r3con → SARIF
SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MED":      "warning",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

# Mapping severity → security-severity score (pour GitHub)
SECURITY_SEVERITY_MAP = {
    "CRITICAL": "9.5",
    "HIGH":     "7.5",
    "MED":      "5.0",
    "MEDIUM":   "5.0",
    "LOW":      "3.0",
    "INFO":     "1.0",
}


class SARIFExporter:
    """Export r3con findings to SARIF format."""

    def __init__(self):
        self.tool_name    = "r3con"
        self.tool_version = "5.0.0"
        self.tool_url     = ""

    def export(self, findings: List[Dict],
               target: str = "unknown",
               output_path: Optional[str] = None) -> str:
        """
        Export findings to SARIF format.

        Args:
            findings: List of r3con findings
            target: Target file/directory analyzed
            output_path: Where to save the SARIF file

        Returns:
            Path to the generated SARIF file
        """
        sarif = self._build_sarif(findings, target)

        # Determine output path
        if not output_path:
            reports_dir = Path.home() / ".r3con" / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(reports_dir / f"r3con_{ts}.sarif")

        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)

        return output_path

    def export_string(self, findings: List[Dict], target: str = "unknown") -> str:
        """Export findings to SARIF as a JSON string."""
        sarif = self._build_sarif(findings, target)
        return json.dumps(sarif, indent=2)

    def _build_sarif(self, findings: List[Dict], target: str) -> Dict:
        """Build the complete SARIF document."""
        # Collect unique rules from findings
        rules = self._build_rules(findings)

        # Build results
        results = [self._build_result(f, i) for i, f in enumerate(findings)]

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":            self.tool_name,
                            "version":         self.tool_version,
                            "informationUri":  self.tool_url,
                            "rules":           rules,
                            "properties": {
                                "tags": ["security", "binary-analysis",
                                         "apk", "firmware", "static-analysis"]
                            }
                        }
                    },
                    "results":   results,
                    "artifacts": self._build_artifacts(findings, target),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": f"r3con audit {target}",
                            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ]
                }
            ]
        }

    def _build_rules(self, findings: List[Dict]) -> List[Dict]:
        """Build unique rules list from findings."""
        seen  = set()
        rules = []

        for f in findings:
            rule_id = self._rule_id(f.get("type", "UNKNOWN"))
            if rule_id in seen:
                continue
            seen.add(rule_id)

            sev     = f.get("severity", "INFO")
            cwe     = f.get("cwe", "")
            cvss    = f.get("cvss", SECURITY_SEVERITY_MAP.get(sev, "5.0"))

            rule = {
                "id":   rule_id,
                "name": f.get("type", "Unknown").replace(" ", ""),
                "shortDescription": {
                    "text": f.get("type", "Unknown vulnerability")
                },
                "fullDescription": {
                    "text": f.get("description", "")[:500]
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html" if cwe else None,
                "help": {
                    "text": f.get("fix", f.get("recommendation", "Review and fix the identified issue.")),
                },
                "properties": {
                    "tags":              ["security", sev.lower()],
                    "security-severity": str(cvss),
                    "precision":         "medium",
                    "problem.severity":  SEVERITY_MAP.get(sev, "warning"),
                },
                "defaultConfiguration": {
                    "level": SEVERITY_MAP.get(sev, "warning")
                }
            }

            # Add CWE tag if available
            if cwe:
                rule["properties"]["tags"].append(cwe)

            rules.append(rule)

        return rules

    def _build_result(self, finding: Dict, index: int) -> Dict:
        """Build a single SARIF result from a finding."""
        sev     = finding.get("severity", "INFO")
        rule_id = self._rule_id(finding.get("type", "UNKNOWN"))
        file    = finding.get("file", "unknown")
        line    = finding.get("line") or 1

        result = {
            "ruleId":  rule_id,
            "level":   SEVERITY_MAP.get(sev, "warning"),
            "message": {
                "text": finding.get("description", "")[:500]
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":       self._normalize_path(file),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine":   line,
                            "startColumn": 1,
                        }
                    },
                    "logicalLocations": [
                        {
                            "kind": "function",
                            "name": finding.get("function", "unknown")
                        }
                    ] if finding.get("function") else []
                }
            ],
            "properties": {
                "severity":    sev,
                "cwe":         finding.get("cwe", ""),
                "cvss":        str(finding.get("cvss", "")),
                "fix":         finding.get("fix", finding.get("recommendation", "")),
                "priority":    finding.get("priority", ""),
            }
        }

        # Add fix suggestion if available
        fix = finding.get("fix", finding.get("recommendation", ""))
        if fix:
            result["fixes"] = [
                {
                    "description": {"text": fix},
                }
            ]

        # Add related locations for taint flows
        if finding.get("taint_source"):
            result["relatedLocations"] = [
                {
                    "id":      1,
                    "message": {"text": "Taint source"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": self._normalize_path(
                                finding.get("taint_source_file", file))
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
        files.add(target)
        for f in findings:
            if f.get("file"):
                files.add(f["file"])

        return [
            {
                "location": {
                    "uri":       self._normalize_path(f),
                    "uriBaseId": "%SRCROOT%",
                },
                "roles": ["analysisTarget"]
            }
            for f in files
        ]

    def _rule_id(self, vuln_type: str) -> str:
        """Convert vulnerability type to rule ID."""
        return "R3CON-" + vuln_type.upper().replace(" ", "-").replace("/", "-")[:20]

    def _normalize_path(self, path: str) -> str:
        """Normalize file path for SARIF."""
        return path.replace("\\", "/").lstrip("/")
