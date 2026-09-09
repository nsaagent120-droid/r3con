"""
r3con v6.0 - Knowledge Engine - CVE DB offline
Base CVE offline avec patterns
"""
from __future__ import annotations
from typing import List, Dict, Any
import re
from pathlib import Path

# Mini CVE DB offline - patterns connus
CVE_PATTERNS = [
    {
        "id": "CVE-2023-BOF-001",
        "type": "stack_buffer_overflow",
        "cwe": "CWE-121",
        "severity": "CRITICAL",
        "pattern": r"gets\s*\(",
        "description": "gets() sans vérification taille - stack BOF",
        "recommendation": "Utiliser fgets() avec taille explicite",
        "reference": "CWE-242",
    },
    {
        "id": "CVE-2023-BOF-002",
        "type": "stack_buffer_overflow",
        "cwe": "CWE-121",
        "severity": "HIGH",
        "pattern": r"strcpy\s*\(",
        "description": "strcpy() sans vérification - BOF",
        "recommendation": "Utiliser strncpy() ou strlcpy()",
        "reference": "CWE-120",
    },
    {
        "id": "CVE-2023-CMD-001",
        "type": "command_injection",
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "pattern": r"system\s*\(\s*.*\+.*\)",
        "description": "system() avec concaténation - injection commande",
        "recommendation": "Éviter system(), utiliser execve avec args séparés",
        "reference": "CWE-78",
    },
    {
        "id": "CVE-2023-FMT-001",
        "type": "format_string",
        "cwe": "CWE-134",
        "severity": "HIGH",
        "pattern": r"printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "description": "printf(var) sans format - format string vuln",
        "recommendation": "Utiliser printf(\"%s\", var)",
        "reference": "CWE-134",
    },
]

class OfflineCVEDB:
    def search(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            for cve in CVE_PATTERNS:
                if re.search(cve["pattern"], line):
                    findings.append({
                        "cve_id": cve["id"],
                        "type": cve["type"],
                        "cwe": cve["cwe"],
                        "severity": cve["severity"],
                        "description": cve["description"],
                        "recommendation": cve["recommendation"],
                        "line": idx,
                        "code": line.strip()[:100],
                        "reference": cve["reference"],
                    })
        return findings

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_patterns": len(CVE_PATTERNS),
            "by_severity": {
                "CRITICAL": len([c for c in CVE_PATTERNS if c["severity"] == "CRITICAL"]),
                "HIGH": len([c for c in CVE_PATTERNS if c["severity"] == "HIGH"]),
            },
            "by_type": list(set(c["type"] for c in CVE_PATTERNS)),
        }
