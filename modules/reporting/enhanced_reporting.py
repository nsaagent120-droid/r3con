"""
r3con v6.1 - Enhanced Reporting PRO renforcé
Rapports bug bounty, compliance, executive summary, PDF avec graphs
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import hashlib

class EnhancedReporting:
    """Reporting PRO renforcé."""

    def __init__(self):
        pass

    def generate_bugbounty_report(self, findings: List[Dict[str, Any]], target: str, workspace: str = None) -> Dict[str, Any]:
        """Génère rapport bug bounty (HackerOne/Bugcrowd style)."""

        # Group by severity
        by_sev = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        # Calculate risk score
        risk_score = 0
        risk_score += by_sev.get("CRITICAL", 0) * 10
        risk_score += by_sev.get("HIGH", 0) * 5
        risk_score += by_sev.get("MEDIUM", 0) * 2
        risk_score += by_sev.get("LOW", 0) * 1

        # Determine overall risk
        if risk_score >= 20:
            overall_risk = "CRITICAL"
        elif risk_score >= 10:
            overall_risk = "HIGH"
        elif risk_score >= 5:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        # Generate sections
        report = {
            "title": f"Security Report - {Path(target).name}",
            "target": target,
            "workspace": workspace,
            "generated": datetime.now(timezone.utc).isoformat(),
            "executive_summary": self._executive_summary(findings, overall_risk, risk_score),
            "risk": {
                "overall": overall_risk,
                "score": risk_score,
                "by_severity": by_sev,
                "total_findings": len(findings),
            },
            "findings": [],
            "recommendations": [],
            "compliance": self._compliance_mapping(findings),
            "bugbounty": {
                "platform": "generic",
                "severity": overall_risk,
                "bounty_estimate": self._bounty_estimate(by_sev),
            }
        }

        # Detailed findings for bug bounty
        for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "INFO"), 99))[:50]:
            report["findings"].append({
                "id": f.get("cve_id") or f"R3CON-{hashlib.md5(str(f).encode()).hexdigest()[:8]}",
                "title": f.get("type", "Unknown"),
                "severity": f.get("severity", "INFO"),
                "cvss": f.get("cvss", 0),
                "cwe": f.get("cwe", ""),
                "description": f.get("description", "")[:500],
                "impact": self._impact_description(f),
                "proof_of_concept": f.get("code", "")[:300] or f.get("matched", "")[:300],
                "recommendation": f.get("recommendation", ""),
                "file": f.get("file", ""),
                "line": f.get("line", ""),
                "confidence": f.get("confidence", 0.5),
            })

        # Recommendations
        report["recommendations"] = self._generate_recommendations(findings)

        return report

    def _executive_summary(self, findings: List[Dict], overall_risk: str, risk_score: int) -> str:
        """Génère executive summary."""
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "CRITICAL"])
        high = len([f for f in findings if f.get("severity") == "HIGH"])

        summary = f"""# Executive Summary

**Overall Risk: {overall_risk} (Score: {risk_score})**

This security assessment identified **{total} findings** including **{critical} CRITICAL** and **{high} HIGH** severity issues.

"""

        if critical > 0:
            summary += f"⚠️ **Immediate action required**: {critical} critical vulnerabilities pose significant risk and should be addressed immediately.\n\n"

        # Top types
        by_type = {}
        for f in findings:
            t = f.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        top_types = sorted(by_type.items(), key=lambda x: -x[1])[:5]
        if top_types:
            summary += "## Top Vulnerability Types\n"
            for t, count in top_types:
                summary += f"- **{t}**: {count} occurrences\n"
            summary += "\n"

        summary += """## Impact

If exploited, these vulnerabilities could lead to:
- Remote code execution
- Data breach and information disclosure
- Privilege escalation
- Denial of service

## Recommendation

Prioritize remediation of CRITICAL and HIGH severity findings. Implement secure coding practices and regular security assessments.
"""

        return summary

    def _impact_description(self, finding: Dict) -> str:
        """Génère description impact."""
        f_type = finding.get("type", "").lower()

        impacts = {
            "buffer_overflow": "Buffer overflow can lead to remote code execution, crash, or privilege escalation. Attacker can overwrite memory and control execution flow.",
            "command_injection": "Command injection allows attacker to execute arbitrary OS commands on server, leading to full compromise.",
            "sql_injection": "SQL injection can lead to data breach, authentication bypass, and database compromise.",
            "xss": "Cross-site scripting can lead to session hijacking, defacement, and theft of sensitive data.",
            "format_string": "Format string vulnerability can lead to information disclosure, crash, or code execution.",
            "use_after_free": "Use-after-free can lead to code execution, information disclosure, or crash.",
        }

        for key, desc in impacts.items():
            if key in f_type:
                return desc

        return f"{finding.get('severity', 'MEDIUM')} severity vulnerability. {finding.get('description', '')[:200]}"

    def _bounty_estimate(self, by_sev: Dict[str, int]) -> Dict[str, Any]:
        """Estime bounty bug bounty."""
        # Simplified bounty estimation
        bounty = 0
        bounty += by_sev.get("CRITICAL", 0) * 2000
        bounty += by_sev.get("HIGH", 0) * 500
        bounty += by_sev.get("MEDIUM", 0) * 100
        bounty += by_sev.get("LOW", 0) * 25

        return {
            "estimated_min": bounty,
            "estimated_max": bounty * 2,
            "currency": "USD",
            "note": "Estimation basée sur sévérité, bounty réel dépend plateforme et impact",
        }

    def _compliance_mapping(self, findings: List[Dict]) -> Dict[str, Any]:
        """Mapping compliance OWASP, CWE, NIST."""
        by_owasp = {}
        by_cwe = {}

        for f in findings:
            owasp = f.get("owasp", "Unknown")
            cwe = f.get("cwe", "Unknown")
            by_owasp[owasp] = by_owasp.get(owasp, 0) + 1
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

        return {
            "owasp_top10_2021": by_owasp,
            "cwe": dict(sorted(by_cwe.items(), key=lambda x: -x[1])[:10]),
            "nist": {
                "PR.DS-1": len([f for f in findings if "crypto" in f.get("type", "").lower()]),
                "PR.AC-4": len([f for f in findings if "auth" in f.get("type", "").lower()]),
                "DE.CM-1": len(findings),  # Monitoring
            },
            "iso27001": {
                "A.14.2.5": len([f for f in findings if "injection" in f.get("type", "").lower()]),
                "A.12.6.1": len(findings),
            }
        }

    def _generate_recommendations(self, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Génère recommandations priorisées."""
        recommendations = []

        # Group by type
        by_type = {}
        for f in findings:
            t = f.get("type", "unknown")
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(f)

        for vuln_type, vuln_findings in by_type.items():
            if not vuln_findings:
                continue

            # Get most common recommendation for this type
            recs = [f.get("recommendation", "") for f in vuln_findings if f.get("recommendation")]
            most_common_rec = max(set(recs), key=recs.count) if recs else "Review and fix vulnerability"

            recommendations.append({
                "type": vuln_type,
                "count": len(vuln_findings),
                "severity": max(vuln_findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "INFO"), 99)).get("severity", "MEDIUM"),
                "recommendation": most_common_rec,
                "priority": "P1" if any(f.get("severity") == "CRITICAL" for f in vuln_findings) else "P2" if any(f.get("severity") == "HIGH" for f in vuln_findings) else "P3",
            })

        # Sort by priority
        priority_order = {"P1": 0, "P2": 1, "P3": 2}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 99))

        return recommendations[:20]

    def generate_sarif(self, findings: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
        """Génère rapport SARIF pour GitHub."""
        rules = []
        results = []

        # Create rules from findings
        seen_types = set()
        for f in findings:
            f_type = f.get("type", "unknown")
            if f_type not in seen_types:
                seen_types.add(f_type)
                rules.append({
                    "id": f_type,
                    "name": f_type,
                    "shortDescription": {"text": f_type},
                    "fullDescription": {"text": f.get("description", "")[:500]},
                    "defaultConfiguration": {"level": "error" if f.get("severity") == "CRITICAL" else "warning" if f.get("severity") == "HIGH" else "note"},
                    "properties": {"tags": ["security", f.get("cwe", ""), f.get("severity", "")]},
                })

        for f in findings[:100]:
            results.append({
                "ruleId": f.get("type", "unknown"),
                "level": "error" if f.get("severity") == "CRITICAL" else "warning" if f.get("severity") == "HIGH" else "note",
                "message": {"text": f.get("description", "")[:500]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", target)},
                        "region": {"startLine": f.get("line", 1)}
                    }
                }],
                "properties": {"severity": f.get("severity", "INFO"), "cwe": f.get("cwe", "")},
            })

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemplify.io/sarif-2.1.0-rtm.5.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "r3con",
                        "version": "6.1.0",
                        "informationUri": "https://github.com/nsaagent120-droid/r3con",
                        "rules": rules,
                    }
                },
                "results": results,
            }]
        }

    def save_report(self, report: Dict[str, Any], output_path: str, format: str = "json") -> str:
        """Sauvegarde rapport."""
        out_path = Path(output_path)

        if format == "json":
            out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        elif format == "md":
            # Generate markdown
            md = f"# {report.get('title', 'Security Report')}\n\n"
            md += report.get("executive_summary", "") + "\n\n"
            md += f"## Findings ({len(report.get('findings', []))})\n\n"
            for finding in report.get("findings", [])[:20]:
                md += f"### [{finding.get('severity')}] {finding.get('title')}\n"
                md += f"- **ID**: {finding.get('id')}\n"
                md += f"- **CWE**: {finding.get('cwe')}\n"
                md += f"- **File**: {finding.get('file')}:{finding.get('line')}\n"
                md += f"- **Description**: {finding.get('description')}\n"
                md += f"- **Impact**: {finding.get('impact')}\n"
                md += f"- **Recommendation**: {finding.get('recommendation')}\n\n"
            out_path.write_text(md, encoding="utf-8")
        elif format == "sarif":
            sarif = self.generate_sarif(report.get("findings", []), report.get("target", ""))
            out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

        return str(out_path)
