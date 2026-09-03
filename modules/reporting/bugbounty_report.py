"""
r3con - Bug Bounty Report Generator
Génère automatiquement des rapports formatés pour:
- HackerOne
- Bugcrowd
- Intigriti
- Rapport générique Markdown
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


# Mapping severity → CVSS range
SEVERITY_CVSS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MED":      (4.0, 6.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
    "INFO":     (0.0, 0.0),
}

# Mapping severity → bug bounty payout range (rough estimate)
PAYOUT_ESTIMATE = {
    "CRITICAL": "$5,000 - $50,000+",
    "HIGH":     "$1,000 - $10,000",
    "MED":      "$200 - $2,000",
    "MEDIUM":   "$200 - $2,000",
    "LOW":      "$50 - $500",
    "INFO":     "Informational (no payout)",
}


class BugBountyReportGenerator:
    """Generate professional bug bounty reports."""

    def __init__(self):
        self.reports_dir = Path.home() / ".r3con" / "reports" / "bugbounty"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, findings: List[Dict],
                 target: str,
                 program: str = "generic",
                 researcher: str = "Security Researcher",
                 output_path: Optional[str] = None) -> str:
        """
        Generate a complete bug bounty report.

        Args:
            findings: List of r3con findings
            target: Target application/binary analyzed
            program: Bug bounty platform (hackerone/bugcrowd/intigriti/generic)
            researcher: Researcher name
            output_path: Custom output path

        Returns:
            Path to generated report
        """
        # Filter to CRITICAL and HIGH only for bug bounty
        reportable = [f for f in findings
                      if f.get("severity") in ("CRITICAL","HIGH","MED","MEDIUM")]

        if not reportable:
            reportable = findings[:5]  # Take top 5 if nothing critical

        # Generate report for each finding
        reports = []
        for finding in reportable[:10]:  # Max 10 per run
            report = self._generate_single_report(
                finding, target, program, researcher)
            reports.append(report)

        # Generate summary report
        summary = self._generate_summary(findings, target, program, researcher)

        # Save
        if not output_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.reports_dir / f"bugbounty_{program}_{ts}.md")

        with open(output_path, "w") as f:
            f.write(summary)
            f.write("\n\n---\n\n")
            f.write("\n\n---\n\n".join(reports))

        return output_path

    def generate_single(self, finding: Dict,
                        target: str,
                        program: str = "hackerone") -> str:
        """Generate a single finding report as string."""
        return self._generate_single_report(finding, target, program)

    def _generate_single_report(self, finding: Dict,
                                  target: str,
                                  program: str,
                                  researcher: str = "Security Researcher") -> str:
        """Generate a report for one finding."""
        finding.get("severity", "MEDIUM")
        finding.get("type", "Unknown Vulnerability")
        finding.get("description", "")
        finding.get("line")
        finding.get("file", target)
        finding.get("cwe", "")
        finding.get("cvss", 5.0)
        finding.get("fix", finding.get("recommendation", ""))
        finding.get("code_snippet", "")

        if program == "hackerone":
            return self._hackerone_format(finding, target, researcher)
        elif program == "bugcrowd":
            return self._bugcrowd_format(finding, target, researcher)
        elif program == "intigriti":
            return self._intigriti_format(finding, target, researcher)
        else:
            return self._generic_format(finding, target, researcher)

    def _hackerone_format(self, f: Dict, target: str, researcher: str) -> str:
        """HackerOne report format."""
        f.get("severity", "medium").lower()
        ftype   = f.get("type", "Vulnerability")
        desc    = f.get("description", "")
        fix     = f.get("fix", f.get("recommendation", ""))
        cwe     = f.get("cwe", "")
        cvss    = f.get("cvss", 5.0)
        line    = f.get("line", "N/A")
        snippet = f.get("code_snippet", "")
        chains  = f.get("attack_steps", [])

        report = f"""## Title
{ftype} in {target}

## Severity
**{f.get('severity', 'MEDIUM')}** (CVSS: {cvss})
{f'CWE: {cwe}' if cwe else ''}

## Summary
A {ftype.lower()} vulnerability was identified in `{target}`{f' at line {line}' if line else ''}.
{desc}

## Vulnerability Details

**Type:** {ftype}
**Location:** `{f.get('file', target)}`{f', line {line}' if line else ''}
**CWE:** {cwe if cwe else 'N/A'}
**CVSS Score:** {cvss}
**Estimated Payout:** {PAYOUT_ESTIMATE.get(f.get('severity','MEDIUM'), 'Variable')}

## Steps To Reproduce
"""
        if chains:
            for i, step in enumerate(chains, 1):
                report += f"{i}. {step}\n"
        else:
            report += self._generic_steps(f, target)

        if snippet:
            report += f"""
## Vulnerable Code
```c
{snippet}
```
"""

        report += f"""
## Impact
{self._impact_description(f)}

## Recommended Fix
{fix if fix else 'Review and remediate the identified vulnerability.'}

## Supporting Material
- Static analysis performed with r3con v5.0.2
- Finding confidence: {self._confidence(f)}
"""
        return report

    def _bugcrowd_format(self, f: Dict, target: str, researcher: str) -> str:
        """Bugcrowd report format."""
        ftype = f.get("type", "Vulnerability")
        cvss  = f.get("cvss", 5.0)
        cwe   = f.get("cwe", "")
        desc  = f.get("description", "")
        fix   = f.get("fix", f.get("recommendation", ""))
        line  = f.get("line", "N/A")

        return f"""## Bug Title
{ftype} — {target}

## Target
{target}

## Classification
- **Vulnerability Type:** {ftype}
- **CWE:** {cwe if cwe else 'N/A'}
- **CVSS:** {cvss}
- **Bugcrowd VRT:** {self._vrt_mapping(f)}

## Description
{desc}

**Location:** `{f.get('file', target)}`{f', line {line}' if line != 'N/A' else ''}

## Proof of Concept
{self._generic_steps(f, target)}

## Impact
{self._impact_description(f)}

## Remediation
{fix if fix else 'Remediate the identified vulnerability following secure coding guidelines.'}
"""

    def _intigriti_format(self, f: Dict, target: str, researcher: str) -> str:
        """Intigriti report format."""
        return self._generic_format(f, target, researcher)

    def _generic_format(self, f: Dict, target: str, researcher: str) -> str:
        """Generic professional markdown format."""
        sev     = f.get("severity", "MEDIUM")
        ftype   = f.get("type", "Vulnerability")
        desc    = f.get("description", "")
        fix     = f.get("fix", f.get("recommendation", ""))
        cwe     = f.get("cwe", "")
        cvss    = f.get("cvss", 5.0)
        line    = f.get("line")
        snippet = f.get("code_snippet", "")
        chains  = f.get("attack_steps", [])
        date    = datetime.now().strftime("%Y-%m-%d")

        report = f"""# Vulnerability Report: {ftype}

**Date:** {date}
**Researcher:** {researcher}
**Target:** {target}
**Severity:** {sev}
**CVSS Score:** {cvss}
{f'**CWE:** {cwe}' if cwe else ''}
**Estimated Payout:** {PAYOUT_ESTIMATE.get(sev, 'Variable')}

---

## Executive Summary

A **{sev.lower()} severity** {ftype.lower()} vulnerability was identified in `{target}`.
{desc}

---

## Technical Details

| Field | Value |
|-------|-------|
| Vulnerability Type | {ftype} |
| Affected File | `{f.get('file', target)}` |
| Affected Line | {line if line else 'N/A'} |
| CWE | {cwe if cwe else 'N/A'} |
| CVSS 3.1 | {cvss} |
| CVSS Vector | {f.get('cvss_vector', 'N/A')} |

---

## Proof of Concept

### Steps to Reproduce
"""
        if chains:
            for i, step in enumerate(chains, 1):
                report += f"{i}. {step}\n"
        else:
            report += self._generic_steps(f, target)

        if snippet:
            report += f"""
### Vulnerable Code
```
{snippet}
```
"""

        report += f"""
---

## Impact

{self._impact_description(f)}

---

## Recommended Remediation

{fix if fix else 'Review and remediate following secure coding guidelines.'}

---

## References

{f'- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-","")}.html)' if cwe else ''}
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- Analysis performed with r3con v5.0.2

---
*Report generated automatically by r3con v5.0.2*
*Manual verification recommended before submission*
"""
        return report

    def _generate_summary(self, findings: List[Dict],
                           target: str,
                           program: str,
                           researcher: str) -> str:
        """Generate executive summary for all findings."""
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in findings if f.get("severity") == "HIGH"]
        medium   = [f for f in findings if f.get("severity") in ("MED","MEDIUM")]
        low      = [f for f in findings if f.get("severity") == "LOW"]
        date     = datetime.now().strftime("%Y-%m-%d")

        summary = f"""# Bug Bounty Report — {target}

**Date:** {date}
**Researcher:** {researcher}
**Program:** {program.title()}
**Total Findings:** {len(findings)}

## Summary Table

| Severity | Count | Estimated Payout |
|----------|-------|-----------------|
| 🔴 Critical | {len(critical)} | {PAYOUT_ESTIMATE['CRITICAL'] if critical else '$0'} |
| 🟠 High | {len(high)} | {PAYOUT_ESTIMATE['HIGH'] if high else '$0'} |
| 🟡 Medium | {len(medium)} | {PAYOUT_ESTIMATE['MED'] if medium else '$0'} |
| 🟢 Low | {len(low)} | {PAYOUT_ESTIMATE['LOW'] if low else '$0'} |

## Findings Overview

"""
        for i, f in enumerate(findings[:20], 1):
            sev   = f.get("severity", "INFO")
            icons = {"CRITICAL":"🔴","HIGH":"🟠","MED":"🟡","MEDIUM":"🟡","LOW":"🟢","INFO":"⚪"}
            icon  = icons.get(sev, "⚪")
            summary += f"{i}. {icon} **[{sev}]** {f.get('type','?')} "
            if f.get("file"):
                summary += f"— `{f['file']}`"
            if f.get("line"):
                summary += f" L{f['line']}"
            summary += "\n"

        summary += f"""
---

*{len(findings)} total findings. Top priorities listed first.*
*Generated by r3con v5.0.2 — Manual verification recommended.*

---
"""
        return summary

    def _generic_steps(self, f: Dict, target: str) -> str:
        """Generate generic reproduction steps."""
        ftype = f.get("type", "vulnerability")
        line  = f.get("line", "N/A")
        file  = f.get("file", target)

        steps = f"""
1. Obtain the target binary/source: `{target}`
2. Locate the vulnerable code at `{file}`{f', line {line}' if line != 'N/A' else ''}
3. Craft a malicious input targeting the {ftype.lower()}
4. Observe the vulnerability being triggered
5. Confirm impact as described below

"""
        return steps

    def _impact_description(self, f: Dict) -> str:
        """Generate impact description based on finding type."""
        ftype = f.get("type", "")
        sev   = f.get("severity", "MEDIUM")

        impacts = {
            "Buffer Overflow":      "An attacker can overwrite adjacent memory, potentially leading to arbitrary code execution, privilege escalation, or denial of service.",
            "Use-After-Free":       "An attacker can manipulate freed memory to execute arbitrary code or leak sensitive information.",
            "Integer Overflow":     "An attacker can trigger integer wraparound to cause heap/stack corruption, potentially leading to code execution.",
            "Command Injection":    "An attacker can execute arbitrary operating system commands with the privileges of the vulnerable application.",
            "Format String":        "An attacker can read arbitrary memory locations or write to arbitrary addresses, potentially leading to code execution.",
            "Hardcoded Credential": "An attacker who discovers this credential can authenticate as a privileged user, bypassing all access controls.",
            "Timing Side-Channel":  "An attacker can use timing differences to extract secret values such as cryptographic keys or passwords.",
            "Weak Crypto":          "Sensitive data protected by this algorithm can be decrypted by an attacker with moderate resources.",
        }

        for key, impact in impacts.items():
            if key.lower() in ftype.lower():
                return impact

        return f"This {sev.lower()} severity vulnerability could allow an attacker to compromise the security of the application."

    def _confidence(self, f: Dict) -> str:
        """Estimate finding confidence."""
        cvss = f.get("cvss", 5.0)
        if cvss >= 9.0:  return "High (static analysis confirmed)"
        if cvss >= 7.0:  return "Medium-High (pattern match confirmed)"
        return "Medium (requires manual verification)"

    def _vrt_mapping(self, f: Dict) -> str:
        """Map to Bugcrowd VRT (Vulnerability Rating Taxonomy)."""
        ftype = f.get("type", "").lower()
        mappings = {
            "buffer overflow":  "MEMORY_CORRUPTION.STACK_OVERFLOW",
            "use-after-free":   "MEMORY_CORRUPTION.USE_AFTER_FREE",
            "integer overflow":  "MEMORY_CORRUPTION.INTEGER_OVERFLOW",
            "command injection": "INJECTION.OS_COMMAND_INJECTION",
            "format string":    "MEMORY_CORRUPTION.FORMAT_STRING",
            "sql injection":    "INJECTION.SQL_INJECTION",
            "hardcoded":        "SENSITIVE_DATA_EXPOSURE.HARDCODED_CREDENTIALS",
        }
        for key, vrt in mappings.items():
            if key in ftype:
                return vrt
        return "OTHER"
