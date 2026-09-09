"""
r3con v7.1 - PDF Reporter PRO
Generate PDF reports with graphs, tables, MITRE mapping
"""
from __future__ import annotations
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime
import json

class PDFReporter:
    """PDF Reporter PRO - generates PDF via markdown + weasyprint or fallback."""

    def __init__(self):
        pass

    def generate_markdown_report(self, findings: List[Dict[str, Any]], target: str = "unknown", title: str = "r3con Security Report") -> str:
        """Generate markdown report."""

        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "CRITICAL"])
        high = len([f for f in findings if f.get("severity") == "HIGH"])
        medium = len([f for f in findings if f.get("severity") in ("MEDIUM", "MED")])
        low = len([f for f in findings if f.get("severity") == "LOW"])

        # Risk score
        risk_score = critical * 10 + high * 5 + medium * 2 + low * 1
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 20:
            risk_level = "HIGH"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        md = f"""# {title}

**Target:** `{target}`
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** r3con v7.1 Titan-Omega-Full-Rival
**Total Findings:** {total}

---

## Executive Summary

This report presents the results of a security analysis performed by r3con v7.1.

- **Risk Level:** {risk_level}
- **Risk Score:** {risk_score}
- **Critical:** {critical}
- **High:** {high}
- **Medium:** {medium}
- **Low:** {low}

### Risk Assessment

The target has been assessed as **{risk_level}** risk with a score of {risk_score}.

"""

        if critical > 0:
            md += f"\n**Immediate action required:** {critical} critical vulnerabilities found that could lead to full system compromise.\n"
        if high > 0:
            md += f"\n**High priority:** {high} high severity issues should be addressed promptly.\n"

        md += """
---

## Findings Overview

| Severity | Count | Percentage |
|----------|-------|------------|
"""
        for sev, count in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
            pct = (count / total * 100) if total > 0 else 0
            md += f"| {sev} | {count} | {pct:.1f}% |\n"

        md += "\n---\n\n## Detailed Findings\n\n"

        # Group by severity
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in findings if f.get("severity") == sev]
            if not sev_findings:
                continue

            md += f"\n### {sev} Severity ({len(sev_findings)} findings)\n\n"

            for i, finding in enumerate(sev_findings[:20], 1):
                md += f"""
#### {i}. {finding.get('type','Unknown')}

- **Severity:** {finding.get('severity','MEDIUM')}
- **File:** `{finding.get('file','unknown')}:{finding.get('line','')}`
- **CWE:** {finding.get('cwe','N/A')}
- **CVSS:** {finding.get('cvss','N/A')}
- **MITRE:** {', '.join(finding.get('mitre', []) or ['N/A'])}

**Description:**
{finding.get('description','No description')}

**Recommendation:**
{finding.get('recommendation','Review code')}

**Evidence:**
```
{finding.get('evidence', {}).get('code','') if isinstance(finding.get('evidence'), dict) else finding.get('code','')[:300]}
```

---
"""

        md += """
## Compliance Mapping

### OWASP Top 10
"""

        owasp_mapping = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable Components",
            "A07": "Auth Failures",
            "A08": "Software & Data Integrity Failures",
            "A09": "Logging & Monitoring Failures",
            "A10": "SSRF",
        }

        for finding in findings[:20]:
            ftype = finding.get("type","").lower()
            if "injection" in ftype or "sqli" in ftype or "xss" in ftype:
                md += f"- {finding.get('type','')} → **A03 Injection**\n"
            elif "crypto" in ftype or "md5" in ftype or "sha1" in ftype:
                md += f"- {finding.get('type','')} → **A02 Cryptographic Failures**\n"
            elif "auth" in ftype or "password" in ftype:
                md += f"- {finding.get('type','')} → **A07 Auth Failures**\n"

        md += f"""

## MITRE ATT&CK Mapping

Techniques identified:
"""

        techniques = set()
        for finding in findings:
            mitre = finding.get("mitre", [])
            if isinstance(mitre, list):
                techniques.update(mitre)
            elif isinstance(mitre, dict):
                for techs in mitre.values():
                    techniques.update(techs)

        for tech in sorted(list(techniques))[:20]:
            md += f"- {tech}\n"

        md += f"""

---

## Recommendations

### Immediate Actions (P1 - Critical)
"""

        critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
        for f in critical_findings[:5]:
            md += f"- **{f.get('type','')}** in `{f.get('file','')}`: {f.get('recommendation','Fix immediately')}\n"

        md += """
### High Priority (P2 - High)
"""

        high_findings = [f for f in findings if f.get("severity") == "HIGH"]
        for f in high_findings[:5]:
            md += f"- **{f.get('type','')}**: {f.get('recommendation','Review')}\n"

        md += f"""

---

## Appendix

- **Tool:** r3con v7.1
- **Analysis Date:** {datetime.now().isoformat()}
- **Total Findings:** {total}
- **Report Generated:** Automatically - manual verification recommended

---

*This report was generated by r3con v7.1 Titan-Omega-Full-Rival - Advanced Binary & Malware & Network Security Research Tool*
"""

        return md

    def save_markdown(self, findings: List[Dict[str, Any]], target: str, output_path: str) -> Dict[str, Any]:
        """Save markdown report."""
        md = self.generate_markdown_report(findings, target)

        try:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(md, encoding="utf-8")
            return {"status": "ok", "path": output_path, "size": len(md), "format": "markdown"}
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def generate_pdf(self, findings: List[Dict[str, Any]], target: str, output_path: str) -> Dict[str, Any]:
        """Generate PDF report - tries weasyprint, falls back to markdown."""
        md = self.generate_markdown_report(findings, target)

        # Try weasyprint
        try:
            import markdown
            from weasyprint import HTML

            html_content = markdown.markdown(md, extensions=['tables', 'fenced_code'])

            # Add CSS
            html_full = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
                    h1 {{ color: #dc2626; border-bottom: 2px solid #dc2626; }}
                    h2 {{ color: #1e293b; border-bottom: 1px solid #ccc; }}
                    h3 {{ color: #475569; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
                    th {{ background-color: #1e293b; color: white; }}
                    code {{ background-color: #f1f5f9; padding: 2px 4px; border-radius: 3px; }}
                    pre {{ background-color: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }}
                    .critical {{ color: #dc2626; font-weight: bold; }}
                    .high {{ color: #ea580c; font-weight: bold; }}
                </style>
            </head>
            <body>
                {html_content}
            </body>
            </html>
            """

            HTML(string=html_full).write_pdf(output_path)
            return {"status": "ok", "path": output_path, "format": "pdf", "tool": "weasyprint"}

        except ImportError:
            # Fallback to markdown
            md_path = output_path.replace(".pdf", ".md")
            return self.save_markdown(findings, target, md_path)
        except Exception as e:
            # Fallback
            md_path = output_path.replace(".pdf", ".md")
            result = self.save_markdown(findings, target, md_path)
            result["pdf_error"] = str(e)[:500]
            result["fallback"] = "markdown"
            return result

    def generate_html(self, findings: List[Dict[str, Any]], target: str, output_path: str) -> Dict[str, Any]:
        """Generate HTML report."""
        md = self.generate_markdown_report(findings, target)

        try:
            import markdown
            html_content = markdown.markdown(md, extensions=['tables', 'fenced_code'])

            html_full = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>r3con Security Report - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 0; background: #f8fafc; color: #1e293b; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        h1 {{ color: #dc2626; border-bottom: 3px solid #dc2626; padding-bottom: 10px; }}
        h2 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 40px; }}
        h3 {{ color: #334155; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 12px; text-align: left; }}
        th {{ background: #1e293b; color: white; }}
        code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
        pre {{ background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; color: white; }}
        .critical {{ background: #dc2626; }} .high {{ background: #ea580c; }} .medium {{ background: #ca8a04; }} .low {{ background: #16a34a; }}
    </style>
</head>
<body>
    <div class="container">
        {html_content}
    </div>
</body>
</html>
"""

            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(html_full, encoding="utf-8")
            return {"status": "ok", "path": output_path, "format": "html"}

        except ImportError:
            # Fallback markdown
            md_path = output_path.replace(".html", ".md")
            return self.save_markdown(findings, target, md_path)
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}
