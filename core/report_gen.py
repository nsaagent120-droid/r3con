"""
r3con - Report Generator - FIXED VERSION
Fixes: include CWE/CVSS, confidence, SARIF, better formatting
"""

import json
from datetime import datetime
from pathlib import Path

from core.__version__ import __version__

REPORTS_DIR = Path.home() / ".r3con" / "reports"

SEV_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MED": "#ca8a04", "MEDIUM": "#ca8a04",
    "LOW": "#16a34a", "INFO": "#2563eb"
}
SEV_ORDER = ["CRITICAL","HIGH","MED","MEDIUM","LOW","INFO"]


class ReportGenerator:
    def __init__(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate(self, data: dict, fmt: str = "md") -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rtype = data.get("type", "report")
        filename = REPORTS_DIR / f"r3con_{rtype}_{ts}.{fmt}"

        if fmt == "html":
            content = self._render_html(data)
        elif fmt == "json":
            content = json.dumps(data, indent=2, default=str)
        elif fmt == "sarif":
            content = self._render_sarif(data)
            filename = REPORTS_DIR / f"r3con_{rtype}_{ts}.sarif"
        else:
            content = self._render_markdown(data)

        filename.write_text(content, encoding="utf-8")
        return str(filename)

    def _render_markdown(self, data: dict) -> str:
        target = data.get("source", data.get("binary", data.get("directory", data.get("target", "N/A"))))
        findings = data.get("findings", [])
        # Also handle normalized findings with finding_type
        lines = [
            f"# r3con Report — {data.get('type','').upper()}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
            f"**Target:** `{target}`  ",
            f"**Findings:** {len(findings)}  ",
            f"**Version:** r3con v{__version__}  ",
            "", "---", "",
        ]
        
        # Stats
        if findings:
            sev_counts = {}
            for f in findings:
                s = f.get("severity", "INFO")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            lines.append("## Summary\n")
            for sev in SEV_ORDER:
                if sev in sev_counts:
                    lines.append(f"- **{sev}**: {sev_counts[sev]}")
            lines.append("")
            
            # Risk rating if available
            if data.get("risk_rating"):
                rr = data["risk_rating"]
                lines.append(f"**Risk Rating:** {rr.get('rating','N/A')} (score: {rr.get('score','N/A')}/100)\n")
        
        if findings:
            lines.append("## Findings\n")
            sorted_f = sorted(findings, key=lambda x: SEV_ORDER.index(x.get("severity","INFO")) if x.get("severity","INFO") in SEV_ORDER else 99)
            for f in sorted_f:
                sev = f.get("severity","INFO")
                ftype = f.get("type", f.get("finding_type", "Unknown"))
                loc = ""
                if f.get("file"):
                    loc += f"`{Path(f['file']).name}` "
                if f.get("line"):
                    loc += f"line {f['line']}"
                if f.get("offset"):
                    loc += f"offset {f['offset']}"
                
                cwe = f.get("cwe", "")
                cvss = f.get("cvss", "")
                confidence = f.get("confidence", "")
                fix = f.get("fix", f.get("recommendation", ""))
                
                lines += [
                    f"### [{sev}] {ftype}",
                    f"**Location:** {loc or 'N/A'}  ",
                ]
                if cwe:
                    lines.append(f"**CWE:** {cwe}  ")
                if cvss:
                    lines.append(f"**CVSS:** {cvss}  ")
                if confidence:
                    lines.append(f"**Confidence:** {confidence}  ")
                if f.get("cwe") or f.get("cvss_vector"):
                    vec = f.get("cvss_vector", "")
                    if vec:
                        lines.append(f"**CVSS Vector:** `{vec}`  ")
                lines += [
                    f"**Description:** {f.get('description','')}  ",
                    f"**Fix:** {fix}  ",
                ]
                if f.get("evidence"):
                    ev = f["evidence"]
                    if isinstance(ev, dict):
                        code = ev.get("code", "")
                        if code:
                            lines.append(f"**Evidence:** `{code[:100]}`  ")
                if f.get("tags"):
                    lines.append(f"**Tags:** {', '.join(f['tags'])}  ")
                lines.append("")
        
        # Exploit chains
        if data.get("exploit_chains"):
            lines.append("## Exploit Chains\n")
            for chain in data["exploit_chains"]:
                lines.append(f"### {chain.get('name','Chain')}")
                lines.append(f"- Impact: {chain.get('impact','')}")
                lines.append(f"- Confidence: {chain.get('confidence','')}")
                lines.append(f"- Steps: {len(chain.get('steps',[]))}")
                lines.append("")
        
        # Taint flows
        if data.get("taint_flows"):
            lines.append("## Taint Flows\n")
            for flow in data["taint_flows"][:10]:
                lines.append(f"- {flow.get('source_name','source')} (L{flow.get('source_line','')}) → {flow.get('sink_name','sink')} (L{flow.get('sink_line','')}) - {flow.get('vulnerability_type','')}")
            lines.append("")
        
        if data.get("output"):
            lines += ["## Raw Output", "", "```", data["output"][:5000], "```", ""]
        
        # Recommendations
        lines += ["## Recommendations", "", "1. Fix CRITICAL and HIGH findings first", "2. Enable compiler protections: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,RELRO,-z,NOW", "3. Use safe functions: strncpy, snprintf, fgets", "4. Validate all user inputs", ""]
        lines += ["---", f"*Generated by r3con v{__version__} - Advanced Security Research Tool*"]
        return "\n".join(lines)

    def _render_html(self, data: dict) -> str:
        target = data.get("source", data.get("binary", data.get("directory", data.get("target","N/A"))))
        findings = data.get("findings", [])
        fhtml = ""
        sorted_f = sorted(findings, key=lambda x: SEV_ORDER.index(x.get("severity","INFO")) if x.get("severity","INFO") in SEV_ORDER else 99)
        for f in sorted_f:
            sev = f.get("severity","INFO")
            color = SEV_COLORS.get(sev, "#666")
            loc = ""
            if f.get("file"):
                loc += f"{Path(f['file']).name} "
            if f.get("line"):
                loc += f"L{f['line']}"
            if f.get("offset"):
                loc += f" @{f['offset']}"
            cwe = f.get("cwe", "")
            cvss = f.get("cvss", "")
            confidence = f.get("confidence", "")
            extra = ""
            if cwe:
                extra += f'<span style="background:#1e293b;color:#7dd3fc;padding:2px 6px;border-radius:3px;font-size:11px;margin-left:6px">{cwe}</span>'
            if cvss:
                extra += f'<span style="background:#1e293b;color:#fbbf24;padding:2px 6px;border-radius:3px;font-size:11px;margin-left:4px">CVSS:{cvss}</span>'
            if confidence:
                extra += f'<span style="background:#1e293b;color:#a78bfa;padding:2px 6px;border-radius:3px;font-size:11px;margin-left:4px">conf:{confidence}</span>'
            
            fhtml += f"""
<div style="border-left:4px solid {color};padding:12px 16px;margin:12px 0;background:#1a1a2e;border-radius:6px">
  <div>
    <span style="background:{color};color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold">{sev}</span>
    <strong style="margin-left:10px;color:#e2e8f0;font-size:14px">{f.get('type', f.get('finding_type',''))}</strong>
    <span style="color:#64748b;font-size:12px;margin-left:8px">{loc}</span>
    {extra}
  </div>
  <p style="margin:8px 0 4px;color:#94a3b8;font-size:13px;line-height:1.4">{f.get('description','')}</p>
  <p style="margin:6px 0;color:#4ade80;font-size:12px">↳ Fix: {f.get('fix', f.get('recommendation',''))}</p>
  {f'<p style="margin:4px 0;color:#64748b;font-size:11px">Evidence: <code>{f.get("evidence",{}).get("code","")[:80]}</code></p>' if f.get("evidence",{}).get("code") else ""}
</div>"""
        
        # Summary stats
        sev_counts = {}
        for f in findings:
            s = f.get("severity","INFO")
            sev_counts[s] = sev_counts.get(s,0)+1
        stats_html = "".join(f'<span style="margin-right:12px"><strong style="color:{SEV_COLORS.get(sev,"#fff")}">{sev}:</strong> {count}</span>' for sev,count in sev_counts.items())
        
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>r3con Report — {data.get('type','').upper()}</title>
<style>
  body{{font-family:'Segoe UI','Courier New',monospace;background:#0f0f1a;color:#e2e8f0;max-width:1024px;margin:40px auto;padding:0 24px;line-height:1.6}}
  h1{{color:#22d3ee;border-bottom:2px solid #1e293b;padding-bottom:12px}}
  .meta{{color:#94a3b8;font-size:13px;margin-bottom:24px;background:#1e293b;padding:16px;border-radius:8px;border:1px solid #334155}}
  h2{{color:#7dd3fc;margin-top:32px;border-bottom:1px solid #1e293b;padding-bottom:6px}}
  .stats{{background:#1a1a2e;padding:12px;border-radius:6px;margin:16px 0}}
  code{{background:#1e293b;padding:2px 6px;border-radius:3px;font-size:12px}}
</style>
</head><body>
<h1>⚡ r3con Report — {data.get('type','').upper()}</h1>
<div class="meta">
  <strong>Target:</strong> {target}<br>
  <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}<br>
  <strong>Findings:</strong> {len(findings)}<br>
  <strong>Tool:</strong> r3con v{__version__}<br>
  <div class="stats">{stats_html or "No findings"}</div>
  {f'<strong>Risk:</strong> {data.get("risk_rating",{}).get("rating","")} ({data.get("risk_rating",{}).get("score","")}/100)<br>' if data.get("risk_rating") else ""}
</div>
<h2>Findings ({len(findings)})</h2>
{fhtml or '<p style="color:#64748b">No findings - target appears clean (or analysis limited).</p>'}
<h2>Recommendations</h2>
<ul style="color:#94a3b8;font-size:13px">
  <li>Fix CRITICAL/HIGH first - potential RCE</li>
  <li>Enable: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,RELRO,-z,NOW -fPIE -pie</li>
  <li>Use safe APIs: strncpy, snprintf, fgets, strlcpy</li>
  <li>Validate all user inputs, use allow-lists</li>
  <li>Run with ASAN: -fsanitize=address,undefined</li>
</ul>
<hr style="border-color:#1e293b;margin-top:40px">
<p style="color:#334155;font-size:11px">Generated by r3con v{__version__} - Advanced Security Research Tool - For authorized testing only</p>
</body></html>"""

    def _render_sarif(self, data: dict) -> str:
        """NEW: SARIF output for integration with GitHub, VSCode, etc."""
        findings = data.get("findings", [])
        target = data.get("source", data.get("binary", data.get("target", "unknown")))
        
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "r3con",
                        "version": __version__,
                        "informationUri": "https://github.com/nsaagent120-droid/r3con",
                        "rules": []
                    }
                },
                "results": [],
                "artifacts": [{"location": {"uri": target}}]
            }]
        }
        
        rules = {}
        for f in findings:
            ftype = f.get("type", f.get("finding_type", "Unknown"))
            if ftype not in rules:
                rules[ftype] = {
                    "id": ftype.replace(" ", "_").lower(),
                    "name": ftype,
                    "shortDescription": {"text": ftype},
                    "fullDescription": {"text": f.get("description", "")},
                    "defaultConfiguration": {"level": "error" if f.get("severity") in ("CRITICAL","HIGH") else "warning"},
                    "properties": {"tags": ["security", f.get("severity","INFO")], "cwe": f.get("cwe",""), "cvss": f.get("cvss","")}
                }
            
            result = {
                "ruleId": ftype.replace(" ", "_").lower(),
                "level": "error" if f.get("severity") in ("CRITICAL","HIGH") else "warning" if f.get("severity") in ("MED","MEDIUM") else "note",
                "message": {"text": f.get("description","")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", target)},
                        "region": {"startLine": f.get("line", 1)}
                    }
                }],
                "properties": {"severity": f.get("severity","INFO"), "confidence": f.get("confidence",0.5)}
            }
            sarif["runs"][0]["results"].append(result)
        
        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
        return json.dumps(sarif, indent=2)
