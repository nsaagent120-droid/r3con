"""
r3con v7.0 - Web Analyzer PRO
DAST: SQLi, XSS, SSTI, LFI, RCE detection via heuristics + payloads
"""
from __future__ import annotations
import re
from typing import Dict, List, Any
from pathlib import Path

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT 1,2,3--",
    "1' AND 1=1--",
    "'; DROP TABLE users--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><svg onload=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "${{7*7}}",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

class WebAnalyzer:
    """Web Analyzer PRO - static code + heuristic."""

    def __init__(self):
        pass

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            content = path.read_text(errors="ignore")[:2*1024*1024]
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        return self.analyze_content(content, str(path))

    def analyze_content(self, content: str, source: str = "memory") -> Dict[str, Any]:
        findings = []

        # SQLi
        sqli_patterns = [
            (r"query\s*\(.*\+.*\)|execute\s*\(.*\+|SELECT.*\+.*req|SELECT.*\+.*request", "SQLi via concatenation", "HIGH"),
            (r"SELECT.*FROM.*WHERE.*\$\{|SELECT.*\+.*request|\"SELECT.*\".*\+.*req", "SQLi in query", "HIGH"),
            (r"db\.query\s*\(.*req\.|db\.execute\s*\(.*req\.|query.*\+.*params|SELECT.*\+.*params", "SQLi via req", "CRITICAL"),
            (r"\$_GET.*query|\$_POST.*query|\$_REQUEST.*SELECT|\$.*=.*\$_GET.*SELECT", "PHP SQLi", "HIGH"),
            (r"SELECT.*FROM.*WHERE.*=.*\+|SELECT.*\+.*\+", "SQLi Generic Concat", "HIGH"),
        ]
        for pat, desc, sev in sqli_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"type": f"Web: {desc}", "severity": sev, "description": desc, "category": "sqli", "pattern": pat[:80]})
            except re.error:
                continue

        # XSS
        xss_patterns = [
            (r"innerHTML\s*=.*\+|innerHTML\s*\+=|innerHTML\s*=\s*[a-zA-Z_]", "XSS via innerHTML", "HIGH"),
            (r"document\.write\s*\(.*\+|document\.writeln.*\+|document\.write\s*\(.*req", "XSS via document.write", "HIGH"),
            (r"echo\s*\$_GET|echo\s*\$_POST|print\s*\$_REQUEST|echo\s*\$.*_GET", "PHP Reflected XSS", "HIGH"),
            (r"\.html\s*\(.*req\.|\.append\s*\(.*req\.|innerHTML\s*=", "jQuery XSS", "MEDIUM"),
        ]
        for pat, desc, sev in xss_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"type": f"Web: {desc}", "severity": sev, "description": desc, "category": "xss"})
            except re.error:
                continue

        # SSTI
        ssti_patterns = [
            (r"render_template_string\s*\(.*\+|render_template_string.*%|render_template_string.*format|render_template_string\s*\(.*request", "SSTI via render_template_string", "CRITICAL"),
            (r"Template\s*\(.*\+|jinja2.*\+.*request|Template\s*\(.*request", "SSTI via Template", "HIGH"),
        ]
        for pat, desc, sev in ssti_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"type": f"Web: {desc}", "severity": sev, "description": desc, "category": "ssti"})
            except re.error:
                continue

        # LFI / Path Traversal
        lfi_patterns = [
            (r"open\s*\(.*\+.*request|fopen\s*\(.*\$_GET|include\s*\(.*\$_GET|require\s*\(.*\$_POST|open\s*\(.*req\.", "LFI/Path Traversal", "HIGH"),
            (r"readFile\s*\(.*req\.|createReadStream.*req\.|readFile\s*\(.*query|createReadStream\s*\(.*params", "Node.js LFI", "HIGH"),
        ]
        for pat, desc, sev in lfi_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"type": f"Web: {desc}", "severity": sev, "description": desc, "category": "lfi"})
            except re.error:
                continue

        # RCE / Command Injection
        rce_patterns = [
            (r"exec\s*\(.*req\.|eval\s*\(.*req\.|child_process\.exec.*req\.", "Node.js RCE", "CRITICAL"),
            (r"os\.system\s*\(.*request|subprocess.*shell=True.*request", "Python RCE", "CRITICAL"),
            (r"Runtime\.getRuntime\(\)\.exec.*request|ProcessBuilder.*request", "Java RCE", "CRITICAL"),
        ]
        for pat, desc, sev in rce_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"type": f"Web: {desc}", "severity": sev, "description": desc, "category": "rce"})
            except re.error:
                continue

        # SSRF
        ssrf_patterns = [
            (r"requests\.get\s*\(.*req\.|urllib.*request.*req\.|fetch\s*\(.*req\.", "SSRF via request", "HIGH"),
            (r"file_get_contents\s*\(.*\$_GET|curl.*\$_POST", "PHP SSRF", "HIGH"),
        ]
        for pat, desc, sev in ssrf_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"type": f"Web: {desc}", "severity": sev, "description": desc, "category": "ssrf"})
            except re.error:
                continue

        return {
            "status": "ok",
            "engine": "web_analyzer",
            "source": source,
            "findings": findings[:100],
            "count": len(findings),
            "by_category": {cat: len([f for f in findings if f.get("category") == cat]) for cat in set(f.get("category") for f in findings)},
        }

    def generate_pocs(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate PoCs for web findings."""
        pocs = []
        for finding in findings[:10]:
            cat = finding.get("category", "")
            if cat == "sqli":
                pocs.append({
                    "type": "SQLi PoC",
                    "payloads": SQLI_PAYLOADS,
                    "description": "Try SQLi payloads in vulnerable parameter",
                })
            elif cat == "xss":
                pocs.append({
                    "type": "XSS PoC",
                    "payloads": XSS_PAYLOADS,
                    "description": "Try XSS payloads",
                })
            elif cat == "ssti":
                pocs.append({
                    "type": "SSTI PoC",
                    "payloads": SSTI_PAYLOADS,
                    "description": "Try SSTI payloads - if {{7*7}} returns 49, vulnerable",
                })
            elif cat == "lfi":
                pocs.append({
                    "type": "LFI PoC",
                    "payloads": LFI_PAYLOADS,
                    "description": "Try LFI payloads to read /etc/passwd",
                })
        return pocs
