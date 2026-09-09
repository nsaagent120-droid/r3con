"""
r3con v6.2 - HTTP Analyzer PRO
HTTP traffic analysis, suspicious UAs, URIs, C2 detection, exfil
"""
from __future__ import annotations
import re
from typing import Dict, List, Any
from collections import Counter, defaultdict

SUSPICIOUS_UAS = {
    "python-requests": "Python script - possible C2",
    "curl": "Curl - possible download",
    "wget": "Wget - possible download",
    "PowerShell": "PowerShell - possible malicious script",
    "Go-http-client": "Go client - possible malware",
    "sqlmap": "SQLMap - SQL injection tool",
    "nikto": "Nikto - web scanner",
    "masscan": "Masscan - port scanner",
    "nmap": "Nmap - scanner",
    "Mozilla/4.0 (compatible; MSIE 6.0": "Very old IE - suspicious",
    "Mozilla/5.0 (compatible; MSIE 9.0": "Old IE - possible malware",
}

SUSPICIOUS_URI_PATTERNS = [
    (r"/admin\.php\?c2|/gate\.php|/connect\.php", "C2 Gate", "CRITICAL"),
    (r"/beacon|/callback|/checkin|/task|/result", "C2 Beacon", "HIGH"),
    (r"\.php\?id=[a-f0-9]{32}", "MD5 ID Param - C2", "HIGH"),
    (r"/[a-z]{2,4}\.php\?[a-z]=[A-Za-z0-9+/=]{30,}", "Base64 Param - C2", "HIGH"),
    (r"/[a-z0-9]{20,}\.php", "Long Random PHP - C2", "MEDIUM"),
    (r"cmd=.*&.*exec|exec=.*&.*cmd", "Command Execution", "CRITICAL"),
    (r"union.*select|select.*union|' OR '1'='1", "SQL Injection", "HIGH"),
    (r"<script.*>.*</script>|javascript:", "XSS Attempt", "MEDIUM"),
    (r"\.\./\.\./|/etc/passwd|/etc/shadow", "Path Traversal", "HIGH"),
    (r"base64_decode|eval\(.*base64", "PHP Code Injection", "HIGH"),
]

class HTTPAnalyzer:
    """HTTP Analyzer PRO."""

    def __init__(self):
        pass

    def analyze_requests(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze HTTP requests."""
        if not requests:
            return {"status": "error", "error": "no_requests"}

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "http_analyzer",
            "total_requests": len(requests),
        }

        # Methods
        method_counter = Counter(r.get("method", "GET") for r in requests)
        result["methods"] = dict(method_counter)

        # Status codes
        status_counter = Counter(r.get("status", 0) for r in requests)
        result["status_codes"] = dict(status_counter)

        # Findings
        findings = []

        for req in requests:
            ua = req.get("user_agent", "")
            uri = req.get("uri", "") or req.get("url", "")

            # Check UA
            for susp_ua, desc in SUSPICIOUS_UAS.items():
                if susp_ua.lower() in ua.lower():
                    findings.append({
                        "type": f"Suspicious User-Agent: {susp_ua}",
                        "severity": "MEDIUM",
                        "description": f"{desc}: {ua[:100]}",
                        "user_agent": ua,
                        "uri": uri,
                    })

            # Check URI
            for pattern, name, severity in SUSPICIOUS_URI_PATTERNS:
                try:
                    if re.search(pattern, uri, re.IGNORECASE):
                        findings.append({
                            "type": f"Suspicious URI: {name}",
                            "severity": severity,
                            "description": f"{name} in URI: {uri[:100]}",
                            "uri": uri,
                            "pattern": pattern,
                        })
                except re.error:
                    continue

            # Large POST - exfil
            if req.get("method") == "POST" and req.get("body_size", 0) > 1024 * 1024:
                findings.append({
                    "type": "Large POST - Possible Exfil",
                    "severity": "HIGH",
                    "description": f"Large POST {req.get('body_size')} bytes to {uri[:100]}",
                    "uri": uri,
                    "size": req.get("body_size"),
                })

        result["findings"] = findings[:100]
        result["suspicious_count"] = len(findings)

        # Top URIs
        uri_counter = Counter(r.get("uri", "") for r in requests)
        result["top_uris"] = [{"uri": uri[:100], "count": c} for uri, c in uri_counter.most_common(20)]

        return result

    def analyze_pcap_http(self, pcap_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP from pcap summary."""
        flows = pcap_summary.get("flows", [])
        http_flows = [f for f in flows if f.get("dport") in (80, 8080, 8000) or f.get("protocol") == "HTTP"]

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "http_analyzer_pcap",
            "total_flows": len(flows),
            "http_flows": len(http_flows),
        }

        # Extract from IoCs
        iocs = pcap_summary.get("iocs", {})
        urls = iocs.get("urls", [])

        findings = []

        for url in urls[:100]:
            for pattern, name, severity in SUSPICIOUS_URI_PATTERNS:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        findings.append({
                            "type": f"Suspicious URL: {name}",
                            "severity": severity,
                            "description": f"{name}: {url[:100]}",
                            "url": url,
                        })
                except re.error:
                    continue

        # Check for many HTTP to same host - C2
        dst_counter = Counter(f.get("dst") for f in http_flows)
        for dst, count in dst_counter.items():
            if count >= 10:
                findings.append({
                    "type": "Frequent HTTP to Same Host - Possible C2",
                    "severity": "MEDIUM",
                    "description": f"Many HTTP connections to {dst}: {count}",
                    "dst": dst,
                    "count": count,
                })

        result["findings"] = findings[:50]
        result["urls_analyzed"] = len(urls)

        return result

    def detect_exfiltration(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect data exfiltration via HTTP."""
        findings = []

        # Group by destination
        dst_groups = defaultdict(list)
        for req in requests:
            dst = req.get("host") or req.get("dst") or "unknown"
            dst_groups[dst].append(req)

        for dst, group in dst_groups.items():
            total_bytes = sum(r.get("body_size", 0) for r in group)
            if total_bytes > 10 * 1024 * 1024:  # 10MB+
                findings.append({
                    "type": "Possible HTTP Exfiltration",
                    "severity": "HIGH",
                    "description": f"Large outbound to {dst}: {total_bytes} bytes in {len(group)} requests",
                    "dst": dst,
                    "bytes": total_bytes,
                    "requests": len(group),
                })

        return findings
