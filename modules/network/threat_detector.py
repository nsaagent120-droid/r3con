"""
r3con v6.2 - Network Threat Detector PRO
IDS-like detection: C2, exfil, scanning, tunneling, malicious patterns
"""
from __future__ import annotations
import re
import ipaddress
from typing import Dict, List, Any
from collections import Counter, defaultdict
from pathlib import Path

THREAT_RULES = {
    "c2_beacon": {
        "description": "C2 beaconing - periodic callbacks",
        "severity": "CRITICAL",
        "mitre": "T1071",
        "detect": lambda flows: ThreatDetector._detect_beaconing(flows),
    },
    "port_scan": {
        "description": "Port scanning activity",
        "severity": "HIGH",
        "mitre": "T1046",
        "detect": lambda flows: ThreatDetector._detect_port_scan(flows),
    },
    "data_exfil": {
        "description": "Possible data exfiltration - large outbound",
        "severity": "HIGH",
        "mitre": "T1041",
        "detect": lambda flows: ThreatDetector._detect_exfil(flows),
    },
    "dns_tunneling": {
        "description": "DNS tunneling - long TXT or high entropy",
        "severity": "HIGH",
        "mitre": "T1071.004",
        "detect": lambda flows: ThreatDetector._detect_dns_tunnel(flows),
    },
    "http_c2": {
        "description": "HTTP C2 - suspicious user-agent or URIs",
        "severity": "HIGH",
        "mitre": "T1071.001",
        "detect": lambda flows: ThreatDetector._detect_http_c2(flows),
    },
}

SUSPICIOUS_USER_AGENTS = [
    "python-requests", "curl", "wget", "PowerShell", "Go-http-client",
    "Mozilla/5.0 (compatible; MSIE 9.0",  # Old IE
    "sqlmap", "nikto", "masscan", "nmap",
]

SUSPICIOUS_URIS = [
    r"/admin\.php\?c2", r"/gate\.php", r"/connect\.php", r"/beacon",
    r"/callback", r"/checkin", r"/task", r"/result",
    r"\.php\?id=[a-f0-9]{32}",  # MD5-like
    r"/[a-z]{2,4}\.php\?[a-z]=[A-Za-z0-9+/=]{20,}",  # Base64 param
]

class ThreatDetector:
    """Threat Detector PRO."""

    def __init__(self):
        pass

    def analyze_pcap_summary(self, pcap_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze from ProtocolAnalyzer summary."""
        flows = pcap_summary.get("flows", [])
        findings = []

        # Run all threat rules
        for rule_name, rule in THREAT_RULES.items():
            try:
                result = rule["detect"](flows)
                if result:
                    for finding in result:
                        finding["rule"] = rule_name
                        finding["rule_description"] = rule["description"]
                        finding["severity"] = rule["severity"]
                        finding["mitre"] = rule["mitre"]
                        findings.append(finding)
            except Exception:
                continue

        # Additional checks from findings
        existing_findings = pcap_summary.get("findings", [])
        for f in existing_findings:
            if f.get("severity") in ("CRITICAL", "HIGH"):
                findings.append({
                    "type": f"Network: {f.get('type','unknown')}",
                    "severity": f.get("severity", "MEDIUM"),
                    "description": f"{f.get('protocol','')} on port {f.get('port','')} - {f.get('rule','')}",
                    "rule": "existing",
                    "src": f.get("src"),
                    "dst": f.get("dst"),
                })

        return {
            "status": "ok",
            "engine": "threat_detector",
            "findings": findings[:100],
            "threat_count": len(findings),
            "threat_by_severity": Counter(f.get("severity", "MEDIUM") for f in findings),
            "rules_triggered": list(set(f.get("rule") for f in findings)),
        }

    def analyze_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze IoCs for threats."""
        findings = []

        # Check for known malicious TLDs
        malicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc", ".onion"}
        for domain in iocs.get("domains", []):
            for tld in malicious_tlds:
                if domain.endswith(tld):
                    findings.append({
                        "type": "Suspicious TLD",
                        "severity": "MEDIUM",
                        "description": f"Domain {domain} uses suspicious TLD {tld}",
                        "ioc": domain,
                        "rule": "suspicious_tld",
                    })

        # Check for DGA-like domains
        for domain in iocs.get("domains", []):
            if self._is_dga_like(domain):
                findings.append({
                    "type": "DGA-like Domain",
                    "severity": "HIGH",
                    "description": f"Domain {domain} looks DGA-generated (high entropy, no vowels)",
                    "ioc": domain,
                    "rule": "dga",
                })

        return {
            "status": "ok",
            "engine": "threat_detector_ioc",
            "findings": findings[:100],
        }

    @staticmethod
    def _detect_beaconing(flows: List[Dict]) -> List[Dict]:
        """Detect periodic beaconing - same src/dst with regular intervals."""
        # Group by src-dst
        groups = defaultdict(list)
        for flow in flows:
            key = (flow.get("src"), flow.get("dst"), flow.get("dport"))
            groups[key].append(flow)

        findings = []
        for (src, dst, dport), group in groups.items():
            if len(group) >= 5:  # At least 5 connections
                # Check if packets/bytes are similar (beaconing)
                packets = [f.get("packets", 0) for f in group]
                bytes_list = [f.get("bytes", 0) for f in group]
                # If variance is low, it's beaconing
                if len(set(packets)) <= 2 and len(set(bytes_list)) <= 3:
                    findings.append({
                        "type": "C2 Beaconing",
                        "severity": "CRITICAL",
                        "description": f"Possible C2 beaconing: {src} -> {dst}:{dport} ({len(group)} similar flows)",
                        "src": src,
                        "dst": dst,
                        "port": dport,
                        "count": len(group),
                    })
        return findings

    @staticmethod
    def _detect_port_scan(flows: List[Dict]) -> List[Dict]:
        """Detect port scanning - one src scanning many ports on same dst."""
        src_to_ports = defaultdict(lambda: defaultdict(set))
        for flow in flows:
            src = flow.get("src")
            dst = flow.get("dst")
            dport = flow.get("dport")
            if src and dst and dport:
                src_to_ports[src][dst].add(dport)

        findings = []
        for src, dst_map in src_to_ports.items():
            for dst, ports in dst_map.items():
                if len(ports) >= 10:  # Scanning 10+ ports
                    findings.append({
                        "type": "Port Scan",
                        "severity": "HIGH",
                        "description": f"Port scan: {src} scanned {len(ports)} ports on {dst}",
                        "src": src,
                        "dst": dst,
                        "ports_scanned": len(ports),
                        "ports": sorted(list(ports))[:20],
                    })
        return findings

    @staticmethod
    def _detect_exfil(flows: List[Dict]) -> List[Dict]:
        """Detect large outbound transfers."""
        findings = []
        for flow in flows:
            bytes_out = flow.get("bytes", 0)
            if bytes_out > 10 * 1024 * 1024:  # 10MB+
                findings.append({
                    "type": "Large Outbound Transfer",
                    "severity": "HIGH",
                    "description": f"Large outbound {bytes_out} bytes {flow.get('src')} -> {flow.get('dst')}:{flow.get('dport')}",
                    "src": flow.get("src"),
                    "dst": flow.get("dst"),
                    "bytes": bytes_out,
                })
        return findings

    @staticmethod
    def _detect_dns_tunnel(flows: List[Dict]) -> List[Dict]:
        """Detect DNS tunneling via long queries or many TXT."""
        # This needs DNS payload inspection - simplified
        findings = []
        dns_flows = [f for f in flows if f.get("dport") == 53 or f.get("sport") == 53]
        if len(dns_flows) > 100:
            # Many DNS queries - possible tunneling
            src_counts = Counter(f.get("src") for f in dns_flows)
            for src, count in src_counts.items():
                if count > 50:
                    findings.append({
                        "type": "High DNS Query Rate",
                        "severity": "MEDIUM",
                        "description": f"High DNS query rate from {src}: {count} queries - possible tunneling",
                        "src": src,
                        "count": count,
                    })
        return findings

    @staticmethod
    def _detect_http_c2(flows: List[Dict]) -> List[Dict]:
        """Detect HTTP C2 via payload inspection."""
        # Simplified - check for HTTP flows with suspicious patterns
        findings = []
        http_flows = [f for f in flows if f.get("dport") in (80, 8080, 8000) or f.get("protocol") == "HTTP"]
        # If many small HTTP flows to same host, possible C2
        host_groups = defaultdict(list)
        for flow in http_flows:
            key = (flow.get("src"), flow.get("dst"))
            host_groups[key].append(flow)

        for (src, dst), group in host_groups.items():
            if len(group) >= 10:
                findings.append({
                    "type": "Frequent HTTP Connections",
                    "severity": "MEDIUM",
                    "description": f"Frequent HTTP {src} -> {dst}: {len(group)} connections - possible C2",
                    "src": src,
                    "dst": dst,
                    "count": len(group),
                })
        return findings

    def _is_dga_like(self, domain: str) -> bool:
        """Heuristic DGA detection."""
        # Remove TLD
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        name = parts[0]
        if len(name) < 8:
            return False
        # Check vowel ratio
        vowels = sum(1 for c in name.lower() if c in "aeiou")
        vowel_ratio = vowels / len(name) if name else 0
        # DGA often has low vowel ratio and high entropy
        if vowel_ratio < 0.2 and len(name) >= 10:
            # Check entropy
            import math
            from collections import Counter
            counter = Counter(name.lower())
            entropy = 0.0
            for count in counter.values():
                p = count / len(name)
                entropy -= p * math.log2(p)
            if entropy > 3.5:
                return True
        return False
