"""
r3con v6.1 - IoC Correlator PRO renforcé
Corrélation firmware strings ↔ PCAP IoCs ↔ YARA hits ↔ findings
"""
from __future__ import annotations
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Set
import hashlib
from collections import defaultdict

class IoCCorrelator:
    """Corrélateur IoC PRO."""

    def __init__(self):
        self.iocs = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "emails": set(),
            "hashes": set(),
            "cves": set(),
        }

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extrait IoCs depuis texte."""
        if not text:
            return {}

        # IP
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, text)
        # Filter valid IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                if not ip.startswith(("0.", "127.", "10.", "192.168.", "172.")):
                    valid_ips.append(ip)

        # Domains
        domain_pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        domains = re.findall(domain_pattern, text)
        # Filter
        valid_domains = [d for d in domains if "." in d and len(d) > 4 and not d[0].isdigit()][:50]

        # URLs
        url_pattern = r"https?://[^\s\"'<>]+"
        urls = re.findall(url_pattern, text)[:20]

        # Emails
        email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        emails = re.findall(email_pattern, text)[:20]

        # Hashes
        hash_patterns = {
            "md5": r"\b[a-fA-F0-9]{32}\b",
            "sha1": r"\b[a-fA-F0-9]{40}\b",
            "sha256": r"\b[a-fA-F0-9]{64}\b",
        }
        hashes = []
        for htype, pat in hash_patterns.items():
            hashes.extend(re.findall(pat, text)[:10])

        # CVEs
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cves = re.findall(cve_pattern, text, re.IGNORECASE)[:20]

        return {
            "ips": list(set(valid_ips))[:20],
            "domains": list(set(valid_domains))[:20],
            "urls": list(set(urls))[:20],
            "emails": list(set(emails))[:20],
            "hashes": list(set(hashes))[:20],
            "cves": list(set(cves))[:20],
        }

    def correlate_firmware_pcap(self, firmware_path: str, pcap_path: str) -> Dict[str, Any]:
        """Corrèle firmware strings avec PCAP IoCs (comme binary_diff mais renforcé)."""
        from modules.firmware.firmware_analyzer import FirmwareAnalyzer
        from modules.network.protocol_analyzer import ProtocolAnalyzer

        # Extract firmware strings
        try:
            fw = FirmwareAnalyzer(firmware_path)
            fw.load()
            fw_strings = fw.extract_strings()[:10000]
            fw_text = "\n".join([s.get("value", "") for s in fw_strings])
            fw_iocs = self.extract_iocs(fw_text)
        except Exception as e:
            fw_iocs = {}
            fw_strings = []

        # Extract PCAP IoCs
        try:
            pcap = ProtocolAnalyzer(pcap_path)
            pcap_result = pcap.analyze()
            pcap_iocs_raw = pcap_result.get("iocs", {})
            # Convert to our format
            pcap_text = json.dumps(pcap_iocs_raw)
            pcap_iocs = self.extract_iocs(pcap_text)
            # Merge with pcap's own iocs
            for k in ["dns", "http_hosts", "tls_sni"]:
                if k in pcap_iocs_raw:
                    pcap_iocs["domains"].extend(pcap_iocs_raw[k][:10])
        except Exception as e:
            pcap_iocs = {}

        # Correlation
        correlations = []
        for ioc_type in ["ips", "domains", "urls"]:
            fw_set = set(fw_iocs.get(ioc_type, []))
            pcap_set = set(pcap_iocs.get(ioc_type, []))
            common = fw_set & pcap_set
            if common:
                for item in common:
                    correlations.append({
                        "type": ioc_type,
                        "value": item,
                        "sources": ["firmware", "pcap"],
                        "severity": "HIGH" if ioc_type in ["ips", "domains"] else "MEDIUM",
                        "description": f"{ioc_type} {item} trouvé dans firmware ET pcap - communication possible",
                    })

        # Also check if firmware contains hardcoded IPs that appear in pcap
        for ip in fw_iocs.get("ips", []):
            if ip in pcap_iocs.get("ips", []):
                correlations.append({
                    "type": "ip_correlation",
                    "value": ip,
                    "sources": ["firmware_hardcoded", "pcap_observed"],
                    "severity": "CRITICAL",
                    "description": f"IP hardcodée {ip} dans firmware observée dans trafic réseau - C2 possible",
                })

        return {
            "firmware": firmware_path,
            "pcap": pcap_path,
            "firmware_iocs": fw_iocs,
            "pcap_iocs": pcap_iocs,
            "correlations": correlations,
            "total_correlations": len(correlations),
            "critical": len([c for c in correlations if c["severity"] == "CRITICAL"]),
            "high": len([c for c in correlations if c["severity"] == "HIGH"]),
        }

    def correlate_findings_iocs(self, findings: List[Dict[str, Any]], iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Corrèle findings avec IoCs."""
        correlations = []

        for finding in findings:
            desc = finding.get("description", "") + " " + finding.get("code", "")
            finding_iocs = self.extract_iocs(desc)

            for ioc_type, values in finding_iocs.items():
                for val in values:
                    # Check if this IoC also in global IoCs
                    if val in iocs.get(ioc_type, []):
                        correlations.append({
                            "finding_type": finding.get("type"),
                            "finding_severity": finding.get("severity"),
                            "ioc_type": ioc_type,
                            "ioc_value": val,
                            "description": f"Finding {finding.get('type')} contient IoC {val} qui est aussi dans IoCs globaux",
                        })

        return correlations

    def build_graph(self, workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Construit graphe de connaissances IoCs cross-workspaces."""
        graph = {
            "nodes": [],
            "edges": [],
            "iocs": defaultdict(list),
        }

        for ws in workspaces:
            ws_name = ws.get("name", "unknown")
            # Extract IoCs from workspace findings
            findings = ws.get("findings", [])
            for finding in findings:
                text = finding.get("description", "") + " " + json.dumps(finding)
                iocs = self.extract_iocs(text)
                for ioc_type, values in iocs.items():
                    for val in values:
                        graph["iocs"][val].append({
                            "workspace": ws_name,
                            "finding": finding.get("type"),
                            "severity": finding.get("severity"),
                        })

            graph["nodes"].append({
                "id": ws_name,
                "type": ws.get("type", "custom"),
                "findings": len(findings),
            })

        # Edges: workspaces sharing same IoC
        for ioc_value, occurrences in graph["iocs"].items():
            if len(occurrences) > 1:
                # Create edges between workspaces sharing this IoC
                for i in range(len(occurrences)):
                    for j in range(i+1, len(occurrences)):
                        ws1 = occurrences[i]["workspace"]
                        ws2 = occurrences[j]["workspace"]
                        if ws1 != ws2:
                            graph["edges"].append({
                                "source": ws1,
                                "target": ws2,
                                "ioc": ioc_value,
                                "type": "shares_ioc",
                            })

        return {
            "total_iocs": len(graph["iocs"]),
            "total_nodes": len(graph["nodes"]),
            "total_edges": len(graph["edges"]),
            "iocs": dict(graph["iocs"]),
            "nodes": graph["nodes"],
            "edges": graph["edges"][:100],  # Limit
        }
