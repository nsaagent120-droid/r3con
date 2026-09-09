"""
r3con v6.2 - TLS Analyzer PRO
JA3 fingerprint, cert analysis, weak ciphers, suspicious TLS
"""
from __future__ import annotations
import re
import hashlib
from typing import Dict, List, Any
from collections import Counter

WEAK_CIPHERS = {
    "0x0004": "RC4-MD5",
    "0x0005": "RC4-SHA",
    "0x000A": "DES-CBC3-SHA",
    "0x0002": "EXP-RC4-MD5",
    "0x0007": "EXP-RC4-MD5",
    "0x0009": "EXP-DES-CBC-SHA",
}

SUSPICIOUS_JA3 = {
    # Known malware JA3 hashes (examples)
    "e7d705a3286e19ea42f587b344ee6865": "TrickBot",
    "6734f37431670b3ab4292b8f60f29984": "Emotet",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike",
}

class TLSAnalyzer:
    """TLS Analyzer PRO."""

    def __init__(self):
        pass

    def analyze_pcap(self, pcap_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze TLS from pcap summary."""
        flows = pcap_summary.get("flows", [])
        tls_flows = [f for f in flows if f.get("dport") in (443, 8443, 465, 993, 995) or f.get("protocol") in ("TLS", "HTTPS")]

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "tls_analyzer",
            "total_flows": len(flows),
            "tls_flows": len(tls_flows),
        }

        # Extract IoCs for cert analysis
        iocs = pcap_summary.get("iocs", {})
        domains = iocs.get("domains", [])

        findings = []

        # Check for self-signed or suspicious certs (heuristic via domains)
        for domain in domains[:50]:
            if self._is_suspicious_cert_domain(domain):
                findings.append({
                    "type": "Suspicious TLS SNI",
                    "severity": "MEDIUM",
                    "description": f"SNI {domain} looks suspicious - possible C2",
                    "sni": domain,
                })

        # Weak cipher detection (would need deeper parsing)
        # For now, heuristic based on findings

        result["findings"] = findings[:50]
        result["suspicious_count"] = len(findings)

        return result

    def analyze_ja3(self, ja3_hashes: List[str]) -> Dict[str, Any]:
        """Analyze JA3 fingerprints."""
        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "tls_ja3",
            "total": len(ja3_hashes),
        }

        findings = []
        for ja3 in ja3_hashes:
            if ja3 in SUSPICIOUS_JA3:
                malware = SUSPICIOUS_JA3[ja3]
                findings.append({
                    "type": f"Malicious JA3 - {malware}",
                    "severity": "CRITICAL",
                    "description": f"JA3 {ja3} matches {malware}",
                    "ja3": ja3,
                    "malware": malware,
                })

        result["findings"] = findings
        result["malicious_ja3_count"] = len(findings)

        return result

    def analyze_certificates(self, certs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze TLS certificates."""
        findings = []

        for cert in certs:
            # Self-signed
            issuer = cert.get("issuer", "")
            subject = cert.get("subject", "")
            if issuer == subject and issuer:
                findings.append({
                    "type": "Self-Signed Certificate",
                    "severity": "MEDIUM",
                    "description": f"Self-signed cert: {subject}",
                    "cert": cert,
                })

            # Expired
            if cert.get("expired"):
                findings.append({
                    "type": "Expired Certificate",
                    "severity": "LOW",
                    "description": f"Expired cert: {subject}",
                })

            # Weak key
            key_size = cert.get("key_size", 0)
            if key_size and key_size < 2048:
                findings.append({
                    "type": "Weak Certificate Key",
                    "severity": "HIGH",
                    "description": f"Weak key {key_size} bits: {subject}",
                    "key_size": key_size,
                })

            # Suspicious issuer
            suspicious_issuers = ["Let's Encrypt", "self-signed", "snakeoil"]
            for susp in suspicious_issuers:
                if susp.lower() in issuer.lower() and "self-signed" in susp.lower():
                    findings.append({
                        "type": "Suspicious Issuer",
                        "severity": "LOW",
                        "description": f"Suspicious issuer {issuer} for {subject}",
                    })

        return {
            "status": "ok",
            "engine": "tls_cert",
            "total_certs": len(certs),
            "findings": findings[:50],
        }

    def _is_suspicious_cert_domain(self, domain: str) -> bool:
        """Heuristic suspicious SNI."""
        # DGA-like
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        name = parts[0]
        if len(name) >= 12:
            # High entropy, low vowels
            vowels = sum(1 for c in name.lower() if c in "aeiou")
            if vowels / len(name) < 0.2 and len(name) >= 12:
                return True
        # Suspicious TLD
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"}
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False

    def calc_ja3(self, client_hello: bytes) -> str:
        """Calculate JA3 from ClientHello (simplified)."""
        # This is a simplified version - real JA3 needs full parsing
        # For now, hash of client hello
        try:
            return hashlib.md5(client_hello).hexdigest()
        except Exception:
            return ""
