"""
r3con v6.2 - DNS Analyzer PRO
DNS tunneling, DGA, exfil, suspicious queries
"""
from __future__ import annotations
import re
import math
from typing import Dict, List, Any
from collections import Counter, defaultdict

class DNSAnalyzer:
    """DNS Analyzer PRO."""

    def __init__(self):
        pass

    def analyze_queries(self, queries: List[str]) -> Dict[str, Any]:
        """Analyze list of DNS queries."""
        if not queries:
            return {"status": "error", "error": "no_queries"}

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "dns_analyzer",
            "total_queries": len(queries),
        }

        # Unique domains
        unique = list(set(queries))
        result["unique_domains"] = len(unique)

        # TLD distribution
        tld_counter = Counter()
        for q in queries:
            parts = q.split(".")
            if len(parts) >= 2:
                tld = parts[-1].lower()
                tld_counter[tld] += 1
        result["tld_distribution"] = dict(tld_counter.most_common(20))

        # Findings
        findings = []

        # DGA detection
        dga_domains = []
        for domain in unique:
            if self._is_dga(domain):
                dga_domains.append(domain)
                findings.append({
                    "type": "DGA Domain",
                    "severity": "HIGH",
                    "description": f"DGA-like domain {domain}",
                    "domain": domain,
                    "rule": "dga_heuristic",
                })

        result["dga_domains"] = dga_domains[:50]
        result["dga_count"] = len(dga_domains)

        # Long domains - possible tunneling
        long_domains = [d for d in unique if len(d) > 50]
        for domain in long_domains[:20]:
            findings.append({
                "type": "Long DNS Query - Possible Tunneling",
                "severity": "MEDIUM",
                "description": f"Long DNS query {len(domain)} chars: {domain[:100]}",
                "domain": domain,
                "length": len(domain),
            })

        # High entropy domains
        high_entropy = []
        for domain in unique:
            if len(domain) >= 15:
                entropy = self._calc_entropy(domain.split(".")[0])
                if entropy > 4.0:
                    high_entropy.append((domain, entropy))

        high_entropy.sort(key=lambda x: x[1], reverse=True)
        for domain, entropy in high_entropy[:20]:
            findings.append({
                "type": "High Entropy DNS Query",
                "severity": "MEDIUM",
                "description": f"High entropy {entropy:.2f} domain {domain}",
                "domain": domain,
                "entropy": entropy,
            })

        # TXT record abuse (if queries contain TXT pattern)
        txt_like = [d for d in unique if "txt" in d.lower() or len(d) > 100]
        if len(txt_like) > 10:
            findings.append({
                "type": "Possible DNS TXT Tunneling",
                "severity": "HIGH",
                "description": f"Many long/TXT-like queries: {len(txt_like)} - possible tunneling",
                "count": len(txt_like),
            })

        # Suspicious TLDs
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc"}
        for domain in unique:
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    findings.append({
                        "type": "Suspicious TLD",
                        "severity": "LOW",
                        "description": f"Domain {domain} uses suspicious TLD {tld}",
                        "domain": domain,
                    })
                    break

        result["findings"] = findings[:100]
        result["threat_count"] = len(findings)

        return result

    def analyze_pcap_dns(self, pcap_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DNS from pcap summary."""
        # Extract DNS queries from IoCs or flows
        iocs = pcap_summary.get("iocs", {})
        domains = iocs.get("domains", [])
        if not domains:
            # Try to extract from payloads or flows
            domains = []

        if domains:
            return self.analyze_queries(domains)
        else:
            return {"status": "ok", "engine": "dns_analyzer", "total_queries": 0, "findings": []}

    def _is_dga(self, domain: str) -> bool:
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

        # DGA often low vowel ratio, high consonant runs, high entropy
        if vowel_ratio < 0.15 and len(name) >= 10:
            entropy = self._calc_entropy(name)
            if entropy > 3.5:
                # Check for repeated patterns (not DGA)
                if len(set(name)) / len(name) > 0.6:  # Diverse chars
                    return True

        # Check for random-looking
        if len(name) >= 12:
            # Many consonants in a row
            consonant_runs = re.findall(r"[^aeiou]{5,}", name.lower())
            if consonant_runs and len(name) >= 15:
                return True

        return False

    def _calc_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        counter = Counter(s.lower())
        length = len(s)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def detect_tunneling(self, queries: List[str]) -> List[Dict[str, Any]]:
        """Detect DNS tunneling."""
        findings = []

        # Group by base domain
        base_groups = defaultdict(list)
        for q in queries:
            parts = q.split(".")
            if len(parts) >= 2:
                base = ".".join(parts[-2:])
                base_groups[base].append(q)

        for base, group in base_groups.items():
            if len(group) >= 20:
                # Many subdomains for same base - tunneling
                subdomains = [q.replace(f".{base}", "").replace(base, "") for q in group]
                avg_len = sum(len(s) for s in subdomains) / len(subdomains) if subdomains else 0
                if avg_len > 20:
                    findings.append({
                        "type": "DNS Tunneling - Many Long Subdomains",
                        "severity": "HIGH",
                        "description": f"Base {base} has {len(group)} subdomains avg len {avg_len:.1f} - tunneling",
                        "base": base,
                        "count": len(group),
                        "avg_subdomain_len": avg_len,
                    })

        return findings
