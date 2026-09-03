"""
r3con - Advanced Hypothesis Engine
Rule-based vulnerability hypothesis generation (no AI required).
Formulates complex exploitation chains and attack paths.
"""

import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class VulnPattern:
    """Vulnerability pattern definition."""
    name: str
    category: str
    cwe: str
    severity: str
    pattern: str
    requires: List[str] = None
    enables: List[str] = None
    exploitability: float = 0.5


# Vulnerability pattern library
VULN_PATTERNS = [
    # Memory corruption
    VulnPattern("Stack Buffer Overflow", "memory", "CWE-121",
                "CRITICAL", r"(gets|strcpy|strcat|sprintf)\s*\(",
                requires=["user_input"], enables=["code_exec", "info_leak"],
                exploitability=0.95),

    VulnPattern("Heap Overflow", "memory", "CWE-122",
                "CRITICAL", r"(memcpy|memmove|strcpy)\s*\(\s*\w+.*\w+\s*\)",
                requires=["user_input"], enables=["code_exec", "info_leak"],
                exploitability=0.85),

    VulnPattern("Use-After-Free", "memory", "CWE-416",
                "HIGH", r"free\s*\(\s*\w+\s*\);\s*\n.*\w+\s*[-=>]",
                requires=["control_flow"], enables=["code_exec", "info_leak"],
                exploitability=0.80),

    VulnPattern("Double Free", "memory", "CWE-415",
                "HIGH", r"free\s*\(\s*(\w+)\s*\);.*free\s*\(\s*\1\s*\)",
                requires=["error_path"], enables=["heap_corrupt"],
                exploitability=0.75),

    # Crypto
    VulnPattern("Weak PRNG", "crypto", "CWE-338",
                "HIGH", r"(rand|srand|random)\s*\(",
                requires=["seed_control"], enables=["predict_token"],
                exploitability=0.70),

    VulnPattern("Hardcoded Secret", "crypto", "CWE-798",
                "CRITICAL", r'(password|key|secret)\s*=\s*["\']',
                requires=[], enables=["auth_bypass"],
                exploitability=1.0),

    # Kernel
    VulnPattern("Integer Overflow in Alloc", "kernel", "CWE-190",
                "CRITICAL", r"kmalloc\s*\(\s*\w+\s*\*\s*\w+",
                requires=["size_control"], enables=["heap_corrupt", "privesc"],
                exploitability=0.90),

    VulnPattern("Missing copy_from_user", "kernel", "CWE-125",
                "HIGH", r"__user\s*\*.*\*\w+(?!copy_from_user)",
                requires=["control_flow"], enables=["info_leak", "privesc"],
                exploitability=0.85),

    # Race conditions
    VulnPattern("TOCTOU", "race", "CWE-367",
                "HIGH", r"(access|stat)\s*\([^)]+\).*\n.*\n.*(open|unlink)",
                requires=["filesystem_access"], enables=["privesc", "bypass"],
                exploitability=0.60),

    VulnPattern("Double Acquire", "race", "CWE-362",
                "MEDIUM", r"(mutex_lock|spin_lock).*\n.*\1",
                requires=["concurrent_access"], enables=["deadlock"],
                exploitability=0.50),
]


class AdvancedHypothesisEngine:
    """Generate exploitation hypotheses without AI."""

    def __init__(self):
        self.patterns = VULN_PATTERNS
        self.chains = []

    def analyze_code(self, code: str) -> Dict:
        """Analyze code and generate hypotheses."""
        # Detect vulnerabilities
        vulns = self._detect_vulns(code)

        # Build attack surface
        surface = self._build_attack_surface(code)

        # Find exploit chains
        chains = self._find_exploit_chains(vulns, surface)

        # Calculate exploitation difficulty
        for chain in chains:
            chain["difficulty"] = self._calc_difficulty(chain)
            chain["confidence"] = self._calc_confidence(chain)

        return {
            "vulnerabilities": vulns,
            "attack_surface": surface,
            "exploit_chains": chains,
            "summary": self._generate_summary(vulns, chains)
        }

    def _detect_vulns(self, code: str) -> List[Dict]:
        """Detect vulnerabilities using pattern matching."""
        findings = []
        lines = code.splitlines()

        for pattern in self.patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern.pattern, line):
                    # Check if prerequisites are met
                    prereqs_met = self._check_prerequisites(pattern, code, i)
                    if prereqs_met:
                        findings.append({
                            "name": pattern.name,
                            "category": pattern.category,
                            "cwe": pattern.cwe,
                            "severity": pattern.severity,
                            "line": i,
                            "exploitability": pattern.exploitability,
                            "enables": pattern.enables or [],
                            "requires": pattern.requires or [],
                            "code_snippet": line.strip()[:100]
                        })

        return sorted(findings, key=lambda x: x["exploitability"], reverse=True)

    def _check_prerequisites(self, pattern: VulnPattern, code: str, line: int) -> bool:
        """Check if vulnerability prerequisites are met."""
        if not pattern.requires:
            return True

        code_before = "\n".join(code.splitlines()[:line])

        checks = {
            "user_input": lambda c: bool(re.search(r"(argv|stdin|recv|read|input)", c)),
            "control_flow": lambda c: bool(re.search(r"(if|while|for|switch)", c)),
            "error_path": lambda c: bool(re.search(r"(error|fail|ERR|goto err)", c)),
            "seed_control": lambda c: bool(re.search(r"(time\(\)|clock\(\))", c)),
            "size_control": lambda c: bool(re.search(r"(\w+\s*[*+]|\bsize\b)", c)),
            "filesystem_access": lambda c: bool(re.search(r"(open|stat|access|lstat)", c)),
            "concurrent_access": lambda c: bool(re.search(r"(pthread|thread|concurrent)", c)),
        }

        for req in pattern.requires:
            if req in checks and not checks[req](code_before):
                return False
        return True

    def _build_attack_surface(self, code: str) -> Dict:
        """Map the attack surface."""
        entry_points = []
        dangerous_sinks = []

        # Entry points
        entry_patterns = [
            (r"\brecv\s*\(", "network"),
            (r"\bread\s*\(", "file"),
            (r"\bargv\s*\[", "cmdline"),
            (r"\bgetenv\s*\(", "env"),
            (r"copy_from_user\s*\(", "userspace"),
            (r"\bfgets\s*\(", "stdin"),
        ]

        for pattern, ep_type in entry_patterns:
            if re.search(pattern, code):
                entry_points.append(ep_type)

        # Sinks
        sink_patterns = [
            (r"\bmemcpy\s*\(", "memory_write"),
            (r"\bstrcpy\s*\(", "memory_write"),
            (r"\bsystem\s*\(", "code_exec"),
            (r"\bexec\w*\s*\(", "code_exec"),
            (r"\bprintf\s*\(", "format_string"),
            (r"\bfree\s*\(", "heap_manage"),
            (r"\bmalloc\s*\(", "heap_manage"),
        ]

        for pattern, sink_type in sink_patterns:
            if re.search(pattern, code):
                dangerous_sinks.append(sink_type)

        return {
            "entry_points": list(set(entry_points)),
            "dangerous_sinks": list(set(dangerous_sinks)),
            "entry_to_sink_distance": len(set(entry_points)) + len(set(dangerous_sinks))
        }

    def _find_exploit_chains(self, vulns: List[Dict], surface: Dict) -> List[Dict]:
        """Find exploitation chains by linking vulnerabilities."""
        chains = []

        # Single-step chains
        for vuln in vulns:
            chain = {
                "name": f"{vuln['name']} → {' + '.join(vuln['enables'][:2]) if vuln['enables'] else 'Impact'}",
                "steps": [vuln["name"]],
                "vulnerabilities": [vuln],
                "impact": self._calc_impact(vuln["enables"]),
                "requires": vuln["requires"],
                "entry_points": surface["entry_points"],
            }
            chains.append(chain)

        # Multi-step chains
        if len(vulns) >= 2:
            for i, v1 in enumerate(vulns):
                for v2 in vulns[i+1:]:
                    # Check if v1 enables v2
                    if any(e in v2["category"] for e in v1["enables"]):
                        chain = {
                            "name": f"{v1['name']} → {v2['name']}",
                            "steps": [v1["name"], v2["name"]],
                            "vulnerabilities": [v1, v2],
                            "impact": self._calc_impact(v2["enables"]),
                            "requires": list(set(v1["requires"] + v2["requires"])),
                            "entry_points": surface["entry_points"],
                            "multi_step": True,
                        }
                        chains.append(chain)

        return chains[:10]  # Top 10 chains

    def _calc_impact(self, enables: List[str]) -> str:
        """Calculate impact based on enabled primitives."""
        if "code_exec" in enables or "privesc" in enables:
            return "Remote Code Execution"
        if "info_leak" in enables:
            return "Information Disclosure"
        if "auth_bypass" in enables:
            return "Authentication Bypass"
        if "heap_corrupt" in enables:
            return "Heap Corruption"
        return "Denial of Service"

    def _calc_difficulty(self, chain: Dict) -> str:
        """Calculate exploitation difficulty (1-10)."""
        score = 0
        for vuln in chain["vulnerabilities"]:
            score += (1 - vuln["exploitability"]) * 5

        if "multi_step" in chain and chain.get("multi_step"):
            score += 2

        if score < 3:
            return "Very Easy (1-3)"
        elif score < 5:
            return "Easy (3-5)"
        elif score < 7:
            return "Medium (5-7)"
        elif score < 9:
            return "Hard (7-9)"
        else:
            return "Very Hard (9+)"

    def _calc_confidence(self, chain: Dict) -> float:
        """Calculate confidence in the chain (0-1)."""
        confidence = 1.0

        # Reduce confidence if vulnerabilities are not well-connected
        if len(chain.get("vulnerabilities", [])) > 1:
            # Multi-step chains are less certain
            confidence *= 0.85

        # Increase confidence based on exploitability
        for vuln in chain.get("vulnerabilities", []):
            confidence *= vuln["exploitability"]

        return round(confidence, 2)

    def _generate_summary(self, vulns: List[Dict], chains: List[Dict]) -> Dict:
        """Generate analysis summary."""
        critical = len([v for v in vulns if v["severity"] == "CRITICAL"])
        high = len([v for v in vulns if v["severity"] == "HIGH"])

        return {
            "total_vulns": len(vulns),
            "critical_count": critical,
            "high_count": high,
            "exploitable_chains": len([c for c in chains if c.get("confidence", 0) > 0.7]),
            "worst_case_impact": chains[0]["impact"] if chains else "No vulnerabilities",
            "primary_attack_vector": "User-controlled input" if any(
                "user_input" in v["requires"] for v in vulns
            ) else "System misconfiguration",
        }
