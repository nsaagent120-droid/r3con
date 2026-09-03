"""
r3con - Couche 3 : Intelligence
Expert System + Knowledge Base + CVSS Scoring.
Active avec R3CON_EXPERT_MODE=true
Rend les analyses plus profondes sans IA.
"""

from typing import List, Dict


# ── Knowledge Base ────────────────────────────────────────────

CWE_DATABASE = {
    "Buffer Overflow":          {"cwe": "CWE-121", "cvss_base": 9.8,  "attack": "Network",  "complexity": "Low"},
    "Heap Overflow":            {"cwe": "CWE-122", "cvss_base": 9.0,  "attack": "Network",  "complexity": "Low"},
    "Use-After-Free":           {"cwe": "CWE-416", "cvss_base": 8.8,  "attack": "Local",    "complexity": "Low"},
    "Double Free":              {"cwe": "CWE-415", "cvss_base": 8.4,  "attack": "Local",    "complexity": "Low"},
    "Integer Overflow":         {"cwe": "CWE-190", "cvss_base": 8.1,  "attack": "Network",  "complexity": "Low"},
    "Off-by-One":               {"cwe": "CWE-193", "cvss_base": 7.8,  "attack": "Local",    "complexity": "Low"},
    "Format String":            {"cwe": "CWE-134", "cvss_base": 9.8,  "attack": "Network",  "complexity": "Low"},
    "Command Injection":        {"cwe": "CWE-78",  "cvss_base": 9.8,  "attack": "Network",  "complexity": "Low"},
    "SQL Injection":            {"cwe": "CWE-89",  "cvss_base": 9.8,  "attack": "Network",  "complexity": "Low"},
    "TOCTOU Race Condition":    {"cwe": "CWE-367", "cvss_base": 7.0,  "attack": "Local",    "complexity": "High"},
    "Double Acquire":           {"cwe": "CWE-362", "cvss_base": 7.5,  "attack": "Local",    "complexity": "High"},
    "Hardcoded Credential":     {"cwe": "CWE-798", "cvss_base": 9.8,  "attack": "Network",  "complexity": "Low"},
    "Weak PRNG":                {"cwe": "CWE-338", "cvss_base": 7.5,  "attack": "Network",  "complexity": "Low"},
    "Timing Side-Channel":      {"cwe": "CWE-208", "cvss_base": 5.9,  "attack": "Network",  "complexity": "High"},
    "Weak Crypto":              {"cwe": "CWE-327", "cvss_base": 7.5,  "attack": "Network",  "complexity": "Low"},
    "Insecure Deserialization": {"cwe": "CWE-502", "cvss_base": 9.8,  "attack": "Network",  "complexity": "Low"},
    "Missing Input Validation": {"cwe": "CWE-20",  "cvss_base": 7.3,  "attack": "Network",  "complexity": "Low"},
    "Info Leak":                {"cwe": "CWE-200", "cvss_base": 5.3,  "attack": "Network",  "complexity": "Low"},
    "Kernel Pointer Leak":      {"cwe": "CWE-200", "cvss_base": 5.5,  "attack": "Local",    "complexity": "Low"},
    "Privilege Escalation":     {"cwe": "CWE-269", "cvss_base": 7.8,  "attack": "Local",    "complexity": "Low"},
}

# Exploitation techniques par type de vuln
EXPLOITATION_TECHNIQUES = {
    "Buffer Overflow": [
        "Classic stack smashing (overwrite return address)",
        "ROP chain construction (bypass NX/DEP)",
        "ret2libc / ret2plt attack",
        "Stack canary bypass (brute force or leak)",
        "ASLR bypass via memory leak",
    ],
    "Heap Overflow": [
        "Chunk header corruption",
        "Fake chunk injection",
        "House of Force / House of Spirit",
        "Heap spray for ASLR bypass",
        "Tcache/fastbin poisoning",
    ],
    "Use-After-Free": [
        "Heap grooming (fill freed chunk with attacker data)",
        "Type confusion via object reuse",
        "Virtual table pointer hijacking",
        "Double fetch exploitation",
    ],
    "Format String": [
        "Stack memory disclosure (%x / %s)",
        "Arbitrary write with %n",
        "GOT overwrite for code exec",
        "Return address overwrite",
    ],
    "Command Injection": [
        "Direct shell command injection (;, &&, ||, |)",
        "Subshell execution via $() or backticks",
        "Environment variable injection",
        "Path traversal for binary execution",
    ],
    "Hardcoded Credential": [
        "Direct authentication bypass",
        "API key reuse across environments",
        "Decryption of encrypted payloads",
        "Pivot to other services using same cred",
    ],
}

# Recommandations de fix par type
FIX_RECOMMENDATIONS = {
    "Buffer Overflow": "Use strncpy/snprintf with explicit bounds. Enable -fstack-protector-all. Use FORTIFY_SOURCE.",
    "Heap Overflow":   "Validate allocation sizes. Use safe allocators. Enable heap canaries.",
    "Use-After-Free":  "Set pointer to NULL after free(). Use smart pointers in C++.",
    "Double Free":     "Set pointer to NULL immediately after free(). Use ownership tracking.",
    "Format String":   "Never pass user input as format string. Use printf(\"%s\", user_input).",
    "Command Injection": "Use execve() with explicit arguments. Never pass user input to system().",
    "Hardcoded Credential": "Use environment variables or secret managers. Never commit secrets.",
    "Weak PRNG":       "Use cryptographically secure PRNG (getrandom(), /dev/urandom, RAND_bytes()).",
    "Timing Side-Channel": "Use constant-time comparison (crypto_memcmp, CRYPTO_memcmp).",
    "Weak Crypto":     "Replace MD5/SHA1/DES with SHA-256/AES-256. Use authenticated encryption (AES-GCM).",
    "Integer Overflow": "Check arithmetic before allocation. Use checked_mul(), __builtin_mul_overflow().",
    "TOCTOU Race Condition": "Use O_NOFOLLOW flag. Open file first, then fstat() on the fd.",
    "Insecure Deserialization": "Use safe deserializers. Validate/whitelist types. Sign serialized data.",
    "Info Leak":       "Clear sensitive data with explicit_bzero(). Initialize all struct fields.",
}


# ── Expert System Rules ───────────────────────────────────────

class ExpertRule:
    """Règle d'expert pour la déduction de sécurité."""
    def __init__(self, name: str, conditions: List[str],
                 conclusions: List[str], confidence: float):
        self.name        = name
        self.conditions  = conditions
        self.conclusions = conclusions
        self.confidence  = confidence

    def applies(self, findings_types: List[str]) -> bool:
        return any(
            any(c.lower() in ft.lower() for c in self.conditions)
            for ft in findings_types
        )


EXPERT_RULES = [
    ExpertRule(
        "BOF with user input → RCE",
        ["Buffer Overflow", "Format String"],
        ["Remote Code Execution", "Arbitrary Write", "Stack Smashing"],
        0.92
    ),
    ExpertRule(
        "UAF → Code Exec",
        ["Use-After-Free", "Double Free"],
        ["Heap Exploitation", "Code Execution", "Type Confusion"],
        0.85
    ),
    ExpertRule(
        "Integer Overflow → Heap",
        ["Integer Overflow"],
        ["Heap Corruption", "Under-allocation", "Heap Overflow"],
        0.88
    ),
    ExpertRule(
        "Hardcoded Cred → Auth Bypass",
        ["Hardcoded Credential", "Hardcoded"],
        ["Authentication Bypass", "Privilege Escalation", "Lateral Movement"],
        1.00
    ),
    ExpertRule(
        "Weak Crypto → Data Compromise",
        ["Weak Crypto", "Timing Side-Channel", "Weak PRNG"],
        ["Data Decryption", "Token Forgery", "Session Hijacking"],
        0.87
    ),
    ExpertRule(
        "Command Injection → Full Takeover",
        ["Command Injection"],
        ["Remote Code Execution", "Full System Takeover", "Data Exfiltration"],
        0.98
    ),
    ExpertRule(
        "TOCTOU → Privilege Escalation",
        ["TOCTOU", "Race Condition"],
        ["Privilege Escalation", "Arbitrary File Access"],
        0.70
    ),
    ExpertRule(
        "Kernel vuln → Local Privilege Escalation",
        ["Kernel", "Privilege", "kmalloc"],
        ["Local Privilege Escalation", "Root Access", "Kernel Code Execution"],
        0.90
    ),
    ExpertRule(
        "Multiple vulns → Complex Chain",
        ["Buffer Overflow", "Info Leak"],
        ["ASLR Bypass + RCE Chain", "Full Memory Corruption"],
        0.80
    ),
]


# ── Intelligence Layer ────────────────────────────────────────

class IntelligenceLayer:
    """
    Couche 3 — Expert System, Knowledge Base, CVSS Scoring.
    Active avec R3CON_EXPERT_MODE=true
    """

    def __init__(self):
        self.rules   = EXPERT_RULES
        self.cwe_db  = CWE_DATABASE
        self.fixes   = FIX_RECOMMENDATIONS
        self.techniques = EXPLOITATION_TECHNIQUES

    def enrich(self, analysis_result: Dict) -> Dict:
        """
        Enrichit les résultats de la Couche 2 avec :
        - CWE + CVSS scores
        - Techniques d'exploitation
        - Fix recommendations
        - Expert deductions
        - Risk prioritization
        """
        findings = analysis_result.get("findings", [])

        # 1. Enrichir chaque finding avec CWE + CVSS
        enriched_findings = [self._enrich_finding(f) for f in findings]

        # 2. Appliquer les règles expert
        deductions = self._apply_rules(enriched_findings)

        # 3. Générer les techniques d'exploitation
        techniques = self._get_techniques(enriched_findings)

        # 4. Prioritization matrix
        priority_matrix = self._build_priority_matrix(enriched_findings)

        # 5. Executive summary (sans IA)
        exec_summary = self._executive_summary(enriched_findings, deductions)

        # 6. Attack scenarios
        attack_scenarios = self._build_attack_scenarios(enriched_findings, deductions)

        return {
            **analysis_result,
            "findings":           enriched_findings,
            "expert_deductions":  deductions,
            "attack_scenarios":   attack_scenarios,
            "exploitation_techniques": techniques,
            "priority_matrix":    priority_matrix,
            "executive_summary":  exec_summary,
            "risk_rating":        self._risk_rating(enriched_findings),
        }

    def _enrich_finding(self, finding: Dict) -> Dict:
        """Ajoute CWE, CVSS, fix, techniques à un finding."""
        ftype = finding.get("type", "")

        # Find matching CWE
        cwe_info = {}
        for key, info in self.cwe_db.items():
            if key.lower() in ftype.lower() or ftype.lower() in key.lower():
                cwe_info = info
                break

        # CVSS score
        cvss = cwe_info.get("cvss_base", self._severity_to_cvss(finding.get("severity", "INFO")))

        # Fix recommendation
        fix = ""
        for key, rec in self.fixes.items():
            if key.lower() in ftype.lower() or ftype.lower() in key.lower():
                fix = rec
                break

        if not fix:
            fix = finding.get("recommendation", "Review and fix the identified issue.")

        return {
            **finding,
            "cwe":          cwe_info.get("cwe", "CWE-Unknown"),
            "cvss":         cvss,
            "cvss_vector":  self._build_cvss_vector(cwe_info),
            "attack_vector": cwe_info.get("attack", "Unknown"),
            "complexity":   cwe_info.get("complexity", "Unknown"),
            "fix":          fix,
            "priority":     self._calc_priority(cvss, finding.get("severity", "INFO")),
        }

    def _apply_rules(self, findings: List[Dict]) -> List[Dict]:
        """Appliquer les règles expert pour déduire des impacts."""
        types     = [f.get("type", "") for f in findings]
        deductions = []

        for rule in self.rules:
            if rule.applies(types):
                deductions.append({
                    "rule":        rule.name,
                    "conclusions": rule.conclusions,
                    "confidence":  rule.confidence,
                    "triggered_by": [t for t in types
                                     if any(c.lower() in t.lower()
                                            for c in rule.conditions)],
                })

        return sorted(deductions, key=lambda x: x["confidence"], reverse=True)

    def _get_techniques(self, findings: List[Dict]) -> Dict[str, List[str]]:
        """Retourner les techniques d'exploitation pertinentes."""
        techniques = {}
        for finding in findings:
            ftype = finding.get("type", "")
            for key, techs in self.techniques.items():
                if key.lower() in ftype.lower():
                    techniques[ftype] = techs
                    break
        return techniques

    def _build_priority_matrix(self, findings: List[Dict]) -> List[Dict]:
        """Matrice de priorité: CVSSv3 × Exploitability × Business Impact."""
        matrix = []
        for f in findings:
            cvss  = f.get("cvss", 5.0)
            sev   = f.get("severity", "INFO")
            score = cvss * (1.2 if sev == "CRITICAL" else
                            1.0 if sev == "HIGH"     else
                            0.7 if sev in ("MED","MEDIUM") else 0.4)
            matrix.append({
                "finding": f.get("type", ""),
                "line":    f.get("line"),
                "cvss":    cvss,
                "priority_score": round(min(score, 10.0), 1),
                "fix_effort":     f.get("complexity", "Unknown"),
                "action": "Fix immediately" if cvss >= 9.0 else
                           "Fix this sprint" if cvss >= 7.0 else
                           "Fix next sprint" if cvss >= 4.0 else
                           "Monitor",
            })

        return sorted(matrix, key=lambda x: x["priority_score"], reverse=True)

    def _build_attack_scenarios(self, findings: List[Dict],
                                 deductions: List[Dict]) -> List[Dict]:
        """Construire des scénarios d'attaque concrets."""
        scenarios = []

        for ded in deductions[:5]:
            scenario = {
                "name":      ded["rule"],
                "trigger":   ded["triggered_by"],
                "impact":    ded["conclusions"],
                "confidence": f"{int(ded['confidence'] * 100)}%",
                "steps": self._build_attack_steps(ded),
            }
            scenarios.append(scenario)

        return scenarios

    def _build_attack_steps(self, deduction: Dict) -> List[str]:
        """Construire les étapes d'attaque pour un scénario."""
        triggers    = deduction.get("triggered_by", [])
        conclusions = deduction.get("conclusions", [])

        steps = []

        # Step 1: Entry point
        steps.append(f"1. Identify entry point linked to: {', '.join(triggers[:2])}")

        # Step 2: Vulnerability trigger
        steps.append("2. Trigger vulnerability: craft malicious input to reach vulnerable code")

        # Step 3: Exploitation
        if "Code Execution" in str(conclusions):
            steps.append("3. Overwrite control-flow structure (return address / vtable / function pointer)")
            steps.append("4. Redirect execution to shellcode or ROP chain")
            steps.append("5. Execute arbitrary code with process privileges")
        elif "Information" in str(conclusions) or "Leak" in str(conclusions):
            steps.append("3. Trigger memory read past buffer boundary")
            steps.append("4. Extract leaked data from response or error output")
            steps.append("5. Use leaked addresses to bypass ASLR for follow-up exploit")
        elif "Privilege" in str(conclusions):
            steps.append("3. Exploit kernel vulnerability or SUID binary")
            steps.append("4. Overwrite credential structure in kernel memory")
            steps.append("5. Gain root/SYSTEM privileges")
        elif "Bypass" in str(conclusions):
            steps.append("3. Use hardcoded credential or forged token")
            steps.append("4. Authenticate as privileged user")
            steps.append("5. Access restricted functionality")

        return steps

    def _executive_summary(self, findings: List[Dict],
                            deductions: List[Dict]) -> str:
        """Générer un résumé exécutif (sans IA) basé sur les règles."""
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in findings if f.get("severity") == "HIGH"]

        if not findings:
            return "No significant vulnerabilities detected in static analysis."

        summary_parts = []

        # Risk overview
        if critical:
            summary_parts.append(
                f"CRITICAL RISK: {len(critical)} critical vulnerabilities identified "
                f"including {', '.join(set(f['type'] for f in critical[:3]))}."
            )

        if high:
            summary_parts.append(
                f"HIGH RISK: {len(high)} high-severity issues including "
                f"{', '.join(set(f['type'] for f in high[:3]))}."
            )

        # Deduction summary
        if deductions:
            top = deductions[0]
            summary_parts.append(
                f"Expert analysis indicates potential for: "
                f"{', '.join(top['conclusions'][:2])} "
                f"(confidence: {int(top['confidence']*100)}%)."
            )

        # Overall risk
        risk = self._risk_rating(findings)
        summary_parts.append(
            f"Overall risk rating: {risk['rating']} "
            f"(score: {risk['score']}/100). "
            f"Immediate remediation {'required' if risk['score'] >= 70 else 'recommended'}."
        )

        return " ".join(summary_parts)

    def _risk_rating(self, findings: List[Dict]) -> Dict:
        """Calculer le rating de risque global."""
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium   = sum(1 for f in findings if f.get("severity") in ("MED","MEDIUM"))
        low      = sum(1 for f in findings if f.get("severity") == "LOW")

        score = min(critical*40 + high*20 + medium*8 + low*2, 100)

        if score >= 80:  rating = "CRITICAL"
        elif score >= 60: rating = "HIGH"
        elif score >= 40: rating = "MEDIUM"
        elif score >= 20: rating = "LOW"
        else:             rating = "MINIMAL"

        return {
            "score":    score,
            "rating":   rating,
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
        }

    def _severity_to_cvss(self, sev: str) -> float:
        return {"CRITICAL": 9.5, "HIGH": 7.5, "MED": 5.5,
                "MEDIUM": 5.5, "LOW": 3.5, "INFO": 1.0}.get(sev, 5.0)

    def _build_cvss_vector(self, cwe_info: Dict) -> str:
        attack     = "N" if cwe_info.get("attack") == "Network" else "L"
        complexity = "L" if cwe_info.get("complexity") == "Low"  else "H"
        return f"CVSS:3.1/AV:{attack}/AC:{complexity}/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def _calc_priority(self, cvss: float, sev: str) -> str:
        if cvss >= 9.0 or sev == "CRITICAL": return "P0 — Fix now"
        if cvss >= 7.0 or sev == "HIGH":     return "P1 — Fix this sprint"
        if cvss >= 4.0:                       return "P2 — Fix next sprint"
        return "P3 — Backlog"
