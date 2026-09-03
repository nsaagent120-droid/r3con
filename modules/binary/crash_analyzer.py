"""
r3con - Crash Analyzer
Analyse les crashes (core dumps, ASAN/UBSAN reports, GDB output)
pour déterminer l'exploitabilité et le type de vulnérabilité.
100% offline, sans dépendances externes.
"""

import re
from typing import List, Dict, Optional
from pathlib import Path


# ── Patterns d'analyse ───────────────────────────────────────

# Patterns ASAN (AddressSanitizer)
ASAN_PATTERNS = {
    "heap-buffer-overflow": {
        "severity":    "CRITICAL",
        "type":        "Heap Buffer Overflow",
        "cwe":         "CWE-122",
        "exploitable": True,
        "description": "Write/read past end of heap allocation",
        "primitives":  ["heap_overflow", "potential_rce"],
    },
    "stack-buffer-overflow": {
        "severity":    "CRITICAL",
        "type":        "Stack Buffer Overflow",
        "cwe":         "CWE-121",
        "exploitable": True,
        "description": "Write/read past end of stack allocation",
        "primitives":  ["stack_overflow", "return_address_overwrite"],
    },
    "use-after-free": {
        "severity":    "CRITICAL",
        "type":        "Use-After-Free",
        "cwe":         "CWE-416",
        "exploitable": True,
        "description": "Memory accessed after being freed",
        "primitives":  ["heap_reuse", "type_confusion", "potential_rce"],
    },
    "double-free": {
        "severity":    "HIGH",
        "type":        "Double Free",
        "cwe":         "CWE-415",
        "exploitable": True,
        "description": "Memory freed twice",
        "primitives":  ["heap_corruption", "potential_rce"],
    },
    "heap-use-after-free": {
        "severity":    "CRITICAL",
        "type":        "Heap Use-After-Free",
        "cwe":         "CWE-416",
        "exploitable": True,
        "description": "Heap memory accessed after being freed",
        "primitives":  ["heap_reuse", "potential_rce"],
    },
    "stack-use-after-return": {
        "severity":    "HIGH",
        "type":        "Stack Use-After-Return",
        "cwe":         "CWE-562",
        "exploitable": True,
        "description": "Stack memory accessed after function returned",
        "primitives":  ["stack_corruption"],
    },
    "stack-use-after-scope": {
        "severity":    "HIGH",
        "type":        "Stack Use-After-Scope",
        "cwe":         "CWE-562",
        "exploitable": False,
        "description": "Variable accessed outside its scope",
        "primitives":  [],
    },
    "global-buffer-overflow": {
        "severity":    "HIGH",
        "type":        "Global Buffer Overflow",
        "cwe":         "CWE-119",
        "exploitable": True,
        "description": "Write/read past end of global buffer",
        "primitives":  ["data_section_overflow"],
    },
    "null-deref": {
        "severity":    "MEDIUM",
        "type":        "Null Pointer Dereference",
        "cwe":         "CWE-476",
        "exploitable": False,
        "description": "Null pointer dereference — likely crash/DoS",
        "primitives":  ["dos"],
    },
    "memory-leak": {
        "severity":    "LOW",
        "type":        "Memory Leak",
        "cwe":         "CWE-401",
        "exploitable": False,
        "description": "Memory allocated but not freed",
        "primitives":  [],
    },
    "SEGV on unknown address": {
        "severity":    "HIGH",
        "type":        "Segmentation Fault",
        "cwe":         "CWE-119",
        "exploitable": True,
        "description": "Access to invalid memory address",
        "primitives":  ["potential_arbitrary_read_write"],
    },
}

# Patterns UBSAN (UndefinedBehaviorSanitizer)
UBSAN_PATTERNS = {
    "signed integer overflow": {
        "severity":    "HIGH",
        "type":        "Signed Integer Overflow",
        "cwe":         "CWE-190",
        "exploitable": True,
        "description": "Signed integer overflow (undefined behavior)",
        "primitives":  ["integer_overflow", "heap_corruption"],
    },
    "unsigned integer overflow": {
        "severity":    "MEDIUM",
        "type":        "Unsigned Integer Overflow",
        "cwe":         "CWE-190",
        "exploitable": True,
        "description": "Unsigned integer wraparound",
        "primitives":  ["integer_overflow"],
    },
    "index out of bounds": {
        "severity":    "HIGH",
        "type":        "Array Index Out of Bounds",
        "cwe":         "CWE-125",
        "exploitable": True,
        "description": "Array access out of bounds",
        "primitives":  ["oob_read_write"],
    },
    "null pointer": {
        "severity":    "MEDIUM",
        "type":        "Null Pointer Dereference",
        "cwe":         "CWE-476",
        "exploitable": False,
        "description": "Null pointer dereference",
        "primitives":  ["dos"],
    },
    "shift exponent": {
        "severity":    "MEDIUM",
        "type":        "Invalid Shift",
        "cwe":         "CWE-190",
        "exploitable": False,
        "description": "Shift by negative or too-large exponent",
        "primitives":  [],
    },
    "division by zero": {
        "severity":    "MEDIUM",
        "type":        "Division by Zero",
        "cwe":         "CWE-369",
        "exploitable": False,
        "description": "Division or modulo by zero",
        "primitives":  ["dos"],
    },
    "type mismatch": {
        "severity":    "HIGH",
        "type":        "Type Confusion",
        "cwe":         "CWE-843",
        "exploitable": True,
        "description": "Object used with wrong type",
        "primitives":  ["type_confusion", "potential_rce"],
    },
}

# Signaux de crash et leur signification
CRASH_SIGNALS = {
    "SIGSEGV": {
        "severity": "HIGH",
        "description": "Segmentation fault — invalid memory access",
        "likely_exploitable": True,
    },
    "SIGABRT": {
        "severity": "MEDIUM",
        "description": "Abort signal — heap corruption or assertion failure",
        "likely_exploitable": True,
    },
    "SIGBUS":  {
        "severity": "HIGH",
        "description": "Bus error — alignment or hardware access fault",
        "likely_exploitable": False,
    },
    "SIGFPE":  {
        "severity": "MEDIUM",
        "description": "Floating point exception — usually division by zero",
        "likely_exploitable": False,
    },
    "SIGILL":  {
        "severity": "HIGH",
        "description": "Illegal instruction — code corruption or CFI violation",
        "likely_exploitable": True,
    },
    "SIGTRAP": {
        "severity": "HIGH",
        "description": "Trace trap — breakpoint or CFI violation",
        "likely_exploitable": True,
    },
}


class CrashAnalyzer:
    """
    Analyze crash reports to determine exploitability.
    Supports: ASAN output, UBSAN output, GDB backtrace, core dumps.
    """

    def analyze(self, crash_text: str, source: str = "unknown") -> Dict:
        """
        Analyze crash report text.

        Args:
            crash_text: Raw crash output (ASAN/UBSAN/GDB)
            source: Source of the crash report

        Returns:
            Complete analysis with exploitability assessment
        """
        results = {
            "source":        source,
            "crash_type":    "unknown",
            "findings":      [],
            "exploitability": {},
            "primitives":    [],
            "backtrace":     [],
            "recommendation": "",
        }

        # Detect crash type
        crash_type = self._detect_type(crash_text)
        results["crash_type"] = crash_type

        # Parse based on type
        if crash_type == "asan":
            results.update(self._parse_asan(crash_text))
        elif crash_type == "ubsan":
            results.update(self._parse_ubsan(crash_text))
        elif crash_type == "gdb":
            results.update(self._parse_gdb(crash_text))
        elif crash_type == "valgrind":
            results.update(self._parse_valgrind(crash_text))
        else:
            results.update(self._parse_generic(crash_text))

        # Extract backtrace
        results["backtrace"] = self._extract_backtrace(crash_text)

        # Extract crash address
        results["crash_address"] = self._extract_crash_address(crash_text)

        # Overall exploitability assessment
        results["exploitability"] = self._assess_exploitability(results)

        # Recommendation
        results["recommendation"] = self._generate_recommendation(results)

        return results

    def analyze_file(self, filepath: str) -> Dict:
        """Analyze a crash report file."""
        try:
            text = Path(filepath).read_text(errors="ignore")
            return self.analyze(text, source=filepath)
        except Exception as e:
            return {"error": str(e)}

    def _detect_type(self, text: str) -> str:
        """Detect the type of crash report."""
        if "AddressSanitizer" in text or "==ERROR==" in text:
            return "asan"
        if "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
            return "ubsan"
        if "Valgrind" in text or "Invalid read" in text or "Invalid write" in text:
            return "valgrind"
        # GDB: has register info OR backtrace frames OR address in ??
        if (re.search(r"rip\s*=?\s*0x[0-9a-fA-F]+", text, re.IGNORECASE) or
                re.search(r"eip\s*=?\s*0x[0-9a-fA-F]+", text, re.IGNORECASE) or
                re.search(r"0x[0-9a-fA-F]+\s+in\s+\?\?", text) or
                re.search(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\w+", text)):
            return "gdb"
        if "Segmentation fault" in text or "core dumped" in text:
            return "generic"
        return "generic"

    def _parse_asan(self, text: str) -> Dict:
        """Parse AddressSanitizer output."""
        findings  = []
        crash_type = "unknown"
        primitives = []

        # Find the ASAN error type
        for pattern, info in ASAN_PATTERNS.items():
            if pattern in text:
                crash_type = info["type"]
                primitives.extend(info["primitives"])

                findings.append({
                    "severity":    info["severity"],
                    "type":        info["type"],
                    "cwe":         info["cwe"],
                    "description": info["description"],
                    "exploitable": info["exploitable"],
                    "recommendation": self._fix_for_type(info["type"]),
                })
                break

        # Extract allocation info
        alloc_size = re.search(r"of size (\d+)", text)
        re.search(r"allocated by thread.*at", text)

        if alloc_size:
            for f in findings:
                f["allocation_size"] = int(alloc_size.group(1))

        # Extract overflow offset
        overflow_match = re.search(r"(\d+) bytes? (?:to the right|to the left|after)", text)
        if overflow_match:
            offset = int(overflow_match.group(1))
            for f in findings:
                f["overflow_offset"] = offset
                # Small overflow → more likely exploitable
                if offset <= 8:
                    f["exploitable"] = True
                    f["description"] += f" (offset: {offset} bytes — precise overflow)"

        return {
            "crash_type": crash_type,
            "findings":   findings,
            "primitives": list(set(primitives)),
        }

    def _parse_ubsan(self, text: str) -> Dict:
        """Parse UndefinedBehaviorSanitizer output."""
        findings  = []
        primitives = []

        for pattern, info in UBSAN_PATTERNS.items():
            if pattern in text.lower():
                primitives.extend(info["primitives"])
                findings.append({
                    "severity":    info["severity"],
                    "type":        info["type"],
                    "cwe":         info["cwe"],
                    "description": info["description"],
                    "exploitable": info["exploitable"],
                    "recommendation": self._fix_for_type(info["type"]),
                })

        # Extract location
        loc_match = re.search(r"([\w/\.]+):(\d+):(\d+):", text)
        if loc_match and findings:
            findings[0]["file"] = loc_match.group(1)
            findings[0]["line"] = int(loc_match.group(2))

        return {
            "crash_type": findings[0]["type"] if findings else "ubsan",
            "findings":   findings,
            "primitives": list(set(primitives)),
        }

    def _parse_gdb(self, text: str) -> Dict:
        """Parse GDB backtrace output."""
        findings   = []
        signal     = None
        primitives = []

        # Find signal
        for sig, info in CRASH_SIGNALS.items():
            if sig in text:
                signal = sig
                findings.append({
                    "severity":    info["severity"],
                    "type":        f"Crash via {sig}",
                    "description": info["description"],
                    "exploitable": info["likely_exploitable"],
                    "signal":      sig,
                    "recommendation": "Analyze crash with ASAN/UBSAN for more details",
                })
                break

        # Extract instruction pointer — check multiple formats
        ip_match = (
            re.search(r"rip\s*=?\s*(0x[0-9a-fA-F]+)", text, re.IGNORECASE) or
            re.search(r"eip\s*=?\s*(0x[0-9a-fA-F]+)", text, re.IGNORECASE) or
            re.search(r"^(0x[4][14][14][14][0-9a-fA-F]+)\s+in", text, re.MULTILINE)
        )

        # Also check if the address appears directly in GDB output
        # e.g. "0x4141414141414141 in ?? ()"
        addr_match = re.search(r"(0x[0-9a-fA-F]{8,16})\s+in\s+\?\?", text)

        ip = None
        if ip_match:
            ip = ip_match.group(1)
        elif addr_match:
            ip = addr_match.group(1)

        # Check for controlled IP
        controlled = False
        if ip:
            ip_clean = ip.lower().replace("0x","")
            controlled = (
                "41414141" in ip_clean or
                "42424242" in ip_clean or
                "43434343" in ip_clean or
                ip_clean == "4141414141414141" or
                ip_clean == "41414141"
            )

        if controlled:
            primitives.append("rip_control")
            primitives.append("full_rce")
            # Add or update finding
            if findings:
                findings[0]["exploitable"]  = True
                findings[0]["severity"]     = "CRITICAL"
                findings[0]["description"] += (
                    f" — CONTROLLED INSTRUCTION POINTER "
                    f"({ip} overwritten with attacker data!)"
                )
                findings[0]["primitives"] = ["rip_control", "full_rce"]
            else:
                findings.append({
                    "severity":    "CRITICAL",
                    "type":        "Controlled Instruction Pointer",
                    "description": (
                        f"RIP/EIP controlled by attacker ({ip}). "
                        "Arbitrary code execution confirmed."
                    ),
                    "exploitable": True,
                    "signal":      signal or "SIGSEGV",
                    "primitives":  ["rip_control", "full_rce"],
                    "recommendation": "Fix root cause BOF/UAF. Apply ASLR+PIE+canaries.",
                })
        elif ip and findings:
            findings[0]["instruction_pointer"] = ip

        if not findings:
            findings.append({
                "severity":    "MEDIUM",
                "type":        "GDB Crash",
                "description": "Crash detected via GDB. Manual analysis required.",
                "exploitable": None,
                "recommendation": "Run with ASAN for detailed analysis.",
            })

        return {
            "crash_type": (
                "controlled_ip" if controlled else
                f"signal_{signal}" if signal else
                "gdb_crash"
            ),
            "findings":   findings,
            "primitives": primitives,
        }

    def _parse_valgrind(self, text: str) -> Dict:
        """Parse Valgrind memcheck output."""
        findings  = []

        patterns = {
            "Invalid read":  ("HIGH",     "CWE-125", "Out-of-bounds read"),
            "Invalid write": ("CRITICAL", "CWE-787", "Out-of-bounds write"),
            "Use of uninitialised": ("MEDIUM", "CWE-457", "Use of uninitialized memory"),
            "Invalid free":  ("HIGH",     "CWE-415", "Invalid free / double free"),
            "definitely lost": ("LOW",    "CWE-401", "Memory leak"),
        }

        for pattern, (sev, cwe, desc) in patterns.items():
            if pattern in text:
                count = text.count(pattern)
                findings.append({
                    "severity":    sev,
                    "type":        desc,
                    "cwe":         cwe,
                    "description": f"{desc} ({count} occurrence{'s' if count > 1 else ''})",
                    "exploitable": sev in ("CRITICAL", "HIGH"),
                    "recommendation": self._fix_for_type(desc),
                })

        return {
            "crash_type": "valgrind",
            "findings":   findings,
            "primitives": [f["type"] for f in findings if f["exploitable"]],
        }

    def _parse_generic(self, text: str) -> Dict:
        """Parse generic crash output."""
        findings = []

        for sig, info in CRASH_SIGNALS.items():
            if sig in text:
                findings.append({
                    "severity":    info["severity"],
                    "type":        f"{sig} crash",
                    "description": info["description"],
                    "exploitable": info["likely_exploitable"],
                    "recommendation": "Run with ASAN/UBSAN for detailed analysis",
                })

        if not findings:
            findings.append({
                "severity":    "MEDIUM",
                "type":        "Unknown crash",
                "description": "Crash detected — type undetermined",
                "exploitable": None,
                "recommendation": "Run with ASAN for detailed analysis: gcc -fsanitize=address",
            })

        return {
            "crash_type": "generic",
            "findings":   findings,
            "primitives": [],
        }

    def _extract_backtrace(self, text: str) -> List[Dict]:
        """Extract stack backtrace frames."""
        frames  = []

        # GDB format: #0  0x00007f... in function_name (...)
        gdb_pattern = re.compile(
            r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\w+)\s*\(([^)]*)\)"
            r"(?:\s+at\s+([\w/\.]+):(\d+))?")

        for m in gdb_pattern.finditer(text):
            frames.append({
                "frame":    int(m.group(1)),
                "address":  m.group(2),
                "function": m.group(3),
                "args":     m.group(4),
                "file":     m.group(5),
                "line":     int(m.group(6)) if m.group(6) else None,
            })

        # ASAN format: #0 0x... (binary+0x...)
        if not frames:
            asan_pattern = re.compile(r"#(\d+) (0x[0-9a-fA-F]+) in (\w+)")
            for m in asan_pattern.finditer(text):
                frames.append({
                    "frame":    int(m.group(1)),
                    "address":  m.group(2),
                    "function": m.group(3),
                })

        return frames[:20]

    def _extract_crash_address(self, text: str) -> Optional[str]:
        """Extract the crash address."""
        patterns = [
            r"address (0x[0-9a-fA-F]+)",
            r"SIGSEGV.*?(0x[0-9a-fA-F]+)",
            r"Accessing address (0x[0-9a-fA-F]+)",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                return m.group(1)
        return None

    def _assess_exploitability(self, results: Dict) -> Dict:
        """Overall exploitability assessment."""
        findings   = results.get("findings", [])
        primitives = results.get("primitives", [])

        # Check for critical indicators
        controlled_ip = "rip_control" in primitives or \
                        any("CONTROLLED" in f.get("description","") for f in findings)
        write_prim    = any(p in primitives for p in
                            ["heap_overflow","stack_overflow","oob_read_write"])
        exploitable   = any(f.get("exploitable") for f in findings)

        if controlled_ip:
            rating  = "EXPLOITABLE"
            severity = "CRITICAL"
            score   = 95
        elif write_prim and exploitable:
            rating  = "LIKELY EXPLOITABLE"
            severity = "HIGH"
            score   = 75
        elif exploitable:
            rating  = "POSSIBLY EXPLOITABLE"
            severity = "MEDIUM"
            score   = 50
        else:
            rating  = "NOT EXPLOITABLE (DoS only)"
            severity = "LOW"
            score   = 20

        return {
            "rating":          rating,
            "severity":        severity,
            "score":           score,
            "controlled_ip":   controlled_ip,
            "write_primitive": write_prim,
            "primitives":      primitives,
        }

    def _generate_recommendation(self, results: Dict) -> str:
        """Generate actionable recommendation."""
        exploit = results.get("exploitability", {})
        rating  = exploit.get("rating", "")

        if "EXPLOITABLE" in rating:
            return (
                "CRITICAL: Confirmed exploitable crash. "
                "Develop PoC immediately. "
                "Patch: fix root cause vulnerability (BOF/UAF/etc). "
                "Mitigations: ASLR, PIE, stack canaries, RELRO."
            )
        elif "LIKELY" in rating:
            return (
                "HIGH: Likely exploitable. "
                "Run with ASAN/GDB to confirm exploitation path. "
                "Fix the underlying vulnerability before shipping."
            )
        else:
            return (
                "Investigate root cause. "
                "Run with -fsanitize=address,undefined for full analysis. "
                "Even non-exploitable crashes indicate code quality issues."
            )

    def _fix_for_type(self, vuln_type: str) -> str:
        """Get fix recommendation for a vulnerability type."""
        fixes = {
            "Heap Buffer Overflow":  "Use size-bounded functions. Validate allocation sizes.",
            "Stack Buffer Overflow": "Use strncpy/snprintf. Enable stack canaries.",
            "Use-After-Free":        "Set pointer to NULL after free(). Use smart pointers.",
            "Double Free":           "Set pointer to NULL after first free().",
            "Integer Overflow":      "Use checked arithmetic. Validate sizes before allocation.",
            "Type Confusion":        "Add type tags. Use RTTI. Validate casts.",
            "Memory Leak":           "Free all allocations. Use RAII or smart pointers.",
        }
        for k, v in fixes.items():
            if k.lower() in vuln_type.lower():
                return v
        return "Review and fix the identified crash cause."
