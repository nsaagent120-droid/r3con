"""
r3con - Kernel Pattern Scanner
Detects kernel-specific vulnerability patterns.
"""

import re
from typing import List, Dict


class KernelPatternScanner:
    def analyze(self, code: str, ktype: str = "auto") -> List[Dict]:
        findings = []
        lines = code.splitlines()
        findings += self._boundary(lines)
        findings += self._race(lines)
        findings += self._integer(lines)
        findings += self._privesc(lines)
        findings += self._leak(lines)
        findings += self._ioctl(lines)
        return findings

    def _boundary(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r'__user\s*\*', line) and re.search(r'\*\s*\w+__user|\w+__user\s*->', line):
                findings.append({
                    "severity": "CRITICAL", "type": "Missing copy_from_user",
                    "line": i,
                    "description": "Direct __user pointer dereference — bypasses user/kernel boundary",
                    "recommendation": "Use copy_from_user() / get_user() for all userspace reads"
                })
            if re.search(r'memcpy\s*\([^,]+,\s*\w*user\w*', line, re.I):
                findings.append({
                    "severity": "HIGH", "type": "Unsafe User Copy",
                    "line": i,
                    "description": "memcpy() from userspace — use copy_from_user()",
                    "recommendation": "Replace with copy_from_user() which validates the pointer"
                })
            # copy_from_user called directly — validate size parameter
            if re.search(r'\bcopy_from_user\s*\(', line):
                findings.append({
                    "severity": "HIGH", "type": "copy_from_user — Validate Size",
                    "line": i,
                    "description": "copy_from_user() — verify size is bounded before calling",
                    "recommendation": "Check size <= MAX_COPY_SIZE before copy_from_user()"
                })
        return findings

    def _race(self, lines):
        findings = []
        locked = False
        lock_line = 0
        for i, line in enumerate(lines, 1):
            if re.search(r'spin_lock|mutex_lock|down\s*\(|read_lock', line):
                locked = True; lock_line = i
            if re.search(r'spin_unlock|mutex_unlock|up\s*\(|read_unlock', line):
                locked = False
            if locked and re.search(r'\bmsleep\b|ssleep\b|wait_event[^_]', line):
                findings.append({
                    "severity": "HIGH", "type": "Sleep in Atomic Context",
                    "line": i,
                    "description": f"Sleep while holding lock (acquired L{lock_line}) — kernel panic risk",
                    "recommendation": "Release lock before sleeping or use wait_event_interruptible()"
                })
        return findings

    def _integer(self, lines):
        findings = []
        PATS = [
            (r'kmalloc\s*\(\s*\w+\s*\*\s*\w+',  "CRITICAL", "Integer Overflow (kmalloc)",
             "Multiplication before kmalloc — use kmalloc_array()"),
            (r'kzalloc\s*\(\s*\w+\s*\*\s*\w+',  "CRITICAL", "Integer Overflow (kzalloc)",
             "Multiplication before kzalloc — use kmalloc_array() + memset"),
            (r'vmalloc\s*\(\s*\w+\s*\*\s*\w+',  "HIGH",     "Integer Overflow (vmalloc)",
             "Check for overflow before vmalloc"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATS:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": "Use kmalloc_array(), array_size(), or check_mul_overflow()"
                    })
        return findings

    def _privesc(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r'commit_creds|prepare_creds', line):
                findings.append({
                    "severity": "CRITICAL", "type": "Credential Modification",
                    "line": i,
                    "description": "Credential modification — high-value target for privilege escalation",
                    "recommendation": "Verify all paths here require CAP_SETUID or equivalent"
                })
            if re.search(r'capable\s*\(|ns_capable\s*\(', line):
                findings.append({
                    "severity": "INFO", "type": "Capability Check",
                    "line": i,
                    "description": "Capability check — verify correct capability, no bypass path",
                    "recommendation": "Ensure check covers ALL privileged code paths"
                })
        return findings

    def _leak(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r'copy_to_user', line):
                findings.append({
                    "severity": "MED", "type": "Potential Info Leak",
                    "line": i,
                    "description": "copy_to_user() — verify source buffer fully initialized (no padding with kernel ptrs)",
                    "recommendation": "memset() structs to zero before filling fields"
                })
            if re.search(r'printk.*%p|pr_info.*%p|pr_debug.*%p', line):
                findings.append({
                    "severity": "HIGH", "type": "Kernel Pointer Leak",
                    "line": i,
                    "description": "printk %p leaks kernel addresses — defeats KASLR",
                    "recommendation": "Use %pK to respect kptr_restrict setting"
                })
        return findings

    def _ioctl(self, lines):
        findings = []
        in_ioctl = False
        for i, line in enumerate(lines, 1):
            if re.search(r'ioctl|unlocked_ioctl|compat_ioctl', line):
                in_ioctl = True
            if in_ioctl:
                if re.search(r'copy_from_user|get_user', line):
                    if not re.search(r'sizeof|size\b|len\b', line):
                        findings.append({
                            "severity": "HIGH", "type": "IOCTL Input Validation",
                            "line": i,
                            "description": "copy_from_user in ioctl without explicit size validation",
                            "recommendation": "Always validate input size against expected struct size"
                        })
                if re.search(r'^\s*}', line):
                    in_ioctl = False
        return findings
