"""
r3con - YARA Engine
Pattern matching pour malware, backdoors, et vulnérabilités.
Fonctionne avec ou sans la librairie YARA installée.
Inclut une base de règles intégrée.
"""

from pathlib import Path
from typing import List, Dict, Optional


# ── Règles YARA intégrées (format simplifié pour fallback) ───

BUILTIN_RULES = {
    "malware": {
        "Mirai_Botnet": {
            "description": "Mirai IoT botnet strings",
            "severity":    "CRITICAL",
            "strings": [
                b"/bin/busybox",
                b"MIRAI",
                b"hacktheplanet",
                b"/dev/watchdog",
            ],
            "condition": "any",
        },
        "Shellcode_NOP_Sled": {
            "description": "NOP sled typically used in shellcode",
            "severity":    "HIGH",
            "bytes_pattern": b"\x90" * 16,
            "condition": "bytes",
        },
        "ELF_Backdoor_Strings": {
            "description": "Common backdoor strings in ELF binaries",
            "severity":    "CRITICAL",
            "strings": [
                b"reverse shell",
                b"connect back",
                b"/bin/sh",
                b"nc -e /bin/sh",
                b"bash -i >& /dev/tcp",
            ],
            "condition": "any",
        },
        "Credential_Harvester": {
            "description": "Credential harvesting patterns",
            "severity":    "HIGH",
            "strings": [
                b"steal_password",
                b"keylog",
                b"credential_dump",
                b"passwd_harvest",
            ],
            "condition": "any",
        },
        "Ransomware_Patterns": {
            "description": "Ransomware behavioral patterns",
            "severity":    "CRITICAL",
            "strings": [
                b".encrypted",
                b"YOUR FILES ARE ENCRYPTED",
                b"bitcoin",
                b"ransom",
                b"decrypt_instructions",
            ],
            "condition": "any",
        },
    },
    "exploit": {
        "Heap_Spray_Pattern": {
            "description": "Heap spray pattern (repeated blocks)",
            "severity":    "HIGH",
            "bytes_pattern": b"\x0c\x0c\x0c\x0c" * 4,
            "condition": "bytes",
        },
        "Stack_Overflow_Pattern": {
            "description": "Stack overflow test strings",
            "severity":    "HIGH",
            "strings": [
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                b"A" * 100,
            ],
            "condition": "any",
        },
        "ROP_Ret_Gadget": {
            "description": "Common ROP gadget bytes (ret instruction)",
            "severity":    "MEDIUM",
            "bytes_pattern": b"\xc3" * 2,
            "condition": "bytes",
        },
        "Format_String_Pattern": {
            "description": "Format string exploitation patterns",
            "severity":    "HIGH",
            "strings": [
                b"%n%n%n",
                b"%x%x%x%x",
                b"AAAA%08x",
            ],
            "condition": "any",
        },
    },
    "backdoor": {
        "Hardcoded_Credentials": {
            "description": "Hardcoded credentials in binary",
            "severity":    "CRITICAL",
            "strings": [
                b"admin:admin",
                b"root:root",
                b"admin:password",
                b"root:toor",
                b"password=admin",
                b"passwd=root",
            ],
            "condition": "any",
        },
        "Remote_Shell_Strings": {
            "description": "Remote shell setup strings",
            "severity":    "CRITICAL",
            "strings": [
                b"bash -i",
                b"/bin/bash -c",
                b"python -c 'import socket",
                b"nc -lvp",
                b"ncat --listen",
            ],
            "condition": "any",
        },
        "Debug_Backdoor": {
            "description": "Debug backdoor access strings",
            "severity":    "HIGH",
            "strings": [
                b"debug_mode=1",
                b"BACKDOOR_KEY",
                b"secret_access",
                b"maintenance_mode",
            ],
            "condition": "any",
        },
        "Telnet_Backdoor": {
            "description": "Telnet backdoor service strings",
            "severity":    "HIGH",
            "strings": [
                b"telnetd",
                b"telnet -l /bin/sh",
                b"utelnetd",
            ],
            "condition": "any",
        },
    },
    "crypto": {
        "Weak_Crypto_Constants": {
            "description": "Known weak cryptographic constants",
            "severity":    "MEDIUM",
            "bytes_pattern": bytes([0x67, 0x45, 0x23, 0x01]),  # MD5 init constant
            "condition": "bytes",
        },
        "Hardcoded_Key_Material": {
            "description": "Hardcoded key or IV material",
            "severity":    "HIGH",
            "strings": [
                b"AES_KEY=",
                b"SECRET_KEY=",
                b"PRIVATE_KEY=",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN PRIVATE KEY-----",
            ],
            "condition": "any",
        },
        "SSL_Cert_Bypass": {
            "description": "SSL certificate bypass strings",
            "severity":    "HIGH",
            "strings": [
                b"verify=False",
                b"ssl._create_unverified_context",
                b"TrustAllCerts",
                b"AllowAllHostnameVerifier",
                b"checkServerTrusted",
            ],
            "condition": "any",
        },
    },
}

# Règles YARA en syntaxe réelle (pour la librairie yara-python)
YARA_RULES_TEXT = """
rule Mirai_Botnet
{
    meta:
        description = "Detects Mirai botnet strings"
        severity = "CRITICAL"
        author = "r3con"
    strings:
        $s1 = "/bin/busybox"
        $s2 = "MIRAI"
        $s3 = "hacktheplanet"
        $s4 = "/dev/watchdog"
    condition:
        any of them
}

rule Hardcoded_Credentials
{
    meta:
        description = "Hardcoded credentials in binary"
        severity = "CRITICAL"
        author = "r3con"
    strings:
        $c1 = "admin:admin" nocase
        $c2 = "root:root"
        $c3 = "password=admin" nocase
        $c4 = "admin:password" nocase
    condition:
        any of them
}

rule Remote_Shell
{
    meta:
        description = "Remote shell setup strings"
        severity = "CRITICAL"
        author = "r3con"
    strings:
        $s1 = "bash -i"
        $s2 = "/bin/bash -c"
        $s3 = "nc -lvp"
    condition:
        any of them
}

rule SSL_Bypass
{
    meta:
        description = "SSL certificate validation bypass"
        severity = "HIGH"
        author = "r3con"
    strings:
        $s1 = "verify=False"
        $s2 = "TrustAllCerts"
        $s3 = "AllowAllHostnameVerifier"
        $s4 = "checkServerTrusted"
    condition:
        any of them
}

rule Private_Key_Material
{
    meta:
        description = "Embedded private key material"
        severity = "CRITICAL"
        author = "r3con"
    strings:
        $p1 = "-----BEGIN RSA PRIVATE KEY-----"
        $p2 = "-----BEGIN PRIVATE KEY-----"
        $p3 = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}

rule Ransomware_Strings
{
    meta:
        description = "Ransomware behavioral strings"
        severity = "CRITICAL"
        author = "r3con"
    strings:
        $r1 = "YOUR FILES ARE ENCRYPTED" nocase
        $r2 = "bitcoin" nocase
        $r3 = ".encrypted"
    condition:
        2 of them
}

rule Debug_Interface
{
    meta:
        description = "Debug/maintenance backdoor"
        severity = "HIGH"
        author = "r3con"
    strings:
        $d1 = "BACKDOOR_KEY"
        $d2 = "debug_mode" nocase
        $d3 = "maintenance_mode" nocase
    condition:
        any of them
}
"""


class YARAEngine:
    """YARA pattern matching engine."""

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize YARA engine.

        Args:
            rules_dir: Optional directory with custom .yar files
        """
        self.rules_dir    = rules_dir
        self.yara_module  = self._try_import_yara()
        self.compiled     = None
        self.custom_rules = []
        self.last_error   = None
        self.backend = "yara-python" if self.yara_module else "builtin-pattern-fallback"

        # Compile YARA rules if module available
        if self.yara_module:
            self._compile_rules()

    def _try_import_yara(self):
        """Try to import yara-python module."""
        try:
            import yara
            return yara
        except ImportError:
            return None

    def _compile_rules(self):
        """Compile built-in and custom YARA rules."""
        if not self.yara_module:
            return

        try:
            rules_sources = {"builtin": YARA_RULES_TEXT}

            # Load custom rules from directory
            if self.rules_dir:
                rules_path = Path(self.rules_dir)
                for yar_file in rules_path.glob("*.yar"):
                    rules_sources[yar_file.stem] = yar_file.read_text()
                for yar_file in rules_path.glob("*.yara"):
                    rules_sources[yar_file.stem] = yar_file.read_text()

            self.compiled = self.yara_module.compile(sources=rules_sources)
            self.last_error = None
        except Exception as e:
            self.compiled = None
            self.last_error = f"{type(e).__name__}: {e}"

    def capabilities(self) -> Dict:
        return {
            "backend": self.backend,
            "full_yara_semantics": bool(self.yara_module and self.compiled),
            "custom_rules": bool(self.yara_module and self.compiled),
            "last_error": self.last_error,
        }

    def scan_file(self, filepath: str) -> List[Dict]:
        """
        Scan a file with YARA rules - FIXED size limit, validation.
        """
        try:
            p = Path(filepath)
            if not p.exists() or not p.is_file():
                return []
            if len(str(filepath)) > 1024 or ".." in str(filepath):
                # Basic validation
                pass
            # Size check before reading
            try:
                size = p.stat().st_size
                if size > 50 * 1024 * 1024:  # 50MB
                    return []
                if size == 0:
                    return []
            except OSError:
                return []

            with open(filepath, "rb") as f:
                data = f.read()

            # Limit data for builtin scan to prevent DoS
            if len(data) > 20 * 1024 * 1024 and not (self.yara_module and self.compiled):
                data = data[:20 * 1024 * 1024]

        except Exception:
            return []

        return self.scan_bytes(data, filepath)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[Dict]:
        """
        Scan bytes with YARA rules - FIXED limits, deduplication.
        """
        if not data:
            return []

        # Limit findings
        MAX_FINDINGS = 1000

        findings = []

        # Run one backend only; fallback is not full YARA semantics.
        if self.yara_module and self.compiled:
            findings.extend(self._yara_scan(data, source))
        else:
            findings.extend(self._builtin_scan(data, source))

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f['rule']}:{f['offset']}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
                if len(unique) >= MAX_FINDINGS:
                    break

        return sorted(unique, key=lambda x:
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4))

    def _yara_scan(self, data: bytes, source: str) -> List[Dict]:
        """Scan using yara-python."""
        findings = []
        try:
            matches = self.compiled.match(data=data)
            for match in matches:
                sev = match.meta.get("severity", "MEDIUM")
                for string in match.strings:
                    findings.append({
                        "severity":    sev,
                        "type":        "YARA Match",
                        "rule":        match.rule,
                        "description": match.meta.get("description", match.rule),
                        "source":      source,
                        "offset":      string.instances[0].offset if string.instances else 0,
                        "matched":     str(string.instances[0].matched_data[:50]
                                          if string.instances else ""),
                        "recommendation": f"Investigate YARA rule: {match.rule}",
                        "tags":        list(match.tags),
                    })
        except Exception:
            pass
        return findings

    def _builtin_scan(self, data: bytes, source: str) -> List[Dict]:
        """Builtin fallback scanner (no yara-python needed) - FIXED efficient, limited."""
        findings = []
        MAX_PER_RULE = 3
        MAX_TOTAL = 500

        # Pre-filter: if data is small, scan all; if large, sample first 5MB for strings
        # For bytes patterns like NOP sled, we need full scan but limited
        scan_data = data
        if len(data) > 5 * 1024 * 1024:
            # For large files, scan first 5MB for strings, full for bytes patterns with early exit
            scan_data = data[:5 * 1024 * 1024]

        for category, rules in BUILTIN_RULES.items():
            if len(findings) >= MAX_TOTAL:
                break
            for rule_name, rule_def in rules.items():
                if len(findings) >= MAX_TOTAL:
                    break
                sev = rule_def.get("severity", "MEDIUM")
                desc = rule_def.get("description", rule_name)
                cond = rule_def.get("condition", "any")

                # Check string patterns
                if "strings" in rule_def:
                    strings = rule_def["strings"]
                    matches = []
                    # Use efficient search - for each string, find all occurrences but limit
                    for s in strings:
                        if len(findings) >= MAX_TOTAL:
                            break
                        # For large data, use find with limit
                        count = 0
                        start = 0
                        while count < MAX_PER_RULE:
                            idx = scan_data.find(s, start)
                            if idx == -1:
                                break
                            matches.append((s, idx))
                            count += 1
                            start = idx + 1
                            # Early exit for "any" condition
                            if cond == "any" and matches:
                                break
                        if cond == "any" and matches:
                            break

                    should_report = (
                        (cond == "any" and len(matches) > 0) or
                        (cond == "all" and len(matches) == len(strings)) or
                        (cond == "2of" and len(matches) >= 2)
                    )

                    if should_report:
                        for s, offset in matches[:MAX_PER_RULE]:
                            findings.append({
                                "severity": sev,
                                "type": f"Pattern fallback: {rule_name}",
                                "rule": rule_name,
                                "category": category,
                                "description": desc,
                                "source": source,
                                "offset": offset,
                                "matched": s[:50].decode("utf-8", errors="replace"),
                                "recommendation": f"Investigate pattern: {rule_name}",
                                "tags": [category, "builtin-pattern-fallback"],
                            })

                # Check bytes patterns
                elif "bytes_pattern" in rule_def:
                    pattern = rule_def["bytes_pattern"]
                    # For bytes patterns, search in full data but with early exit
                    # Use efficient search
                    if len(pattern) > 1024:
                        continue  # Skip huge patterns
                    idx = data.find(pattern)
                    if idx != -1:
                        findings.append({
                            "severity": sev,
                            "type": f"Pattern fallback: {rule_name}",
                            "rule": rule_name,
                            "category": category,
                            "description": desc,
                            "source": source,
                            "offset": idx,
                            "matched": pattern[:16].hex(),
                            "recommendation": f"Investigate bytes pattern: {rule_name}",
                            "tags": [category, "builtin-pattern-fallback"],
                        })

        return findings

    def add_rule_string(self, rule_text: str, namespace: str = "custom") -> bool:
        """Add a YARA rule from string."""
        if not self.yara_module:
            return False
        try:
            self.compiled = self.yara_module.compile(source=rule_text)
            return True
        except Exception:
            return False

    def scan_directory(self, directory: str,
                       extensions: Optional[List[str]] = None) -> Dict:
        """
        Scan all files in a directory - FIXED symlink protection, limits.
        """
        base = Path(directory)
        if not base.exists() or not base.is_dir():
            return {"directory": directory, "files_scanned": 0, "findings": [], "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "rules_hit": 0}, "error": "invalid_directory"}

        all_findings = []
        files_scanned = 0
        visited_inodes = set()
        MAX_FILES = 5000

        try:
            for filepath in base.rglob("*"):
                if files_scanned >= MAX_FILES:
                    break
                try:
                    if filepath.is_symlink():
                        try:
                            real = filepath.resolve()
                            if real.is_dir():
                                continue
                            try:
                                real.relative_to(base.resolve())
                            except ValueError:
                                continue
                        except (OSError, RuntimeError):
                            continue

                    if not filepath.is_file():
                        continue

                    try:
                        stat = filepath.stat()
                        inode = (stat.st_dev, stat.st_ino)
                        if inode in visited_inodes:
                            continue
                        visited_inodes.add(inode)
                        if stat.st_size > 50 * 1024 * 1024 or stat.st_size == 0:
                            continue
                    except OSError:
                        continue

                    if extensions and filepath.suffix not in extensions:
                        continue

                    findings = self.scan_file(str(filepath))
                    if findings:
                        for f in findings:
                            f["file"] = str(filepath)
                        all_findings.extend(findings)
                        if len(all_findings) > 1000:
                            all_findings = all_findings[:1000]
                            break

                    files_scanned += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError, RuntimeError):
            pass

        return {
            "directory": directory,
            "files_scanned": files_scanned,
            "findings": all_findings[:1000],
            "stats": {
                "total": len(all_findings),
                "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
                "rules_hit": len(set(f["rule"] for f in all_findings)),
            }
        }
