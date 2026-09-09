"""
r3con v6.1 - YARA Manager PRO renforcé
Gestion règles YARA: list, scan, create, update, import
"""
from __future__ import annotations
import json
import hashlib
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import os

YARA_RULES_DIR = Path.home() / ".r3con" / "yara"
YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)

# Built-in YARA rules PRO
BUILTIN_RULES = {
    "credential_harvester": """
rule CredentialHarvester {
    meta:
        description = "Detects credential harvesting patterns"
        severity = "HIGH"
        cwe = "CWE-798"
    strings:
        $a = "password" nocase
        $b = "api_key" nocase
        $c = "secret" nocase
        $d = "BEGIN PRIVATE KEY"
        $e = "BEGIN RSA PRIVATE KEY"
    condition:
        2 of ($a, $b, $c) or any of ($d, $e)
}
""",
    "bof_patterns": """
rule BufferOverflowPatterns {
    meta:
        description = "Detects BOF vulnerable functions"
        severity = "HIGH"
        cwe = "CWE-121"
    strings:
        $gets = "gets" fullword
        $strcpy = "strcpy" fullword
        $strcat = "strcat" fullword
        $sprintf = "sprintf" fullword
    condition:
        any of them
}
""",
    "crypto_weak": """
rule WeakCrypto {
    meta:
        description = "Detects weak crypto"
        severity = "MEDIUM"
        cwe = "CWE-327"
    strings:
        $md5 = "MD5" fullword
        $sha1 = "SHA1" fullword
        $des = "DES" fullword
        $rc4 = "RC4" fullword
    condition:
        any of them
}
""",
    "malware_generic": """
rule GenericMalware {
    meta:
        description = "Generic malware indicators"
        severity = "CRITICAL"
    strings:
        $a = "CreateRemoteThread"
        $b = "VirtualAllocEx"
        $c = "WriteProcessMemory"
        $d = "keylogger" nocase
        $e = "ransom" nocase
    condition:
        2 of them
}
""",
    "firmware_indicators": """
rule FirmwareIndicators {
    meta:
        description = "Firmware indicators"
        severity = "INFO"
    strings:
        $squashfs = "squashfs"
        $uboot = "u-boot"
        $busybox = "busybox"
        $jffs2 = "jffs2"
    condition:
        any of them
}
""",
}


class YaraManager:
    """Gestionnaire YARA PRO."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or YARA_RULES_DIR
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_builtin()

    def _ensure_builtin(self):
        """Crée règles builtin si absentes."""
        for name, content in BUILTIN_RULES.items():
            rule_path = self.rules_dir / f"{name}.yar"
            if not rule_path.is_file():
                rule_path.write_text(content, encoding="utf-8")

    def list_rules(self) -> List[Dict[str, Any]]:
        """Liste règles disponibles."""
        rules = []
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                content = rule_file.read_text(encoding="utf-8")
                # Parse meta
                import re
                desc_match = re.search(r'description\s*=\s*"([^"]+)"', content)
                sev_match = re.search(r'severity\s*=\s*"([^"]+)"', content)
                cwe_match = re.search(r'cwe\s*=\s*"([^"]+)"', content)

                rules.append({
                    "name": rule_file.stem,
                    "path": str(rule_file),
                    "size": rule_file.stat().st_size,
                    "description": desc_match.group(1) if desc_match else "—",
                    "severity": sev_match.group(1) if sev_match else "INFO",
                    "cwe": cwe_match.group(1) if cwe_match else "—",
                    "sha256": hashlib.sha256(content.encode()).hexdigest()[:16],
                    "builtin": rule_file.stem in BUILTIN_RULES,
                })
            except Exception:
                continue
        return sorted(rules, key=lambda x: x["name"])

    def scan_file(self, target_path: str, rules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan fichier avec YARA (si yara disponible, sinon fallback regex)."""
        target = Path(target_path)
        if not target.is_file():
            return {"status": "error", "error": "target_not_found"}

        # Try yara-python if available
        try:
            import yara
            YARA_AVAILABLE = True
        except ImportError:
            YARA_AVAILABLE = False

        if YARA_AVAILABLE:
            try:
                # Compile rules
                if rules:
                    rule_files = [self.rules_dir / f"{r}.yar" for r in rules if (self.rules_dir / f"{r}.yar").is_file()]
                else:
                    rule_files = list(self.rules_dir.glob("*.yar"))

                if not rule_files:
                    return {"status": "error", "error": "no_rules"}

                # Compile all
                rules_dict = {}
                for rf in rule_files:
                    try:
                        rules_dict[rf.stem] = str(rf)
                    except Exception:
                        continue

                compiled = yara.compile(filepaths=rules_dict)
                matches = compiled.match(str(target))

                findings = []
                for match in matches:
                    findings.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [{"identifier": s.identifier, "instances": len(s.instances)} for s in match.strings],
                        "severity": match.meta.get("severity", "INFO"),
                    })

                return {
                    "status": "ok",
                    "engine": "yara-python",
                    "target": str(target),
                    "rules_scanned": len(rule_files),
                    "matches": len(matches),
                    "findings": findings,
                }
            except Exception as e:
                # Fallback to regex
                pass

        # Fallback: simple string matching (no yara)
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")[:100000]
            findings = []
            for rule_info in self.list_rules():
                rule_path = Path(rule_info["path"])
                rule_content = rule_path.read_text(encoding="utf-8")
                # Extract strings from rule (simplified)
                import re
                strings = re.findall(r'\$[a-zA-Z0-9_]+\s*=\s*"([^"]+)"', rule_content)
                matched_strings = []
                for s in strings:
                    if s.lower() in content.lower():
                        matched_strings.append(s)

                if matched_strings:
                    findings.append({
                        "rule": rule_info["name"],
                        "meta": {"description": rule_info["description"], "severity": rule_info["severity"]},
                        "matched_strings": matched_strings[:5],
                        "severity": rule_info["severity"],
                    })

            return {
                "status": "ok",
                "engine": "r3con-regex-fallback",
                "target": str(target),
                "rules_scanned": len(self.list_rules()),
                "matches": len(findings),
                "findings": findings,
                "note": "yara-python non disponible, fallback regex utilisé. Installe avec pip install yara-python",
            }
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def create_rule(self, name: str, description: str, strings: List[str], condition: str = "any of them", severity: str = "MEDIUM", cwe: str = "CWE-000") -> Dict[str, Any]:
        """Créer règle YARA depuis findings."""

        # Sanitize name
        safe_name = "".join(c for c in name if c.isalnum() or c in "_-")[:50]
        if not safe_name:
            safe_name = f"rule_{int(datetime.now().timestamp())}"

        rule_content = f"""
rule {safe_name} {{
    meta:
        description = "{description[:200]}"
        severity = "{severity}"
        cwe = "{cwe}"
        created = "{datetime.now(timezone.utc).isoformat()}"
        author = "r3con v6.1"

    strings:
"""

        for i, s in enumerate(strings[:20]):
            # Escape string
            escaped = s.replace("\\", "\\\\").replace('"', '\\"')[:100]
            rule_content += f'        $s{i} = "{escaped}" nocase\n'

        rule_content += f"""
    condition:
        {condition}
}}
"""

        rule_path = self.rules_dir / f"{safe_name}.yar"
        if rule_path.exists():
            return {"status": "error", "error": f"Rule {safe_name} already exists"}

        rule_path.write_text(rule_content, encoding="utf-8")

        return {
            "status": "ok",
            "name": safe_name,
            "path": str(rule_path),
            "strings": len(strings),
            "content": rule_content[:500],
        }

    def delete_rule(self, name: str) -> Dict[str, Any]:
        """Supprimer règle."""
        rule_path = self.rules_dir / f"{name}.yar"
        if not rule_path.is_file():
            return {"status": "error", "error": "rule_not_found"}

        if name in BUILTIN_RULES:
            return {"status": "error", "error": "cannot_delete_builtin"}

        rule_path.unlink()
        return {"status": "ok", "deleted": name}

    def import_rules(self, source_dir: str) -> Dict[str, Any]:
        """Importer règles depuis dossier."""
        src = Path(source_dir)
        if not src.is_dir():
            return {"status": "error", "error": "source_not_dir"}

        imported = 0
        for yar_file in src.glob("*.yar"):
            try:
                dest = self.rules_dir / yar_file.name
                if not dest.exists():
                    shutil.copy2(yar_file, dest)
                    imported += 1
            except Exception:
                continue

        return {"status": "ok", "imported": imported, "source": str(src), "total_rules": len(self.list_rules())}

    def get_stats(self) -> Dict[str, Any]:
        """Stats YARA."""
        rules = self.list_rules()
        by_sev = {}
        for r in rules:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1

        return {
            "total_rules": len(rules),
            "builtin": len([r for r in rules if r["builtin"]]),
            "custom": len([r for r in rules if not r["builtin"]]),
            "by_severity": by_sev,
            "rules_dir": str(self.rules_dir),
            "yara_python_available": self._check_yara_python(),
        }

    def _check_yara_python(self) -> bool:
        try:
            import yara
            return True
        except ImportError:
            return False
