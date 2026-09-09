"""
r3con v7.1 - Secret Scanner PRO
Trufflehog-like secret detection + entropy + verification
"""
from __future__ import annotations
import re
import math
import hashlib
from pathlib import Path
from typing import Dict, List, Any
from collections import Counter

SECRET_RULES = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CRITICAL", "AWS access key - check IAM permissions"),
    (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret Access Key", "CRITICAL", "AWS secret key - rotate immediately"),
    (r"aws_session_token\s*=\s*[A-Za-z0-9/+=]{100,}", "AWS Session Token", "HIGH", "AWS session token - temporary credential"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "CRITICAL", "GitHub PAT - revoke immediately"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "CRITICAL", "GitHub OAuth token"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Fine-grained PAT", "CRITICAL", "GitHub fine-grained PAT"),
    # Generic API keys
    (r"api_key\s*[:=]\s*['\"][A-Za-z0-9-_]{20,}['\"]", "Generic API Key", "HIGH", "API key - rotate and use env vars"),
    (r"apikey\s*[:=]\s*['\"][A-Za-z0-9-_]{20,}['\"]", "API Key (apikey)", "HIGH", "API key"),
    (r"secret\s*[:=]\s*['\"][A-Za-z0-9-_+/=]{16,}['\"]", "Generic Secret", "HIGH", "Hardcoded secret"),
    (r"password\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password", "HIGH", "Hardcoded password - use env var or vault"),
    (r"passwd\s*[:=]\s*['\"][^'\"]{4,}['\"]", "Hardcoded Passwd", "HIGH", "Hardcoded password"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", "CRITICAL", "Private key - must not be committed"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate", "MEDIUM", "Certificate - check if private key also present"),
    # Database
    (r"mongodb://[^:]+:[^@]+@[^/]+|postgres://[^:]+:[^@]+@|mysql://[^:]+:[^@]+@", "DB Connection String with Password", "CRITICAL", "DB connection string with password in code"),
    (r"jdbc:.*password.*=.*['\"][^'\"]+['\"]", "JDBC Password", "HIGH", "JDBC connection with password"),
    # Tokens
    (r"Bearer\s+[A-Za-z0-9-_.]{20,}", "Bearer Token", "HIGH", "Bearer token - possible credential leak"),
    (r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}", "JWT Token", "HIGH", "JWT token - check if secret key leaked"),
    (r"xox[bprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}", "Slack Token", "CRITICAL", "Slack token - revoke"),
    # Cloud
    (r"AIza[0-9A-Za-z-_]{35}", "Google API Key", "CRITICAL", "Google API key"),
    (r"ya29\.[0-9A-Za-z-_]+", "Google OAuth Token", "CRITICAL", "Google OAuth token"),
    (r"AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}", "AWS Keys", "CRITICAL", "AWS key"),
    # Generic high entropy
    # Handled separately
]

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

class SecretScanner:
    """Secret Scanner PRO - trufflehog-like."""

    def __init__(self, min_entropy: float = 4.5):
        self.min_entropy = min_entropy

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            content = path.read_text(errors="ignore", encoding="utf-8")[:5*1024*1024]
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        return self.scan_content(content, str(path))

    def scan_content(self, content: str, source: str = "memory") -> Dict[str, Any]:
        findings = []

        # Rule-based
        for pattern, name, severity, desc in SECRET_RULES:
            try:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches:
                    for m in matches[:10]:
                        # Get line number
                        line_num = content[:m.start()].count("\n") + 1
                        # Get context
                        start = max(0, m.start() - 30)
                        end = min(len(content), m.end() + 30)
                        context = content[start:end].replace("\n", " ")[:150]

                        # Verify entropy for generic secrets
                        secret_value = m.group(0)
                        entropy = calculate_entropy(secret_value)

                        # Skip low entropy for generic patterns
                        if "Generic" in name and entropy < self.min_entropy:
                            continue

                        findings.append({
                            "type": f"Secret: {name}",
                            "severity": severity,
                            "description": desc,
                            "secret_type": name,
                            "match": secret_value[:100],
                            "entropy": entropy,
                            "line": line_num,
                            "context": context,
                            "source": source,
                            "recommendation": "Remove secret from code, use environment variable or secret manager (Vault, AWS Secrets Manager)",
                        })
            except re.error:
                continue

        # High entropy strings (generic secret detection)
        high_entropy_findings = self._find_high_entropy_strings(content, source)
        findings.extend(high_entropy_findings)

        # Deduplicate by match
        seen = set()
        unique = []
        for f in findings:
            key = f.get("match", "")[:50]
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return {
            "status": "ok",
            "engine": "secret_scanner",
            "source": source,
            "findings": unique[:100],
            "count": len(unique),
            "by_type": Counter(f.get("secret_type", "unknown") for f in unique),
            "by_severity": Counter(f.get("severity", "MEDIUM") for f in unique),
        }

    def scan_directory(self, dir_path: str, exclude_patterns: List[str] = None) -> Dict[str, Any]:
        base = Path(dir_path)
        if not base.is_dir():
            return {"status": "error", "error": "not_a_directory"}

        exclude_patterns = exclude_patterns or [".git", "__pycache__", "node_modules", ".venv", "venv", ".env.example"]

        all_findings = []
        files_scanned = []

        try:
            for file_path in base.rglob("*"):
                if not file_path.is_file():
                    continue

                # Exclude
                if any(ex in str(file_path) for ex in exclude_patterns):
                    continue

                # Skip large files
                try:
                    if file_path.stat().st_size > 5*1024*1024:
                        continue
                    if file_path.stat().st_size == 0:
                        continue
                except Exception:
                    continue

                # Skip binary extensions
                if file_path.suffix in (".exe", ".dll", ".so", ".dylib", ".bin", ".jpg", ".png", ".gif", ".mp4", ".zip", ".tar", ".gz"):
                    continue

                try:
                    result = self.scan_file(str(file_path))
                    if result.get("status") == "ok" and result.get("count", 0) > 0:
                        all_findings.extend(result.get("findings", []))
                        files_scanned.append(str(file_path))
                except Exception:
                    continue

                if len(files_scanned) > 1000:
                    break

        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        return {
            "status": "ok",
            "engine": "secret_scanner_dir",
            "directory": str(base),
            "files_scanned": len(files_scanned),
            "files_with_secrets": files_scanned[:100],
            "findings": all_findings[:200],
            "count": len(all_findings),
            "by_type": dict(Counter(f.get("secret_type", "unknown") for f in all_findings)),
            "by_severity": dict(Counter(f.get("severity", "MEDIUM") for f in all_findings)),
        }

    def _find_high_entropy_strings(self, content: str, source: str) -> List[Dict[str, Any]]:
        """Find high entropy strings that look like secrets."""
        findings = []

        # Find potential secrets: long strings with high entropy
        # Pattern: 20+ chars alphanumeric + special
        pattern = r"[A-Za-z0-9-_+/=]{20,100}"

        try:
            matches = re.findall(pattern, content)
            for match in matches[:100]:
                if len(match) < 20:
                    continue

                entropy = calculate_entropy(match)

                # High entropy + mixed case + digits = likely secret
                has_upper = any(c.isupper() for c in match)
                has_lower = any(c.islower() for c in match)
                has_digit = any(c.isdigit() for c in match)

                if entropy >= self.min_entropy and has_upper and has_lower and has_digit:
                    # Skip if looks like hash (hex only)
                    if re.match(r"^[a-fA-F0-9]+$", match):
                        continue
                    # Skip if looks like URL or path
                    if "/" in match or "." in match and len(match) < 30:
                        continue

                    findings.append({
                        "type": "Secret: High Entropy String",
                        "severity": "MEDIUM",
                        "description": f"High entropy string ({entropy}) - possible secret",
                        "secret_type": "High Entropy",
                        "match": match[:100],
                        "entropy": entropy,
                        "source": source,
                        "recommendation": "Verify if this is a secret, if yes rotate and use env var",
                    })
        except re.error:
            pass

        return findings[:20]
