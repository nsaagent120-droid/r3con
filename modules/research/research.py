"""
r3con - Research Modules - FIXED P3
Fixes: input validation, rate limiting, regex safety, size limits
"""

import re
import time
import urllib.request
import urllib.error
import json
from typing import Dict, List, Optional
from pathlib import Path

MAX_CODE_SIZE = 1 * 1024 * 1024
MAX_PATTERN_DB = 20
MAX_MATCHES = 50
RATE_LIMIT_SECONDS = 1
_last_nvd_call = 0


def _validate_code(code: str) -> bool:
    """Validate code input."""
    if not code or not isinstance(code, str):
        return False
    if len(code) > MAX_CODE_SIZE or "\x00" in code:
        return False
    return True


def _validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format."""
    if not cve_id or not isinstance(cve_id, str):
        return False
    if len(cve_id) > 20:
        return False
    # CVE-YYYY-NNNNN
    if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
        return False
    return True


def _safe_search(pattern: str, text: str) -> bool:
    """Safe regex search."""
    if not pattern or not text or len(pattern) > 500 or len(text) > 10000:
        return False
    try:
        return bool(re.search(pattern, text, re.DOTALL))
    except re.error:
        return False


# ── Hypothesis Engine ─────────────────────────────────────────

class HypothesisEngine:
    """Build attack surface - FIXED P3 validation, limits."""

    def build_attack_surface(self, code: str) -> Dict:
        if not _validate_code(code):
            return {"entry_points": [], "dangerous_sinks": [], "error": "invalid_code"}

        lines = code.splitlines()
        if len(lines) > 10000:
            lines = lines[:10000]

        surface = {
            "entry_points": [],
            "dangerous_sinks": [],
        }
        ENTRIES = [
            (r'\bread\s*\(|recv\s*\(|recvfrom\s*\(', "Network input"),
            (r'\bfread\s*\(|fgets\s*\(|getline\s*\(', "File input"),
            (r'\bgetenv\s*\(', "Environment variable"),
            (r'\bargv\s*\[', "Command-line argument"),
            (r'\bscanf\s*\(|gets\s*\(', "stdin"),
            (r'copy_from_user\s*\(', "Userspace (kernel)"),
        ]
        SINKS = [
            (r'\bmemcpy\s*\(|memmove\s*\(', "Memory operation"),
            (r'\bstrcpy\s*\(|strcat\s*\(', "String operation"),
            (r'\bsystem\s*\(|exec\w*\s*\(', "Code execution"),
            (r'\bmalloc\s*\(|kmalloc\s*\(', "Heap allocation"),
            (r'commit_creds\s*\(', "Privilege change"),
            (r'\bfree\s*\(|kfree\s*\(', "Memory free"),
        ]

        for i, line in enumerate(lines, 1):
            if len(line) > 1000:
                line = line[:1000]
            if len(surface["entry_points"]) >= MAX_MATCHES and len(surface["dangerous_sinks"]) >= MAX_MATCHES:
                break

            for pat, label in ENTRIES:
                if len(surface["entry_points"]) >= MAX_MATCHES:
                    break
                if _safe_search(pat, line):
                    surface["entry_points"].append(
                        {"line": i, "type": label, "code": line.strip()[:80]})

            for pat, label in SINKS:
                if len(surface["dangerous_sinks"]) >= MAX_MATCHES:
                    break
                if _safe_search(pat, line):
                    surface["dangerous_sinks"].append(
                        {"line": i, "type": label, "code": line.strip()[:80]})

        return surface


# ── CVE Matcher ───────────────────────────────────────────────

PATTERN_DB = [
    {"pattern": r'\bgets\s*\(',
     "finding_class": "Stack Buffer Overflow via gets()",
     "reference_cves": ["CVE-2021-3156","CVE-2017-1000253"],
     "cwe": "CWE-121",
     "description": "Unbounded gets() — stack smashing vector"},
    {"pattern": r'free\s*\([^)]+\).*free\s*\(',
     "finding_class": "Use-After-Free / Double-Free",
     "reference_cves": ["CVE-2016-5195 (Dirty COW)","CVE-2022-0847 (Dirty Pipe)"],
     "cwe": "CWE-416",
     "description": "Consecutive free() — heap corruption primitive"},
    {"pattern": r'kmalloc\s*\(\s*\w+\s*\*\s*\w+',
     "finding_class": "Integer Overflow before kmalloc",
     "reference_cves": ["CVE-2019-11884","CVE-2021-3490"],
     "cwe": "CWE-190",
     "description": "Unchecked multiplication before kernel allocation"},
    {"pattern": r'memcmp.*(?:key|hmac|hash|token|secret)',
     "finding_class": "Timing Side-Channel",
     "reference_cves": ["CVE-2013-0169 (Lucky Thirteen)","CVE-2018-0737"],
     "cwe": "CWE-208",
     "description": "Non-constant-time comparison of secret material"},
    {"pattern": r'(?i)(MD5|RC4|\bDES\b)',
     "finding_class": "Weak Cryptographic Algorithm",
     "reference_cves": ["CVE-2004-2761","CVE-2015-2808 (RC4 NOMORE)"],
     "cwe": "CWE-327",
     "description": "Broken cryptographic primitive"},
    {"pattern": r'sprintf\s*\([^,]+,[^\"]*\w+[^\"]*\)',
     "finding_class": "Format String Vulnerability",
     "reference_cves": ["CVE-2012-3569","CVE-2006-0900"],
     "cwe": "CWE-134",
     "description": "User-controlled format string"},
    {"pattern": r'access\s*\([^)]+\)',
     "finding_class": "TOCTOU Race Condition",
     "reference_cves": ["CVE-2017-1000253","CVE-2019-14899"],
     "cwe": "CWE-367",
     "description": "Check-then-use race — symlink attack"},
    {"pattern": r'srand\s*\(\s*time|rand\s*\(\s*\)',
     "finding_class": "Weak PRNG",
     "reference_cves": ["CVE-2008-0166 (Debian OpenSSL)","CVE-2012-2459"],
     "cwe": "CWE-338",
     "description": "Predictable random number generation"},
    {"pattern": r'(?i)(password|key|secret)[^=\n]{0,20}=\s*\"[^\"]{4,}\"',
     "finding_class": "Hardcoded Credentials",
     "reference_cves": ["CVE-2022-29582","CVE-2021-21985"],
     "cwe": "CWE-798",
     "description": "Hardcoded secret in source"},
    {"pattern": r'strcpy\s*\(|strcat\s*\(',
     "finding_class": "Buffer Overflow (strcpy/strcat)",
     "reference_cves": [],
     "cwe": "CWE-120",
     "description": "Unbounded string copy"},
]


class CVEMatcher:
    """CVE matcher - FIXED P3 validation, rate limiting, safe regex."""

    def extract_patterns(self, code: str) -> List[Dict]:
        if not _validate_code(code):
            return []

        matches = []
        lines = code.splitlines()
        if len(lines) > 10000:
            lines = lines[:10000]

        for entry in PATTERN_DB[:MAX_PATTERN_DB]:
            if len(matches) >= MAX_MATCHES:
                break
            pattern = entry["pattern"]
            if len(pattern) > 500:
                continue

            for i, line in enumerate(lines, 1):
                if len(line) > 1000:
                    line = line[:1000]
                if _safe_search(pattern, line):
                    matches.append({
                        "line": i,
                        "finding_class": entry["finding_class"][:200],
                        "cwe": entry["cwe"][:20],
                        "reference_cves": entry["reference_cves"][:5],
                        "description": entry["description"][:300],
                        "code_snippet": line.strip()[:100],
                        "evidence_type": "heuristic-pattern",
                        "confidence": 0.35,
                        "disclaimer": "Pattern resemblance only; not proof of a specific CVE."
                    })
                    break

        return matches

    def fetch_cve_nvd(self, cve_id: str) -> Dict:
        """Fetch CVE from NVD - FIXED validation, rate limiting."""
        if not _validate_cve_id(cve_id):
            return {"id": str(cve_id)[:20], "description": "Invalid CVE ID format", "cvss": 0.0, "pattern": "", "status": "error", "error": "invalid_cve_format"}

        from core.offline import is_offline
        if is_offline():
            return {"id": cve_id, "status": "unavailable", "reason": "offline_mode",
                    "description": "NVD inaccessible en mode hors ligne", "cvss": 0.0, "pattern": ""}

        global _last_nvd_call
        # Rate limiting
        now = time.time()
        elapsed = now - _last_nvd_call
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
        _last_nvd_call = time.time()

        error = ""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "r3con/5.0.1"})
            with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 - endpoint NVD HTTPS contrôlé
                data = json.loads(resp.read().decode())
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0]["cve"]
                    desc = cve.get("descriptions", [{}])[0].get("value", "")[:500]
                    cvss = 0.0
                    m = cve.get("metrics", {})
                    if "cvssMetricV31" in m:
                        try:
                            cvss = float(m["cvssMetricV31"][0]["cvssData"]["baseScore"])
                        except (KeyError, ValueError, IndexError, TypeError):
                            pass
                    elif "cvssMetricV2" in m:
                        try:
                            cvss = float(m["cvssMetricV2"][0]["cvssData"]["baseScore"])
                        except (KeyError, ValueError, IndexError, TypeError):
                            pass
                    return {"id": cve_id, "description": desc, "cvss": cvss, "pattern": self._infer_pattern(desc)}
        except (OSError, ValueError, KeyError, urllib.error.URLError, json.JSONDecodeError) as exc:
            error = str(exc)[:200]

        return {"id": cve_id, "description": "NVD lookup failed (offline or rate-limited)", "cvss": 0.0, "pattern": "", "status": "error", "error": error or "unknown lookup error"}

    def _infer_pattern(self, desc: str) -> str:
        if not desc or len(desc) > 1000:
            return ""
        d = desc.lower()
        if "buffer overflow" in d:
            return r'strcpy|gets|sprintf|memcpy'
        if "use.after.free" in d:
            return r'free\s*\('
        if "integer overflow" in d:
            return r'malloc\s*\(\s*\w+\s*\*'
        if "format string" in d:
            return r'printf\s*\(\s*\w+'
        if "race condition" in d:
            return r'access\s*\(|stat\s*\('
        return ""


class VariantFinder:
    """Variant finder - FIXED validation."""

    def __init__(self):
        self.matcher = CVEMatcher()

    def fetch_cve(self, cve_id: str) -> Dict:
        return self.matcher.fetch_cve_nvd(cve_id)

    def find_in_code(self, code: str, cve_info: Dict) -> Optional[str]:
        if not _validate_code(code):
            return None
        if not isinstance(cve_info, dict):
            return None

        pattern = cve_info.get("pattern", "")
        if not pattern or len(pattern) > 500:
            return None

        try:
            lines = code.splitlines()
            if len(lines) > 10000:
                lines = lines[:10000]

            for i, line in enumerate(lines, 1):
                if len(line) > 1000:
                    line = line[:1000]
                if _safe_search(pattern, line):
                    return (
                        f"Match at line {i}: `{line.strip()[:80]}`\n"
                        f"Resembles: {cve_info.get('id','')[:20]} — "
                        f"{cve_info.get('description','')[:120]}"
                    )
        except re.error:
            pass
        return None
