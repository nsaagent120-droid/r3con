"""
r3con - Crypto Checker v2
"""
import re
from typing import List, Dict

CRYPTO_PATTERNS = [
    (r'(?i)\bMD5(_Init|_CTX|_Update|_Final|_hex|hash)\b',
     "HIGH","CWE-328",7.5,"Broken Hash (MD5)","MD5 broken — use SHA-256 or SHA-3"),
    (r'(?i)\bSHA1(_Init|_CTX|_Update|_Final)\b',
     "MED","CWE-328",5.5,"Broken Hash (SHA-1)","SHA-1 deprecated — use SHA-256"),
    (r'(?i)\bDES(_ecb|_cbc|_cfb|_encrypt|_decrypt|_key_schedule|_set_key)\b',
     "CRITICAL","CWE-327",9.0,"Broken Cipher (DES)","DES 56-bit — brute-forceable. Use AES-256-GCM"),
    (r'(?i)\bRC4(_KEY|_set_key|_encrypt|_decrypt)\b',
     "HIGH","CWE-327",7.5,"Broken Cipher (RC4)","RC4 biased — use ChaCha20-Poly1305 or AES-GCM"),
    (r'(?i)\b(AES|DES)_?(ECB|ecb)_(encrypt|decrypt|new)\b',
     "HIGH","CWE-327",7.4,"Insecure Mode (ECB)","ECB reveals patterns — use AES-GCM"),
    (r'\bmemcmp\s*\([^,]*?(hmac|mac|hash|token|sign|key|secret|pass)',
     "HIGH","CWE-208",5.9,"Timing Side-Channel (memcmp)","Use CRYPTO_memcmp() for constant-time comparison"),
    (r'\b(strcmp|strncmp)\s*\([^,]*?(password|passwd|token|secret|key|pin)',
     "HIGH","CWE-208",5.9,"Timing Side-Channel (strcmp)","Use constant-time comparison"),
    (r'\brand\s*\(\s*\)',
     "HIGH","CWE-338",7.4,"Weak PRNG (rand)","rand() not crypto-safe — use getrandom()"),
    (r'\bsrand\s*\(\s*time\s*\(',
     "HIGH","CWE-337",7.5,"Predictable PRNG Seed","srand(time()) is predictable — use crypto entropy"),
    (r'(?i)(key|secret|password|passwd|iv|nonce)\s*\[\s*\]\s*=\s*"[^"]{4,}"',
     "CRITICAL","CWE-321",9.1,"Hardcoded Cryptographic Material","Load keys from KMS or env vars"),
    (r'(?i)(SSLv2|SSLv3|TLSv1_0|TLSv1_1|SSLv2_method|SSLv3_method|TLSv1_method)\b',
     "HIGH","CWE-327",7.4,"Deprecated TLS/SSL Version","Use TLS 1.2+: TLS_method()"),
    (r'\bRSA_generate_key\s*\(\s*(512|1024)\s*,',
     "HIGH","CWE-326",7.5,"Weak RSA Key Size","Use RSA-2048+ or ECDSA-P256"),
    (r'\bEVP_EncryptInit[_ex]*\s*\([^,]*,\s*EVP_aes_\d+_cbc',
     "MEDIUM","CWE-311",6.5,"Unauthenticated CBC Encryption","Use AES-GCM or add HMAC-SHA256"),
    (r'(?i)EVP_DecryptInit.*cbc|AES.*cbc.*decrypt',
     "HIGH","CWE-696",7.4,"Potential Padding Oracle","Use authenticated encryption (AES-GCM)"),
    (r'(?i)(EVP|AES).*key.*password|password.*(EVP|AES).*key',
     "HIGH","CWE-916",7.5,"Missing Key Derivation Function","Use PBKDF2/bcrypt/scrypt/Argon2"),
]

class CryptoChecker:
    def analyze(self, code: str) -> List[Dict]:
        findings = []
        lines    = code.splitlines()
        for pattern, severity, cwe, cvss, vuln_type, rec in CRYPTO_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "severity": severity, "type": vuln_type,
                        "cwe": cwe, "cvss": cvss, "line": i,
                        "description": vuln_type, "recommendation": rec,
                        "code_snippet": line.strip()[:100],
                    })
        findings += self._check_iv_nonce(lines)
        findings += self._check_nonce_reuse(lines)
        return self._deduplicate(findings)

    def _check_iv_nonce(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            if (re.search(r'(?i)(iv|nonce)\s*\[', line) and
                    re.search(r'=\s*\{?\s*0\b', line)):
                findings.append({
                    "severity":"HIGH","type":"Zero IV/Nonce","cwe":"CWE-329","cvss":7.5,
                    "line":i,"description":"IV/nonce initialized to zero",
                    "recommendation":"Use RAND_bytes(iv, sizeof(iv)).",
                })
            if re.search(r'memset\s*\([^,]*?(iv|nonce)[^,]*,\s*0', line, re.I):
                findings.append({
                    "severity":"HIGH","type":"Zero IV/Nonce","cwe":"CWE-329","cvss":7.5,
                    "line":i,"description":"IV zeroed with memset",
                    "recommendation":"Generate random IV: RAND_bytes(iv, IV_SIZE);",
                })
            if re.search(r'(?i)static\s+\w+\s+(nonce|iv)\s*=', line):
                findings.append({
                    "severity":"CRITICAL","type":"Static/Hardcoded Nonce","cwe":"CWE-329","cvss":9.1,
                    "line":i,"description":"Static nonce — reuse breaks GCM auth",
                    "recommendation":"Use a counter or random nonce per message.",
                })
        return findings

    def _check_nonce_reuse(self, lines):
        findings = []; seen = {}
        for i, line in enumerate(lines, 1):
            m = re.search(
                r'(?i)(iv|nonce)\s*(?:\[\s*\])?\s*=\s*["\']([a-zA-Z0-9+/=\-_]{4,})["\']', line)
            if m:
                val = m.group(2)
                if val in seen:
                    findings.append({
                        "severity":"CRITICAL","type":"Nonce/IV Reuse","cwe":"CWE-329","cvss":9.1,
                        "line":seen[val],
                        "description":f"Same IV/nonce reused at L{seen[val]} and L{i}",
                        "recommendation":"Generate unique random IV per encryption.",
                    })
                else:
                    seen[val] = i
        return findings

    def _deduplicate(self, findings):
        seen = set(); result = []
        for f in findings:
            key = (f.get("type"), f.get("line"))
            if key not in seen:
                seen.add(key); result.append(f)
        sev_o = {"CRITICAL":0,"HIGH":1,"MED":2,"MEDIUM":2,"LOW":3}
        return sorted(result, key=lambda x: sev_o.get(x.get("severity","LOW"),3))
