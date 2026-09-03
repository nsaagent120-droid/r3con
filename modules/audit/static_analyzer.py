"""
r3con - Static Analyzer
Pattern-based static analysis for C/C++, Python, Java, Go, Rust.
"""

import re
from typing import List, Dict

from modules.ast_engine.c_frontend import parse_functions, AST_AVAILABLE


class StaticAnalyzer:
    def __init__(self, lang: str = "auto"):
        self.lang = lang
        self._real_calls: Dict[int, set] = {}   # line -> {func_names réellement appelés}, rempli par analyze()

    def _pattern_func_name(self, pat: str):
        m = re.match(r'\\b([A-Za-z_]\w*)', pat)
        return m.group(1) if m else None

    def _ast_confirms(self, line: int, func_name: str) -> bool:
        """
        True si l'appel est confirmé par l'AST (donc pas un match dans un
        commentaire/chaîne/code désactivé), ou si on ne peut pas trancher
        (AST indisponible, nom non extrait du pattern, langage != C) — dans
        ce dernier cas on garde l'ancien comportement (pas de nouveau faux
        négatif introduit par ce filtre).
        """
        if not AST_AVAILABLE or not self._real_calls or func_name is None:
            return True
        return func_name in self._real_calls.get(line, set())

    def analyze(self, code: str, focus: str = "all") -> List[Dict]:
        findings = []
        lines    = code.splitlines()

        if self.lang in ("auto","c","cpp") and AST_AVAILABLE:
            self._real_calls = {}
            for fdef in parse_functions(code).values():
                for c in fdef.calls:
                    self._real_calls.setdefault(c.line, set()).add(c.function_name)

        if self.lang in ("auto","c","cpp"):
            findings += self._check_memory(lines)
            findings += self._check_format_strings(lines)
            findings += self._check_dangerous_funcs(lines)
            findings += self._check_integer(lines)

        findings += self._check_crypto(lines)
        findings += self._check_toctou(lines)

        if self.lang in ("auto","python"):
            findings += self._check_python(lines)

        if self.lang in ("auto","go","golang"):
            findings += self._check_go(lines)

        if self.lang in ("auto","java"):
            findings += self._check_java(lines)

        if self.lang in ("auto","rust"):
            findings += self._check_rust(lines)

        if focus != "all":
            fmap = {
                "memory":  ["Buffer Overflow","Use-After-Free","Double Free","Integer Overflow","Heap"],
                "crypto":  ["Crypto","PRNG","Hardcoded","Timing","IV","Nonce","Padding"],
                "race":    ["Race","TOCTOU"],
                "kernel":  ["Kernel","Privilege","IOCTL","kmalloc"],
                "proto":   ["Protocol","Deserialization","Parser","State"],
            }
            allowed = fmap.get(focus, [])
            findings = [f for f in findings
                        if any(a in f.get("type","") for a in allowed)]

        return self._enrich_findings(findings, lines)

    def _enrich_findings(self, findings, lines):
        """Attach local source context and a computed confidence.

        La confiance n'est plus un simple lookup statique indexé par
        sévérité (ce que c'était avant) : elle part toujours de ce prior
        par sévérité, puis est ajustée par deux signaux factuels :
        - AST-vérifié : le finding provient d'un vrai site d'appel confirmé
          par tree-sitter (pas un match dans un commentaire/chaîne) — bonus.
        - Corroboration : plusieurs findings indépendants pointent sur la
          même ligne — bonus borné, reflétant un accord entre vérifications.
        Sans tree-sitter-c installé, le comportement (et la valeur) est
        identique à l'ancienne version — aucune régression silencieuse.
        """
        from collections import Counter
        line_counts = Counter(
            f.get("line") for f in findings if isinstance(f.get("line"), int)
        )

        enriched = []
        for finding in findings:
            item = dict(finding)
            line_no = item.get("line")
            if isinstance(line_no, int) and 1 <= line_no <= len(lines):
                start = max(1, line_no - 2)
                end = min(len(lines), line_no + 2)
                item["evidence"] = {"file_line": line_no, "code": lines[line_no - 1], "context": [{"line": n, "code": lines[n - 1]} for n in range(start, end + 1)]}
            else:
                item["evidence"] = {"file_line": None, "code": None, "context": []}

            severity = str(item.get("severity", "INFO")).upper()
            confidence = {"CRITICAL": 0.90, "HIGH": 0.82, "MED": 0.70, "MEDIUM": 0.70, "LOW": 0.55, "INFO": 0.45}.get(severity, 0.50)

            ast_verified = bool(AST_AVAILABLE and self._real_calls)
            if ast_verified:
                confidence = min(confidence + 0.08, 0.98)

            corroboration = line_counts.get(line_no, 1) if isinstance(line_no, int) else 1
            if corroboration > 1:
                confidence = min(confidence + 0.04 * (corroboration - 1), 0.99)

            item["confidence"] = round(confidence, 2)
            item["ast_verified"] = ast_verified
            item["corroborating_findings_same_line"] = corroboration
            item["analysis_kind"] = "ast_verified_static" if ast_verified else "heuristic_static"
            enriched.append(item)
        return enriched

    # ── C/C++ Memory ──────────────────────────────────────────

    def _check_memory(self, lines):
        findings = []
        PATTERNS = [
            (r'\bgets\s*\(',       "CRITICAL","Stack Buffer Overflow",
             "gets() has no bounds check — use fgets(buf, sizeof(buf), stdin)"),
            (r'\bstrcpy\s*\(',     "HIGH",    "Buffer Overflow",
             "strcpy() has no bounds check — use strncpy() or strlcpy()"),
            (r'\bstrcat\s*\(',     "HIGH",    "Buffer Overflow",
             "strcat() has no bounds check — use strncat()"),
            (r'\bsprintf\s*\(',    "MED",     "Buffer Overflow",
             "sprintf() — use snprintf() with explicit size"),
            (r'\bscanf\s*\(\s*"[^"]*%s',"HIGH","Buffer Overflow",
             "scanf %s without width — stack overflow risk"),
            (r'\bwcscpy\s*\(',     "HIGH",    "Buffer Overflow",
             "wcscpy() — wide-char strcpy, same vulnerability"),
            (r'alloca\s*\(',       "MED",     "Stack Overflow Risk",
             "alloca() with variable size can overflow the stack"),
            (r'\btmpnam\s*\(',     "MED",     "TOCTOU",
             "tmpnam() is racy — use mkstemp()"),
            (r'\batoi\s*\(',       "LOW",     "Integer Parsing",
             "atoi() has no error detection — use strtol()"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line) and self._ast_confirms(i, self._pattern_func_name(pat)):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                        if "—" in desc else "Review this call"
                    })

        # UAF / double-free detection
        findings += self._check_uaf(lines)
        findings += self._check_double_free(lines)
        return findings

    def _check_uaf(self, lines):
        findings = []
        freed = {}
        for i, line in enumerate(lines, 1):
            m = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if m:
                freed[m.group(1)] = i
        for i, line in enumerate(lines, 1):
            for var, free_line in freed.items():
                if i > free_line:
                    if re.search(rf'\b{re.escape(var)}\s*(?:->|\[|\()', line):
                        if not re.search(
                                rf'{re.escape(var)}\s*=\s*(?:malloc|calloc|realloc|NULL)',
                                line):
                            findings.append({
                                "severity": "HIGH", "type": "Use-After-Free",
                                "line": i,
                                "description": f"'{var}' used at L{i} after free() at L{free_line}",
                                "recommendation": "Set pointer to NULL after free(). Use RAII in C++."
                            })
        return findings

    def _check_double_free(self, lines):
        findings = []
        freed = {}
        for i, line in enumerate(lines, 1):
            m = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if m:
                var = m.group(1)
                freed.setdefault(var, []).append(i)
        for var, lns in freed.items():
            if len(lns) >= 2:
                findings.append({
                    "severity": "CRITICAL", "type": "Double Free",
                    "line": lns[0],
                    "description": f"'{var}' freed at lines {lns} — heap corruption primitive",
                    "recommendation": "Set pointer to NULL after free(). Check all error paths."
                })
        return findings

    def _check_format_strings(self, lines):
        findings = []
        FMT_FUNCS = r'\b(printf|fprintf|syslog|err|warn)\s*\('
        for i, line in enumerate(lines, 1):
            if re.search(FMT_FUNCS, line):
                m = re.search(FMT_FUNCS, line)
                if m:
                    rest = line[m.end():].strip()
                    if rest and not rest.startswith('"'):
                        findings.append({
                            "severity": "HIGH", "type": "Format String",
                            "line": i,
                            "description": "User-controlled format arg — stack read/write primitive",
                            "recommendation": 'Use printf("%s", var) instead of printf(var)'
                        })
        return findings

    def _check_dangerous_funcs(self, lines):
        findings = []
        DANGEROUS = [
            (r'\bsystem\s*\(',   "HIGH", "Command Injection",
             "system() — user input may reach shell"),
            (r'\bpopen\s*\(',    "HIGH", "Command Injection",
             "popen() — user input may reach shell"),
            (r'\bexecve?\s*\(',  "MED",  "Code Execution",
             "exec() family — verify all arguments are sanitized"),
            (r'\bgetenv\s*\(',   "LOW",  "Environment Injection",
             "getenv() — sanitize before security-sensitive use"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in DANGEROUS:
                if re.search(pat, line) and self._ast_confirms(i, self._pattern_func_name(pat)):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })
        return findings

    def _check_integer(self, lines):
        findings = []
        PATTERNS = [
            (r'malloc\s*\(\s*\w+\s*\*\s*\w+', "HIGH", "Integer Overflow in malloc",
             "Unchecked multiplication before malloc — undersized allocation"),
            (r'kmalloc\s*\(\s*\w+\s*\*\s*\w+', "CRITICAL", "Integer Overflow in kmalloc",
             "Unchecked multiplication before kmalloc — use kmalloc_array()"),
            (r'int\s+\w+\s*=.*strlen', "LOW", "Integer Truncation",
             "strlen returns size_t, assigning to int may truncate on 64-bit"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": "Use checked arithmetic or size_t consistently"
                    })
        return findings

    # ── Crypto ────────────────────────────────────────────────

    def _check_crypto(self, lines):
        findings = []
        PATTERNS = [
            (r'(?i)MD5|md5_init|MD5_Init',     "HIGH",     "Broken Hash (MD5)",
             "MD5 is cryptographically broken — use SHA-256"),
            (r'(?i)SHA1|SHA1_Init|sha1_digest', "MED",      "Weak Hash (SHA-1)",
             "SHA-1 deprecated — use SHA-256 minimum"),
            (r'(?i)DES_ecb|des_crypt|\bDES\b',  "CRITICAL", "Broken Cipher (DES)",
             "DES 56-bit key, broken — use AES-256-GCM"),
            (r'(?i)RC4|ARC4|rc4_crypt',          "CRITICAL", "Broken Cipher (RC4)",
             "RC4 has known biases — use ChaCha20-Poly1305"),
            (r'(?i)AES.*ECB|ECB.*AES',           "HIGH",     "Weak Mode (ECB)",
             "ECB leaks patterns — use AES-GCM"),
            (r'memcmp.*(?:hmac|hash|token|key|secret)', "HIGH", "Timing Side-Channel",
             "Non-constant-time comparison — use CRYPTO_memcmp()"),
            (r'\brand\s*\(\s*\)',                 "HIGH",     "Weak PRNG",
             "rand() is predictable — use /dev/urandom"),
            (r'\bsrand\s*\(\s*time',              "CRITICAL", "Predictable PRNG Seed",
             "srand(time()) — predictable, brute-forceable"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })

        # Hardcoded key material
        for i, line in enumerate(lines, 1):
            m = re.search(
                r'(?i)(key|iv|nonce|secret|password|salt)[^=\n]{0,20}=\s*"([^"]{4,})"',
                line)
            if m:
                findings.append({
                    "severity": "CRITICAL", "type": "Hardcoded Cryptographic Material",
                    "line": i,
                    "description": f"Hardcoded {m.group(1)}: '{m.group(2)[:20]}...'",
                    "recommendation": "Use environment variables or a key management system"
                })
        return findings

    # ── TOCTOU ────────────────────────────────────────────────

    def _check_toctou(self, lines):
        findings = []
        CHECK_PAT = [r'\baccess\s*\(', r'\bstat\s*\(', r'\blstat\s*\(']
        USE_PAT   = [r'\bopen\s*\(', r'\bfopen\s*\(', r'\bunlink\s*\(', r'\bexecve?\s*\(']
        checks, uses = [], []
        for i, line in enumerate(lines, 1):
            if any(re.search(p, line) for p in CHECK_PAT): checks.append(i)
            if any(re.search(p, line) for p in USE_PAT):   uses.append(i)
        for c in checks:
            for u in uses:
                if 0 < u - c <= 15:
                    findings.append({
                        "severity": "HIGH", "type": "TOCTOU Race Condition",
                        "line": c,
                        "description": f"Check at L{c}, use at L{u} — exploitable via symlink attack",
                        "recommendation": "Use O_NOFOLLOW, or open() first then fstat() on the fd"
                    })
                    break
        return findings

    # ── Python-specific ───────────────────────────────────────

    def _check_python(self, lines):
        findings = []
        PATTERNS = [
            (r'\beval\s*\(',         "CRITICAL", "Code Injection (eval)",
             "eval() on user input — arbitrary code execution"),
            (r'\bexec\s*\(',         "CRITICAL", "Code Injection (exec)",
             "exec() on user input — arbitrary code execution"),
            (r'pickle\.loads?\s*\(', "HIGH",     "Insecure Deserialization",
             "pickle.load() on untrusted data — arbitrary code execution"),
            (r'subprocess.*shell\s*=\s*True', "HIGH", "Command Injection",
             "shell=True with user input — command injection"),
            (r'os\.system\s*\(',     "HIGH",     "Command Injection",
             "os.system() — use subprocess with list args"),
            (r'yaml\.load\s*\(',     "HIGH",     "Insecure Deserialization",
             "yaml.load() — use yaml.safe_load()"),
            (r'hashlib\.md5\s*\(',   "MED",      "Weak Hash",
             "MD5 — use hashlib.sha256()"),
            (r'random\.',            "MED",      "Weak PRNG",
             "random module not crypto-safe — use secrets module"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })
        return findings

    def _check_go(self, lines):
        """Go-specific vulnerability patterns."""
        findings = []
        PATTERNS = [
            (r'fmt\.Sprintf.*\+\s*\w+|db\.(Query|Exec)\s*\([^,)]*\+',
             "HIGH", "SQL Injection",
             "String concatenation in SQL — use parameterized queries"),
            (r'exec\.Command\s*\([^)]*\+',
             "CRITICAL", "Command Injection",
             "exec.Command with string concat — validate/escape all args"),
            (r'os\.Setenv\s*\([^)]*\+',
             "MEDIUM", "Environment Variable Injection",
             "Validate env var value before setting"),
            (r'ioutil\.ReadAll\s*\(|io\.ReadAll\s*\(',
             "LOW", "Unbounded Read",
             "ReadAll has no size limit — use io.LimitReader"),
            (r'math/rand',
             "HIGH", "Weak PRNG",
             "math/rand is not crypto-safe — use crypto/rand"),
            (r'md5\.(New|Sum)',
             "HIGH", "Weak Hash (MD5)",
             "MD5 broken — use crypto/sha256"),
            (r'sha1\.(New|Sum)',
             "MED", "Weak Hash (SHA-1)",
             "SHA-1 deprecated — use crypto/sha256"),
            (r'http\.ListenAndServe\s*\(\s*"[^"]*80',
             "LOW", "Unencrypted HTTP Server",
             "Use ListenAndServeTLS for HTTPS"),
            (r'tls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true',
             "CRITICAL", "TLS Verification Disabled",
             "Never set InsecureSkipVerify: true in production"),
            (r'panic\s*\(',
             "LOW", "Panic in Production",
             "Unrecovered panic crashes the server — use recover()"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })
        return findings

    def _check_java(self, lines):
        """Java-specific vulnerability patterns."""
        findings = []
        PATTERNS = [
            (r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder',
             "CRITICAL", "Command Injection",
             "exec() with user input — validate all arguments"),
            (r'Statement\.execute|createStatement\(\)',
             "HIGH", "SQL Injection (Statement)",
             "Use PreparedStatement instead of Statement"),
            (r'ObjectInputStream|readObject\s*\(',
             "CRITICAL", "Insecure Deserialization",
             "Java deserialization RCE — use Jackson/Gson with safe types"),
            (r'MessageDigest\.getInstance\s*\(\s*"MD5"',
             "HIGH", "Weak Hash (MD5)",
             "MD5 broken — use SHA-256"),
            (r'MessageDigest\.getInstance\s*\(\s*"SHA-1"',
             "MED", "Weak Hash (SHA-1)",
             "SHA-1 deprecated — use SHA-256"),
            (r'new\s+Random\s*\(',
             "HIGH", "Weak PRNG",
             "java.util.Random not crypto-safe — use SecureRandom"),
            (r'SSLContext\.getInstance\s*\(\s*"SSL"',
             "HIGH", "Deprecated SSL Version",
             "Use TLSv1.2 or TLSv1.3"),
            (r'setHostnameVerifier.*ALLOW_ALL|AllowAllHostnameVerifier',
             "CRITICAL", "Hostname Verification Disabled",
             "Never disable hostname verification"),
            (r'printStackTrace\s*\(',
             "LOW", "Stack Trace Exposure",
             "Avoid exposing stack traces to users"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })
        return findings

    def _check_rust(self, lines):
        """Rust-specific vulnerability patterns."""
        findings = []
        PATTERNS = [
            (r'\bunsafe\s*\{',
             "HIGH", "Unsafe Block",
             "unsafe block bypasses Rust safety — audit carefully"),
            (r'std::ptr::(read|write|copy)',
             "HIGH", "Raw Pointer Operation",
             "Raw pointer ops in unsafe — validate bounds"),
            (r'unwrap\s*\(\s*\)',
             "MEDIUM", "Panic on Error (unwrap)",
             "unwrap() panics on None/Err — use expect() or match"),
            (r'\.parse::<\w+>\s*\(\s*\)\.unwrap',
             "MEDIUM", "Panic on Parse Failure",
             "Parse + unwrap panics on bad input — handle error"),
            (r'mem::transmute',
             "CRITICAL", "Type Transmutation",
             "transmute is unsafe type punning — may cause UB"),
            (r'from_utf8_unchecked',
             "HIGH", "Unchecked UTF-8",
             "from_utf8_unchecked — may cause UB on invalid UTF-8"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })
        return findings
