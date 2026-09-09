"""
r3con - Static Analyzer - FIXED VERSION
Fixes: buffer size tracking, better TOCTOU, command injection, null deref, improved patterns
"""

import re
from typing import List, Dict

from modules.ast_engine.c_frontend import parse_functions, AST_AVAILABLE


class StaticAnalyzer:
    def __init__(self, lang: str = "auto"):
        self.lang = lang
        self._real_calls: Dict[int, set] = {}

    def _pattern_func_name(self, pat: str):
        m = re.match(r'\\b([A-Za-z_]\w*)', pat)
        return m.group(1) if m else None

    def _ast_confirms(self, line: int, func_name: str) -> bool:
        if not AST_AVAILABLE or not self._real_calls or func_name is None:
            return True
        return func_name in self._real_calls.get(line, set())

    def analyze(self, code: str, focus: str = "all") -> List[Dict]:
        findings = []
        lines = code.splitlines()

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
            findings += self._check_buffer_size(lines)
            findings += self._check_command_injection_advanced(lines)
            findings += self._check_null_deref(lines)
            findings += self._check_file_operations(lines)

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

        if self.lang in ("auto","js","javascript","ts","typescript"):
            findings += self._check_javascript(lines)

        if self.lang in ("auto","php"):
            findings += self._check_php(lines)

        if focus != "all":
            fmap = {
                "memory":  ["Buffer Overflow","Use-After-Free","Double Free","Integer Overflow","Heap","Null Deref","File"],
                "crypto":  ["Crypto","PRNG","Hardcoded","Timing","IV","Nonce","Padding"],
                "race":    ["Race","TOCTOU"],
                "kernel":  ["Kernel","Privilege","IOCTL","kmalloc"],
                "proto":   ["Protocol","Deserialization","Parser","State"],
                "injection": ["Injection","Command","SQL","XSS"],
            }
            allowed = fmap.get(focus, [])
            findings = [f for f in findings if any(a in f.get("type","") for a in allowed)]

        return self._enrich_findings(findings, lines)

    def _enrich_findings(self, findings, lines):
        from collections import Counter
        line_counts = Counter(f.get("line") for f in findings if isinstance(f.get("line"), int))
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

    def _check_memory(self, lines):
        findings = []
        PATTERNS = [
            (r'\bgets\s*\(',       "CRITICAL","Stack Buffer Overflow", "gets() has no bounds check — use fgets(buf, sizeof(buf), stdin)"),
            (r'\bstrcpy\s*\(',     "HIGH",    "Buffer Overflow", "strcpy() has no bounds check — use strncpy() or strlcpy()"),
            (r'\bstrcat\s*\(',     "HIGH",    "Buffer Overflow", "strcat() has no bounds check — use strncat()"),
            (r'\bsprintf\s*\(',    "MED",     "Buffer Overflow", "sprintf() — use snprintf() with explicit size"),
            (r'\bscanf\s*\(\s*"[^"]*%s',"HIGH","Buffer Overflow", "scanf %s without width — stack overflow risk"),
            (r'\bwcscpy\s*\(',     "HIGH",    "Buffer Overflow", "wcscpy() — wide-char strcpy, same vulnerability"),
            (r'alloca\s*\(',       "MED",     "Stack Overflow Risk", "alloca() with variable size can overflow the stack"),
            (r'\btmpnam\s*\(',     "MED",     "TOCTOU", "tmpnam() is racy — use mkstemp()"),
            (r'\batoi\s*\(',       "LOW",     "Integer Parsing", "atoi() has no error detection — use strtol()"),
            (r'\bstrncpy\s*\([^,]+,[^,]+,\s*sizeof', "LOW", "Potential strncpy null-termination", "strncpy may not null-terminate — ensure explicit null byte"),
            (r'\bmemcpy\s*\([^,]+,[^,]+,\s*strlen', "HIGH", "Buffer Overflow via memcpy+strlen", "memcpy with strlen without +1 may overflow if dest is strlen-sized"),
        ]
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line) and self._ast_confirms(i, self._pattern_func_name(pat)):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip() if "—" in desc else "Review this call"
                    })
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
                    if re.search(rf'\b{re.escape(var)}\s*(?:->|\[|\(|=\s*\*|=\s*\w+->)', line):
                        if not re.search(rf'{re.escape(var)}\s*=\s*(?:malloc|calloc|realloc|NULL|0)', line):
                            # Check if var is reallocated between free and use
                            reallocated = False
                            for check_line in range(free_line+1, i):
                                if re.search(rf'\b{re.escape(var)}\s*=\s*(?:malloc|calloc|realloc)', lines[check_line-1]):
                                    reallocated = True
                                    break
                            if not reallocated:
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
            # Check for NULL assignment which sanitizes
            null_m = re.search(r'(\w+)\s*=\s*NULL', line)
            if null_m and null_m.group(1) in freed:
                del freed[null_m.group(1)]
                continue
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
        FMT_FUNCS = r'\b(printf|fprintf|syslog|err|warn|sprintf|snprintf)\s*\('
        for i, line in enumerate(lines, 1):
            if re.search(FMT_FUNCS, line):
                m = re.search(FMT_FUNCS, line)
                if m:
                    rest = line[m.end():].strip()
                    # If rest doesn't start with " and contains a variable that could be user-controlled
                    if rest and not rest.startswith('"'):
                        # Check if it's a single variable (user-controlled)
                        if re.match(r'^\w+\s*\)', rest) or re.match(r'^\w+\s*,', rest):
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
            (r'\bsystem\s*\(',   "HIGH", "Command Injection", "system() — user input may reach shell"),
            (r'\bpopen\s*\(',    "HIGH", "Command Injection", "popen() — user input may reach shell"),
            (r'\bexecve?\s*\(',  "MED",  "Code Execution", "exec() family — verify all arguments are sanitized"),
            (r'\bgetenv\s*\(',   "LOW",  "Environment Injection", "getenv() — sanitize before security-sensitive use"),
            (r'\bmktemp\s*\(',   "HIGH", "Insecure Temp File", "mktemp() is racy — use mkstemp()"),
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
            (r'malloc\s*\(\s*\w+\s*\*\s*\w+', "HIGH", "Integer Overflow in malloc", "Unchecked multiplication before malloc — undersized allocation"),
            (r'kmalloc\s*\(\s*\w+\s*\*\s*\w+', "CRITICAL", "Integer Overflow in kmalloc", "Unchecked multiplication before kmalloc — use kmalloc_array()"),
            (r'kzalloc\s*\(\s*\w+\s*\*\s*\w+', "CRITICAL", "Integer Overflow in kzalloc", "Unchecked multiplication before kzalloc"),
            (r'vmalloc\s*\(\s*\w+\s*\*\s*\w+', "HIGH", "Integer Overflow in vmalloc", "Unchecked multiplication before vmalloc"),
            (r'int\s+\w+\s*=.*strlen', "LOW", "Integer Truncation", "strlen returns size_t, assigning to int may truncate on 64-bit"),
            (r'\b\w+\s*\*\s*\w+\s*;\s*.*malloc\s*\(\s*\w+\s*\*\s*\w+', "HIGH", "Integer Overflow with assignment", "Multiplication before malloc - check overflow"),
            (r'size_t.*\+.*size_t|int.*\+.*int.*malloc', "MED", "Potential Integer Overflow", "Addition before malloc - check overflow"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": "Use checked arithmetic or size_t consistently, use __builtin_mul_overflow"
                    })
        return findings

    def _check_crypto(self, lines):
        findings = []
        PATTERNS = [
            (r'(?i)MD5|md5_init|MD5_Init',     "HIGH",     "Broken Hash (MD5)", "MD5 is cryptographically broken — use SHA-256"),
            (r'(?i)SHA1|SHA1_Init|sha1_digest', "MED",      "Weak Hash (SHA-1)", "SHA-1 deprecated — use SHA-256 minimum"),
            (r'(?i)DES_ecb|des_crypt|\bDES\b.*encrypt',  "CRITICAL", "Broken Cipher (DES)", "DES 56-bit key, broken — use AES-256-GCM"),
            (r'(?i)RC4|ARC4|rc4_crypt',          "CRITICAL", "Broken Cipher (RC4)", "RC4 has known biases — use ChaCha20-Poly1305"),
            (r'(?i)AES.*ECB|ECB.*AES',           "HIGH",     "Weak Mode (ECB)", "ECB leaks patterns — use AES-GCM"),
            (r'memcmp.*(?:hmac|hash|token|key|secret)', "HIGH", "Timing Side-Channel", "Non-constant-time comparison — use CRYPTO_memcmp()"),
            (r'\brand\s*\(\s*\)',                 "HIGH",     "Weak PRNG", "rand() is predictable — use /dev/urandom"),
            (r'\bsrand\s*\(\s*time',              "CRITICAL", "Predictable PRNG Seed", "srand(time()) — predictable, brute-forceable"),
            (r'(?i)SSLv2|SSLv3|TLSv1_0|TLSv1_1', "HIGH", "Deprecated TLS", "Deprecated TLS version — use TLS 1.2+"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "type": vtype, "line": i,
                        "description": desc,
                        "recommendation": desc.split("—")[-1].strip()
                    })
        for i, line in enumerate(lines, 1):
            m = re.search(r'(?i)(key|iv|nonce|secret|password|salt)[^=\n]{0,20}=\s*"([^"]{4,})"', line)
            if m:
                findings.append({
                    "severity": "CRITICAL", "type": "Hardcoded Cryptographic Material",
                    "line": i,
                    "description": f"Hardcoded {m.group(1)}: '{m.group(2)[:20]}...'",
                    "recommendation": "Use environment variables or a key management system"
                })
        return findings

    def _check_toctou(self, lines):
        findings = []
        CHECK_PAT = [r'\baccess\s*\(', r'\bstat\s*\(', r'\blstat\s*\(', r'\bfaccessat\s*\(']
        USE_PAT   = [r'\bopen\s*\(', r'\bfopen\s*\(', r'\bunlink\s*\(', r'\bexecve?\s*\(', r'\bchmod\s*\(', r'\bchown\s*\(']
        checks = []
        for i, line in enumerate(lines, 1):
            for pat in CHECK_PAT:
                m = re.search(pat + r'[^)]*?(\w+)(?:\s*[,)])', line)
                if m or re.search(pat, line):
                    var = m.group(1) if m else "unknown"
                    checks.append((i, var, line.strip()[:80]))
            for pat in USE_PAT:
                if re.search(pat, line):
                    for c_line, c_var, c_code in checks[-10:]:
                        if 0 < i - c_line <= 25:
                            if "O_NOFOLLOW" not in line:
                                findings.append({
                                    "severity": "HIGH", "type": "TOCTOU Race Condition",
                                    "line": c_line,
                                    "description": f"Check at L{c_line} ({c_code[:40]}), use at L{i} — symlink attack window {i-c_line}",
                                    "recommendation": "Use O_NOFOLLOW, or open() first then fstat() on fd",
                                    "evidence": {"check_line": c_line, "use_line": i, "window": i-c_line}
                                })
                                break
        return findings

    def _check_buffer_size(self, lines):
        findings = []
        buffers = {}
        for i, line in enumerate(lines, 1):
            m = re.search(r'\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]', line)
            if m:
                var, size = m.group(1), int(m.group(2))
                buffers[var] = size
            m = re.search(r'\bchar\s+(\w+)\s*\[\s*(\w+)\s*\]', line)
            if m:
                var = m.group(1)
                size_var = m.group(2)
                for prev_line in lines[max(0, i-20):i-1]:
                    dm = re.search(rf'#define\s+{re.escape(size_var)}\s+(\d+)', prev_line)
                    if dm:
                        buffers[var] = int(dm.group(1))
                        break
            for func in ("strcpy", "strcat", "sprintf", "gets", "scanf"):
                if re.search(rf'\b{func}\s*\(\s*(\w+)\s*,', line):
                    m2 = re.search(rf'\b{func}\s*\(\s*(\w+)\s*,', line)
                    if m2:
                        dest = m2.group(1)
                        if dest in buffers:
                            findings.append({
                                "severity": "HIGH", "type": f"Buffer Overflow into {buffers[dest]}-byte buffer",
                                "line": i,
                                "description": f"{func}() into {dest}[{buffers[dest]}] - no bounds check",
                                "recommendation": f"Use strncpy({dest}, src, {buffers[dest]-1}) or snprintf",
                                "buffer_size": buffers[dest],
                                "buffer_name": dest,
                            })
        return findings

    def _check_command_injection_advanced(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            # system() with variable concatenation
            if re.search(r'system\s*\(.*\+.*\)', line) or re.search(r'system\s*\(.*\$\{.*\}', line) or re.search(r'system\s*\(.*strcat', line):
                findings.append({
                    "severity": "CRITICAL", "type": "Command Injection via concatenation",
                    "line": i,
                    "description": "system() with string concatenation — command injection if input controlled",
                    "recommendation": "Use execve() with explicit args, never shell concatenation"
                })
            # popen with user input
            if re.search(r'popen\s*\(.*(?:argv|getenv|fgets|read)\s*\[', line):
                findings.append({
                    "severity": "CRITICAL", "type": "Command Injection via user input",
                    "line": i,
                    "description": "popen() with user-controlled input directly",
                    "recommendation": "Validate and sanitize all input to popen()"
                })
        return findings

    def _check_null_deref(self, lines):
        findings = []
        # Track potential NULL assignments
        null_vars = {}
        for i, line in enumerate(lines, 1):
            m = re.search(r'(\w+)\s*=\s*NULL', line)
            if m:
                null_vars[m.group(1)] = i
            # Check deref after NULL check without reassignment
            for var, null_line in list(null_vars.items()):
                if i > null_line and i - null_line < 10:
                    if re.search(rf'\b{var}\s*->', line) or re.search(rf'\*\s*{var}\b', line):
                        # Check if there's a NULL check in between
                        has_check = False
                        for check_i in range(null_line, i):
                            if re.search(rf'if\s*\(\s*{re.escape(var)}\s*!=\s*NULL|if\s*\(\s*{re.escape(var)}\s*\)', lines[check_i-1]):
                                has_check = True
                                break
                        if not has_check:
                            findings.append({
                                "severity": "MED", "type": "Potential NULL Dereference",
                                "line": i,
                                "description": f"'{var}' may be NULL (set at L{null_line}) dereferenced at L{i} without check",
                                "recommendation": f"Check if {var} != NULL before dereference"
                            })
        return findings

    def _check_file_operations(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r'\bfopen\s*\(.*,\s*"w"', line) and "tmp" in line.lower():
                findings.append({
                    "severity": "MED", "type": "Insecure Temp File Write",
                    "line": i,
                    "description": "fopen with 'w' in /tmp without O_EXCL — TOCTOU race",
                    "recommendation": "Use mkstemp() or open with O_CREAT|O_EXCL"
                })
            if re.search(r'chmod\s*\(.*,\s*0*777', line):
                findings.append({
                    "severity": "HIGH", "type": "World-Writable Permission",
                    "line": i,
                    "description": "chmod 777 — world-writable file",
                    "recommendation": "Use restrictive permissions (e.g., 0750, 0640)"
                })
        return findings

    def _check_python(self, lines):
        findings = []
        PATTERNS = [
            (r'\beval\s*\(',         "CRITICAL", "Code Injection (eval)", "eval() on user input — arbitrary code execution"),
            (r'\bexec\s*\(',         "CRITICAL", "Code Injection (exec)", "exec() on user input — arbitrary code execution"),
            (r'pickle\.loads?\s*\(', "HIGH",     "Insecure Deserialization", "pickle.load() on untrusted data — arbitrary code execution"),
            (r'subprocess.*shell\s*=\s*True', "HIGH", "Command Injection", "shell=True with user input — command injection"),
            (r'os\.system\s*\(',     "HIGH",     "Command Injection", "os.system() — use subprocess with list args"),
            (r'yaml\.load\s*\(',     "HIGH",     "Insecure Deserialization", "yaml.load() — use yaml.safe_load()"),
            (r'hashlib\.md5\s*\(',   "MED",      "Weak Hash", "MD5 — use hashlib.sha256()"),
            (r'random\.',            "MED",      "Weak PRNG", "random module not crypto-safe — use secrets module"),
            (r'hashlib\.sha1\s*\(',  "MED",      "Weak Hash SHA1", "SHA1 deprecated — use sha256"),
            (r'flask.*debug\s*=\s*True', "MED", "Debug Mode", "Flask debug=True in production"),
            (r'secret_key\s*=\s*["\']\w+["\']', "CRITICAL", "Hardcoded Secret Key", "Hardcoded secret_key — use env var"),
            (r'SECURE_SSL_REDIRECT\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False', "HIGH", "Insecure Cookie", "Insecure cookie settings"),
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
        findings = []
        PATTERNS = [
            (r'fmt\.Sprintf.*\+\s*\w+|db\.(Query|Exec)\s*\([^,)]*\+', "HIGH", "SQL Injection", "String concatenation in SQL — use parameterized queries"),
            (r'exec\.Command\s*\([^)]*\+', "CRITICAL", "Command Injection", "exec.Command with string concat — validate/escape all args"),
            (r'os\.Setenv\s*\([^)]*\+', "MEDIUM", "Environment Variable Injection", "Validate env var value before setting"),
            (r'ioutil\.ReadAll\s*\(|io\.ReadAll\s*\(', "LOW", "Unbounded Read", "ReadAll has no size limit — use io.LimitReader"),
            (r'math/rand', "HIGH", "Weak PRNG", "math/rand is not crypto-safe — use crypto/rand"),
            (r'md5\.(New|Sum)', "HIGH", "Weak Hash (MD5)", "MD5 broken — use crypto/sha256"),
            (r'sha1\.(New|Sum)', "MED", "Weak Hash (SHA-1)", "SHA-1 deprecated — use crypto/sha256"),
            (r'http\.ListenAndServe\s*\(\s*"[^"]*80', "LOW", "Unencrypted HTTP Server", "Use ListenAndServeTLS for HTTPS"),
            (r'tls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true', "CRITICAL", "TLS Verification Disabled", "Never set InsecureSkipVerify: true"),
            (r'panic\s*\(', "LOW", "Panic in Production", "Unrecovered panic crashes the server — use recover()"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({"severity": sev, "type": vtype, "line": i, "description": desc, "recommendation": desc.split("—")[-1].strip()})
        return findings

    def _check_java(self, lines):
        findings = []
        PATTERNS = [
            (r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder', "CRITICAL", "Command Injection", "exec() with user input — validate all arguments"),
            (r'Statement\.execute|createStatement\(\)', "HIGH", "SQL Injection (Statement)", "Use PreparedStatement instead of Statement"),
            (r'ObjectInputStream|readObject\s*\(', "CRITICAL", "Insecure Deserialization", "Java deserialization RCE — use Jackson/Gson with safe types"),
            (r'MessageDigest\.getInstance\s*\(\s*"MD5"', "HIGH", "Weak Hash (MD5)", "MD5 broken — use SHA-256"),
            (r'MessageDigest\.getInstance\s*\(\s*"SHA-1"', "MED", "Weak Hash (SHA-1)", "SHA-1 deprecated — use SHA-256"),
            (r'new\s+Random\s*\(', "HIGH", "Weak PRNG", "java.util.Random not crypto-safe — use SecureRandom"),
            (r'SSLContext\.getInstance\s*\(\s*"SSL"', "HIGH", "Deprecated SSL Version", "Use TLSv1.2 or TLSv1.3"),
            (r'setHostnameVerifier.*ALLOW_ALL|AllowAllHostnameVerifier', "CRITICAL", "Hostname Verification Disabled", "Never disable hostname verification"),
            (r'printStackTrace\s*\(', "LOW", "Stack Trace Exposure", "Avoid exposing stack traces to users"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({"severity": sev, "type": vtype, "line": i, "description": desc, "recommendation": desc.split("—")[-1].strip()})
        return findings

    def _check_rust(self, lines):
        findings = []
        PATTERNS = [
            (r'\bunsafe\s*\{', "HIGH", "Unsafe Block", "unsafe block bypasses Rust safety — audit carefully"),
            (r'std::ptr::(read|write|copy)', "HIGH", "Raw Pointer Operation", "Raw pointer ops in unsafe — validate bounds"),
            (r'unwrap\s*\(\s*\)', "MEDIUM", "Panic on Error (unwrap)", "unwrap() panics on None/Err — use expect() or match"),
            (r'\.parse::<\w+>\s*\(\s*\)\.unwrap', "MEDIUM", "Panic on Parse Failure", "Parse + unwrap panics on bad input — handle error"),
            (r'mem::transmute', "CRITICAL", "Type Transmutation", "transmute is unsafe type punning — may cause UB"),
            (r'from_utf8_unchecked', "HIGH", "Unchecked UTF-8", "from_utf8_unchecked — may cause UB on invalid UTF-8"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({"severity": sev, "type": vtype, "line": i, "description": desc, "recommendation": desc.split("—")[-1].strip()})
        return findings

    def _check_javascript(self, lines):
        findings = []
        PATTERNS = [
            (r'\beval\s*\(', "CRITICAL", "Code Injection (eval)", "eval() - code injection"),
            (r'innerHTML\s*=\s*.*\+', "HIGH", "XSS via innerHTML", "innerHTML with concatenation - XSS"),
            (r'document\.write\s*\(', "HIGH", "XSS via document.write", "document.write with user input - XSS"),
            (r'\.exec\s*\(.*\+', "HIGH", "Command Injection", "exec with concatenation"),
            (r'Math\.random\s*\(\s*\)', "MED", "Weak PRNG", "Math.random not crypto-safe - use crypto.getRandomValues"),
            (r'localStorage.*password|sessionStorage.*password', "HIGH", "Password in storage", "Password in localStorage/sessionStorage"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line):
                    findings.append({"severity": sev, "type": vtype, "line": i, "description": desc, "recommendation": "Sanitize input"})
        return findings

    def _check_php(self, lines):
        findings = []
        PATTERNS = [
            (r'\beval\s*\(', "CRITICAL", "Code Injection (eval)", "eval() in PHP - RCE"),
            (r'\bexec\s*\(|\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(', "HIGH", "Command Injection", "Command execution function - validate input"),
            (r'\$_GET.*\$_POST|\$_REQUEST', "MED", "User Input", "Direct use of $_GET/$_POST - validate"),
            (r'md5\s*\(|sha1\s*\(', "MED", "Weak Hash", "MD5/SHA1 - use password_hash()"),
            (r'unserialize\s*\(\s*\$_', "CRITICAL", "PHP Object Injection", "unserialize on user input - object injection"),
        ]
        for i, line in enumerate(lines, 1):
            for pat, sev, vtype, desc in PATTERNS:
                if re.search(pat, line, re.I):
                    findings.append({"severity": sev, "type": vtype, "line": i, "description": desc, "recommendation": "Validate and sanitize"})
        return findings

    def analyze_with_knowledge(self, code: str, file_path: str = None, use_cve_db: bool = True, use_yara: bool = True) -> Dict:
        """Analyse PRO avec CVE DB + YARA + base patterns."""
        import tempfile, os

        base_findings = self.analyze(code)

        extra_findings = []
        knowledge_stats = {}

        # CVE DB scan
        if use_cve_db:
            try:
                from modules.knowledge.cve_db import CVEDatabase
                db = CVEDatabase()
                if file_path and os.path.isfile(file_path):
                    cve_findings = db.search(file_path, min_confidence=0.3)
                else:
                    # Temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as tf:
                        tf.write(code[:500000])
                        tf_path = tf.name
                    try:
                        cve_findings = db.search(tf_path, min_confidence=0.3)
                    finally:
                        try:
                            os.unlink(tf_path)
                        except Exception:
                            pass
                extra_findings.extend(cve_findings)
                knowledge_stats["cve_db"] = {"patterns": len(db.get_stats()), "hits": len(cve_findings)}
            except Exception as e:
                knowledge_stats["cve_db_error"] = str(e)[:200]

        # YARA scan
        if use_yara and file_path:
            try:
                from modules.knowledge.yara_manager import YaraManager
                ym = YaraManager()
                if os.path.isfile(file_path):
                    yara_result = ym.scan_file(file_path)
                    for match in yara_result.get("matches", []):
                        extra_findings.append({
                            "severity": match.get("severity", "MEDIUM"),
                            "type": f"YARA: {match.get('rule','unknown')}",
                            "line": 1,
                            "description": match.get("description", ""),
                            "file": file_path,
                            "engine": "yara",
                        })
                    knowledge_stats["yara"] = yara_result.get("stats", {})
            except Exception as e:
                knowledge_stats["yara_error"] = str(e)[:200]

        # IoC extraction
        try:
            from modules.knowledge.ioc_correlator import IoCCorrelator
            corr = IoCCorrelator()
            iocs = corr.extract_iocs(code[:100000])
            total_iocs = sum(len(v) for v in iocs.values())
            knowledge_stats["iocs"] = {"total": total_iocs, "breakdown": {k: len(v) for k, v in iocs.items()}}
            # High-value IoCs as findings
            for ip in iocs.get("ips", [])[:5]:
                if ip not in ("127.0.0.1", "0.0.0.0"):
                    extra_findings.append({
                        "severity": "MED", "type": "IoC: Hardcoded IP",
                        "line": 1, "description": f"Hardcoded IP {ip} - possible C2",
                        "ioc": ip,
                    })
        except Exception as e:
            knowledge_stats["ioc_error"] = str(e)[:200]

        all_findings = base_findings + extra_findings

        # Enrich
        enriched = self._enrich_findings(all_findings, code.splitlines())

        return {
            "status": "ok",
            "engine": "static_analyzer_pro",
            "findings": enriched,
            "total": len(enriched),
            "base_count": len(base_findings),
            "knowledge_count": len(extra_findings),
            "knowledge_stats": knowledge_stats,
            "severity_breakdown": {
                "CRITICAL": len([f for f in enriched if f.get("severity") == "CRITICAL"]),
                "HIGH": len([f for f in enriched if f.get("severity") == "HIGH"]),
                "MEDIUM": len([f for f in enriched if f.get("severity") in ("MEDIUM", "MED")]),
                "LOW": len([f for f in enriched if f.get("severity") == "LOW"]),
            }
        }
