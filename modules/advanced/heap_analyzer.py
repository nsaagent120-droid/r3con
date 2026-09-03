"""
r3con - Heap Analyzer v2
"""
import re
from typing import List, Dict

HEAP_PATTERNS = {
    "off_by_one_null": {
        "pattern": r"malloc\s*\(\s*strlen\s*\([^)]+\)\s*\)",
        "severity":"HIGH","cwe":"CWE-193","description":"malloc(strlen(s)) missing +1 for null terminator",
        "recommendation":"Use malloc(strlen(s) + 1)","exploitability":0.70,"primitive":"heap_overflow",
    },
    "off_by_one_loop": {
        "pattern": r"for\s*\([^;]*;\s*\w+\s*<=\s*(sizeof|strlen|len|size)\s*\(",
        "severity":"HIGH","cwe":"CWE-193","description":"Off-by-one in loop: <= writes one byte past end",
        "recommendation":"Use < instead of <=","exploitability":0.65,"primitive":"heap_overflow",
    },
    "heap_overflow_memcpy": {
        "pattern": r"memcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)",
        "severity":"HIGH","cwe":"CWE-122","description":"Potential heap overflow via memcpy",
        "recommendation":"Validate size <= allocation_size","exploitability":0.80,"primitive":"heap_overflow",
    },
    "integer_overflow_alloc": {
        "pattern": r"malloc\s*\(\s*\w+\s*\*\s*\w+",
        "severity":"CRITICAL","cwe":"CWE-190","description":"Integer overflow in allocation: size*count can wrap",
        "recommendation":"Use __builtin_mul_overflow() or checked arithmetic","exploitability":0.88,"primitive":"undersized_allocation",
    },
    "calloc_overflow": {
        "pattern": r"calloc\s*\(\s*\w+\s*,\s*\w+\s*\)",
        "severity":"MEDIUM","cwe":"CWE-190","description":"calloc(nmemb, size) — verify no integer overflow",
        "recommendation":"Validate that nmemb * size does not overflow","exploitability":0.50,"primitive":"undersized_allocation",
    },
    "realloc_null": {
        "pattern": r"realloc\s*\(\s*(\w+)\s*,",
        "severity":"MEDIUM","cwe":"CWE-401","description":"realloc() — on failure original ptr NOT freed",
        "recommendation":"Use tmp=realloc(ptr,size); if(!tmp){free(ptr);} ptr=tmp;","exploitability":0.40,"primitive":"memory_leak",
    },
    "type_confusion": {
        "pattern": r"\((\w+\s*\*)\)\s*\w+\s*[->=]",
        "severity":"HIGH","cwe":"CWE-843","description":"Type confusion via cast — potential vtable hijack",
        "recommendation":"Use safe casting with type checks","exploitability":0.75,"primitive":"type_confusion",
    },
    "heap_spray": {
        "pattern": r"for\s*\([^)]+\)\s*\{[^}]*malloc\s*\(",
        "severity":"MEDIUM","cwe":"CWE-119","description":"Loop allocating memory — potential heap spray",
        "recommendation":"Validate loop bounds and total allocation size","exploitability":0.60,"primitive":"heap_spray",
    },
}

ALLOCATOR_NOTES = {
    "glibc": {
        "double_free":"glibc 2.31+: tcache double-free check — may need bypass via chunk index",
        "uaf":"glibc: UAF on tcache chunk → control fd pointer → arbitrary alloc",
        "heap_overflow":"glibc: overflow chunk header → corrupt size/prev_size → unlink attack",
    },
    "jemalloc": {
        "double_free":"jemalloc: double-free detected by run bitmap — harder to exploit",
        "uaf":"jemalloc: UAF → corrupt slab metadata → potential RCE",
        "heap_overflow":"jemalloc: overflow into arena metadata → heap layout control",
    },
    "tcmalloc": {
        "double_free":"tcmalloc: central freelist → double-free → control freelist pointer",
        "uaf":"tcmalloc: UAF → thread cache corruption",
        "heap_overflow":"tcmalloc: overflow → span metadata corruption",
    },
}

class HeapAnalyzer:
    def __init__(self, allocator: str = "glibc"):
        self.allocator = allocator

    def analyze(self, code: str) -> List[Dict]:
        findings = []
        lines    = code.splitlines()
        findings += self._check_double_free(lines)
        findings += self._check_uaf(lines)
        findings += self._check_dangling(lines)
        for vuln_name, info in HEAP_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                if re.search(info["pattern"], line, re.IGNORECASE):
                    findings.append({
                        "severity": info["severity"],
                        "type": self._type_name(vuln_name),
                        "cwe": info["cwe"], "line": i,
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                        "exploitability": info["exploitability"],
                        "primitive": info["primitive"],
                        "code_snippet": line.strip()[:100],
                        "allocator_note": self._allocator_note("heap_overflow", self.allocator),
                    })
        if len(findings) >= 2:
            findings = self._enrich_chains(findings)
        return self._deduplicate(findings)

    def _check_double_free(self, lines):
        findings = []; freed = {}
        for i, line in enumerate(lines, 1):
            null_m = re.search(r'(\w+)\s*=\s*NULL', line)
            if null_m and null_m.group(1) in freed:
                del freed[null_m.group(1)]; continue
            assign_m = re.search(r'(\w+)\s*=\s*(?!NULL)\w+', line)
            if assign_m and assign_m.group(1) in freed:
                del freed[assign_m.group(1)]
            m = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if m:
                var = m.group(1)
                if var in freed:
                    first_line = freed[var][0]
                    findings.append({
                        "severity":"CRITICAL","type":"Double Free","cwe":"CWE-415","line":first_line,
                        "description":f"'{var}' freed at L{first_line} and L{i} — heap corruption",
                        "recommendation":"Set pointer to NULL after free(): free(p); p = NULL;",
                        "exploitability":0.85,"primitive":"heap_corruption",
                        "code_snippet":f"free({var}) twice: L{first_line} and L{i}",
                        "allocator_note":self._allocator_note("double_free", self.allocator),
                    })
                else:
                    freed[var] = [i]
        return findings

    def _check_uaf(self, lines):
        findings = []; freed_vars = {}
        for i, line in enumerate(lines, 1):
            m = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if m:
                freed_vars[m.group(1)] = i; continue
            null_m = re.search(r'(\w+)\s*=\s*NULL', line)
            if null_m and null_m.group(1) in freed_vars:
                del freed_vars[null_m.group(1)]; continue
            for var, free_line in list(freed_vars.items()):
                if (re.search(rf'\b{var}\s*[->=\[\.]', line) or
                        re.search(rf'\b{var}\s*[,)]', line)):
                    findings.append({
                        "severity":"CRITICAL","type":"Use-After-Free","cwe":"CWE-416","line":free_line,
                        "description":f"'{var}' freed at L{free_line}, used at L{i}",
                        "recommendation":"Set pointer to NULL after free(). Check all code paths.",
                        "exploitability":0.90,"primitive":"arbitrary_read_write",
                        "code_snippet":line.strip()[:100],
                        "allocator_note":self._allocator_note("uaf", self.allocator),
                    })
        return findings

    def _check_dangling(self, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            m = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if m:
                var = m.group(1)
                next_lines = lines[i:min(len(lines), i+3)]
                if not any(re.search(rf'\b{var}\s*=\s*NULL', nl) for nl in next_lines):
                    findings.append({
                        "severity":"HIGH","type":"Dangling Pointer","cwe":"CWE-825","line":i,
                        "description":f"'{var}' freed but not set to NULL — dangling pointer risk",
                        "recommendation":f"Add '{var} = NULL;' immediately after free({var});",
                        "exploitability":0.65,"primitive":"dangling_pointer",
                        "code_snippet":line.strip()[:100],
                    })
        return findings

    def _enrich_chains(self, findings):
        primitives = set(f.get("primitive") for f in findings)
        if "heap_overflow" in primitives and "arbitrary_read_write" in primitives:
            for f in findings:
                if f.get("primitive") == "arbitrary_read_write":
                    f["chain_hint"] = "Combined with heap overflow → potential full RCE chain"
        if "undersized_allocation" in primitives:
            for f in findings:
                if f.get("primitive") == "undersized_allocation":
                    f["chain_hint"] = "Integer overflow → small alloc → overflow into adjacent heap chunk"
        return findings

    def _allocator_note(self, vuln_name: str, allocator: str) -> str:
        return ALLOCATOR_NOTES.get(allocator, {}).get(vuln_name, "")

    def _type_name(self, vuln_name: str) -> str:
        types = {
            "off_by_one_null":"Off-by-One (NULL terminator)",
            "off_by_one_loop":"Off-by-One (loop boundary)",
            "heap_overflow_memcpy":"Heap Buffer Overflow (memcpy)",
            "integer_overflow_alloc":"Integer Overflow in Allocation",
            "calloc_overflow":"Integer Overflow in calloc()",
            "realloc_null":"Unsafe realloc() Pattern",
            "type_confusion":"Type Confusion",
            "heap_spray":"Heap Spray Pattern",
        }
        return types.get(vuln_name, vuln_name.replace("_"," ").title())

    def _deduplicate(self, findings):
        seen = set(); result = []
        for f in findings:
            key = (f.get("type"), f.get("line"))
            if key not in seen:
                seen.add(key); result.append(f)
        sev_o = {"CRITICAL":0,"HIGH":1,"MED":2,"MEDIUM":2,"LOW":3}
        return sorted(result, key=lambda x: sev_o.get(x.get("severity","LOW"),3))
