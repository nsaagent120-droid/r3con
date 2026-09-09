"""
r3con - Symbolic Execution Light - FIXED P3
Fixes: input validation, ReDoS protection, limits, resource guards
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field

MAX_CODE_SIZE = 2 * 1024 * 1024
MAX_FUNCTIONS = 100
MAX_PATHS = 20
MAX_CONDITIONS = 50
MAX_LINE_LEN = 1000


def _validate_code(code: str) -> bool:
    """Validate code input."""
    if not code or not isinstance(code, str):
        return False
    if len(code) > MAX_CODE_SIZE:
        return False
    if "\x00" in code:
        return False
    return True


def _safe_search(pattern: str, text: str) -> bool:
    """Safe regex search with length limits to prevent ReDoS."""
    if not pattern or not text:
        return False
    if len(text) > 10000:
        text = text[:10000]
    if len(pattern) > 500:
        return False
    try:
        # Use timeout via limiting complexity - avoid catastrophic backtracking patterns
        # Our patterns are simple, but we still guard
        return bool(re.search(pattern, text))
    except re.error:
        return False


@dataclass
class SymbolicValue:
    """Valeur symbolique — peut être contrôlée ou constante."""
    name: str
    tainted: bool = False
    value: Optional[int] = None
    source: str = ""


@dataclass
class ExecutionPath:
    """Un chemin d'exécution possible."""
    path_id: int
    conditions: List[str] = field(default_factory=list)
    variables: Dict[str, SymbolicValue] = field(default_factory=dict)
    reached_sinks: List[Dict] = field(default_factory=list)
    vulnerable: bool = False
    confidence: float = 0.0


class SymbolicExecutor:
    """
    Symbolic execution light — explore les chemins d'exécution - FIXED P3.
    """

    # Sources d'entrée attaquant - FIXED safe patterns, no ReDoS
    SOURCES = {
        r'\bargv\s*\[': "argv",
        r'\bgetenv\s*\(': "getenv",
        r'\bfgets?\s*\(': "stdin",
        r'\brecv\s*\(': "network",
        r'\bread\s*\(': "read",
        r'\bscanf\s*\(': "stdin",
        r'\bcopy_from_user\s*\(': "kernel_user",
    }

    # Sinks dangereux - FIXED simplified to avoid ReDoS
    SINKS = {
        r'\bstrcpy\s*\(': ("BOF", "strcpy without bounds"),
        r'\bgets\s*\(': ("BOF", "gets — no bounds"),
        r'\bsprintf\s*\(': ("BOF", "sprintf overflow"),
        r'\bsystem\s*\(': ("CmdInj", "system() execution"),
        r'\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)': ("FmtStr", "format string"),
        r'\bmemcpy\s*\(': ("BOF", "memcpy overflow"),
    }

    # Validations (sanitizers)
    SANITIZERS = [
        r'\bstrlen\s*\(',
        r'\bstrnlen\s*\(',
        r'\bstrncpy\s*\(',
        r'\bsnprintf\s*\(',
        r'\bvalidate\s*\(',
        r'\bsanitize\s*\(',
        r'\bcheck_input\s*\(',
    ]

    def __init__(self):
        self.paths = []
        self.path_id = 0

    def analyze(self, code: str, filename: str = "unknown") -> Dict:
        """Analyser le code et explorer les chemins d'exécution - FIXED validation."""
        if not _validate_code(code):
            return {"filename": filename, "paths_explored": 0, "vulnerable_paths": [], "conditions": [], "findings": [], "error": "invalid_code"}

        if not filename or len(filename) > 1024:
            filename = "unknown"

        lines = code.splitlines()
        # Limit lines
        if len(lines) > 10000:
            lines = lines[:10000]

        results = {
            "filename": filename,
            "paths_explored": 0,
            "vulnerable_paths": [],
            "conditions": [],
            "findings": [],
        }

        # Extraire les fonctions with limit
        functions = self._extract_functions(code)
        if len(functions) > MAX_FUNCTIONS:
            functions = dict(list(functions.items())[:MAX_FUNCTIONS])

        for func_name, func_body in functions.items():
            try:
                paths = self._explore_function(func_name, func_body, lines)
                for path in paths:
                    results["paths_explored"] += 1
                    if path.vulnerable:
                        results["vulnerable_paths"].append({
                            "function": func_name[:100],
                            "path_id": path.path_id,
                            "conditions": path.conditions[:MAX_CONDITIONS],
                            "sinks": path.reached_sinks[:10],
                            "confidence": path.confidence,
                        })
                        if len(results["vulnerable_paths"]) >= MAX_PATHS:
                            break
            except Exception:
                continue

            if len(results["vulnerable_paths"]) >= MAX_PATHS:
                break

        results["findings"] = self._paths_to_findings(results["vulnerable_paths"], filename)

        return results

    def _extract_functions(self, code: str) -> Dict[str, str]:
        """Extraire les corps de fonctions - FIXED limits, safe regex."""
        functions = {}
        # Safe pattern without catastrophic backtracking
        pattern = re.compile(r'(?:[a-zA-Z_][\w\*\s]*?)\s+([a-zA-Z_]\w*)\s*\([^)]{0,500}\)\s*\{', re.MULTILINE)
        skip_kw = {'if','while','for','switch','else','do','struct','enum','typedef','return'}

        count = 0
        for match in pattern.finditer(code):
            if count >= MAX_FUNCTIONS:
                break
            name = match.group(1)
            if name in skip_kw or len(name) > 100:
                continue

            start = match.end()
            if start >= len(code):
                continue

            depth = 1
            pos = start
            # Limit search to prevent O(n^2)
            max_search = min(len(code), start + 50000)
            while pos < max_search and depth > 0:
                c = code[pos]
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                pos += 1

            if depth == 0:
                body = code[start:pos-1]
                if len(body) > 100000:
                    body = body[:100000]
                functions[name] = body
                count += 1

        return functions

    def _explore_function(self, func_name: str, func_body: str, all_lines: List[str]) -> List[ExecutionPath]:
        """Explorer les chemins d'une fonction - FIXED limits."""
        paths = []

        main_path = ExecutionPath(path_id=self.path_id)
        self.path_id += 1

        lines = func_body.splitlines()
        if len(lines) > 5000:
            lines = lines[:5000]

        vars_state: Dict[str, SymbolicValue] = {}

        # Phase 1 : Identifier les variables tainted
        for line in lines:
            if len(line) > MAX_LINE_LEN:
                line = line[:MAX_LINE_LEN]
            for pattern, source_name in self.SOURCES.items():
                if _safe_search(pattern, line):
                    var = self._extract_assigned_var(line)
                    if var and len(var) <= 100:
                        vars_state[var] = SymbolicValue(name=var, tainted=True, source=source_name)
                        if len(main_path.conditions) < MAX_CONDITIONS:
                            main_path.conditions.append(f"'{var}' tainted from {source_name}")

        # Phase 2 : Vérifier si sanitizers présents
        is_sanitized = self._check_sanitizers(func_body)

        # Phase 3 : Vérifier si sinks atteints avec données tainted
        for pattern, (vuln_type, desc) in self.SINKS.items():
            try:
                for match in re.finditer(pattern, func_body):
                    if len(main_path.reached_sinks) >= 10:
                        break
                    line_num = func_body[:match.start()].count('\n') + 1
                    # Simplified tainted check
                    matched_text = match.group(0)
                    tainted_arg = self._check_tainted_args_simple(matched_text, vars_state)

                    if tainted_arg and not is_sanitized:
                        main_path.reached_sinks.append({
                            "type": vuln_type,
                            "desc": desc,
                            "line": line_num,
                            "arg": tainted_arg[:100],
                            "match": matched_text[:60],
                        })
                        main_path.vulnerable = True
            except re.error:
                continue

        # Phase 4 : Explorer les branches (if/else) with limit
        try:
            branch_paths = self._explore_branches(func_body, vars_state)
            paths.append(main_path)
            for bp in branch_paths:
                if len(paths) >= MAX_PATHS:
                    break
                if bp.reached_sinks:
                    bp.vulnerable = True
                paths.append(bp)
        except Exception:
            paths.append(main_path)

        # Calculer la confidence
        for path in paths:
            path.confidence = self._calc_confidence(path, bool(vars_state), is_sanitized)

        return paths

    def _explore_branches(self, code: str, vars_state: Dict) -> List[ExecutionPath]:
        """Explorer les branches if/else - FIXED limits, safe."""
        paths = []
        if_pattern = re.compile(r'\bif\s*\(([^)]{0,200})\)')

        count = 0
        for match in if_pattern.finditer(code):
            if count >= 5:
                break
            condition = match.group(1)
            if len(condition) > 200:
                continue

            path = ExecutionPath(path_id=self.path_id)
            self.path_id += 1

            if len(condition) > 0 and len(path.conditions) < MAX_CONDITIONS:
                path.conditions.append(f"if ({condition[:100]}) == True")

            then_start = match.end()
            block = self._extract_block(code, then_start)
            if len(block) > 10000:
                block = block[:10000]

            for pattern, (vuln_type, desc) in self.SINKS.items():
                try:
                    for sink_match in re.finditer(pattern, block):
                        if len(path.reached_sinks) >= 5:
                            break
                        matched = sink_match.group(0)
                        tainted_arg = self._check_tainted_args_simple(matched, vars_state)
                        if tainted_arg:
                            path.reached_sinks.append({
                                "type": vuln_type,
                                "desc": desc,
                                "arg": tainted_arg[:100],
                                "match": matched[:60],
                                "in_branch": True,
                            })
                except re.error:
                    continue

            if path.conditions or path.reached_sinks:
                paths.append(path)
                count += 1

        return paths[:5]

    def _extract_block(self, code: str, start: int) -> str:
        """Extraire un bloc {} à partir d'une position - FIXED limits."""
        if start >= len(code):
            return ""

        pos = start
        # Skip whitespace
        while pos < len(code) and pos < start + 100 and code[pos] in (' ', '\t', '\n', '\r'):
            pos += 1

        if pos >= len(code):
            return ""

        if code[pos] == '{':
            depth = 1
            pos += 1
            block_start = pos
            max_search = min(len(code), block_start + 20000)
            while pos < max_search and depth > 0:
                c = code[pos]
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                pos += 1
            return code[block_start:pos-1] if depth == 0 else code[block_start:max_search]

        # Single line block
        end = code.find('\n', pos)
        if end == -1:
            return code[pos:pos+500]
        return code[pos:min(end, pos+500)]

    def _extract_assigned_var(self, line: str) -> Optional[str]:
        """Extraire le nom de la variable assignée - FIXED safe."""
        if len(line) > MAX_LINE_LEN:
            line = line[:MAX_LINE_LEN]

        patterns = [
            r'([a-zA-Z_]\w*)\s*=\s*',
            r'[a-zA-Z_]\w*\s+([a-zA-Z_]\w*)\s*[=;]',
        ]
        for pat in patterns:
            try:
                m = re.search(pat, line)
                if m:
                    var = m.group(1)
                    if var not in ('if','while','for','return','int','char','void','unsigned','static','const') and len(var) <= 100:
                        return var
            except re.error:
                continue
        return None

    def _check_tainted_args_simple(self, matched_text: str, vars_state: Dict) -> Optional[str]:
        """Vérifier si les arguments sont tainted - FIXED simple, safe."""
        if not vars_state or not matched_text:
            return None

        if len(matched_text) > 500:
            matched_text = matched_text[:500]

        for var_name, sym_val in vars_state.items():
            if sym_val.tainted and var_name in matched_text:
                return var_name

        return None

    def _check_sanitizers(self, code: str) -> bool:
        """Vérifier si des sanitizers sont présents - FIXED safe."""
        if len(code) > 100000:
            code = code[:100000]
        for s in self.SANITIZERS:
            if _safe_search(s, code):
                return True
        return False

    def _calc_confidence(self, path: ExecutionPath, has_sources: bool, is_sanitized: bool) -> float:
        """Calculer la confiance dans la vulnérabilité."""
        confidence = 0.0
        if has_sources:
            confidence += 0.4
        if path.reached_sinks:
            confidence += 0.4
        if not is_sanitized:
            confidence += 0.2
        if path.conditions:
            confidence += 0.1
        if len(path.reached_sinks) > 1:
            confidence += 0.1
        return min(round(confidence, 2), 1.0)

    def _paths_to_findings(self, vulnerable_paths: List[Dict], filename: str) -> List[Dict]:
        """Convertir les chemins vulnérables en findings r3con - FIXED limits."""
        findings = []
        for vp in vulnerable_paths[:MAX_PATHS]:
            for sink in vp.get("sinks", [])[:5]:
                sev = "CRITICAL" if sink["type"] in ("BOF","CmdInj") else "HIGH"
                findings.append({
                    "severity": sev,
                    "type": f"Symbolic: {sink['type']}"[:100],
                    "file": filename[:500],
                    "line": sink.get("line"),
                    "description": (
                        f"[Symbolic Path {vp['path_id']}] "
                        f"{sink['desc'][:200]} via tainted var '{sink.get('arg','')[:50]}'. "
                        f"Conditions: {', '.join(vp['conditions'][:2])}"[:500]
                    ),
                    "confidence": vp.get("confidence", 0.5),
                    "recommendation": "Validate and sanitize input before use.",
                    "in_branch": sink.get("in_branch", False),
                })
                if len(findings) >= 50:
                    break
            if len(findings) >= 50:
                break
        return sorted(findings, key=lambda x: x["confidence"], reverse=True)
