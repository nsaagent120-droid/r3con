"""
r3con - Symbolic Execution Light
Simulation des chemins d'exécution sans Z3.
Trouve les conditions exactes d'exploitation.
100% offline, sans dépendances externes.
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class SymbolicValue:
    """Valeur symbolique — peut être contrôlée ou constante."""
    name:       str
    tainted:    bool  = False   # Contrôlée par l'attaquant
    value:      Optional[int] = None
    source:     str = ""


@dataclass
class ExecutionPath:
    """Un chemin d'exécution possible."""
    path_id:    int
    conditions: List[str] = field(default_factory=list)
    variables:  Dict[str, SymbolicValue] = field(default_factory=dict)
    reached_sinks: List[Dict] = field(default_factory=list)
    vulnerable: bool = False
    confidence: float = 0.0


class SymbolicExecutor:
    """
    Symbolic execution light — explore les chemins d'exécution.
    Identifie les conditions d'exploitation sans exécuter le code.
    """

    # Sources d'entrée attaquant
    SOURCES = {
        r'\bargv\s*\[':                     "argv",
        r'\bgetenv\s*\(':                   "getenv",
        r'\bfgets?\s*\(':                   "stdin",
        r'\brecv\s*\(':                     "network",
        r'\bread\s*\(':                     "read",
        r'\bscanf\s*\(':                    "stdin",
        r'\bcopy_from_user\s*\(':           "kernel_user",
    }

    # Sinks dangereux
    SINKS = {
        r'\bstrcpy\s*\(([^,]+),\s*([^)]+)\)':   ("BOF",     "strcpy without bounds"),
        r'\bgets\s*\(([^)]+)\)':                 ("BOF",     "gets — no bounds"),
        r'\bsprintf\s*\(([^,]+),\s*"[^"]*"\s*,\s*([^)]+)\)': ("BOF", "sprintf overflow"),
        r'\bsystem\s*\(([^)]+)\)':               ("CmdInj",  "system() execution"),
        r'\bprintf\s*\(([^,")][^)]*)\)':         ("FmtStr",  "format string"),
        r'\bmemcpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)': ("BOF", "memcpy overflow"),
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
        r'\bif\s*\(\s*\w+\s*[<>]=?\s*\d+\s*\)',   # bounds check
    ]

    def __init__(self):
        self.paths   = []
        self.path_id = 0

    def analyze(self, code: str, filename: str = "unknown") -> Dict:
        """
        Analyser le code et explorer les chemins d'exécution.
        """
        lines   = code.splitlines()
        results = {
            "filename":       filename,
            "paths_explored": 0,
            "vulnerable_paths": [],
            "conditions":     [],
            "findings":       [],
        }

        # Extraire les fonctions
        functions = self._extract_functions(code)

        for func_name, func_body in functions.items():
            paths = self._explore_function(func_name, func_body, lines)
            for path in paths:
                results["paths_explored"] += 1
                if path.vulnerable:
                    results["vulnerable_paths"].append({
                        "function":   func_name,
                        "path_id":    path.path_id,
                        "conditions": path.conditions,
                        "sinks":      path.reached_sinks,
                        "confidence": path.confidence,
                    })

        # Générer des findings
        results["findings"] = self._paths_to_findings(
            results["vulnerable_paths"], filename)

        return results

    def _extract_functions(self, code: str) -> Dict[str, str]:
        """Extraire les corps de fonctions."""
        functions = {}
        pattern   = re.compile(
            r'(?:[\w\*\s]+)\s+(\w+)\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )
        skip_kw = {'if','while','for','switch','else','do','struct','enum','typedef'}

        for match in pattern.finditer(code):
            name = match.group(1)
            if name in skip_kw:
                continue

            start = match.end()
            depth = 1
            pos   = start
            while pos < len(code) and depth > 0:
                if code[pos] == '{':   depth += 1
                elif code[pos] == '}': depth -= 1
                pos += 1

            functions[name] = code[start:pos-1]

        return functions

    def _explore_function(self, func_name: str,
                           func_body: str,
                           all_lines: List[str]) -> List[ExecutionPath]:
        """Explorer les chemins d'une fonction."""
        paths = []

        # Chemin 1 : linéaire (pas de branchement)
        main_path = ExecutionPath(path_id=self.path_id)
        self.path_id += 1

        lines = func_body.splitlines()
        vars_state: Dict[str, SymbolicValue] = {}

        # Phase 1 : Identifier les variables tainted
        for line in lines:
            for pattern, source_name in self.SOURCES.items():
                if re.search(pattern, line):
                    # Extraire le nom de la variable
                    var = self._extract_assigned_var(line)
                    if var:
                        vars_state[var] = SymbolicValue(
                            name=var, tainted=True, source=source_name)
                        main_path.conditions.append(
                            f"'{var}' tainted from {source_name}")

        # Phase 2 : Vérifier si sanitizers présents
        is_sanitized = self._check_sanitizers(func_body)

        # Phase 3 : Vérifier si sinks atteints avec données tainted
        for pattern, (vuln_type, desc) in self.SINKS.items():
            for match in re.finditer(pattern, func_body):
                line_num = func_body[:match.start()].count('\n') + 1
                sink_args = match.groups()

                # Est-ce que les arguments sont tainted ?
                tainted_arg = self._check_tainted_args(
                    sink_args, vars_state)

                if tainted_arg and not is_sanitized:
                    main_path.reached_sinks.append({
                        "type":     vuln_type,
                        "desc":     desc,
                        "line":     line_num,
                        "arg":      tainted_arg,
                        "match":    match.group(0)[:60],
                    })
                    main_path.vulnerable = True

        # Phase 4 : Explorer les branches (if/else)
        branch_paths = self._explore_branches(func_body, vars_state)
        paths.append(main_path)

        for bp in branch_paths:
            if bp.reached_sinks:
                bp.vulnerable = True
            paths.append(bp)

        # Calculer la confidence
        for path in paths:
            path.confidence = self._calc_confidence(
                path, bool(vars_state), is_sanitized)

        return paths

    def _explore_branches(self, code: str,
                           vars_state: Dict) -> List[ExecutionPath]:
        """Explorer les branches if/else."""
        paths   = []
        # Trouver tous les if
        if_pattern = re.compile(r'\bif\s*\(([^)]+)\)')

        for match in if_pattern.finditer(code):
            condition = match.group(1)
            path = ExecutionPath(path_id=self.path_id)
            self.path_id += 1

            # Condition vraie
            path.conditions.append(f"if ({condition}) == True")

            # Vérifier le bloc then pour des sinks
            then_start = match.end()
            # Trouver le bloc
            block = self._extract_block(code, then_start)
            for pattern, (vuln_type, desc) in self.SINKS.items():
                for sink_match in re.finditer(pattern, block):
                    args        = sink_match.groups()
                    tainted_arg = self._check_tainted_args(args, vars_state)
                    if tainted_arg:
                        path.reached_sinks.append({
                            "type":  vuln_type,
                            "desc":  desc,
                            "arg":   tainted_arg,
                            "match": sink_match.group(0)[:60],
                            "in_branch": True,
                        })

            if path.conditions or path.reached_sinks:
                paths.append(path)

        return paths[:5]  # Max 5 branches

    def _extract_block(self, code: str, start: int) -> str:
        """Extraire un bloc {} à partir d'une position."""
        pos = start
        while pos < len(code) and code[pos] in (' ', '\t', '\n'):
            pos += 1

        if pos >= len(code):
            return ""

        if code[pos] == '{':
            depth = 1
            pos += 1
            block_start = pos
            while pos < len(code) and depth > 0:
                if code[pos] == '{':   depth += 1
                elif code[pos] == '}': depth -= 1
                pos += 1
            return code[block_start:pos-1]

        # Single line block
        end = code.find('\n', pos)
        return code[pos:end] if end != -1 else code[pos:]

    def _extract_assigned_var(self, line: str) -> Optional[str]:
        """Extraire le nom de la variable assignée."""
        patterns = [
            r'(\w+)\s*=\s*',
            r'(\w+)\s*\[',
            r'\w+\s+(\w+)\s*[=;]',
        ]
        for pat in patterns:
            m = re.search(pat, line)
            if m:
                var = m.group(1)
                if var not in ('if','while','for','return','int','char','void','unsigned'):
                    return var
        return None

    def _check_tainted_args(self, args: tuple,
                             vars_state: Dict) -> Optional[str]:
        """Vérifier si les arguments sont tainted."""
        if not vars_state:
            return None

        for arg in args:
            if not arg:
                continue
            arg_clean = arg.strip()
            # Vérifier si l'argument correspond à une variable tainted
            for var_name, sym_val in vars_state.items():
                if sym_val.tainted and var_name in arg_clean:
                    return var_name

        return None

    def _check_sanitizers(self, code: str) -> bool:
        """Vérifier si des sanitizers sont présents."""
        return any(re.search(s, code) for s in self.SANITIZERS)

    def _calc_confidence(self, path: ExecutionPath,
                          has_sources: bool,
                          is_sanitized: bool) -> float:
        """Calculer la confiance dans la vulnérabilité."""
        confidence = 0.0
        if has_sources:             confidence += 0.4
        if path.reached_sinks:      confidence += 0.4
        if not is_sanitized:        confidence += 0.2
        if path.conditions:         confidence += 0.1
        if len(path.reached_sinks) > 1: confidence += 0.1
        return min(round(confidence, 2), 1.0)

    def _paths_to_findings(self, vulnerable_paths: List[Dict],
                            filename: str) -> List[Dict]:
        """Convertir les chemins vulnérables en findings r3con."""
        findings = []
        for vp in vulnerable_paths:
            for sink in vp.get("sinks", []):
                sev = "CRITICAL" if sink["type"] in ("BOF","CmdInj") else "HIGH"
                findings.append({
                    "severity":    sev,
                    "type":        f"Symbolic: {sink['type']}",
                    "file":        filename,
                    "line":        sink.get("line"),
                    "description": (
                        f"[Symbolic Path {vp['path_id']}] "
                        f"{sink['desc']} via tainted var '{sink.get('arg','')}'. "
                        f"Conditions: {', '.join(vp['conditions'][:2])}"
                    ),
                    "confidence":  vp.get("confidence", 0.5),
                    "recommendation": "Validate and sanitize input before use.",
                    "in_branch":   sink.get("in_branch", False),
                })
        return sorted(findings, key=lambda x: x["confidence"], reverse=True)
