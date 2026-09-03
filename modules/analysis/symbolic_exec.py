"""
r3con - Symbolic Execution Light
Analyse des chemins d'exécution sans Z3 solver.
Détecter les conditions d'exploitation exactes.
"""

import re
from typing import List, Dict, Set

from modules.ast_engine.z3_reach import check_path_satisfiability, Z3_AVAILABLE


class SymbolicVar:
    """Variable symbolique."""
    def __init__(self, name: str, tainted: bool = False):
        self.name    = name
        self.tainted = tainted
        self.constraints: List[str] = []

    def __repr__(self):
        return f"Sym({self.name}, tainted={self.tainted})"


class PathCondition:
    """Condition de chemin."""
    def __init__(self):
        self.conditions: List[str] = []
        self.is_feasible = True

    def add(self, cond: str):
        self.conditions.append(cond)

    def __str__(self):
        return " AND ".join(self.conditions) if self.conditions else "TRUE"


class SymbolicExecutor:
    """
    Moteur d'exécution symbolique léger.
    Analyse les chemins d'exécution sans exécuter le code.
    Identifie les conditions nécessaires pour atteindre des sinks dangereux.
    """

    DANGEROUS_SINKS = {
        "gets":    "Stack BOF — no bounds",
        "strcpy":  "BOF — no bounds check",
        "sprintf": "BOF — unbounded write",
        "system":  "Command execution",
        "exec":    "Command execution",
        "printf":  "Format string if arg is user input",
    }

    SANITIZERS = {
        "strlen": "length_check",
        "sizeof": "size_check",
        "strncpy": "bounded_copy",
        "snprintf": "bounded_format",
        "validate": "validation",
        "check": "validation",
        "is_valid": "validation",
    }

    def __init__(self):
        self.vars:  Dict[str, SymbolicVar] = {}
        self.paths: List[Dict] = []

    def analyze(self, code: str, filename: str = "unknown") -> Dict:
        """
        Analyser un fichier source symboliquement.
        Retourne les chemins qui atteignent des sinks dangereux.
        """
        code.splitlines()
        functions      = self._extract_functions(code)
        dangerous_paths = []

        for func_name, func_body, start_line in functions:
            func_paths = self._analyze_function(
                func_name, func_body, start_line, filename
            )
            dangerous_paths.extend(func_paths)

        return {
            "dangerous_paths": dangerous_paths,
            "functions_analyzed": len(functions),
            "findings": self._paths_to_findings(dangerous_paths, filename),
        }

    def _extract_functions(self, code: str) -> List:
        """Extraire les fonctions du code."""
        functions = []
        code.splitlines()

        func_re = re.compile(
            r'^(?:[\w\*\s]+)\s+(\w+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        for match in func_re.finditer(code):
            name     = match.group(1)
            if name in ("if","while","for","switch","return","do"):
                continue

            start    = code[:match.start()].count('\n')
            body     = self._extract_body(code, match.end())
            functions.append((name, body, start))

        return functions

    def _extract_body(self, code: str, start: int) -> str:
        """Extraire le corps d'une fonction."""
        depth = 1
        pos   = start
        while pos < len(code) and depth > 0:
            if code[pos] == '{':   depth += 1
            elif code[pos] == '}': depth -= 1
            pos += 1
        return code[start:pos-1]

    def _analyze_function(self, func_name: str, body: str,
                           start_line: int, filename: str) -> List[Dict]:
        """Analyser une fonction et trouver les chemins dangereux."""
        dangerous = []
        lines     = body.splitlines()

        # Variables symboliques dans cette fonction
        local_vars: Dict[str, SymbolicVar] = {}

        # État courant
        tainted_vars: Set[str] = set()
        path_conditions: List[str] = []

        for i, line in enumerate(lines):
            line_num = start_line + i + 1
            stripped = line.strip()

            # Détecter les sources de taint (entrées utilisateur)
            taint_sources = {
                "argv":       "command_line",
                "getenv":     "environment",
                "fgets":      "stdin",
                "gets":       "stdin",
                "recv":       "network",
                "read":       "file_or_network",
                "scanf":      "stdin",
                "copy_from_user": "kernel_user",
            }

            for source, source_type in taint_sources.items():
                if re.search(rf'\b{source}\s*\(', stripped):
                    var_match = re.search(r'(\w+)\s*[,\)]', stripped)
                    if var_match:
                        var = var_match.group(1)
                        tainted_vars.add(var)
                        local_vars[var] = SymbolicVar(var, tainted=True)

            # Propager le taint via assignments
            assign = re.match(r'\s*(\w+)\s*=\s*(.+)', stripped)
            if assign:
                lhs = assign.group(1)
                rhs = assign.group(2)
                # Si RHS contient une variable taintée
                if any(tv in rhs for tv in tainted_vars):
                    tainted_vars.add(lhs)
                    local_vars[lhs] = SymbolicVar(lhs, tainted=True)

            # Détecter les conditions (branches)
            cond_match = re.search(r'\bif\s*\(([^)]+)\)', stripped)
            if cond_match:
                cond = cond_match.group(1)
                path_conditions.append(f"if({cond})")

                # Vérifier si la condition est une validation
                has_validation = any(
                    s in cond for s in
                    ["<", ">", "<=", ">=", "==", "!=",
                     "strlen", "sizeof", "NULL"]
                )
                if has_validation and any(tv in cond for tv in tainted_vars):
                    path_conditions[-1] += " [VALIDATION]"

            # Vérifier les sinks dangereux
            for sink, desc in self.DANGEROUS_SINKS.items():
                if re.search(rf'\b{sink}\s*\(', stripped):
                    # Vérifier si des variables taintées arrivent ici
                    args_match = re.search(rf'\b{sink}\s*\(([^)]*)\)', stripped)
                    if args_match:
                        args = args_match.group(1)

                        # Vérifier si taint dans les args
                        taint_in_args = any(tv in args for tv in tainted_vars)

                        # Vérifier si sanitisé avant
                        is_sanitized = self._check_sanitization(
                            lines[:i], list(tainted_vars)
                        )

                        # Construire le chemin
                        path = {
                            "function":       func_name,
                            "sink":           sink,
                            "sink_line":      line_num,
                            "sink_desc":      desc,
                            "file":           filename,
                            "tainted_vars":   list(tainted_vars),
                            "taint_in_args":  taint_in_args,
                            "is_sanitized":   is_sanitized,
                            "path_conditions": list(path_conditions),
                            "exploitable":    taint_in_args and not is_sanitized,
                            "code_snippet":   stripped[:100],
                        }

                        # Calculer la condition d'exploitation
                        path["exploit_condition"] = self._exploit_condition(
                            path, path_conditions
                        )

                        # Vérifier la satisfiabilité RÉELLE de la conjonction
                        # de conditions (sous-ensemble arithmétique/relationnel,
                        # via z3) — un chemin prouvé UNSAT est mathématiquement
                        # inatteignable, ce n'est plus une supposition
                        # textuelle. 'unknown' (hors sous-ensemble, ou z3
                        # absent) ne change rien au comportement existant.
                        raw_conds = [
                            re.sub(r"^if\(|\)\s*\[VALIDATION\]$|\)$", "", c)
                            for c in path_conditions
                        ]
                        reachability = check_path_satisfiability(raw_conds) if Z3_AVAILABLE else "unknown"
                        path["reachability"] = reachability
                        if reachability == "unsat":
                            path["exploitable"] = False
                            path["exploit_condition"] = (
                                "UNSAT — chemin mathématiquement inatteignable "
                                f"(z3 a prouvé la conjonction {raw_conds} contradictoire)"
                            )

                        if path["exploitable"]:
                            dangerous.append(path)

        return dangerous

    def _check_sanitization(self, lines_before: List[str],
                              tainted: List[str]) -> bool:
        """Vérifier si une variable taintée est sanitisée avant le sink.

        Correctif (2 volets) par rapport à la version d'origine, qui
        traitait la simple PRÉSENCE d'un motif ('sizeof(', 'if(...<...)')
        n'importe où dans les 20 lignes précédentes comme une preuve de
        sanitisation — y compris quand ce motif ne concernait aucune des
        variables taintées (ex: `sizeof(input)` dans l'appel `fgets(input,
        sizeof(input), stdin)` marquait `input` comme sanitisé alors que
        c'est justement la ligne qui le tainte). Désormais :
        1. Pour les appels (strlen/strncpy/snprintf/validate/check...), on
           exige qu'une variable taintée apparaisse dans les ARGUMENTS de
           cet appel précis.
        2. Pour les `if(...)`, on exige que la condition mentionne
           explicitement une variable taintée.
        """
        call_fns = ["strlen", "strncpy", "snprintf", "validate", r"check\w*"]
        code_before = "\n".join(lines_before[-20:])

        for fn in call_fns:
            for m in re.finditer(rf'\b{fn}\s*\(([^)]*)\)', code_before):
                args = m.group(1)
                if any(re.search(rf'\b{re.escape(tv)}\b', args) for tv in tainted):
                    return True

        for if_match in re.finditer(r'\bif\s*\(([^)]*)\)', code_before):
            cond = if_match.group(1)
            mentions_tainted = any(
                re.search(rf'\b{re.escape(tv)}\b', cond) for tv in tainted
            )
            if mentions_tainted and re.search(r'<|>|==\s*NULL', cond):
                return True

        return False

    def _exploit_condition(self, path: Dict,
                            conditions: List[str]) -> str:
        """Générer la condition d'exploitation."""
        if not path["taint_in_args"]:
            return "N/A — no tainted data in sink"

        if path["is_sanitized"]:
            return "Sanitized — validation present (may be bypassable)"

        sink = path["sink"]

        conditions_clean = [c for c in conditions
                             if "[VALIDATION]" not in c]

        base_cond = (
            f"Control {path['tainted_vars'][:2]} → "
            f"Reach {sink}() without validation"
        )

        if conditions_clean:
            return f"{base_cond} | Path: {' → '.join(conditions_clean[-3:])}"
        return base_cond

    def _paths_to_findings(self, paths: List[Dict],
                            filename: str) -> List[Dict]:
        """Convertir les chemins en findings r3con."""
        findings = []
        for path in paths:
            if not path.get("exploitable"):
                continue

            findings.append({
                "severity":    "CRITICAL" if path["sink"] in
                               ("gets","strcpy","system","exec") else "HIGH",
                "type":        f"Symbolic: Taint reaches {path['sink']}()",
                "file":        filename,
                "line":        path["sink_line"],
                "description": (
                    f"Tainted data ({', '.join(path['tainted_vars'][:2])}) "
                    f"reaches {path['sink']}() in {path['function']}(). "
                    f"{path['sink_desc']}"
                ),
                "exploit_condition": path["exploit_condition"],
                "recommendation": (
                    f"Validate/sanitize input before {path['sink']}(). "
                    f"Check bounds and use safe alternatives."
                ),
                "path_conditions": path["path_conditions"],
            })

        return findings
