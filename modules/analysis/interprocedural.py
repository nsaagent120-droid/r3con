"""
r3con - Interprocedural Analysis
Analyse des vulnérabilités qui traversent plusieurs fonctions.
Complète le Call Graph avec des flux de données cross-function.
"""

import re
from typing import List, Dict, Set
from collections import defaultdict

from modules.ast_engine.c_frontend import parse_functions, AST_AVAILABLE


class InterproceduralAnalyzer:
    """
    Analyse interprocédurale — détecte les vulnérabilités
    qui se propagent à travers plusieurs appels de fonctions.
    """

    SOURCES = {
        "argv", "getenv", "fgets", "gets", "recv",
        "read", "scanf", "fread", "copy_from_user",
    }

    SINKS = {
        "gets":    ("CRITICAL", "Stack BOF"),
        "strcpy":  ("HIGH",     "Buffer Overflow"),
        "sprintf": ("HIGH",     "Buffer Overflow"),
        "system":  ("CRITICAL", "Command Injection"),
        "exec":    ("CRITICAL", "Code Execution"),
        "printf":  ("HIGH",     "Format String"),
        "memcpy":  ("MEDIUM",   "Possible Overflow"),
    }

    def __init__(self):
        self.functions: Dict[str, Dict] = {}
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)
        self.taint_summary: Dict[str, Dict] = {}

    def analyze(self, code: str, filename: str = "unknown") -> Dict:
        """Analyser le code de façon interprocédurale."""
        # 1. Extraire les fonctions et leur signature
        self.functions = self._extract_functions(code)

        # 2. Construire le call graph
        self._build_call_graph(code)

        # 3. Calculer le taint summary pour chaque fonction
        self._compute_taint_summaries(code)

        # 4. Propager le taint interprocéduralement
        findings = self._propagate_interprocedural(filename)

        return {
            "functions":    list(self.functions.keys()),
            "call_graph":   {k: list(v) for k,v in self.call_graph.items()},
            "findings":     findings,
            "taint_summary": {
                k: v for k,v in self.taint_summary.items()
                if v.get("has_source") or v.get("has_sink")
            },
            "stats": {
                "functions_analyzed": len(self.functions),
                "cross_function_vulns": len(findings),
                "taint_propagated": sum(
                    1 for v in self.taint_summary.values()
                    if v.get("tainted_params")
                ),
            }
        }

    def _extract_functions(self, code: str) -> Dict:
        """Extraire les fonctions avec leurs paramètres.

        Chemin AST (tree-sitter) quand disponible : bornes de fonction et
        sites d'appel réels, insensibles aux commentaires/chaînes/#if 0.
        Repli sur l'extraction regex ci-dessous si tree-sitter-c n'est
        pas installé — comportement identique à l'ancienne version.
        """
        if AST_AVAILABLE:
            return self._extract_functions_ast(code)
        return self._extract_functions_regex(code)

    def _extract_functions_ast(self, code: str) -> Dict:
        functions = {}
        for name, fdef in parse_functions(code).items():
            call_names = [c.function_name for c in fdef.calls]
            functions[name] = {
                "params": fdef.param_names,
                "param_is_pointer": fdef.param_is_pointer,
                "line": fdef.start_line,
                "body": None,        # non requis en mode AST
                "calls_raw": fdef.calls,   # CallSite réels (pour le call graph)
                "calls": [],          # résolu dans _build_call_graph
                "has_source": any(cn in self.SOURCES for cn in call_names),
                "has_sink": any(cn in self.SINKS for cn in call_names),
            }
        return functions

    def _extract_functions_regex(self, code: str) -> Dict:
        """Ancien chemin regex (repli si tree-sitter-c est absent)."""
        functions = {}
        pattern   = re.compile(
            r'(?:[\w\*\s]+)\s+(\w+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )
        skip = {"if","while","for","switch","do","else"}

        for m in pattern.finditer(code):
            name   = m.group(1)
            params = m.group(2)
            if name in skip:
                continue

            line   = code[:m.start()].count('\n') + 1
            body   = self._get_body(code, m.end())
            params_list = [
                p.strip().split()[-1].lstrip('*')
                for p in params.split(',')
                if p.strip()
            ]

            functions[name] = {
                "params":  params_list,
                "line":    line,
                "body":    body,
                "calls":   [],
                "has_source": any(
                    re.search(rf'\b{s}\s*\(', body)
                    for s in self.SOURCES
                ),
                "has_sink": any(
                    re.search(rf'\b{s}\s*\(', body)
                    for s in self.SINKS
                ),
            }

        return functions

    def _get_body(self, code: str, start: int) -> str:
        """Extraire le corps d'une fonction."""
        depth = 1; pos = start
        while pos < len(code) and depth > 0:
            if code[pos] == '{':   depth += 1
            elif code[pos] == '}': depth -= 1
            pos += 1
        return code[start:pos-1]

    def _build_call_graph(self, code: str):
        """Construire le call graph entre fonctions."""
        if AST_AVAILABLE:
            for fname, finfo in self.functions.items():
                called_names = {c.function_name for c in finfo.get("calls_raw", [])}
                for callee in called_names:
                    if callee != fname and callee in self.functions:
                        self.call_graph[fname].add(callee)
                        finfo["calls"].append(callee)
            return
        for fname, finfo in self.functions.items():
            body = finfo["body"]
            for callee in self.functions:
                if callee != fname and re.search(rf'\b{callee}\s*\(', body):
                    self.call_graph[fname].add(callee)
                    finfo["calls"].append(callee)

    def _compute_taint_summaries(self, code: str):
        """Calculer le résumé de taint pour chaque fonction."""
        if AST_AVAILABLE:
            self._compute_taint_summaries_ast()
            return

        for fname, finfo in self.functions.items():
            body   = finfo["body"]
            params = finfo["params"]

            # Paramètres qui peuvent être taintés (par position)
            tainted_params = []
            for i, param in enumerate(params):
                # Un param est potentiellement tainté si c'est un ptr/char*
                if '*' in code[code.find(fname):code.find(fname)+200]:
                    tainted_params.append(i)
                elif param in ("input","buf","data","src","str","s","p"):
                    tainted_params.append(i)

            # Chercher si la fonction passe des params à des sinks
            reaches_sink = {}
            for sink, (sev, desc) in self.SINKS.items():
                if re.search(rf'\b{sink}\s*\([^)]*(?:'
                              + '|'.join(params) + r')[^)]*\)', body):
                    reaches_sink[sink] = (sev, desc)

            self.taint_summary[fname] = {
                "tainted_params":  tainted_params,
                "reaches_sink":    reaches_sink,
                "has_source":      finfo["has_source"],
                "has_sink":        finfo["has_sink"],
                "calls":           finfo["calls"],
            }

    def _compute_taint_summaries_ast(self):
        """
        Version AST : un paramètre est jugé potentiellement tainté s'il est
        un pointeur (fait réel extrait de la déclaration, plus le heuristique
        de nommage en repli) ; un sink n'est retenu que si un de ses
        arguments réels (identifiants de l'appel, pas une sous-chaîne de la
        ligne) correspond exactement à un nom de paramètre de la fonction.
        """
        for fname, finfo in self.functions.items():
            params = finfo["params"]
            calls = finfo.get("calls_raw", [])
            param_is_pointer = {}
            # param_is_pointer vient du FunctionDef d'origine ; on le
            # retrouve via une deuxième passe légère plutôt que de dupliquer
            # l'état — stocké directement sur finfo par _extract_functions_ast
            # si présent (voir ci-dessous).
            param_is_pointer = finfo.get("param_is_pointer", {})

            tainted_params = []
            for i, param in enumerate(params):
                if param_is_pointer.get(param):
                    tainted_params.append(i)
                elif param in ("input", "buf", "data", "src", "str", "s", "p"):
                    tainted_params.append(i)

            reaches_sink = {}
            for c in calls:
                if c.function_name not in self.SINKS:
                    continue
                # arguments réels de l'appel = identifiants trouvés dans le
                # texte des arguments ; on ne matche que des noms complets.
                arg_idents = set(re.findall(r'\b[A-Za-z_]\w*\b', c.arg_text))
                if arg_idents & set(params):
                    sev, desc = self.SINKS[c.function_name]
                    reaches_sink[c.function_name] = (sev, desc)

            self.taint_summary[fname] = {
                "tainted_params": tainted_params,
                "reaches_sink": reaches_sink,
                "has_source": finfo["has_source"],
                "has_sink": finfo["has_sink"],
                "calls": finfo["calls"],
            }

    def _calc_confidence(self, severity: str, chain_depth: int) -> float:
        """Confiance calculée (pas un lookup statique) : prior par
        sévérité, pénalisé par la profondeur de la chaîne d'appels
        (plus le chemin traverse de fonctions, plus il y a d'occasions
        qu'une validation intermédiaire non modélisée existe réellement),
        et légèrement remonté quand le call graph est AST-vérifié plutôt
        que reconstruit par regex."""
        base = {"CRITICAL": 0.80, "HIGH": 0.72, "MED": 0.60, "MEDIUM": 0.60, "LOW": 0.45}.get(
            str(severity).upper(), 0.50
        )
        base -= min((chain_depth - 2) * 0.06, 0.25)
        if AST_AVAILABLE:
            base += 0.08
        return round(max(0.2, min(base, 0.95)), 2)

    def _propagate_interprocedural(self, filename: str) -> List[Dict]:
        """Propager le taint à travers le call graph."""
        findings = []

        # Pour chaque fonction qui reçoit des données externes (source)
        source_funcs = [
            fname for fname, summary in self.taint_summary.items()
            if summary.get("has_source")
        ]

        for source_func in source_funcs:
            # BFS pour trouver des sinks accessibles
            visited = set()
            queue   = [(source_func, [source_func])]

            while queue:
                current, path = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                summary = self.taint_summary.get(current, {})

                # Vérifier si on atteint un sink dans cette fonction
                for sink, (sev, desc) in summary.get("reaches_sink", {}).items():
                    if len(path) > 1:  # Chemin interprocédural
                        findings.append({
                            "severity":   sev,
                            "type":       f"Interprocedural: {source_func}→{current}→{sink}()",
                            "file":       filename,
                            "line":       self.functions.get(current, {}).get("line"),
                            "description": (
                                f"Tainted data from {source_func}() "
                                f"propagates through {' → '.join(path)} "
                                f"to reach dangerous sink {sink}(). {desc}"
                            ),
                            "call_chain":   " → ".join(path),
                            "chain_depth":  len(path),
                            "confidence":   self._calc_confidence(sev, len(path)),
                            "ast_verified": bool(AST_AVAILABLE),
                            "recommendation": (
                                f"Validate input in {source_func}() before "
                                f"passing to {path[1]}(). "
                                f"Use safe alternatives for {sink}()."
                            ),
                        })

                # Continuer le BFS
                for callee in self.call_graph.get(current, set()):
                    if callee not in visited:
                        queue.append((callee, path + [callee]))

        # Dédupliquer
        seen    = set()
        unique  = []
        for f in findings:
            key = f["call_chain"]
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
