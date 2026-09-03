"""
r3con - Taint Analysis Module
Tracks data flow from attacker-controlled sources to dangerous sinks.
Identifies exploitable information flow paths.
"""

import re
from typing import List, Dict, Set
from dataclasses import dataclass

from modules.ast_engine.c_frontend import parse_functions, AST_AVAILABLE


@dataclass
class TaintSource:
    """Source of tainted data."""
    name: str
    pattern: str
    file: str
    line: int


@dataclass
class TaintSink:
    """Dangerous use of tainted data."""
    name: str
    pattern: str
    file: str
    line: int
    vulnerability_type: str


class TaintAnalyzer:
    """Perform taint analysis on code."""

    # Data sources (attacker-controlled)
    SOURCES = {
        "argv": re.compile(r"argv\s*\[\s*\d+\s*\]"),
        "stdin": re.compile(r"(fgets|gets|scanf|cin)\s*\("),
        "network": re.compile(r"(recv|read)\s*\("),
        "file": re.compile(r"(fopen|open|read)\s*\("),
        "env": re.compile(r"getenv\s*\("),
        "user": re.compile(r"copy_from_user\s*\("),
        "form": re.compile(r"(POST|GET|request)\s*\["),
    }

    # Dangerous operations (sinks)
    SINKS = {
        "buffer_write": (re.compile(r"(strcpy|strcat|sprintf|memcpy)\s*\("), "BOF"),
        "command_exec": (re.compile(r"(system|exec|popen)\s*\("), "Command Injection"),
        "format_string": (re.compile(r"printf\s*\(\s*\w+"), "Format String"),
        "sql_query": (re.compile(r"(execute|query|exec)\s*\([^)]*\+"), "SQL Injection"),
        "xpath_eval": (re.compile(r"xpath\s*\("), "XPath Injection"),
        "malloc_size": (re.compile(r"malloc\s*\(\s*\w+\s*[\*+]"), "Integer Overflow"),
        "file_open": (re.compile(r"(open|fopen)\s*\(\s*\w+"), "Path Traversal"),
    }

    def __init__(self):
        self.flows = []
        self.tainted_vars = {}

    def analyze(self, code: str, filename: str = "unknown") -> List[Dict]:
        """Perform taint analysis on code.

        Chemin AST (tree-sitter-c) quand disponible : le traçage se fait
        par identifiant réel, fonction par fonction, dans l'ordre des
        instructions (assignments/appels réels), plutôt que par simple
        co-occurrence textuelle dans une fenêtre de lignes. Repli sur
        l'ancien chemin regex si tree-sitter-c n'est pas installé.
        """
        if AST_AVAILABLE:
            ast_flows = self._analyze_ast(code, filename)
            if ast_flows is not None:
                return ast_flows

        lines = code.splitlines()
        flows = []

        # Find all sources
        sources = self._find_sources(code, lines, filename)

        # Find all sinks
        sinks = self._find_sinks(code, lines, filename)

        # Trace flows from sources to sinks
        for source in sources:
            for sink in sinks:
                flow = self._trace_flow(code, source, sink, lines)
                if flow:
                    flows.append(flow)

        return flows

    def _find_sources(self, code: str, lines: List[str], filename: str) -> List[TaintSource]:
        """Find all tainted data sources."""
        sources = []

        for source_name, pattern in self.SOURCES.items():
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    # Extract variable name if possible
                    var_match = re.search(r"(\w+)\s*=", line)
                    var_name = var_match.group(1) if var_match else f"tainted_{i}"

                    sources.append(TaintSource(
                        name=f"{source_name}_{var_name}",
                        pattern=pattern.pattern,
                        file=filename,
                        line=i
                    ))
                    self.tainted_vars[var_name] = True

        return sources

    def _find_sinks(self, code: str, lines: List[str], filename: str) -> List[TaintSink]:
        """Find all dangerous sink operations."""
        sinks = []

        for sink_type, (pattern, vuln_type) in self.SINKS.items():
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    sinks.append(TaintSink(
                        name=sink_type,
                        pattern=pattern.pattern,
                        file=filename,
                        line=i,
                        vulnerability_type=vuln_type
                    ))

        return sinks

    def _trace_flow(self, code: str, source: TaintSource, sink: TaintSink,
                     lines: List[str]) -> Dict:
        """Trace if data from source can reach sink."""
        path = []
        exploitable = False

        # Extract variable names from source
        source_vars = self._extract_vars(source.pattern, lines[source.line - 1])

        # Trace through code
        current_vars = source_vars.copy()
        line_range = range(source.line, sink.line)

        for i in line_range:
            if i - 1 < len(lines):
                line = lines[i - 1]

                # Check for variable assignments/transformations
                for var in current_vars:
                    # Simple assignment tracking
                    if re.search(rf"{var}\s*=\s*", line):
                        path.append((i, line.strip()))

                    # Check for sanitization
                    if self._is_sanitized(line, var):
                        return None  # Data is sanitized, no exploit

                    # Check if variable is passed to dangerous function
                    if re.search(rf"(strcpy|system|exec|printf)\s*\(\s*[^)]*{var}", line):
                        exploitable = True

        # Check if sink receives tainted data
        sink_line = lines[sink.line - 1] if sink.line - 1 < len(lines) else ""
        for var in current_vars:
            if var in sink_line or any(v in sink_line for v in source_vars):
                path.append((sink.line, sink_line.strip()))

                return {
                    "source_file": source.file,
                    "source_line": source.line,
                    "source_name": source.name,
                    "sink_file": sink.file,
                    "sink_line": sink.line,
                    "sink_name": sink.name,
                    "vulnerability_type": sink.vulnerability_type,
                    "path_length": len(path),
                    "path": path,
                    "exploitable": exploitable or (sink.line - source.line < 5),
                    "confidence": self._calc_confidence(source, sink, len(path))
                }

        return None

    def _analyze_ast(self, code: str, filename: str):
        """
        Traçage par identifiant réel, borné à la fonction (pas de faux flux
        inter-fonctions qui partageraient juste un nom de variable local).
        Rejoue les affectations et appels DANS L'ORDRE réel du code (fourni
        par l'AST, indépendant des commentaires/chaînes), et invalide la
        teinte d'une variable dès qu'un sanitizer apparaît sur son chemin.

        Retourne None si le fichier ne contient aucune fonction C valide
        (ex: extrait non parseable) — l'appelant retombe alors sur le
        chemin regex existant plutôt que de renvoyer une liste vide.
        """
        functions = parse_functions(code)
        if not functions:
            return None

        flows: List[Dict] = []
        SOURCE_FUNCS = {"fgets", "gets", "scanf", "recv", "read", "fopen",
                         "open", "getenv", "recvfrom"}
        SINK_FUNCS = {
            "strcpy": "BOF", "strcat": "BOF", "sprintf": "BOF", "memcpy": "BOF",
            "system": "Command Injection", "exec": "Command Injection",
            "execve": "Command Injection", "popen": "Command Injection",
            "printf": "Format String",
        }
        SANITIZER_FUNCS = {"strlen", "strnlen", "strncpy", "strncat",
                            "snprintf", "validate", "check", "filter",
                            "escape", "sanitize"}
        # Fonctions qui ÉCRIVENT dans leur 1er argument (out-param) : le
        # flux de teinte doit se propager vers ce paramètre même quand
        # l'écriture ne prend pas la forme `x = f(...)` (cas majoritaire
        # en C : sprintf(dst, ...), strcpy(dst, src), memcpy(dst, src, n)).
        WRITE_SINK_FUNCS = {"sprintf", "strcpy", "strcat", "memcpy", "memmove"}
        WRITE_SANITIZING_FUNCS = {"strncpy", "strncat", "snprintf"}
        # Sources qui écrivent le résultat dans leur 1er argument plutôt que
        # via une valeur de retour assignée (le style dominant en C réel :
        # `fgets(buf, n, stdin);`, jamais `buf = fgets(...)`).
        WRITE_SOURCE_FUNCS = {"fgets", "recv", "recvfrom", "read", "fread"}

        def _dest_and_src_idents(arg_text: str):
            dest_match = re.match(r"\(\s*([A-Za-z_]\w*)", arg_text)
            dest = dest_match.group(1) if dest_match else None
            all_idents = set(re.findall(r"\b[A-Za-z_]\w*\b", arg_text))
            src_idents = all_idents - {dest} if dest else all_idents
            return dest, src_idents

        for fname, fdef in functions.items():
            # Timeline unique (assignment | call), triée par ligne, pour
            # rejouer le flux dans l'ordre réel des instructions.
            events = (
                [("assign", a.line, a) for a in fdef.assignments]
                + [("call", c.line, c) for c in fdef.calls]
            )
            events.sort(key=lambda e: e[1])

            tainted: Dict[str, Dict] = {}   # var -> {origin_line, origin_name, hops}

            for kind, line, ev in events:
                if kind == "assign":
                    rhs = ev.rhs_text or ""
                    call_in_rhs = re.match(r"\s*([A-Za-z_]\w*)\s*\(", rhs)
                    rhs_ident = call_in_rhs.group(1) if call_in_rhs else None

                    if rhs_ident in SOURCE_FUNCS:
                        tainted[ev.var_name] = {
                            "origin_line": line, "origin_name": rhs_ident, "hops": 0,
                        }
                    elif rhs_ident in SANITIZER_FUNCS:
                        tainted.pop(ev.var_name, None)
                    else:
                        rhs_idents = set(re.findall(r"\b[A-Za-z_]\w*\b", rhs))
                        carried = rhs_idents & tainted.keys()
                        if carried:
                            src = min((tainted[v] for v in carried), key=lambda d: d["origin_line"])
                            tainted[ev.var_name] = {
                                "origin_line": src["origin_line"],
                                "origin_name": src["origin_name"],
                                "hops": src["hops"] + 1,
                            }
                        else:
                            tainted.pop(ev.var_name, None)

                elif kind == "call":
                    if ev.function_name in WRITE_SOURCE_FUNCS:
                        dest, _ = _dest_and_src_idents(ev.arg_text)
                        if dest:
                            tainted[dest] = {
                                "origin_line": line,
                                "origin_name": ev.function_name,
                                "hops": 0,
                            }
                        continue

                    if ev.function_name in SOURCE_FUNCS:
                        continue  # style `x = f(...)` déjà capturé par la branche assign

                    if ev.function_name in WRITE_SANITIZING_FUNCS:
                        dest, _ = _dest_and_src_idents(ev.arg_text)
                        if dest:
                            tainted.pop(dest, None)
                    elif ev.function_name in WRITE_SINK_FUNCS:
                        dest, src_idents = _dest_and_src_idents(ev.arg_text)
                        carried = src_idents & tainted.keys()
                        if dest and carried:
                            src = min((tainted[v] for v in carried), key=lambda d: d["origin_line"])
                            tainted[dest] = {
                                "origin_line": src["origin_line"],
                                "origin_name": src["origin_name"],
                                "hops": src["hops"] + 1,
                            }
                        elif dest:
                            tainted.pop(dest, None)

                    if ev.function_name in SINK_FUNCS:
                        arg_idents = set(re.findall(r"\b[A-Za-z_]\w*\b", ev.arg_text))
                        hit = arg_idents & tainted.keys()
                        if hit:
                            info = min((tainted[v] for v in hit), key=lambda d: d["origin_line"])
                            hops = info["hops"]
                            flows.append({
                                "source_file": filename,
                                "source_line": info["origin_line"],
                                "source_name": info["origin_name"],
                                "sink_file": filename,
                                "sink_line": line,
                                "sink_name": ev.function_name,
                                "vulnerability_type": SINK_FUNCS[ev.function_name],
                                "path_length": hops + 1,
                                "path": [(info["origin_line"], info["origin_name"]),
                                         (line, ev.function_name)],
                                "exploitable": hops <= 2,
                                "confidence": self._calc_confidence_ast(
                                    SINK_FUNCS[ev.function_name], hops),
                                "enclosing_function": fname,
                                "analysis_kind": "ast_verified",
                            })
        return flows

    def _calc_confidence_ast(self, vuln_type: str, hops: int) -> float:
        """Confiance calculée à partir de faits réels (pas un lookup
        statique) : nombre de réaffectations traversées entre la source et
        le sink, et gravité intrinsèque du type de sink. Chemin AST vérifié
        => pas de pénalité de bruit texte, donc plancher plus haut que le
        chemin regex."""
        confidence = 0.65
        confidence -= min(hops * 0.08, 0.3)
        if vuln_type in ("BOF", "Command Injection"):
            confidence += 0.15
        return max(0.2, min(confidence, 0.97))

    def _extract_vars(self, pattern: str, line: str) -> Set[str]:
        """Extract variable names from a pattern match."""
        vars_found = set()

        # Try to find assignments
        m = re.search(r"(\w+)\s*=", line)
        if m:
            vars_found.add(m.group(1))

        # Try to find function arguments
        m = re.search(r"\(([^)]+)\)", line)
        if m:
            args = [a.strip() for a in m.group(1).split(",")]
            for arg in args:
                var = arg.split()[0] if arg else ""
                if var and var.isidentifier():
                    vars_found.add(var)

        return vars_found

    def _is_sanitized(self, line: str, var: str) -> bool:
        """Check if a variable is sanitized/validated."""
        sanitizers = [
            r"strlen\s*\(",
            r"strnlen\s*\(",
            r"strncpy\s*\(",
            r"strncat\s*\(",
            r"snprintf\s*\(",
            r"validate\s*\(",
            r"check\s*\(",
            r"filter\s*\(",
            r"escape\s*\(",
            r"sanitize\s*\(",
        ]

        for san in sanitizers:
            if re.search(san + rf".*{var}", line):
                return True

        return False

    def _calc_confidence(self, source: TaintSource, sink: TaintSink,
                          path_length: int) -> float:
        """Calculate confidence in the exploitation path (0-1)."""
        confidence = 0.5

        # Direct flow (no intermediate transformations) = higher confidence
        if path_length <= 2:
            confidence += 0.4

        # Certain sink types are more reliably exploitable
        if sink.vulnerability_type in ("BOF", "Command Injection"):
            confidence += 0.2

        return min(confidence, 1.0)


class ExploitChainBuilder:
    """Build multi-step exploitation chains from taint flows."""

    def build_chains(self, taint_flows: List[Dict]) -> List[Dict]:
        """Build exploitation chains from taint flows."""
        chains = []

        # Single-step chains
        for flow in taint_flows:
            if flow["exploitable"]:
                chains.append({
                    "name": f"{flow['source_name']} → {flow['vulnerability_type']}",
                    "steps": [flow],
                    "impact": self._calc_impact(flow["vulnerability_type"]),
                    "confidence": flow["confidence"],
                    "difficulty": "Easy" if flow["path_length"] < 3 else "Medium"
                })

        # Multi-step chains (combine exploits)
        if len(taint_flows) >= 2:
            for i, f1 in enumerate(taint_flows):
                for f2 in taint_flows[i+1:]:
                    # Check if f1 output can be input to f2
                    if f1["sink_line"] < f2["source_line"]:
                        chain = {
                            "name": f"{f1['vulnerability_type']} → {f2['vulnerability_type']}",
                            "steps": [f1, f2],
                            "impact": "Remote Code Execution",
                            "confidence": min(f1["confidence"] * f2["confidence"], 1.0),
                            "difficulty": "Hard",
                            "multi_step": True
                        }
                        chains.append(chain)

        return chains

    def _calc_impact(self, vuln_type: str) -> str:
        """Calculate impact based on vulnerability type."""
        impacts = {
            "BOF": "Memory Corruption / Code Execution",
            "Command Injection": "Remote Code Execution",
            "SQL Injection": "Database Compromise",
            "Path Traversal": "Arbitrary File Access",
            "XPath Injection": "Information Disclosure",
            "Format String": "Memory Leak / Code Execution",
            "Integer Overflow": "Heap Corruption",
        }
        return impacts.get(vuln_type, "Information Disclosure")
