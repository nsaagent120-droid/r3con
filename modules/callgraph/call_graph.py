"""
r3con v6.1 - Call Graph PRO renforcé
Graphe d'appels + intégration pipeline + visualisation
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Set
from collections import defaultdict
import json

class CallGraph:
    """Call Graph PRO."""

    def __init__(self):
        self.functions: Dict[str, Dict] = {}
        self.calls: List[Dict] = []
        self.graph: Dict[str, Set[str]] = defaultdict(set)

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyse fichier source et construit call graph."""
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            code = path.read_text(encoding="utf-8", errors="ignore")[:500000]
        except Exception as e:
            return {"status": "error", "error": str(e)}

        # Extract functions
        func_pattern = re.compile(r'(?:[a-zA-Z_][\w\*\s]*?)\s+([a-zA-Z_]\w*)\s*\([^)]{0,500}\)\s*\{', re.MULTILINE)
        functions = {}
        for match in func_pattern.finditer(code):
            name = match.group(1)
            if name in ('if', 'while', 'for', 'switch', 'return', 'sizeof'):
                continue
            start = match.end()
            # Find body
            depth = 1
            pos = start
            max_search = min(len(code), start + 20000)
            while pos < max_search and depth > 0:
                if code[pos] == '{':
                    depth += 1
                elif code[pos] == '}':
                    depth -= 1
                pos += 1
            body = code[start:pos-1] if depth == 0 else code[start:max_search]
            functions[name] = {
                "name": name,
                "body": body[:5000],
                "calls": [],
                "line": code[:match.start()].count('\n') + 1,
            }

        # Extract calls per function
        for func_name, func_info in functions.items():
            body = func_info["body"]
            # Find function calls in body
            call_pattern = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
            called = set()
            for call_match in call_pattern.finditer(body):
                called_name = call_match.group(1)
                if called_name != func_name and called_name in functions:
                    called.add(called_name)
                    self.graph[func_name].add(called_name)
                    self.calls.append({
                        "caller": func_name,
                        "callee": called_name,
                        "file": str(path),
                    })
            func_info["calls"] = list(called)

        self.functions = functions

        # Find entry points and dangerous sinks
        entry_points = [name for name in functions if name in ('main', 'start', 'init', 'handle', 'process')]
        dangerous_sinks = []
        dangerous_funcs = {'gets', 'strcpy', 'strcat', 'sprintf', 'system', 'exec', 'printf'}

        for func_name, func_info in functions.items():
            for sink in dangerous_funcs:
                if sink in func_info["body"]:
                    dangerous_sinks.append({
                        "function": func_name,
                        "sink": sink,
                        "line": func_info["line"],
                    })

        # Find paths from entry to dangerous
        paths = self._find_paths_to_sinks(entry_points, dangerous_sinks)

        return {
            "status": "ok",
            "engine": "call_graph",
            "file": str(path),
            "functions": len(functions),
            "calls": len(self.calls),
            "entry_points": entry_points,
            "dangerous_sinks": dangerous_sinks,
            "paths_to_sinks": paths,
            "graph": {k: list(v) for k, v in self.graph.items()},
            "findings": self._graph_to_findings(paths, str(path)),
        }

    def _find_paths_to_sinks(self, entry_points: List[str], sinks: List[Dict]) -> List[Dict[str, Any]]:
        """Trouve chemins depuis entry points vers sinks dangereux."""
        paths = []

        for entry in entry_points:
            for sink_info in sinks:
                sink_func = sink_info["function"]
                # BFS from entry to sink_func
                visited = set()
                queue = [(entry, [entry])]

                while queue:
                    current, path = queue.pop(0)
                    if current in visited:
                        continue
                    visited.add(current)

                    if current == sink_func:
                        paths.append({
                            "entry": entry,
                            "sink": sink_info["sink"],
                            "sink_function": sink_func,
                            "path": path,
                            "length": len(path),
                            "severity": "CRITICAL" if sink_info["sink"] in ('gets', 'system') else "HIGH",
                        })
                        break

                    for callee in self.graph.get(current, []):
                        if callee not in visited and len(path) < 10:
                            queue.append((callee, path + [callee]))

        return paths[:20]

    def _graph_to_findings(self, paths: List[Dict], file: str) -> List[Dict[str, Any]]:
        """Convertit chemins en findings."""
        findings = []
        for path in paths:
            findings.append({
                "type": f"CallGraph: {path['entry']} -> {path['sink']}()",
                "severity": path["severity"],
                "file": file,
                "description": f"Chemin d'appel: {' -> '.join(path['path'])} atteint sink dangereux {path['sink']}() dans {path['sink_function']}()",
                "path": path["path"],
                "sink": path["sink"],
                "recommendation": f"Vérifier validation avant {path['sink']}() dans chemin depuis {path['entry']}",
            })
        return findings

    def export_dot(self) -> str:
        """Export Graphviz DOT."""
        dot = "digraph CallGraph {\n"
        dot += "  rankdir=LR;\n"
        for caller, callees in self.graph.items():
            for callee in callees:
                dot += f'  "{caller}" -> "{callee}";\n'
        dot += "}\n"
        return dot

    def export_json(self) -> Dict[str, Any]:
        """Export JSON."""
        return {
            "functions": list(self.functions.keys()),
            "calls": self.calls,
            "graph": {k: list(v) for k, v in self.graph.items()},
        }


# Backward compatibility alias for tests
class CallGraphAnalyzer:
    """Compat wrapper - delegates to CallGraph + simple analysis."""

    def analyze(self, code: str, file_name: str = "test.c") -> Dict[str, Any]:
        import tempfile, os
        # Write code to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as tf:
            tf.write(code)
            tf_path = tf.name
        try:
            cg = CallGraph()
            result = cg.analyze_file(tf_path)
            # Build call_graph dict format expected by old test
            call_graph = result.get("graph", {})
            return {
                "call_graph": call_graph,
                "dangerous_paths": result.get("paths_to_sinks", []),
                "functions": result.get("functions", 0),
                "findings": result.get("findings", []),
            }
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        cg = CallGraph()
        return cg.analyze_file(file_path)
