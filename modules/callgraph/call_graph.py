"""Compatibility facade for the canonical AST-first call graph."""
from collections import deque
from typing import Optional
from modules.analysis.interprocedural import InterproceduralAnalyzer

class CallGraphAnalyzer(InterproceduralAnalyzer):
    """Single call-graph implementation with a backwards-compatible API."""
    def analyze(self, code: str, filename: str = "unknown"):
        result = super().analyze(code, filename)
        result["function_count"] = len(result.get("functions", []))
        result["dangerous_paths"] = []
        for finding in result.get("findings", []):
            chain = finding.get("call_chain", "").split(" → ")
            result["dangerous_paths"].append({
                "source": chain[0] if chain else "unknown",
                "sink": finding.get("type", "").split("→")[-1].rstrip("()"),
                "path": chain,
                "depth": len(chain),
                "severity": finding.get("severity", "INFO"),
                "interprocedural": len(chain) > 2,
            })
        result["stats"].update({"total_functions": len(result["functions"]), "dangerous_paths": len(result["dangerous_paths"])})
        return result

    def visualize_dot(self) -> str:
        lines = ["digraph CallGraph {", "  rankdir=LR;"]
        for function in self.functions:
            summary = self.taint_summary.get(function, {})
            color = "red" if summary.get("has_sink") else "yellow" if summary.get("has_source") else "lightblue"
            lines.append(f'  "{function}" [fillcolor={color}, style=filled];')
        for caller, callees in self.call_graph.items():
            for callee in callees:
                lines.append(f'  "{caller}" -> "{callee}";')
        lines.append("}")
        return "\n".join(lines)

    def get_call_chain(self, func_a: str, func_b: str) -> Optional[list]:
        if func_a == func_b:
            return [func_a]
        queue, visited = deque([(func_a, [func_a])]), {func_a}
        while queue:
            node, path = queue.popleft()
            for neighbor in self.call_graph.get(node, set()):
                if neighbor == func_b:
                    return path + [func_b]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return None
