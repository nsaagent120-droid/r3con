"""Compatibility facade for the canonical AST-first call graph - FIXED P3
Fixes: DOT escaping, BFS depth limit, size limits
"""
from collections import deque
import re
from typing import Optional
from modules.analysis.interprocedural import InterproceduralAnalyzer

MAX_FUNCTIONS_DOT = 200
MAX_EDGES_DOT = 500
MAX_BFS_DEPTH = 20
MAX_CHAIN_LEN = 50


def _escape_dot_label(name: str) -> str:
    """Escape DOT label to prevent injection."""
    if not name or not isinstance(name, str):
        return "unknown"
    # Limit length
    if len(name) > 100:
        name = name[:100]
    # Escape quotes and special chars
    # DOT labels in quotes: escape " and \ and newlines
    name = name.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")
    # Remove control chars
    name = "".join(c for c in name if c.isprintable() or c in " _-")
    return name


def _validate_func_name(name: str) -> bool:
    """Validate function name."""
    if not name or not isinstance(name, str):
        return False
    if len(name) > 200 or "\x00" in name:
        return False
    # Allow alphanumeric, _, :, etc but not shell metachars
    if any(c in name for c in ";|&`$()><\n\r"):
        return False
    return True


class CallGraphAnalyzer(InterproceduralAnalyzer):
    """Single call-graph implementation with a backwards-compatible API - FIXED P3."""

    def analyze(self, code: str, filename: str = "unknown"):
        if not code or len(code) > 2 * 1024 * 1024:
            return {"functions": [], "call_graph": {}, "findings": [], "taint_summary": {},
                    "stats": {"functions_analyzed": 0, "cross_function_vulns": 0, "taint_propagated": 0},
                    "function_count": 0, "dangerous_paths": [], "error": "invalid_code"}

        result = super().analyze(code, filename)
        result["function_count"] = len(result.get("functions", []))
        result["dangerous_paths"] = []

        # Limit findings
        findings = result.get("findings", [])[:100]

        for finding in findings:
            try:
                chain = finding.get("call_chain", "").split(" → ")
                # Validate chain
                if len(chain) > MAX_CHAIN_LEN:
                    chain = chain[:MAX_CHAIN_LEN]
                # Validate each func in chain
                chain = [c[:100] for c in chain if _validate_func_name(c) or c == "unknown"]

                result["dangerous_paths"].append({
                    "source": chain[0] if chain else "unknown",
                    "sink": finding.get("type", "").split("→")[-1].rstrip("()")[:100],
                    "path": chain[:20],
                    "depth": len(chain),
                    "severity": finding.get("severity", "INFO"),
                    "interprocedural": len(chain) > 2,
                })
                if len(result["dangerous_paths"]) >= 50:
                    break
            except Exception:
                continue

        result["stats"].update({
            "total_functions": len(result["functions"]),
            "dangerous_paths": len(result["dangerous_paths"])
        })
        return result

    def visualize_dot(self) -> str:
        """Generate DOT - FIXED escaping, limits."""
        lines = ["digraph CallGraph {", "  rankdir=LR;", "  node [shape=box];"]

        # Limit functions
        funcs = list(self.functions.keys())[:MAX_FUNCTIONS_DOT]

        for function in funcs:
            if not _validate_func_name(function):
                continue
            summary = self.taint_summary.get(function, {})
            color = "red" if summary.get("has_sink") else "yellow" if summary.get("has_source") else "lightblue"
            escaped = _escape_dot_label(function)
            lines.append(f'  "{escaped}" [fillcolor={color}, style=filled];')

        edge_count = 0
        for caller, callees in self.call_graph.items():
            if edge_count >= MAX_EDGES_DOT:
                break
            if not _validate_func_name(caller) or caller not in funcs:
                continue
            caller_esc = _escape_dot_label(caller)
            for callee in list(callees)[:20]:  # Limit per caller
                if edge_count >= MAX_EDGES_DOT:
                    break
                if not _validate_func_name(callee):
                    continue
                callee_esc = _escape_dot_label(callee)
                lines.append(f'  "{caller_esc}" -> "{callee_esc}";')
                edge_count += 1

        lines.append("}")
        return "\n".join(lines)

    def get_call_chain(self, func_a: str, func_b: str) -> Optional[list]:
        """Get call chain with depth limit - FIXED."""
        if not _validate_func_name(func_a) or not _validate_func_name(func_b):
            return None

        if func_a == func_b:
            return [func_a]

        # BFS with depth limit
        queue, visited = deque([(func_a, [func_a])]), {func_a}

        while queue:
            node, path = queue.popleft()

            # Depth limit
            if len(path) >= MAX_BFS_DEPTH:
                continue

            # Limit total visited to prevent explosion
            if len(visited) > 10000:
                break

            for neighbor in self.call_graph.get(node, set()):
                if not _validate_func_name(neighbor):
                    continue
                if neighbor == func_b:
                    result = path + [func_b]
                    if len(result) > MAX_CHAIN_LEN:
                        return result[:MAX_CHAIN_LEN]
                    return result
                if neighbor not in visited:
                    visited.add(neighbor)
                    # Limit path length
                    if len(path) < MAX_CHAIN_LEN:
                        queue.append((neighbor, path + [neighbor]))

        return None
