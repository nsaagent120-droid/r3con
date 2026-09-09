"""
r3con v6.1 - Knowledge Graph PRO renforcé
Graphe de connaissances: findings, IoCs, workspaces, CVEs, ATT&CK
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict, Any, Set
from collections import defaultdict
import hashlib
from datetime import datetime, timezone

class KnowledgeGraph:
    """Graphe de connaissances PRO."""

    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path.home() / ".r3con" / "knowledge"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.graph_file = self.base_dir / "knowledge_graph.json"
        self.nodes: Dict[str, Dict] = {}
        self.edges: List[Dict] = []
        self._load()

    def _load(self):
        if self.graph_file.is_file():
            try:
                data = json.loads(self.graph_file.read_text(encoding="utf-8"))
                self.nodes = data.get("nodes", {})
                self.edges = data.get("edges", [])
            except Exception:
                self.nodes = {}
                self.edges = []

    def _save(self):
        data = {
            "nodes": self.nodes,
            "edges": self.edges,
            "updated": datetime.now(timezone.utc).isoformat(),
            "stats": self.get_stats(),
        }
        self.graph_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def add_finding(self, finding: Dict[str, Any], workspace: str = "global", source: str = "manual"):
        """Ajoute finding au graphe."""
        f_type = finding.get("type", "unknown")
        f_id = f"{f_type}:{finding.get('description','')[:50]}:{finding.get('file','')}"
        node_id = hashlib.md5(f_id.encode()).hexdigest()[:16]

        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": "finding",
                "finding_type": f_type,
                "severity": finding.get("severity", "INFO"),
                "cwe": finding.get("cwe", ""),
                "description": finding.get("description", "")[:200],
                "workspaces": [workspace],
                "sources": [source],
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "count": 1,
            }
        else:
            # Update
            if workspace not in self.nodes[node_id]["workspaces"]:
                self.nodes[node_id]["workspaces"].append(workspace)
            if source not in self.nodes[node_id]["sources"]:
                self.nodes[node_id]["sources"].append(source)
            self.nodes[node_id]["count"] += 1

        # Add edges to workspace node
        ws_node_id = f"ws_{workspace}"
        if ws_node_id not in self.nodes:
            self.nodes[ws_node_id] = {
                "id": ws_node_id,
                "type": "workspace",
                "name": workspace,
                "findings": 1,
            }

        edge_id = f"{ws_node_id}->{node_id}"
        if not any(e["id"] == edge_id for e in self.edges):
            self.edges.append({
                "id": edge_id,
                "source": ws_node_id,
                "target": node_id,
                "type": "contains",
                "workspace": workspace,
            })

        self._save()
        return node_id

    def add_ioc(self, ioc_value: str, ioc_type: str, workspace: str = "global", related_finding: str = None):
        """Ajoute IoC au graphe."""
        node_id = f"ioc_{hashlib.md5(f'{ioc_type}:{ioc_value}'.encode()).hexdigest()[:12]}"

        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": "ioc",
                "ioc_type": ioc_type,
                "value": ioc_value,
                "workspaces": [workspace],
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "count": 1,
            }
        else:
            if workspace not in self.nodes[node_id]["workspaces"]:
                self.nodes[node_id]["workspaces"].append(workspace)
            self.nodes[node_id]["count"] += 1

        # Edge workspace -> IoC
        ws_node_id = f"ws_{workspace}"
        edge_id = f"{ws_node_id}->{node_id}"
        if not any(e["id"] == edge_id for e in self.edges):
            self.edges.append({
                "id": edge_id,
                "source": ws_node_id,
                "target": node_id,
                "type": "contains_ioc",
            })

        # Edge IoC -> finding if related
        if related_finding:
            finding_node_id = hashlib.md5(related_finding.encode()).hexdigest()[:16]
            edge_id2 = f"{node_id}->{finding_node_id}"
            if not any(e["id"] == edge_id2 for e in self.edges):
                self.edges.append({
                    "id": edge_id2,
                    "source": node_id,
                    "target": finding_node_id,
                    "type": "related_to",
                })

        self._save()
        return node_id

    def add_workspace_link(self, source_ws: str, target_ws: str, relation: str):
        """Ajoute lien workspace au graphe."""
        src_id = f"ws_{source_ws}"
        tgt_id = f"ws_{target_ws}"
        edge_id = f"{src_id}->{tgt_id}:{relation}"

        if not any(e["id"] == edge_id for e in self.edges):
            self.edges.append({
                "id": edge_id,
                "source": src_id,
                "target": tgt_id,
                "type": relation,
                "relation": relation,
            })

        self._save()

    def get_stats(self) -> Dict[str, Any]:
        """Stats graphe."""
        by_type = defaultdict(int)
        for node in self.nodes.values():
            by_type[node.get("type", "unknown")] += 1

        by_edge_type = defaultdict(int)
        for edge in self.edges:
            by_edge_type[edge.get("type", "unknown")] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "by_type": dict(by_type),
            "by_edge_type": dict(by_edge_type),
        }

    def find_related(self, node_id: str, depth: int = 2) -> Dict[str, Any]:
        """Trouve nodes liés (BFS)."""
        visited = set()
        queue = [(node_id, 0)]
        related = []

        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)

            if current != node_id and current in self.nodes:
                related.append({
                    "node": self.nodes[current],
                    "depth": d,
                })

            if d < depth:
                for edge in self.edges:
                    if edge["source"] == current and edge["target"] not in visited:
                        queue.append((edge["target"], d+1))
                    if edge["target"] == current and edge["source"] not in visited:
                        queue.append((edge["source"], d+1))

        return {
            "source": node_id,
            "depth": depth,
            "related": related,
            "total": len(related),
        }

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Recherche dans graphe."""
        results = []
        query_lower = query.lower()

        for node in self.nodes.values():
            # Search in description, type, value, etc.
            searchable = json.dumps(node).lower()
            if query_lower in searchable:
                results.append(node)

        return results[:50]

    def export(self, format: str = "json") -> str:
        """Export graphe."""
        if format == "json":
            return json.dumps({
                "nodes": list(self.nodes.values()),
                "edges": self.edges,
                "stats": self.get_stats(),
            }, indent=2, ensure_ascii=False)
        elif format == "dot":
            # Graphviz DOT format
            dot = "digraph KnowledgeGraph {\n"
            for node in self.nodes.values():
                label = node.get("finding_type") or node.get("value") or node.get("name") or node["id"][:8]
                color = "red" if node.get("severity") == "CRITICAL" else "orange" if node.get("severity") == "HIGH" else "lightblue"
                dot += f'  "{node["id"]}" [label="{label[:20]}", color={color}];\n'
            for edge in self.edges:
                dot += f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge.get("type","")}"];\n'
            dot += "}\n"
            return dot
        return ""
