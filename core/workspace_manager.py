"""
r3con v5.2.0 PRO - Workspace Manager
Système d'espaces de travail intelligents, cloisonnés, fédérés et connectés

Concepts:
- Workspace = espace de travail par tâche (binary, firmware, apk, bugbounty, exploit...)
- Chaque workspace a son propre profil → outils prioritaires, mais tous les 35+ accessibles
- Cloisonnement hybride: isolation par défaut, mais import/link/share explicite
- Fédération: fork, merge, liens typés, partage sélectif targets/findings/artifacts/notes
- Graphe de workspaces avec relations
"""
from __future__ import annotations

import json
import shutil
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
import os

# Relations types for workspace links
RELATION_TYPES = {
    "depends_on": "Dépend de (prérequis)",
    "shares_target_with": "Partage cible avec",
    "derived_from": "Dérivé de (fork)",
    "correlates_with": "Corrélé avec (firmware<->pcap, etc.)",
    "parent": "Parent",
    "child": "Enfant",
    "merged_from": "Fusionné depuis",
    "references": "Référence",
}

WORKSPACE_TYPES = {
    "binary": {"profile": "binary", "description": "Analyse binaire ELF/PE/MachO", "priority_tools": ["checksec", "ropper", "one_gadget", "r2", "ghidra", "objdump"]},
    "firmware": {"profile": "firmware", "description": "Analyse firmware embarqué", "priority_tools": ["binwalk", "firmwalker", "strings", "r2"]},
    "apk": {"profile": "apk", "description": "Analyse APK Android", "priority_tools": ["jadx", "apktool", "apksigner", "dex2jar"]},
    "network": {"profile": "network", "description": "Analyse réseau PCAP/live", "priority_tools": ["tshark", "zeek", "tcpdump", "capinfos"]},
    "source": {"profile": "deep", "description": "Audit code source", "priority_tools": ["semgrep", "yara"]},
    "bugbounty": {"profile": "bugbounty", "description": "Bug bounty / 0day research", "priority_tools": ["checksec", "r2", "ghidra", "strings", "yara"]},
    "exploit": {"profile": "exploit", "description": "Exploitation & ROP", "priority_tools": ["ropper", "one_gadget", "checksec", "r2", "gdb", "pwndbg"]},
    "forensics": {"profile": "full", "description": "Forensics & investigation", "priority_tools": ["binwalk", "tshark", "strings", "yara", "ssdeep"]},
    "custom": {"profile": "full", "description": "Espace custom", "priority_tools": []},
}


@dataclass
class WorkspaceLink:
    target: str  # target workspace name
    relation: str  # relation type from RELATION_TYPES
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""
    shared_items: List[str] = field(default_factory=list)  # ["targets", "findings", "artifacts", "notes"]
    bidirectional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "WorkspaceLink":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class WorkspaceTarget:
    path: str
    sha256: str
    kind: str
    size: int
    added_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    analysis_results: List[str] = field(default_factory=list)  # paths to result JSONs
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Workspace:
    """Un espace de travail intelligent, cloisonné et fédéré."""

    def __init__(self, name: str, base_dir: Optional[Path] = None):
        self.name = name
        self.base_dir = base_dir or Path.home() / ".r3con" / "workspaces"
        self.path = self.base_dir / name
        self.meta_path = self.path / "workspace.json"
        self.targets_path = self.path / "targets.json"
        self.findings_path = self.path / "findings.json"
        self.links_path = self.path / "links.json"
        self.notes_path = self.path / "notes.md"
        self.artifacts_dir = self.path / "artifacts"
        self.shared_dir = self.path / "shared"

        self._meta: Optional[Dict[str, Any]] = None

    def exists(self) -> bool:
        return self.path.is_dir() and self.meta_path.is_file()

    def load_meta(self) -> Dict[str, Any]:
        if self._meta is None:
            if not self.meta_path.is_file():
                raise FileNotFoundError(f"Workspace {self.name} not found")
            self._meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        return self._meta

    def save_meta(self, meta: Dict[str, Any]):
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        self._meta = meta

    def create(self,
               ws_type: str = "custom",
               profile: Optional[str] = None,
               description: str = "",
               parent: Optional[str] = None,
               tags: Optional[List[str]] = None,
               config_overrides: Optional[Dict[str, Any]] = None,
               isolation: str = "private") -> Dict[str, Any]:

        if self.exists():
            raise FileExistsError(f"Workspace {self.name} already exists")

        ws_type = ws_type if ws_type in WORKSPACE_TYPES else "custom"
        type_info = WORKSPACE_TYPES[ws_type]
        profile = profile or type_info["profile"]

        self.path.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.shared_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc).isoformat()

        meta = {
            "name": self.name,
            "type": ws_type,
            "type_description": type_info["description"],
            "profile": profile,
            "priority_tools": type_info["priority_tools"],
            "description": description,
            "created_at": now,
            "updated_at": now,
            "parent": parent,
            "children": [],
            "tags": tags or [],
            "isolation": isolation,  # private, shared, public
            "config_overrides": config_overrides or {},
            "stats": {
                "targets": 0,
                "findings": 0,
                "artifacts": 0,
                "links": 0,
            },
            "version": "5.2.0",
        }

        self.save_meta(meta)

        # Init empty files
        self.targets_path.write_text("[]", encoding="utf-8")
        self.findings_path.write_text("[]", encoding="utf-8")
        self.links_path.write_text("[]", encoding="utf-8")
        self.notes_path.write_text(f"# {self.name}\n\nType: {ws_type}\nProfile: {profile}\n\n{description}\n\n## Notes\n\n", encoding="utf-8")

        # If parent, create link
        if parent:
            parent_ws = Workspace(parent, base_dir=self.base_dir)
            if parent_ws.exists():
                # Add child to parent
                parent_meta = parent_ws.load_meta()
                if self.name not in parent_meta.get("children", []):
                    parent_meta["children"].append(self.name)
                    parent_ws.save_meta(parent_meta)

                # Add derived_from link to this workspace
                self.add_link(parent, relation="derived_from", description=f"Forked from {parent}")

        return meta

    def get_targets(self) -> List[Dict[str, Any]]:
        if not self.targets_path.is_file():
            return []
        try:
            return json.loads(self.targets_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def add_target(self, target_path: str, kind: str = "auto", tags: Optional[List[str]] = None, notes: str = "") -> Dict[str, Any]:
        target_path = str(Path(target_path).resolve())
        p = Path(target_path)
        if not p.is_file():
            raise FileNotFoundError(f"Target {target_path} not found")

        # Compute sha256
        h = hashlib.sha256()
        size = 0
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024*1024), b""):
                h.update(chunk)
                size += len(chunk)

        # Auto-detect kind if needed
        if kind == "auto":
            kind = self._detect_kind(p)

        target = WorkspaceTarget(
            path=target_path,
            sha256=h.hexdigest(),
            kind=kind,
            size=size,
            tags=tags or [],
            notes=notes,
        )

        targets = self.get_targets()
        # Deduplicate by sha256
        targets = [t for t in targets if t.get("sha256") != target.sha256]
        targets.append(target.to_dict())

        self.targets_path.write_text(json.dumps(targets, indent=2, ensure_ascii=False), encoding="utf-8")

        # Update stats
        meta = self.load_meta()
        meta["stats"]["targets"] = len(targets)
        self.save_meta(meta)

        return target.to_dict()

    def _detect_kind(self, path: Path) -> str:
        try:
            data = path.read_bytes()[:8192]
        except Exception:
            return "unknown"
        if data.startswith(b"\x7fELF"):
            return "binary"
        if data.startswith(b"PK\x03\x04"):
            return "apk" if b"AndroidManifest" in data or b"classes.dex" in data else "archive"
        if data.startswith(b"MZ"):
            return "binary"
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return "network"
        if path.suffix.lower() in {".c", ".h", ".cpp", ".py", ".go", ".rs", ".java", ".js"}:
            return "source"
        return "firmware" if len(data) > 1024*1024 else "binary"

    def get_findings(self) -> List[Dict[str, Any]]:
        if not self.findings_path.is_file():
            return []
        try:
            return json.loads(self.findings_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def add_findings(self, findings: List[Dict[str, Any]], source: str = "manual") -> int:
        existing = self.get_findings()
        # Deduplicate by type+description hash
        seen = set()
        for f in existing:
            key = f"{f.get('type')}:{f.get('description','')[:100]}:{f.get('file','')}:{f.get('line','')}"
            seen.add(hashlib.md5(key.encode()).hexdigest())

        added = 0
        for f in findings:
            key = f"{f.get('type')}:{f.get('description','')[:100]}:{f.get('file','')}:{f.get('line','')}"
            h = hashlib.md5(key.encode()).hexdigest()
            if h not in seen:
                f["workspace"] = self.name
                f["source"] = source
                f["added_at"] = datetime.now(timezone.utc).isoformat()
                existing.append(f)
                seen.add(h)
                added += 1

        self.findings_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

        meta = self.load_meta()
        meta["stats"]["findings"] = len(existing)
        self.save_meta(meta)

        return added

    def get_links(self) -> List[WorkspaceLink]:
        if not self.links_path.is_file():
            return []
        try:
            data = json.loads(self.links_path.read_text(encoding="utf-8"))
            return [WorkspaceLink.from_dict(d) for d in data]
        except Exception:
            return []

    def add_link(self, target_ws: str, relation: str = "references", description: str = "", shared_items: Optional[List[str]] = None, bidirectional: bool = False) -> WorkspaceLink:
        if relation not in RELATION_TYPES:
            raise ValueError(f"Unknown relation {relation}, must be one of {list(RELATION_TYPES.keys())}")

        if target_ws == self.name:
            raise ValueError("Cannot link workspace to itself")

        target = Workspace(target_ws, base_dir=self.base_dir)
        if not target.exists():
            raise FileNotFoundError(f"Target workspace {target_ws} not found")

        links = self.get_links()
        # Remove existing link to same target with same relation
        links = [l for l in links if not (l.target == target_ws and l.relation == relation)]

        link = WorkspaceLink(
            target=target_ws,
            relation=relation,
            description=description,
            shared_items=shared_items or [],
            bidirectional=bidirectional,
        )
        links.append(link)

        self.links_path.write_text(json.dumps([l.to_dict() for l in links], indent=2, ensure_ascii=False), encoding="utf-8")

        meta = self.load_meta()
        meta["stats"]["links"] = len(links)
        self.save_meta(meta)

        # If bidirectional, add reverse link
        if bidirectional:
            try:
                reverse_relation = relation
                # Map reverse
                reverse_map = {"parent": "child", "child": "parent", "derived_from": "child"}
                reverse_relation = reverse_map.get(relation, relation)
                target.add_link(self.name, relation=reverse_relation, description=f"Reverse of {relation} from {self.name}", shared_items=shared_items, bidirectional=False)
            except Exception:
                pass

        return link

    def remove_link(self, target_ws: str, relation: Optional[str] = None) -> int:
        links = self.get_links()
        original_len = len(links)
        if relation:
            links = [l for l in links if not (l.target == target_ws and l.relation == relation)]
        else:
            links = [l for l in links if l.target != target_ws]

        self.links_path.write_text(json.dumps([l.to_dict() for l in links], indent=2, ensure_ascii=False), encoding="utf-8")

        meta = self.load_meta()
        meta["stats"]["links"] = len(links)
        self.save_meta(meta)

        return original_len - len(links)

    def share_with(self, target_ws: str, items: List[str] = None, relation: str = "shares_target_with") -> Dict[str, Any]:
        """
        Partage sélectif: copie targets/findings/artifacts/notes vers workspace cible
        items: ["targets", "findings", "artifacts", "notes"]
        """
        items = items or ["findings"]
        allowed = {"targets", "findings", "artifacts", "notes"}
        for item in items:
            if item not in allowed:
                raise ValueError(f"Invalid share item {item}, must be one of {allowed}")

        target = Workspace(target_ws, base_dir=self.base_dir)
        if not target.exists():
            raise FileNotFoundError(f"Target workspace {target_ws} not found")

        shared_count = {}

        if "targets" in items:
            my_targets = self.get_targets()
            existing_targets = target.get_targets()
            existing_hashes = {t.get("sha256") for t in existing_targets}
            to_add = [t for t in my_targets if t.get("sha256") not in existing_hashes]
            for t in to_add:
                # Copy file reference, not file itself
                new_targets = target.get_targets()
                new_targets.append(t)
                target.targets_path.write_text(json.dumps(new_targets, indent=2, ensure_ascii=False), encoding="utf-8")
            shared_count["targets"] = len(to_add)

        if "findings" in items:
            my_findings = self.get_findings()
            added = target.add_findings(my_findings, source=f"shared_from_{self.name}")
            shared_count["findings"] = added

        if "artifacts" in items:
            count = 0
            for artifact in self.artifacts_dir.glob("*"):
                if artifact.is_file():
                    dest = target.artifacts_dir / f"{self.name}_{artifact.name}"
                    try:
                        shutil.copy2(artifact, dest)
                        count += 1
                    except Exception:
                        pass
            shared_count["artifacts"] = count

        if "notes" in items:
            my_notes = self.notes_path.read_text(encoding="utf-8") if self.notes_path.is_file() else ""
            target_notes_path = target.notes_path
            existing_notes = target_notes_path.read_text(encoding="utf-8") if target_notes_path.is_file() else ""
            # Append shared notes
            new_notes = existing_notes + f"\n\n---\n\n## Shared from {self.name} ({datetime.now(timezone.utc).isoformat()})\n\n" + my_notes
            target_notes_path.write_text(new_notes, encoding="utf-8")
            shared_count["notes"] = 1

        # Create link with shared items
        self.add_link(target_ws, relation=relation, description=f"Shared {','.join(items)} with {target_ws}", shared_items=items, bidirectional=False)
        target.add_link(self.name, relation=relation, description=f"Received {','.join(items)} from {self.name}", shared_items=items, bidirectional=False)

        return shared_count

    def fork(self, new_name: str, description: str = "") -> "Workspace":
        """Fork workspace: crée nouveau workspace dérivé."""
        new_ws = Workspace(new_name, base_dir=self.base_dir)
        if new_ws.exists():
            raise FileExistsError(f"Workspace {new_name} already exists")

        meta = self.load_meta()

        new_ws.create(
            ws_type=meta.get("type", "custom"),
            profile=meta.get("profile", "full"),
            description=description or f"Forked from {self.name}: {meta.get('description','')}",
            parent=self.name,
            tags=meta.get("tags", []).copy(),
            config_overrides=meta.get("config_overrides", {}).copy(),
            isolation=meta.get("isolation", "private"),
        )

        # Copy targets, findings, notes, artifacts
        if self.targets_path.is_file():
            shutil.copy2(self.targets_path, new_ws.targets_path)
        if self.findings_path.is_file():
            shutil.copy2(self.findings_path, new_ws.findings_path)
        if self.notes_path.is_file():
            # Copy notes but add fork header
            notes = self.notes_path.read_text(encoding="utf-8")
            new_notes = f"# {new_name} (forked from {self.name})\n\n{notes}"
            new_ws.notes_path.write_text(new_notes, encoding="utf-8")
        for artifact in self.artifacts_dir.glob("*"):
            if artifact.is_file():
                try:
                    shutil.copy2(artifact, new_ws.artifacts_dir / artifact.name)
                except Exception:
                    pass

        # Update parent children
        meta = self.load_meta()
        if new_name not in meta.get("children", []):
            meta["children"].append(new_name)
            self.save_meta(meta)

        return new_ws

    def get_tools_info(self) -> Dict[str, Any]:
        """Retourne infos outils disponibles pour ce workspace."""
        from modules.integration.tool_manager import ToolManager

        meta = self.load_meta()
        profile = meta.get("profile", "full")
        priority_tools = meta.get("priority_tools", [])
        config_overrides = meta.get("config_overrides", {})

        # Build config dict for ToolManager
        try:
            from core.config_manager import get_config
            cfg = get_config(profile=profile, force_reload=False)
            # Apply overrides
            for k, v in config_overrides.items():
                if "." in k:
                    parts = k.split(".")
                    current = cfg.config
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = v
                else:
                    cfg.config[k] = v
            config_dict = cfg.to_dict()
        except Exception:
            config_dict = {}

        tm = ToolManager(config=config_dict)
        summary = tm.summary()
        inspected = tm.inspect()

        # Mark priority tools
        for tool in inspected:
            tool["is_priority"] = tool["key"] in priority_tools
            tool["priority_reason"] = f"Prioritaire pour profil {profile} (type {meta.get('type')})" if tool["is_priority"] else ""

        # Group by category with priority first
        by_category = {}
        for tool in inspected:
            cat = tool.get("category", "misc")
            if cat not in by_category:
                by_category[cat] = {"priority": [], "others": [], "all": []}
            by_category[cat]["all"].append(tool)
            if tool["is_priority"]:
                by_category[cat]["priority"].append(tool)
            else:
                by_category[cat]["others"].append(tool)

        return {
            "workspace": self.name,
            "type": meta.get("type"),
            "profile": profile,
            "priority_tools": priority_tools,
            "config_overrides": config_overrides,
            "summary": summary,
            "by_category": by_category,
            "all_tools": inspected,
            "total_tools": len(inspected),
            "present_tools": sum(1 for t in inspected if t["present"]),
            "capabilities": summary.get("capabilities", {}),
        }

    def to_dict(self) -> Dict[str, Any]:
        meta = self.load_meta()
        return {
            **meta,
            "path": str(self.path),
            "targets": self.get_targets(),
            "findings_count": len(self.get_findings()),
            "links": [l.to_dict() for l in self.get_links()],
            "artifacts_count": len(list(self.artifacts_dir.glob("*"))) if self.artifacts_dir.is_dir() else 0,
        }


class WorkspaceManager:
    """Gestionnaire global des workspaces."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.home() / ".r3con" / "workspaces"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def list_workspaces(self) -> List[Dict[str, Any]]:
        workspaces = []
        for ws_dir in self.base_dir.iterdir():
            if ws_dir.is_dir():
                meta_path = ws_dir / "workspace.json"
                if meta_path.is_file():
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                        # Quick stats without loading full
                        targets_path = ws_dir / "targets.json"
                        findings_path = ws_dir / "findings.json"
                        links_path = ws_dir / "links.json"

                        targets_count = 0
                        findings_count = 0
                        links_count = 0

                        try:
                            if targets_path.is_file():
                                targets_count = len(json.loads(targets_path.read_text(encoding="utf-8")))
                        except Exception:
                            pass
                        try:
                            if findings_path.is_file():
                                findings_count = len(json.loads(findings_path.read_text(encoding="utf-8")))
                        except Exception:
                            pass
                        try:
                            if links_path.is_file():
                                links_count = len(json.loads(links_path.read_text(encoding="utf-8")))
                        except Exception:
                            pass

                        workspaces.append({
                            "name": meta.get("name", ws_dir.name),
                            "type": meta.get("type", "custom"),
                            "profile": meta.get("profile", "full"),
                            "description": meta.get("description", "")[:80],
                            "created_at": meta.get("created_at"),
                            "updated_at": meta.get("updated_at"),
                            "tags": meta.get("tags", []),
                            "isolation": meta.get("isolation", "private"),
                            "stats": {
                                "targets": targets_count,
                                "findings": findings_count,
                                "links": links_count,
                            },
                            "path": str(ws_dir),
                        })
                    except Exception:
                        continue
        # Sort by updated_at desc
        workspaces.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return workspaces

    def get_workspace(self, name: str) -> Workspace:
        ws = Workspace(name, base_dir=self.base_dir)
        if not ws.exists():
            raise FileNotFoundError(f"Workspace {name} not found in {self.base_dir}")
        return ws

    def create_workspace(self, name: str, **kwargs) -> Workspace:
        ws = Workspace(name, base_dir=self.base_dir)
        ws.create(**kwargs)
        return ws

    def delete_workspace(self, name: str, force: bool = False) -> bool:
        ws = Workspace(name, base_dir=self.base_dir)
        if not ws.exists():
            raise FileNotFoundError(f"Workspace {name} not found")

        # Check if has children
        meta = ws.load_meta()
        if meta.get("children") and not force:
            raise ValueError(f"Workspace {name} has children {meta['children']}, use --force to delete")

        # Remove links from other workspaces that point to this
        for other in self.list_workspaces():
            if other["name"] == name:
                continue
            try:
                other_ws = Workspace(other["name"], base_dir=self.base_dir)
                other_ws.remove_link(name)
            except Exception:
                pass

        shutil.rmtree(ws.path)
        return True

    def merge_workspaces(self, sources: List[str], target: str, description: str = "") -> Workspace:
        """
        Fusionne plusieurs workspaces sources dans un nouveau workspace cible
        """
        if len(sources) < 2:
            raise ValueError("Need at least 2 sources to merge")

        # Create target workspace
        # Use type of first source as base
        first_ws = self.get_workspace(sources[0])
        first_meta = first_ws.load_meta()

        target_ws = Workspace(target, base_dir=self.base_dir)
        if target_ws.exists():
            raise FileExistsError(f"Target workspace {target} already exists")

        target_ws.create(
            ws_type=first_meta.get("type", "custom"),
            profile=first_meta.get("profile", "full"),
            description=description or f"Merged from {', '.join(sources)}",
            tags=list(set(sum([self.get_workspace(s).load_meta().get("tags", []) for s in sources], []))),
        )

        # Merge targets, findings, artifacts, notes
        all_targets = []
        all_findings = []
        merged_notes = f"# {target} (merged from {', '.join(sources)})\n\n"

        for src_name in sources:
            src_ws = self.get_workspace(src_name)
            all_targets.extend(src_ws.get_targets())
            all_findings.extend(src_ws.get_findings())

            # Notes
            if src_ws.notes_path.is_file():
                notes = src_ws.notes_path.read_text(encoding="utf-8")
                merged_notes += f"\n\n---\n\n## From {src_name}\n\n{notes}"

            # Artifacts
            for artifact in src_ws.artifacts_dir.glob("*"):
                if artifact.is_file():
                    try:
                        shutil.copy2(artifact, target_ws.artifacts_dir / f"{src_name}_{artifact.name}")
                    except Exception:
                        pass

            # Create link
            target_ws.add_link(src_name, relation="merged_from", description=f"Merged from {src_name}")

        # Deduplicate targets by sha256
        seen_hashes = set()
        deduped_targets = []
        for t in all_targets:
            h = t.get("sha256")
            if h not in seen_hashes:
                deduped_targets.append(t)
                seen_hashes.add(h)

        target_ws.targets_path.write_text(json.dumps(deduped_targets, indent=2, ensure_ascii=False), encoding="utf-8")
        target_ws.add_findings(all_findings, source="merged")
        target_ws.notes_path.write_text(merged_notes, encoding="utf-8")

        # Update stats
        meta = target_ws.load_meta()
        meta["stats"]["targets"] = len(deduped_targets)
        meta["stats"]["findings"] = len(target_ws.get_findings())
        target_ws.save_meta(meta)

        return target_ws

    def get_graph(self) -> Dict[str, Any]:
        """Retourne graphe complet des workspaces et liens."""
        workspaces = self.list_workspaces()
        nodes = []
        edges = []

        for ws_info in workspaces:
            ws = Workspace(ws_info["name"], base_dir=self.base_dir)
            try:
                links = ws.get_links()
                nodes.append({
                    "id": ws_info["name"],
                    "type": ws_info["type"],
                    "profile": ws_info["profile"],
                    "tags": ws_info["tags"],
                    "stats": ws_info["stats"],
                })
                for link in links:
                    edges.append({
                        "source": ws_info["name"],
                        "target": link.target,
                        "relation": link.relation,
                        "description": link.description,
                        "shared_items": link.shared_items,
                    })
            except Exception:
                continue

        return {
            "nodes": nodes,
            "edges": edges,
            "total_workspaces": len(nodes),
            "total_links": len(edges),
        }

    def find_related(self, name: str, depth: int = 2) -> Dict[str, Any]:
        """Trouve tous les workspaces liés à un workspace donné (BFS jusqu'à depth)."""
        visited = set()
        queue = [(name, 0)]
        related = []

        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)

            if current != name:
                try:
                    ws = self.get_workspace(current)
                    related.append({
                        "name": current,
                        "depth": d,
                        "meta": ws.load_meta(),
                        "targets_count": len(ws.get_targets()),
                        "findings_count": len(ws.get_findings()),
                    })
                except Exception:
                    continue

            if d < depth:
                try:
                    ws = self.get_workspace(current)
                    for link in ws.get_links():
                        if link.target not in visited:
                            queue.append((link.target, d+1))
                except Exception:
                    pass

        return {
            "source": name,
            "depth": depth,
            "related": related,
            "total_related": len(related),
        }
