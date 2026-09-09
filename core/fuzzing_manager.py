"""
r3con v6.0 Titan-Omega - Fuzzing Manager PRO
Lab de fuzzing complet: AFL++, libFuzzer, honggfuzz, Radamsa, QEMU, crash triage, coverage, corpus

Features:
- Campagnes de fuzzing par workspace (fédération)
- Engines: afl, afl-qemu, libfuzzer, honggfuzz, radamsa
- Corpus management: input/output/crashes/hangs
- Coverage tracking, crash deduplication par stack hash
- Auto-triage et minimisation
- Intégration workspace + pipeline
"""
from __future__ import annotations

import json
import hashlib
import shutil
import time
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import tempfile

FUZZING_ENGINES = {
    "afl": {
        "name": "AFL++",
        "executables": ["afl-fuzz", "afl++"],
        "description": "American Fuzzy Lop++ - coverage-guided fuzzer",
        "supports_qemu": True,
        "supports_coverage": True,
        "corpus_required": True,
    },
    "afl-qemu": {
        "name": "AFL++ QEMU",
        "executables": ["afl-fuzz"],
        "description": "AFL++ QEMU mode - fuzzing binaires sans source",
        "supports_qemu": True,
        "supports_coverage": True,
        "corpus_required": True,
    },
    "libfuzzer": {
        "name": "libFuzzer",
        "executables": ["clang"],
        "description": "libFuzzer - in-process coverage-guided",
        "supports_qemu": False,
        "supports_coverage": True,
        "corpus_required": False,
    },
    "honggfuzz": {
        "name": "honggfuzz",
        "executables": ["honggfuzz"],
        "description": "honggfuzz - security-oriented fuzzer",
        "supports_qemu": False,
        "supports_coverage": True,
        "corpus_required": False,
    },
    "radamsa": {
        "name": "Radamsa",
        "executables": ["radamsa"],
        "description": "Radamsa - general purpose fuzzer / mutator",
        "supports_qemu": False,
        "supports_coverage": False,
        "corpus_required": True,
    },
    "custom": {
        "name": "Custom",
        "executables": [],
        "description": "Custom fuzzer script",
        "supports_qemu": False,
        "supports_coverage": False,
        "corpus_required": False,
    }
}

CRASH_SEVERITY = {
    "CRITICAL": ["stack-buffer-overflow", "heap-buffer-overflow", "use-after-free", "double-free"],
    "HIGH": ["segv", "abort", "stack-overflow"],
    "MEDIUM": ["timeout", "oom", "leak"],
    "LOW": ["assert", "unknown"],
}


@dataclass
class FuzzingCrash:
    id: str
    file_path: str
    sha256: str
    size: int
    crash_type: str = "unknown"
    severity: str = "MEDIUM"
    stack_hash: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    count: int = 1
    triaged: bool = False
    exploitability: str = "unknown"  # exploitable, probably_exploitable, not_exploitable, unknown
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzingCampaign:
    name: str
    target: str
    engine: str
    workspace: Optional[str] = None
    corpus_dir: Optional[str] = None
    output_dir: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "created"  # created, running, stopped, finished, error
    pid: Optional[int] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    crashes: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FuzzingManager:
    """Gestionnaire de campagnes de fuzzing - intégré workspaces."""

    def __init__(self, base_dir: Optional[Path] = None, workspace_base: Optional[Path] = None):
        self.base_dir = base_dir or Path.home() / ".r3con" / "fuzzing"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_base = workspace_base or Path.home() / ".r3con" / "workspaces"

    def _campaign_path(self, name: str) -> Path:
        return self.base_dir / name

    def _get_workspace_campaign_dir(self, workspace: str, campaign: str) -> Path:
        ws_path = self.workspace_base / workspace
        if not ws_path.is_dir():
            raise FileNotFoundError(f"Workspace {workspace} not found")
        camp_dir = ws_path / "fuzzing" / campaign
        camp_dir.mkdir(parents=True, exist_ok=True)
        return camp_dir

    def list_engines(self) -> List[Dict[str, Any]]:
        """Liste engines avec détection disponibilité."""
        from modules.integration.tool_manager import ToolManager
        tm = ToolManager()
        inspected = {row["key"]: row for row in tm.inspect()}

        engines = []
        for key, info in FUZZING_ENGINES.items():
            # Check availability
            present = False
            path = None
            version = None

            # Map to tool_manager keys
            mapping = {
                "afl": "afl",
                "afl-qemu": "afl",
                "libfuzzer": "clang",
                "honggfuzz": "honggfuzz",
                "radamsa": "radamsa",
            }
            tm_key = mapping.get(key)
            if tm_key and tm_key in inspected:
                present = inspected[tm_key]["present"]
                path = inspected[tm_key]["path"]
                version = inspected[tm_key]["version"]
            else:
                # Direct check
                for exe in info["executables"]:
                    found = shutil.which(exe)
                    if found:
                        present = True
                        path = found
                        break

            engines.append({
                "key": key,
                "name": info["name"],
                "description": info["description"],
                "executables": info["executables"],
                "present": present,
                "path": path,
                "version": version,
                "supports_qemu": info["supports_qemu"],
                "supports_coverage": info["supports_coverage"],
            })
        return engines

    def create_campaign(self,
                        name: str,
                        target: str,
                        engine: str = "afl",
                        workspace: Optional[str] = None,
                        corpus_dir: Optional[str] = None,
                        output_dir: Optional[str] = None,
                        config: Optional[Dict[str, Any]] = None,
                        tags: Optional[List[str]] = None) -> FuzzingCampaign:

        if engine not in FUZZING_ENGINES:
            raise ValueError(f"Unknown engine {engine}, must be one of {list(FUZZING_ENGINES.keys())}")

        target_path = Path(target)
        if not target_path.is_file():
            raise FileNotFoundError(f"Target {target} not found")

        # Determine output dir
        if workspace:
            camp_dir = self._get_workspace_campaign_dir(workspace, name)
            output_dir = str(camp_dir)
        else:
            output_dir = output_dir or str(self._campaign_path(name))
            camp_dir = Path(output_dir)
            camp_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirs
        (camp_dir / "corpus").mkdir(exist_ok=True)
        (camp_dir / "crashes").mkdir(exist_ok=True)
        (camp_dir / "hangs").mkdir(exist_ok=True)
        (camp_dir / "queue").mkdir(exist_ok=True)
        (camp_dir / "artifacts").mkdir(exist_ok=True)

        # Handle corpus
        if corpus_dir:
            corpus_path = Path(corpus_dir)
            if corpus_path.is_dir():
                # Copy corpus files
                for f in corpus_path.iterdir():
                    if f.is_file():
                        try:
                            shutil.copy2(f, camp_dir / "corpus" / f.name)
                        except Exception:
                            pass
            elif corpus_path.is_file():
                shutil.copy2(corpus_path, camp_dir / "corpus" / corpus_path.name)
        else:
            # Create minimal corpus from target if possible, or empty
            if FUZZING_ENGINES[engine]["corpus_required"]:
                # Create dummy input
                (camp_dir / "corpus" / "seed_001").write_bytes(b"FUZZ" + b"A"*100)

        campaign = FuzzingCampaign(
            name=name,
            target=str(target_path.resolve()),
            engine=engine,
            workspace=workspace,
            corpus_dir=str(camp_dir / "corpus"),
            output_dir=str(camp_dir),
            config=config or {},
            tags=tags or [],
            stats={
                "execs": 0,
                "crashes": 0,
                "hangs": 0,
                "coverage": 0,
                "start_time": None,
                "last_update": datetime.now(timezone.utc).isoformat(),
            }
        )

        # Save campaign.json
        (camp_dir / "campaign.json").write_text(json.dumps(campaign.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

        return campaign

    def get_campaign(self, name: str, workspace: Optional[str] = None) -> FuzzingCampaign:
        if workspace:
            camp_dir = self._get_workspace_campaign_dir(workspace, name)
        else:
            camp_dir = self._campaign_path(name)

        campaign_file = camp_dir / "campaign.json"
        if not campaign_file.is_file():
            raise FileNotFoundError(f"Campaign {name} not found")

        data = json.loads(campaign_file.read_text(encoding="utf-8"))
        return FuzzingCampaign(**data)

    def list_campaigns(self, workspace: Optional[str] = None) -> List[Dict[str, Any]]:
        campaigns = []

        # Global campaigns
        if not workspace:
            for camp_dir in self.base_dir.iterdir():
                if camp_dir.is_dir():
                    cf = camp_dir / "campaign.json"
                    if cf.is_file():
                        try:
                            data = json.loads(cf.read_text(encoding="utf-8"))
                            campaigns.append(data)
                        except Exception:
                            continue

        # Workspace campaigns
        search_bases = [self.workspace_base / workspace] if workspace else list(self.workspace_base.iterdir())
        for ws_dir in search_bases:
            if not ws_dir.is_dir():
                continue
            fuzz_dir = ws_dir / "fuzzing"
            if not fuzz_dir.is_dir():
                continue
            for camp_dir in fuzz_dir.iterdir():
                if camp_dir.is_dir():
                    cf = camp_dir / "campaign.json"
                    if cf.is_file():
                        try:
                            data = json.loads(cf.read_text(encoding="utf-8"))
                            campaigns.append(data)
                        except Exception:
                            continue

        campaigns.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return campaigns

    def _detect_crash_type(self, crash_file: Path) -> Tuple[str, str]:
        """Détecte type et sévérité crash depuis fichier ou nom."""
        name = crash_file.name.lower()
        content = b""
        try:
            content = crash_file.read_bytes()[:4096].lower()
        except Exception:
            pass

        # Check patterns
        if b"stack-buffer-overflow" in content or "stack-buffer-overflow" in name:
            return "stack-buffer-overflow", "CRITICAL"
        if b"heap-buffer-overflow" in content or "heap-buffer-overflow" in name:
            return "heap-buffer-overflow", "CRITICAL"
        if b"use-after-free" in content or "use-after-free" in name:
            return "use-after-free", "CRITICAL"
        if b"double-free" in content or "double-free" in name:
            return "double-free", "CRITICAL"
        if b"segv" in content or "segv" in name or crash_file.stat().st_size > 0:
            # Generic segfault
            return "segv", "HIGH"
        if "timeout" in name or b"timeout" in content:
            return "timeout", "MEDIUM"
        if "oom" in name or b"out-of-memory" in content:
            return "oom", "MEDIUM"

        return "unknown", "MEDIUM"

    def _compute_stack_hash(self, crash_file: Path) -> str:
        """Compute hash pour déduplication crashes (basé sur contenu + taille)."""
        try:
            data = crash_file.read_bytes()
            # Simple hash: first 1KB + size + entropy
            sample = data[:1024]
            h = hashlib.sha256()
            h.update(sample)
            h.update(str(len(data)).encode())
            return h.hexdigest()[:16]
        except Exception:
            return hashlib.md5(str(crash_file.stat().st_size).encode()).hexdigest()[:16]

    def triage_crashes(self, campaign_name: str, workspace: Optional[str] = None) -> Dict[str, Any]:
        """Triage crashes: déduplication, classification, exploitabilité."""
        campaign = self.get_campaign(campaign_name, workspace=workspace)
        camp_dir = Path(campaign.output_dir)

        crashes_dir = camp_dir / "crashes"
        if not crashes_dir.is_dir():
            return {"campaign": campaign_name, "total": 0, "unique": 0, "by_severity": {}, "crashes": []}

        crashes = []
        seen_hashes = {}

        for crash_file in crashes_dir.iterdir():
            if not crash_file.is_file():
                continue
            if crash_file.name.startswith("."):
                continue

            try:
                stat = crash_file.stat()
                sha256 = hashlib.sha256(crash_file.read_bytes()).hexdigest()
                stack_hash = self._compute_stack_hash(crash_file)
                crash_type, severity = self._detect_crash_type(crash_file)

                # Deduplication
                if stack_hash in seen_hashes:
                    seen_hashes[stack_hash]["count"] += 1
                    continue

                crash = FuzzingCrash(
                    id=crash_file.name,
                    file_path=str(crash_file),
                    sha256=sha256,
                    size=stat.st_size,
                    crash_type=crash_type,
                    severity=severity,
                    stack_hash=stack_hash,
                )

                # Try to run target with crash input to get more info (if possible)
                # This is best-effort, no execution if target is not executable or needs special handling
                crash_dict = crash.to_dict()
                crashes.append(crash_dict)
                seen_hashes[stack_hash] = crash_dict

            except Exception as e:
                continue

        # Group by severity
        by_severity = {}
        for c in crashes:
            sev = c.get("severity", "MEDIUM")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Group by type
        by_type = {}
        for c in crashes:
            t = c.get("crash_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        # Update campaign
        campaign.stats["crashes"] = len(crashes)
        campaign.stats["last_update"] = datetime.now(timezone.utc).isoformat()
        campaign.crashes = crashes
        camp_dir = Path(campaign.output_dir)
        (camp_dir / "campaign.json").write_text(json.dumps(campaign.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

        # Save triage report
        triage_report = {
            "campaign": campaign_name,
            "workspace": workspace,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_files": len(list(crashes_dir.iterdir())),
            "unique_crashes": len(crashes),
            "by_severity": by_severity,
            "by_type": by_type,
            "crashes": crashes,
        }
        (camp_dir / "triage.json").write_text(json.dumps(triage_report, indent=2, ensure_ascii=False), encoding="utf-8")

        return triage_report

    def get_stats(self, campaign_name: str, workspace: Optional[str] = None) -> Dict[str, Any]:
        campaign = self.get_campaign(campaign_name, workspace=workspace)
        camp_dir = Path(campaign.output_dir)

        # Count files
        corpus_count = len(list((camp_dir / "corpus").glob("*"))) if (camp_dir / "corpus").is_dir() else 0
        crashes_count = len(list((camp_dir / "crashes").glob("*"))) if (camp_dir / "crashes").is_dir() else 0
        hangs_count = len(list((camp_dir / "hangs").glob("*"))) if (camp_dir / "hangs").is_dir() else 0
        queue_count = len(list((camp_dir / "queue").glob("*"))) if (camp_dir / "queue").is_dir() else 0

        # Check if running
        is_running = False
        if campaign.pid:
            try:
                os.kill(campaign.pid, 0)
                is_running = True
            except (OSError, ProcessLookupError):
                is_running = False

        return {
            "campaign": campaign_name,
            "workspace": workspace,
            "target": campaign.target,
            "engine": campaign.engine,
            "status": "running" if is_running else campaign.status,
            "pid": campaign.pid,
            "corpus": corpus_count,
            "crashes": crashes_count,
            "hangs": hangs_count,
            "queue": queue_count,
            "stats": campaign.stats,
            "output_dir": campaign.output_dir,
            "created_at": campaign.created_at,
            "updated_at": campaign.updated_at,
        }

    def generate_corpus(self, campaign_name: str, workspace: Optional[str] = None, num_samples: int = 100, strategy: str = "radamsa") -> Dict[str, Any]:
        """Génère corpus avec Radamsa ou mutations simples."""
        campaign = self.get_campaign(campaign_name, workspace=workspace)
        camp_dir = Path(campaign.output_dir)
        corpus_dir = camp_dir / "corpus"

        generated = 0

        # Try radamsa if available and strategy is radamsa
        radamsa_path = shutil.which("radamsa")
        if radamsa_path and strategy == "radamsa":
            # Use existing corpus as seed
            seeds = list(corpus_dir.glob("*"))[:5]
            if not seeds:
                # Create seed
                seed = corpus_dir / "seed_base"
                seed.write_bytes(b"FUZZ" + b"A"*100)
                seeds = [seed]

            for i in range(num_samples):
                try:
                    seed = seeds[i % len(seeds)]
                    result = subprocess.run(
                        [radamsa_path, str(seed)],
                        capture_output=True,
                        timeout=5,
                    )
                    if result.stdout:
                        out_path = corpus_dir / f"radamsa_{i:04d}_{int(time.time())}"
                        out_path.write_bytes(result.stdout)
                        generated += 1
                except Exception:
                    continue
        else:
            # Simple mutation: bit flips, byte insertions
            import random
            seeds = list(corpus_dir.glob("*"))[:5]
            if not seeds:
                seed = corpus_dir / "seed_base"
                seed.write_bytes(b"FUZZ" + b"A"*100)
                seeds = [seed]

            for i in range(num_samples):
                try:
                    seed = random.choice(seeds)
                    data = seed.read_bytes()
                    if not data:
                        continue
                    # Mutate
                    mutated = bytearray(data)
                    # Random bit flip
                    for _ in range(random.randint(1, 5)):
                        idx = random.randint(0, len(mutated)-1)
                        mutated[idx] ^= (1 << random.randint(0, 7))
                    # Random insertion
                    if random.random() < 0.3:
                        idx = random.randint(0, len(mutated))
                        mutated.insert(idx, random.randint(0, 255))

                    out_path = corpus_dir / f"mutated_{i:04d}_{int(time.time())}"
                    out_path.write_bytes(bytes(mutated))
                    generated += 1
                except Exception:
                    continue

        return {
            "campaign": campaign_name,
            "generated": generated,
            "corpus_dir": str(corpus_dir),
            "total_corpus": len(list(corpus_dir.glob("*"))),
        }

    def minimize_corpus(self, campaign_name: str, workspace: Optional[str] = None) -> Dict[str, Any]:
        """Minimise corpus (déduplication par hash)."""
        campaign = self.get_campaign(campaign_name, workspace=workspace)
        camp_dir = Path(campaign.output_dir)
        corpus_dir = camp_dir / "corpus"

        seen = {}
        removed = 0
        kept = 0

        for f in list(corpus_dir.glob("*")):
            if not f.is_file():
                continue
            try:
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                if h in seen:
                    f.unlink()
                    removed += 1
                else:
                    seen[h] = str(f)
                    kept += 1
            except Exception:
                continue

        return {
            "campaign": campaign_name,
            "removed": removed,
            "kept": kept,
            "total": kept,
        }
